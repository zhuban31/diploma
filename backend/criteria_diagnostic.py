"""
Diagnostic tool for security criteria checks.
Analyzes all criteria in the database and verifies the check logic.
"""

import os
from database import SessionLocal, engine, Base
import models
import logging
import re

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("criteria_diagnostic.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("criteria-diagnostic")

def analyze_criteria_checks():
    """Analyze all criteria in the database and classify their check logic"""
    db = SessionLocal()
    
    try:
        # Get all criteria
        all_criteria = db.query(models.Criterion).all()
        logger.info(f"Found {len(all_criteria)} criteria in database")
        
        # Define categories of checks
        categories = {
            "standard_presence": [],    # Standard check for presence of text
            "standard_absence": [],     # Check for absence (empty result is good)
            "no_found": [],            # Checks with "No X found" pattern
            "not_something": [],       # Negative checks (not installed, not enabled)
            "complex": [],             # Complex checks that need special handling
            "exit_codes": [],          # Checks that rely on exit codes
            "uncommon": []             # Other uncommon patterns
        }
        
        # Patterns for classification
        patterns = {
            "no_found": r"No\s+\w+(?:\s+\w+)*\s+found",
            "not_something": r"not\s+(?:installed|enabled|configured|running|active)",
            "exit_code": r"exit\s+(?:code|status)",
            "permission_correct": r"Permission(?:s)?\s+correct",
            "correctly_configured": r"Correctly\s+configured",
            "properly_configured": r"properly\s+configured",
            "is_enabled": r"is[-\s]enabled",
            "is_active": r"is[-\s]active",
        }
        
        # Analyze each criterion
        for criterion in all_criteria:
            cmd = criterion.check_command
            expected = criterion.expected_output
            
            # Check for empty command
            if not cmd:
                logger.warning(f"Criterion {criterion.id} ({criterion.name}) has no check command")
                categories["uncommon"].append(criterion.id)
                continue
            
            # Check for empty expected output
            if not expected:
                # Empty expected output usually means we expect no output
                categories["standard_absence"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} has empty expected output - classified as 'standard_absence'")
                continue
            
            # Use patterns to classify
            if re.search(patterns["no_found"], expected, re.IGNORECASE):
                categories["no_found"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} checks for 'No X found' pattern")
            
            elif re.search(patterns["not_something"], expected, re.IGNORECASE):
                categories["not_something"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} checks for 'not something' pattern")
            
            elif re.search(patterns["exit_code"], cmd, re.IGNORECASE):
                categories["exit_codes"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} appears to check exit codes")
            
            elif re.search(patterns["permission_correct"], expected, re.IGNORECASE) or \
                 re.search(patterns["correctly_configured"], expected, re.IGNORECASE) or \
                 re.search(patterns["properly_configured"], expected, re.IGNORECASE):
                categories["complex"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} checks for correct configuration/permissions")
            
            elif re.search(patterns["is_enabled"], expected, re.IGNORECASE) or \
                 re.search(patterns["is_active"], expected, re.IGNORECASE):
                categories["complex"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} checks for enabled/active state")
            
            elif cmd == "find /home -name .forward" or \
                 cmd == "find /home -name .netrc":
                # Special case for find commands that expect empty results
                categories["standard_absence"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} uses find command expecting no results")
            
            else:
                # Standard check for presence
                categories["standard_presence"].append(criterion.id)
                logger.info(f"Criterion {criterion.id} uses standard presence check")
        
        # Print summary
        print("\n" + "="*80)
        print("SECURITY CRITERIA CHECK ANALYSIS")
        print("="*80)
        print(f"\nTotal criteria analyzed: {len(all_criteria)}")
        print("\nBreakdown by check type:")
        for category, ids in categories.items():
            print(f"- {category}: {len(ids)} criteria")
            if len(ids) > 0:
                print(f"  Examples: {', '.join(str(i) for i in ids[:5])}" + 
                     (f"... and {len(ids)-5} more" if len(ids) > 5 else ""))
        
        print("\nRecommendation:")
        if len(categories["complex"]) > 0 or len(categories["not_something"]) > 0 or len(categories["no_found"]) > 0:
            print("- Use the enhanced fix that handles special cases")
            print("- The criteria requiring special handling are:")
            if len(categories["no_found"]) > 0:
                print(f"  - 'No X found' pattern: {categories['no_found']}")
            if len(categories["not_something"]) > 0:
                print(f"  - 'Not installed/enabled' pattern: {categories['not_something']}")
            if len(categories["complex"]) > 0:
                print(f"  - Complex configuration checks: {categories['complex']}")
        else:
            print("- The simple fix should handle all your criteria")
        
        print("="*80)
        
    except Exception as e:
        logger.error(f"Error analyzing criteria: {str(e)}")
    finally:
        db.close()

def analyze_last_scan_for_errors():
    """Find inconsistencies in the last scan results"""
    db = SessionLocal()
    
    try:
        # Get the last scan
        last_scan = db.query(models.Scan).order_by(models.Scan.id.desc()).first()
        if not last_scan:
            print("No scans found in the database.")
            return
        
        print(f"\nAnalyzing results from the last scan (ID: {last_scan.id}, Server: {last_scan.server_ip})")
        
        # Get results from the last scan
        results = db.query(models.ScanResult).filter(models.ScanResult.scan_id == last_scan.id).all()
        print(f"Found {len(results)} results in the last scan")
        
        # Get criteria for these results
        criterion_ids = [r.criterion_id for r in results]
        criteria = db.query(models.Criterion).filter(models.Criterion.id.in_(criterion_ids)).all()
        criteria_dict = {c.id: c for c in criteria}
        
        # Analyze results
        inconsistencies = []
        for result in results:
            criterion = criteria_dict.get(result.criterion_id)
            if not criterion:
                continue
                
            expected = criterion.expected_output
            details = result.details
            status = result.status
            
            # Check for potential inconsistencies
            if status == "Pass":
                # If passed, check if expected output is actually in the details
                if expected and expected not in details:
                    inconsistencies.append({
                        "criterion_id": result.criterion_id,
                        "name": criterion.name,
                        "expected": expected,
                        "actual": details[:100] + "..." if len(details) > 100 else details,
                        "status": status
                    })
            elif status == "Fail":
                # If failed, check if the expected output is actually there
                if expected and expected in details:
                    inconsistencies.append({
                        "criterion_id": result.criterion_id,
                        "name": criterion.name,
                        "expected": expected,
                        "actual": details[:100] + "..." if len(details) > 100 else details,
                        "status": status
                    })
        
        # Print inconsistencies
        if inconsistencies:
            print("\nPotential inconsistencies found:")
            for i, inconsistency in enumerate(inconsistencies, 1):
                print(f"\n{i}. Criterion {inconsistency['criterion_id']} ({inconsistency['name']})")
                print(f"   Status: {inconsistency['status']}")
                print(f"   Expected: '{inconsistency['expected']}'")
                print(f"   Actual: '{inconsistency['actual']}'")
        else:
            print("\nNo obvious inconsistencies found in the last scan.")
        
    except Exception as e:
        logger.error(f"Error analyzing last scan: {str(e)}")
    finally:
        db.close()

if __name__ == "__main__":
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    # Analyze criteria
    analyze_criteria_checks()
    
    # Analyze last scan results
    analyze_last_scan_for_errors()