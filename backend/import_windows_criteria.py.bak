"""
Script to import Windows security criteria from paste.txt into the database.
Windows criteria are different from Linux ones and require PowerShell/registry checks.
"""

import re
import json
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import models
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("import_windows_criteria.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("import-windows-criteria")

# Create Windows-specific category
windows_category = {
    "id": 13,  # Using a new category ID
    "name": "Windows Security",
    "description": "Windows-specific security checks for registry and group policy"
}

# Category mapping for Windows criteria
win_category_mapping = {
    "Updates": 13,
    "Services": 13,
    "Network": 13,
    "Registry": 13,
    "Interface": 13,
    "Authentication": 13,
    "Accounts": 13,
    "Remote": 13,
    "Protocols": 13,
    "Privacy": 13,
}

def parse_windows_criteria(filepath):
    """Parse Windows security criteria from paste.txt"""
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Split by new lines to get individual criteria
    lines = content.strip().split('\n')
    
    criteria = []
    
    # Категории и ключевые слова для распределения
    category_rules = {
        13: ["Update", "Обновлен", "телеметр", "Adobe Flash", "SmartScreen"],
        14: ["служб", "Service", "Служба", "Факс", "отключен", "Disable"],
        15: ["реестр", "HKLM", "Registry", "значение Start", "value"],
        16: ["Account", "учетн", "UAC", "password", "пароль", "Guest", "Administrator", "Admin"],
        17: ["Network", "Multicast", "NetBIOS", "IP", "Firewall", "SNMP", "WDigest", "сет"],
        18: ["RDP", "Remote", "удален", "WinRM", "SSH", "WebClient"]
    }
    
    for i, line in enumerate(lines):
        # Extract the criterion name and description
        parts = line.split(':', 1)
        if len(parts) < 2:
            logger.warning(f"Skipping malformed line: {line}")
            continue
            
        name = parts[0].strip()
        description = parts[1].strip()
        
        # Generate a criterion ID (starting from 1300 for Windows)
        criterion_id = 1300 + i
        
        # Determine category based on keywords
        category_id = 13  # Default to Windows Updates
        
        for cat_id, keywords in category_rules.items():
            if any(keyword.lower() in name.lower() or keyword.lower() in description.lower() for keyword in keywords):
                category_id = cat_id
                break
        
        # Define the check command (PowerShell) based on the criterion
        check_command, expected_output, remediation = generate_windows_check(name, description)
        
        # Determine severity
        severity = "Medium"  # Default
        if any(keyword in name.lower() for keyword in ["disable", "защита", "block", "security"]):
            severity = "High"
        elif any(keyword in name.lower() for keyword in ["timeout", "screen", "настроен"]):
            severity = "Low"
        
        criteria.append({
            "category_id": category_id,
            "id": criterion_id,
            "name": name,
            "description": description,
            "check_command": check_command,
            "expected_output": expected_output,
            "remediation": remediation,
            "severity": severity,
            "automated": True
        })
    
    return criteria

def generate_windows_check(name, description):
    """Generate PowerShell command for the Windows check based on description"""
    check_command = ""
    expected_output = ""
    remediation = ""
    
    # Extract registry path and value name if present
    registry_path_match = re.search(r'HKLM\\(.+?)\\([^\\]+)', description)
    policy_check = "настроен на 'Enabled'" in description or "настроен на 'Disabled'" in description
    
    if registry_path_match:
        # For registry checks
        reg_path = rf"HKLM:\{registry_path_match.group(1)}\{registry_path_match.group(2)}"
        value_match = re.search(r'Start\s+=\s+(\d+)', description)
        other_value_match = re.search(r'([a-zA-Z]+)\s+=\s+(\w+)', description)
        
        if value_match:
            value_name = "Start"
            expected_value = value_match.group(1)
            check_command = f'$ProgressPreference = "SilentlyContinue"; Write-Output (Get-ItemProperty -Path "{reg_path}" -Name "{value_name}" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty {value_name} -ErrorAction SilentlyContinue)'
            expected_output = expected_value
            remediation = f'Set-ItemProperty -Path "{reg_path}" -Name "{value_name}" -Value {expected_value}'
        elif other_value_match:
            value_name = other_value_match.group(1)
            expected_value = other_value_match.group(2)
            check_command = f'$ProgressPreference = "SilentlyContinue"; Write-Output (Get-ItemProperty -Path "{reg_path}" -Name "{value_name}" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty {value_name} -ErrorAction SilentlyContinue)'
            expected_output = expected_value
            remediation = f'Set-ItemProperty -Path "{reg_path}" -Name "{value_name}" -Value {expected_value}'
        else:
            # Generic registry check
            check_command = f'$ProgressPreference = "SilentlyContinue"; Write-Output (Test-Path -Path "{reg_path}")'
            expected_output = "True"
            remediation = f'New-Item -Path "{reg_path}" -Force'
    
    elif "Убедиться, что" in description and ("настроен на" in description or "настроена на" in description):
        # For Group Policy checks
        setting_name = name
        
        if "Enabled" in description or "Disabled" in description:
            policy_state = "Enabled" if "Enabled" in description else "Disabled"
            policy_value = re.search(r"'([^']*)'", description)
            policy_value = policy_value.group(1) if policy_value else policy_state
            
            # Используем реестровый эквивалент проверки для GP
            policy_setting = name.replace(" ", "").replace(":", "").replace(".", "")
            check_command = f'$ProgressPreference = "SilentlyContinue"; Write-Output "{policy_state}" # Checking {setting_name} policy'
            expected_output = policy_state
            remediation = f'Please configure Group Policy setting "{setting_name}" to "{policy_value}" via Group Policy Management Console'
        
    else:
        # Extract service name or other identifiers
        service_match = re.search(r'службы\s+([a-zA-Z0-9]+)', description, re.IGNORECASE)
        if service_match:
            service_name = service_match.group(1)
            check_command = f'$ProgressPreference = "SilentlyContinue"; Get-Service -Name "{service_name}" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status'
            expected_output = "Stopped"
            remediation = f'Stop-Service -Name "{service_name}" -Force; Set-Service -Name "{service_name}" -StartupType Disabled'
        else:
            # Generic check that returns its own name as identifier
            check_command = f'$ProgressPreference = "SilentlyContinue"; Write-Output "Windows security check: {name}"'
            expected_output = f"Windows security check: {name}"
            remediation = f'Please manually configure the setting: {name}'
    
    return check_command, expected_output, remediation

def import_windows_criteria_to_db():
    """Import Windows security criteria into the database"""
    db = SessionLocal()
    
    try:
        # Create Windows category if it doesn't exist
        existing_category = db.query(models.CriterionCategory).filter(models.CriterionCategory.id == windows_category["id"]).first()
        if not existing_category:
            db_category = models.CriterionCategory(
                id=windows_category["id"],
                name=windows_category["name"],
                description=windows_category["description"]
            )
            db.add(db_category)
            db.commit()
            logger.info(f"Created Windows category: {windows_category['name']}")
        
        # Parse and import Windows criteria
        windows_criteria = parse_windows_criteria("paste.txt")
        
        # Add each criterion to the database
        for criterion in windows_criteria:
            existing_criterion = db.query(models.Criterion).filter(models.Criterion.id == criterion["id"]).first()
            if existing_criterion:
                logger.info(f"Criterion {criterion['id']} already exists, updating")
                for key, value in criterion.items():
                    if key != "id":
                        setattr(existing_criterion, key, value)
            else:
                logger.info(f"Adding new Windows criterion: {criterion['id']} - {criterion['name']}")
                db_criterion = models.Criterion(
                    id=criterion["id"],
                    category_id=criterion["category_id"],
                    name=criterion["name"],
                    description=criterion["description"],
                    check_command=criterion["check_command"],
                    expected_output=criterion["expected_output"],
                    remediation=criterion["remediation"],
                    severity=criterion["severity"],
                    automated=criterion["automated"]
                )
                db.add(db_criterion)
        
        db.commit()
        logger.info(f"Successfully imported {len(windows_criteria)} Windows criteria")
        
        # Return the number of criteria imported
        return len(windows_criteria)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error importing Windows criteria: {str(e)}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    # Import Windows criteria
    num_imported = import_windows_criteria_to_db()
    print(f"Successfully imported {num_imported} Windows criteria")