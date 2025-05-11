
def determine_status(criterion_id, output, expected):
    """
    Correctly determines the status of a security check based on criterion-specific rules.
    
    Args:
        criterion_id: The ID of the criterion being checked
        output: The actual output from the command
        expected: The expected output for a passing check
        
    Returns:
        "Pass" if the check passes, "Fail" if it fails
    """
    # Load criterion-specific rules
    try:
        with open("criterion_rules.json", "r") as f:
            rules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # If rules file is missing or invalid, fall back to basic logic
        return "Pass" if expected and expected in output else "Fail"
    
    # Get the rule for this criterion
    rule = rules.get(str(criterion_id), {"check_type": "exact_match", "expected": expected})
    
    # Apply the appropriate check logic based on rule type
    if rule["check_type"] == "empty_result_is_pass":
        # For find commands that expect empty results
        return "Pass" if not output.strip() else "Fail"
        
    elif rule["check_type"] == "no_found_is_pass":
        # For "No X found" patterns
        no_found_patterns = ["No world-writable", "No unowned", "No .netrc files found", 
                           "No empty passwords", "No unconfined daemons"]
        return "Pass" if any(pattern in output for pattern in no_found_patterns) else "Fail"
        
    elif rule["check_type"] == "negative_is_pass":
        # For "not installed", "disabled", etc.
        negative_patterns = ["not installed", "disabled", "Prelink not installed", 
                           "No active wireless interfaces"]
        return "Pass" if any(pattern in output for pattern in negative_patterns) else "Fail"
        
    elif rule["check_type"] == "correct_is_pass":
        # For "correctly configured" checks
        return "Pass" if "correct" in output.lower() or "properly configured" in output.lower() else "Fail"
        
    else:
        # Default exact match check
        return "Pass" if expected and expected in output else "Fail"
