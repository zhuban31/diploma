"""
Complete rewrite of the status evaluation logic for security criteria checks.
This script fixes the critical issue where failed checks are incorrectly marked as passed.
"""

import os
from database import SessionLocal, engine, Base
import models
import logging
import re
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("status_evaluation_fix.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("status-evaluation-fix")

def analyze_all_criteria():
    """Analyze all criteria in the database and create the correct status determination rules"""
    db = SessionLocal()
    
    try:
        all_criteria = db.query(models.Criterion).all()
        logger.info(f"Analyzing {len(all_criteria)} criteria to create proper evaluation rules")
        
        # Create a comprehensive set of rules for each criterion
        rules = {}
        
        for criterion in all_criteria:
            criterion_rule = {
                "id": criterion.id,
                "name": criterion.name,
                "expected": criterion.expected_output,
                "check_type": "exact_match"  # Default rule type
            }
            
            # Special case for empty/absent checks
            if criterion.check_command.startswith("find") and (not criterion.expected_output or criterion.expected_output.strip() == ""):
                criterion_rule["check_type"] = "empty_result_is_pass"
                logger.info(f"Criterion {criterion.id}: Using empty_result_is_pass rule")
            
            # Special cases for "No X found" patterns
            elif any(pattern in criterion.expected_output for pattern in ["No world-writable", "No unowned", "No .netrc", "No empty passwords"]):
                criterion_rule["check_type"] = "no_found_is_pass"
                logger.info(f"Criterion {criterion.id}: Using no_found_is_pass rule")
            
            # Special cases for "not installed", "not enabled", etc.
            elif any(pattern in criterion.expected_output for pattern in ["not installed", "disabled", "Prelink not installed"]):
                criterion_rule["check_type"] = "negative_is_pass"
                logger.info(f"Criterion {criterion.id}: Using negative_is_pass rule")
            
            # Cases with "correct/properly configured" checks
            elif "correct" in criterion.expected_output.lower() or "properly configured" in criterion.expected_output.lower():
                criterion_rule["check_type"] = "correct_is_pass"
                logger.info(f"Criterion {criterion.id}: Using correct_is_pass rule")
                
            # Standard presence check (default)
            else:
                logger.info(f"Criterion {criterion.id}: Using standard exact_match rule")
            
            rules[criterion.id] = criterion_rule
        
        # Save rules to file
        with open("criterion_rules.json", "w") as f:
            json.dump(rules, f, indent=2)
            
        logger.info(f"Created evaluation rules for {len(rules)} criteria")
        return rules
        
    except Exception as e:
        logger.error(f"Error analyzing criteria: {str(e)}")
    finally:
        db.close()

def generate_fixed_function(rules):
    """Generate a fixed version of the status determination code"""
    
    fixed_function = '''
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
'''
    
    return fixed_function

def generate_perform_scan_rewrite():
    """Generate a complete rewrite of the perform_scan function with fixed status logic"""
    
    perform_scan_code = '''
async def perform_scan(server_ip, username, password, ssh_key, connection_type, criteria, use_sudo=False):
    """
    Выполняет сканирование сервера на соответствие указанным критериям.
    Возвращает список результатов сканирования.
    """
    results = []
    
    try:
        # Подключаемся к серверу по SSH
        if connection_type == "ssh":
            logger.info(f"Подключение к серверу {server_ip} по SSH с пользователем {username}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_key:
                logger.info(f"Используется SSH-ключ: {ssh_key}")
                private_key = paramiko.RSAKey.from_private_key_file(ssh_key)
                client.connect(server_ip, username=username, pkey=private_key)
            else:
                logger.info("Используется аутентификация по паролю")
                client.connect(server_ip, username=username, password=password)
                
            logger.info(f"Успешное подключение к {server_ip}. Начинаем выполнение проверок.")
            
            # Проверка доступности sudo, если требуется
            if use_sudo:
                logger.info("Проверка работоспособности sudo...")
                # Тест без sudo
                stdin, stdout, stderr = client.exec_command("id")
                output_without_sudo = stdout.read().decode('utf-8')
                error_without_sudo = stderr.read().decode('utf-8')
                logger.info(f"Тест без sudo: {output_without_sudo}")
                
                # Тест с sudo -n (проверка без пароля)
                stdin, stdout, stderr = client.exec_command("sudo -n id")
                output_with_sudo_n = stdout.read().decode('utf-8')
                error_with_sudo_n = stderr.read().decode('utf-8')
                logger.info(f"Тест с sudo -n: {output_with_sudo_n}, ошибки: {error_with_sudo_n}")
                
                # Если sudo -n не работает, настраиваем временный доступ
                if "password is required" in error_with_sudo_n:
                    logger.info("Sudo -n не работает, пробуем настроить временный sudo доступ")
                    # Создаем временный файл sudoers
                    sudo_command = f'echo "{password}" | sudo -S echo "Настройка временного sudo"'
                    stdin, stdout, stderr = client.exec_command(sudo_command)
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    logger.info(f"Настройка временного sudo: {error}")
                
                    # Создаем временное sudoers правило
                    temp_sudoers_cmd = f"""echo "{password}" | sudo -S bash -c 'echo "{username} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/temp_{username}'"""
                    stdin, stdout, stderr = client.exec_command(temp_sudoers_cmd)
                    
                    # Убедимся, что правило применилось
                    stdin, stdout, stderr = client.exec_command("sudo -n id")
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    
                    if "password is required" in error:
                        logger.warning("Не удалось настроить sudo без пароля, будем использовать обычный sudo")
                        use_sudo_command = f'echo "{password}" | sudo -S'
                    else:
                        use_sudo_command = "sudo -n"
                else:
                    use_sudo_command = "sudo -n"
            
            # Для каждого критерия выполняем проверку
            for criterion in criteria:
                try:
                    # Получаем команду проверки
                    cmd = criterion.check_command
                    
                    logger.info(f"Выполнение команды для критерия {criterion.id} ({criterion.name}): {cmd}")
                    
                    # Проверяем, что команда не пустая
                    if not cmd:
                        logger.warning(f"Пустая команда для критерия {criterion.id}. Пропускаем.")
                        results.append({
                            "criterion_id": criterion.id,
                            "status": "Error",
                            "details": "Команда проверки не определена",
                            "remediation": criterion.remediation
                        })
                        continue
                    
                    # Если нужно использовать sudo, добавляем его к команде
                    if use_sudo and not cmd.startswith("sudo "):
                        original_cmd = cmd
                        cmd = f"{use_sudo_command} {cmd}"
                    
                    # Создаем скрипт для выполнения команды с дополнительным контекстом
                    script_content = f"""#!/bin/bash
echo "=== НАЧАЛО ВЫПОЛНЕНИЯ КОМАНДЫ ==="
echo "Команда: {cmd}"
echo "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ==="
{cmd} 2>&1 || echo "Команда завершилась с ошибкой: $?"
echo "=== КОНЕЦ ВЫПОЛНЕНИЯ ==="
"""
                    # Создаем временный скрипт на удаленном сервере
                    create_script_cmd = f"cat > /tmp/scan_cmd.sh << 'EOF'\\n{script_content}\\nEOF\\nchmod +x /tmp/scan_cmd.sh"
                    stdin, stdout, stderr = client.exec_command(create_script_cmd)
                    
                    # Выполняем скрипт
                    stdin, stdout, stderr = client.exec_command("bash /tmp/scan_cmd.sh")
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    
                    # Удаляем временный скрипт
                    client.exec_command("rm -f /tmp/scan_cmd.sh")
                    
                    # Логируем вывод команды
                    logger.info(f"Результат выполнения команды для критерия {criterion.id}:")
                    logger.info(f"STDOUT: {output}")
                    if error:
                        logger.info(f"STDERR: {error}")
                    
                    # Проверка на ошибки sudo
                    if use_sudo and "sudo:" in error and "command not found" in error:
                        logger.error(f"Ошибка sudo для критерия {criterion.id}: {error}")
                        results.append({
                            "criterion_id": criterion.id,
                            "status": "Error",
                            "details": f"Ошибка выполнения sudo команды: {error}",
                            "remediation": criterion.remediation
                        })
                        continue
                    
                    # Добавляем более очевидные сообщения для пустого вывода
                    if not output.strip() and not error.strip():
                        output = "Команда выполнена, но не вернула никакого вывода"
                    
                    # Анализируем результат и определяем статус
                    expected = criterion.expected_output
                    logger.info(f"Сравниваем с ожидаемым результатом: '{expected}'")
                    
                    # ПОЛНОСТЬЮ ПЕРЕРАБОТАННАЯ ЛОГИКА ОПРЕДЕЛЕНИЯ СТАТУСА
                    # Используем отдельную функцию для определения статуса
                    status = determine_status(criterion.id, output, expected)
                    
                    # Логируем определенный статус
                    if status == "Pass":
                        logger.info(f"Критерий {criterion.id} ПРОЙДЕН")
                    else:
                        logger.info(f"Критерий {criterion.id} НЕ ПРОЙДЕН")
                    
                    # Добавляем результат с правильно определенным статусом
                    results.append({
                        "criterion_id": criterion.id,
                        "status": status,
                        "details": output,
                        "remediation": criterion.remediation if status == "Fail" else ""
                    })
                    
                except Exception as e:
                    # В случае ошибки при выполнении проверки
                    logger.error(f"Ошибка при выполнении команды для критерия {criterion.id}: {str(e)}")
                    results.append({
                        "criterion_id": criterion.id,
                        "status": "Error",
                        "details": f"Ошибка при выполнении проверки: {str(e)}",
                        "remediation": criterion.remediation
                    })
            
            # Удаляем временный файл sudoers, если он был создан
            if use_sudo and "temp_sudoers_cmd" in locals():
                cleanup_cmd = f'echo "{password}" | sudo -S rm -f /etc/sudoers.d/temp_{username}'
                stdin, stdout, stderr = client.exec_command(cleanup_cmd)
                logger.info("Временный файл sudoers удален")
            
            logger.info(f"Сканирование сервера {server_ip} завершено. Закрываем SSH-соединение.")
            client.close()
            
        # Для WinRM (Windows Remote Management)
        elif connection_type == "winrm":
            logger.info(f"Подключение к серверу {server_ip} по WinRM пока не реализовано")
            # Здесь можно реализовать подключение к Windows-серверам через WinRM
            pass
        
    except Exception as e:
        logger.error(f"Ошибка при сканировании: {str(e)}")
        raise
    
    return results
'''
    
    return perform_scan_code

def generate_installation_instructions():
    """Generate detailed instructions for fixing the status evaluation logic"""
    
    instructions = """
#################################################################################
#                SECURITY CRITERIA STATUS EVALUATION FIX                         #
#################################################################################

The issue is that the current system incorrectly evaluates security check results,
causing many failed checks to be incorrectly reported as passed. This fix creates
a completely new logic system to correct these issues.

FOLLOW THESE STEPS:

1. CREATE CRITERION RULES FILE:
   First, this script analyzes your criteria and creates a rules file that will
   be used to properly determine pass/fail status:

   # Run this script to create the rules file
   docker-compose exec backend python status_evaluation_fix.py

2. MODIFY THE MAIN.PY FILE:
   Open backend/main.py and make the following changes:

   a. Find the `perform_scan` function (around line 350-400)
   
   b. Replace it with the complete function in "new_perform_scan.py"
   
   c. Add the `determine_status` function (around line 340, before perform_scan):
      * Copy the determine_status function from "new_determine_status.py"
      * Paste it right before the perform_scan function

3. RESTART THE BACKEND:
   After making these changes, restart your backend:

   docker-compose restart backend

4. RUN A TEST SCAN:
   Run a new scan after applying these changes to verify that the fix works correctly.

5. CHECK THE SCAN RESULTS:
   Verify that the pass/fail statuses now correctly match the actual check results.

#################################################################################
"""
    return instructions

def main():
    """Main function to analyze criteria and generate fixes"""
    logger.info("Starting security criteria status evaluation fix")
    
    # Analyze criteria and create rules
    rules = analyze_all_criteria()
    
    # Generate fixed determine_status function
    determine_status_code = generate_fixed_function(rules)
    with open("new_determine_status.py", "w") as f:
        f.write(determine_status_code)
    logger.info("Generated new determine_status function")
    
    # Generate fixed perform_scan function
    perform_scan_code = generate_perform_scan_rewrite()
    with open("new_perform_scan.py", "w") as f:
        f.write(perform_scan_code)
    logger.info("Generated new perform_scan function")
    
    # Generate installation instructions
    instructions = generate_installation_instructions()
    with open("INSTALLATION.txt", "w") as f:
        f.write(instructions)
    logger.info("Generated installation instructions")
    
    # Print summary
    print("\n" + "="*80)
    print("SECURITY CRITERIA STATUS EVALUATION FIX GENERATED")
    print("="*80)
    print("\nThree files have been created:")
    print("1. new_determine_status.py - Contains the new status determination function")
    print("2. new_perform_scan.py - Contains the rewritten scan function")
    print("3. INSTALLATION.txt - Contains detailed installation instructions")
    print("\nFOLLOW THE INSTRUCTIONS IN INSTALLATION.txt TO FIX THE STATUS EVALUATION ISSUE")
    print("="*80)

if __name__ == "__main__":
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    main()