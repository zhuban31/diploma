import re
import json
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import models

# Создаем категории критериев на основе разделов в paste.txt
categories = [
    {"id": 1, "name": "System Updates", "description": "Check system updates and patches"},
    {"id": 2, "name": "Filesystem Configuration", "description": "Check filesystem security settings"},
    {"id": 3, "name": "Bootloader Configuration", "description": "Check bootloader security"},
    {"id": 4, "name": "Process Hardening", "description": "Check process security settings"},
    {"id": 5, "name": "Network Configuration", "description": "Check network security settings"},
    {"id": 6, "name": "Network Hardening", "description": "Check network hardening settings"},
    {"id": 7, "name": "Logging and Auditing", "description": "Check audit and logging settings"},
    {"id": 8, "name": "User Account Settings", "description": "Check user account security"},
    {"id": 9, "name": "Warning Banners", "description": "Check login warning banners"},
    {"id": 10, "name": "File Permissions", "description": "Check file permissions"},
    {"id": 11, "name": "User Settings", "description": "Check user security settings"},
    {"id": 12, "name": "Account Settings", "description": "Check account security"}
]

def parse_paste_file(filepath):
    """Парсит файл paste.txt и извлекает критерии безопасности"""
    with open(filepath, 'r') as file:
        content = file.read()
    
    # Разбиваем на секции по номерам (1.1, 1.2, 2.1, и т.д.)
    pattern = r'(\d+\.\d+\.\s+[^\n]+)([^0-9.]*(?:\n(?!\d+\.\d+\.).*)*)'
    sections = re.findall(pattern, content, re.DOTALL)
    
    criteria = []
    
    for title, details in sections:
        # Извлекаем номер, название и детали
        match = re.match(r'(\d+)\.(\d+)\.\s+(.*)', title)
        if match:
            category_id = int(match.group(1))
            criterion_number = float(f"{match.group(1)}.{match.group(2)}")
            criterion_name = match.group(3).strip()
            
            # Проверяем есть ли команда проверки
            check_command = ""
            check_match = re.search(r'Check: Run (.+)', details)
            if check_match:
                check_command = check_match.group(1).strip()
            
            # Проверяем ожидаемый вывод
            expected_output = ""
            expected_match = re.search(r'Expected: (.+)', details)
            if expected_match:
                expected_output = expected_match.group(1).strip()
            
            # Извлекаем инструкции по устранению
            remediation = ""
            remediation_match = re.search(r'Remediation: (.+)', details)
            if remediation_match:
                remediation = remediation_match.group(1).strip()
            
            # Определяем тип критерия (ручной/автоматический)
            automated = bool(check_command and expected_output)
            
            # Определяем важность
            severity = "Medium"  # По умолчанию
            if "Высокий" in details:
                severity = "High"
            elif "Низкий" in details:
                severity = "Low"
            
            criteria.append({
                "category_id": category_id,
                "id": int(criterion_number * 100),  # Преобразуем 1.1 в 110
                "name": f"{criterion_number}. {criterion_name}",
                "description": details.strip(),
                "check_command": check_command,
                "expected_output": expected_output,
                "remediation": remediation,
                "severity": severity,
                "automated": automated
            })
    
    # Добавляем дополнительные критерии, которые могут не присутствовать в paste.txt
    additional_criteria = [
        {
            "category_id": 6,
            "id": 615,
            "name": "6.15. Ensure IPv6 is disabled if not in use",
            "description": "Description: If IPv6 is not required in your environment, it should be disabled",
            "check_command": "sysctl net.ipv6.conf.all.disable_ipv6",
            "expected_output": "1",
            "remediation": "Add 'net.ipv6.conf.all.disable_ipv6 = 1' and 'net.ipv6.conf.default.disable_ipv6 = 1' to /etc/sysctl.conf",
            "severity": "Medium",
            "automated": True
        },
        {
            "category_id": 5,
            "id": 520,
            "name": "5.2. Ensure HTTP server is not enabled unless required",
            "description": "Description: HTTP servers should not run unless needed as they increase attack surface",
            "check_command": "systemctl is-enabled apache2 2>/dev/null || systemctl is-enabled nginx 2>/dev/null || echo disabled",
            "expected_output": "disabled",
            "remediation": "Run 'systemctl disable apache2' or 'systemctl disable nginx' as appropriate",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 4,
            "id": 412,
            "name": "4.2. Ensure ASLR is enabled",
            "description": "Description: Address Space Layout Randomization (ASLR) makes it more difficult for an attacker to predict memory addresses",
            "check_command": "sysctl kernel.randomize_va_space",
            "expected_output": "2",
            "remediation": "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf and run 'sysctl -p'",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 6,
            "id": 630,
            "name": "6.30. Ensure firewall is enabled",
            "description": "Description: A properly configured firewall is essential for system security",
            "check_command": "ufw status | grep -E 'Status:\\s*active' || iptables -L -n | grep -q 'REJECT\\|DROP' && echo 'Firewall active'",
            "expected_output": "Firewall active",
            "remediation": "Enable firewall with UFW ('ufw enable') or configure iptables rules",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 8,
            "id": 820,
            "name": "8.2. Ensure all users have a valid password hash",
            "description": "Description: All user accounts should have properly hashed passwords to prevent unauthorized access",
            "check_command": "cat /etc/shadow | awk -F: '($2 == \"\" ) { print $1 \" has no password\" ; exit 1 }' || echo \"No empty passwords\"",
            "expected_output": "No empty passwords",
            "remediation": "Set passwords for accounts with empty password fields using 'passwd <username>'",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 7,
            "id": 730,
            "name": "7.3. Ensure rsyslog or syslog-ng is installed",
            "description": "Description: The rsyslog or syslog-ng software is required to reliably handle system logging",
            "check_command": "dpkg -s rsyslog || dpkg -s syslog-ng || echo 'No syslog service installed'",
            "expected_output": "Status: install ok installed",
            "remediation": "Install rsyslog with 'apt install rsyslog'",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 10,
            "id": 1020,
            "name": "10.2. Ensure permissions on /etc/shadow are configured",
            "description": "Description: The /etc/shadow file contains encrypted passwords",
            "check_command": "stat -c \"%a %u %g\" /etc/shadow",
            "expected_output": "640 0 42",
            "remediation": "Run 'chmod 640 /etc/shadow' and 'chown root:shadow /etc/shadow'",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 5,
            "id": 550,
            "name": "5.5. Ensure SSH PermitRootLogin is disabled",
            "description": "Description: SSH root login should be disabled to prevent direct unauthorized access",
            "check_command": "grep -i \"^PermitRootLogin\" /etc/ssh/sshd_config | grep -i \"no\"",
            "expected_output": "PermitRootLogin no",
            "remediation": "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 5,
            "id": 552,
            "name": "5.5.2 Ensure SSH Protocol is set to 2",
            "description": "Description: SSH protocol version 1 has known vulnerabilities and should not be used",
            "check_command": "grep -i \"^Protocol\" /etc/ssh/sshd_config",
            "expected_output": "Protocol 2",
            "remediation": "Edit /etc/ssh/sshd_config and set 'Protocol 2'",
            "severity": "High",
            "automated": True
        },
        {
            "category_id": 6,
            "id": 620,
            "name": "6.2. Ensure no unconfined daemons exist",
            "description": "Description: AppArmor should confine all system daemons to enhance security",
            "check_command": "ps -eZ | grep -v \"^\\w\\{1,\\}-[\\w\\{1,\\}_]\\{1,\\} \" | grep -v \"^system_u:system_r:initrc_t:s0
            "expected_output": "No unconfined daemons",
            "remediation": "Configure AppArmor profiles for any unconfined daemons",
            "severity": "Medium",
            "automated": True
        }
    ]
    
    # Добавляем дополнительные критерии в общий список
    for criteria_item in additional_criteria:
        # Проверяем, есть ли такой критерий уже в нашем списке
        if not any(c["id"] == criteria_item["id"] for c in criteria):
            criteria.append(criteria_item)
    
    return criteria

def import_criteria_to_db():
    """Импортирует категории и критерии в базу данных"""
    db = SessionLocal()
    
    try:
        # Импорт категорий
        for category in categories:
            # Проверяем, существует ли уже такая категория
            existing_category = db.query(models.CriterionCategory).filter(models.CriterionCategory.id == category["id"]).first()
            if not existing_category:
                db_category = models.CriterionCategory(
                    id=category["id"],
                    name=category["name"],
                    description=category["description"]
                )
                db.add(db_category)
        
        # Импорт критериев из файла
        criteria = parse_paste_file("paste.txt")
        for criterion in criteria:
            # Проверяем, существует ли уже такой критерий
            existing_criterion = db.query(models.Criterion).filter(models.Criterion.id == criterion["id"]).first()
            if not existing_criterion:
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
        print(f"Successfully imported {len(categories)} categories and {len(criteria)} criteria.")
        
    except Exception as e:
        db.rollback()
        print(f"Error importing criteria: {str(e)}")
    finally:
        db.close()

def export_criteria_to_json():
    """Экспортирует категории и критерии в JSON-файл"""
    try:
        # Извлекаем критерии из файла
        criteria = parse_paste_file("paste.txt")
        
        data = {
            "categories": categories,
            "criteria": criteria
        }
        
        with open("security_criteria.json", "w") as json_file:
            json.dump(data, json_file, indent=2)
        
        print(f"Successfully exported {len(categories)} categories and {len(criteria)} criteria to security_criteria.json.")
        
    except Exception as e:
        print(f"Error exporting criteria: {str(e)}")

if __name__ == "__main__":
    # Создаем таблицы, если они не существуют
    Base.metadata.create_all(bind=engine)
    
    # Импортируем данные
    import_criteria_to_db()
    
    # Экспортируем в JSON для резервной копии
    export_criteria_to_json()