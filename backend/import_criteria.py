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
