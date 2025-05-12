import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("add-commands")

db = SessionLocal()

try:
    # Читаем текущий файл windows_scanner.py
    with open("windows_scanner.py", "r") as f:
        scanner_code = f.read()
    
    # Ищем строку с добавлением деталей в результаты
    target_line = '"details": output,'
    replacement_line = '"details": f"Command: ```powershell\\n{criterion.check_command}\\n```\\n\\nOutput:\\n{output}",'
    
    if target_line in scanner_code:
        # Заменяем строку
        new_code = scanner_code.replace(target_line, replacement_line)
        
        # Сохраняем изменённый файл
        with open("windows_scanner.py", "w") as f:
            f.write(new_code)
        
        logger.info("Файл windows_scanner.py успешно обновлен!")
    else:
        logger.warning(f"Строка '{target_line}' не найдена в windows_scanner.py")
    
    # Также обновим текущие результаты сканирования
    updated_count = 0
    
    # Получаем все результаты для Windows-сканирований
    results = db.query(models.ScanResult).join(
        models.Scan, models.ScanResult.scan_id == models.Scan.id
    ).filter(
        models.Scan.connection_type == "winrm"
    ).all()
    
    # Обновляем результаты
    for result in results:
        criterion = db.query(models.Criterion).filter(models.Criterion.id == result.criterion_id).first()
        if criterion and not result.details.startswith("Command:"):
            result.details = f"Command: ```powershell\n{criterion.check_command}\n```\n\nOutput:\n{result.details}"
            updated_count += 1
    
    if updated_count > 0:
        db.commit()
        logger.info(f"Обновлено {updated_count} результатов сканирования")
    
except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при обновлении: {str(e)}")
finally:
    db.close()
