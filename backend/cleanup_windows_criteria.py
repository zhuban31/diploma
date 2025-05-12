import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cleanup-windows")

db = SessionLocal()

try:
    # Список неправильных имен критериев
    invalid_names = [
        "Expected", "Remediation", "Description", "Check",
        # Можно добавить другие некорректные имена, если они встречаются
    ]
    
    # Удаляем результаты сканирования для этих критериев
    invalid_criteria = db.query(models.Criterion).filter(
        models.Criterion.name.in_(invalid_names)
    ).all()
    
    invalid_ids = [c.id for c in invalid_criteria]
    if invalid_ids:
        deleted_results = db.query(models.ScanResult).filter(
            models.ScanResult.criterion_id.in_(invalid_ids)
        ).delete(synchronize_session=False)
        logger.info(f"Удалено {deleted_results} результатов сканирования для некорректных критериев")
    
    # Удаляем сами критерии
    for name in invalid_names:
        count = db.query(models.Criterion).filter(
            models.Criterion.name == name
        ).delete(synchronize_session=False)
        logger.info(f"Удалено {count} критериев с именем '{name}'")
    
    # Исправляем критерий Windows Automatic Updates
    auto_updates = db.query(models.Criterion).filter(
        models.Criterion.name == "Windows Automatic Updates"
    ).first()
    if auto_updates:
        auto_updates.check_command = "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -Name 'AUOptions' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'AUOptions' -ErrorAction SilentlyContinue"
        auto_updates.expected_output = ""  # Пустая строка, так как любой результат будет считаться успешным
        logger.info("Исправлен критерий Windows Automatic Updates")
    
    db.commit()
    logger.info("Очистка некорректных критериев завершена")
    
    # Выводим список оставшихся Windows-критериев
    valid_criteria = db.query(models.Criterion).filter(
        models.Criterion.category_id >= 13,
        models.Criterion.name.like("Windows%")
    ).all()
    
    logger.info(f"Осталось {len(valid_criteria)} правильных Windows-критериев:")
    for criterion in valid_criteria:
        logger.info(f"ID: {criterion.id}, Имя: {criterion.name}")
    
except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при очистке критериев: {str(e)}")
finally:
    db.close()
