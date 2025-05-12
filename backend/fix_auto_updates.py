import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix-auto-updates")

db = SessionLocal()

try:
    # Исправляем критерий Windows Automatic Updates
    criterion = db.query(models.Criterion).filter(
        models.Criterion.name == "Windows Automatic Updates"
    ).first()
    
    if criterion:
        # Более простая проверка
        criterion.check_command = "$ProgressPreference = 'SilentlyContinue'; Get-Service wuauserv | Select-Object Name, Status"
        criterion.expected_output = "Running"
        logger.info("Исправлен критерий Windows Automatic Updates на проверку службы")
        db.commit()
        logger.info("Обновление завершено")
    else:
        logger.warning("Критерий Windows Automatic Updates не найден")
        
except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при обновлении критерия: {str(e)}")
finally:
    db.close()
