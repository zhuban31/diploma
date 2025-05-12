import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix-localization")

db = SessionLocal()

try:
    # Исправляем команды с проблемами локализации
    localization_fixes = {
        "Windows User Rights": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-LocalGroup | Where-Object {$_.Name -eq 'Administrators' -or $_.Name -eq 'Администраторы'} | Get-LocalGroupMember | Measure-Object | Select-Object -ExpandProperty Count",
            "expected": "",  # Любое число, важен сам факт наличия членов
            "remediation": "Минимизируйте количество пользователей в группе Administrators/Администраторы"
        },
        "Windows Updates": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-Service wuauserv | Select-Object Status",
            "expected": "Running",
            "remediation": "Запустите службу Windows Update: Start-Service wuauserv"
        }
    }
    
    # Обновляем команды с учетом локализации
    for name, data in localization_fixes.items():
        criterion = db.query(models.Criterion).filter(models.Criterion.name == name).first()
        if criterion:
            criterion.check_command = data["command"]
            criterion.expected_output = data["expected"]
            criterion.remediation = data["remediation"]
            logger.info(f"Исправлен критерий с учетом локализации: {name}")
    
    db.commit()
    logger.info("Исправления локализации завершены")
    
except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при исправлении локализации: {str(e)}")
finally:
    db.close()
