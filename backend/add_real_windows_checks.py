import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("windows-checks")

db = SessionLocal()

try:
    # Словарь с реальными командами проверки
    real_checks = {
        "Windows Automatic Updates": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -Name 'AUOptions' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'AUOptions' -ErrorAction SilentlyContinue || Write-Output 'Not configured'",
            "expected": "4",
            "description": "Проверка настроек автоматического обновления Windows. Значение 4 означает, что автоматические обновления включены."
        },
        "Windows Firewall": {
            "command": "$ProgressPreference = 'SilentlyContinue'; (Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count",
            "expected": "3",
            "description": "Проверка настроек брандмауэра Windows. Все три профиля (доменный, публичный, частный) должны быть включены."
        },
        "Windows User Accounts": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-LocalUser Guest | Select-Object -ExpandProperty Enabled",
            "expected": "False",
            "description": "Проверка отключения гостевой учетной записи. Должно быть False (отключена)."
        }
    }

    # Обновляем только несколько критериев для примера
    for name, data in real_checks.items():
        criterion = db.query(models.Criterion).filter(models.Criterion.name == name).first()
        if criterion:
            criterion.check_command = data["command"]
            criterion.expected_output = data["expected"]
            criterion.description = data["description"]
            logger.info(f"Обновлен критерий: {name}")

    db.commit()
    logger.info("Критерии успешно обновлены")

except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при обновлении критериев: {str(e)}")
finally:
    db.close()
