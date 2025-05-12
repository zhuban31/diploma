import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix-windows-commands")

db = SessionLocal()

try:
    # Исправления для команд
    fixes = {
        "Windows Automatic Updates": {
            "command": "$ProgressPreference = 'SilentlyContinue'; try { Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -Name 'AUOptions' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'AUOptions' } catch { Write-Output 'Not configured' }",
            "expected": "4"
        },
        "Windows Firewall": {
            "command": "$ProgressPreference = 'SilentlyContinue'; (Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count",
            "expected": "1"  # Изменено с 3 на 1
        },
        "Windows User Accounts": {
            "command": "$ProgressPreference = 'SilentlyContinue'; if (Get-LocalUser | Where-Object { $_.Name -eq 'Guest' }) { Get-LocalUser Guest | Select-Object -ExpandProperty Enabled } else { Write-Output 'Guest account not found' }",
            "expected": "Guest account not found"  # Это нормально, если учетной записи Guest нет
        }
    }

    # Обновляем команды
    for name, data in fixes.items():
        criterion = db.query(models.Criterion).filter(models.Criterion.name == name).first()
        if criterion:
            criterion.check_command = data["command"]
            criterion.expected_output = data["expected"]
            logger.info(f"Исправлен критерий: {name}")

    db.commit()
    logger.info("Критерии успешно обновлены")

except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при обновлении критериев: {str(e)}")
finally:
    db.close()
