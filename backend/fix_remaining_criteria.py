import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("final-windows-fix")

db = SessionLocal()

try:
    # Словарь с командами и ожидаемыми результатами для оставшихся критериев
    final_fixes = {
        "Windows Authentication": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RestrictAnonymous",
            "expected": "1",
            "remediation": "Настройте параметр 'RestrictAnonymous' на значение 1 или 2 для ограничения анонимного доступа"
        },
        "Windows User Rights": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-LocalGroupMember -Group 'Administrators' | Measure-Object | Select-Object -ExpandProperty Count",
            "expected": "2",
            "remediation": "Уменьшите количество пользователей в группе 'Администраторы' до минимально необходимого (для повседневной работы используйте учетные записи без прав администратора)"
        },
        "Windows UAC": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableLUA",
            "expected": "1",
            "remediation": "Включите UAC, установив значение 'EnableLUA' на 1 в реестре или через Панель управления"
        },
        "Windows Basic Test": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-HotFix | Measure-Object | Select-Object -ExpandProperty Count",
            "expected": "",  # Любое число обновлений, важен сам факт их наличия
            "remediation": "Регулярно устанавливайте обновления безопасности Windows"
        },
        "Windows Remote Desktop": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserAuthentication",
            "expected": "1",
            "remediation": "Включите безопасную авторизацию для RDP, установив 'UserAuthentication' на 1"
        },
        "Windows Updates": {
            "command": "$ProgressPreference = 'SilentlyContinue'; (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count",
            "expected": "0",
            "remediation": "Установите все доступные обновления Windows"
        },
        # Улучшаем уже работающие критерии
        "Windows Automatic Updates": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-Service wuauserv | Select-Object Name, Status | Format-Table -AutoSize | Out-String",
            "expected": "Running",
            "remediation": "Включите службу автоматических обновлений Windows: Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv"
        },
        "Windows Registry": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableLUA",
            "expected": "1",
            "remediation": "Включите UAC, установив значение 'EnableLUA' равным 1 в реестре: Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1"
        }
    }
    
    # Обновляем команды для соответствующих критериев
    for name, data in final_fixes.items():
        criterion = db.query(models.Criterion).filter(models.Criterion.name == name).first()
        if criterion:
            criterion.check_command = data["command"]
            criterion.expected_output = data["expected"]
            criterion.remediation = data["remediation"]
            logger.info(f"Обновлен критерий: {name}")
        else:
            logger.warning(f"Критерий '{name}' не найден")
    
    # Удаляем дубликаты критериев, если они есть
    duplicate_check = {}
    criteria = db.query(models.Criterion).filter(models.Criterion.category_id >= 13).all()
    for crit in criteria:
        if crit.name in duplicate_check:
            logger.info(f"Найден дубликат: {crit.name} (ID: {crit.id})")
            # Удаляем результаты для этого критерия
            db.query(models.ScanResult).filter(models.ScanResult.criterion_id == crit.id).delete()
            # Удаляем сам критерий
            db.delete(crit)
        else:
            duplicate_check[crit.name] = crit.id
    
    db.commit()
    logger.info("Все критерии успешно обновлены и дубликаты удалены")
    
except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при обновлении критериев: {str(e)}")
finally:
    db.close()
