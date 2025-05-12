import logging
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("update-windows-criteria")

db = SessionLocal()

try:
    # Словарь реальных команд проверки для каждого критерия
    real_commands = {
        "Windows Registry": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object -ExpandProperty Property",
            "expected": "EnableLUA",  # Проверка наличия параметра UAC
            "remediation": "Включите UAC через Панель управления или редактор реестра"
        },
        "Windows Event Logging": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-Service EventLog | Select-Object -ExpandProperty Status",
            "expected": "Running",
            "remediation": "Запустите службу журнала событий: Start-Service EventLog"
        },
        "Windows SMB": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol",
            "expected": "False",
            "remediation": "Отключите протокол SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false"
        },
        "Windows Services": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-Service 'RemoteRegistry' | Select-Object -ExpandProperty Status",
            "expected": "Stopped",
            "remediation": "Остановите и отключите службу удаленного реестра: Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled"
        },
        "Windows Security Policy": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin",
            "expected": "2",
            "remediation": "Настройте UAC так, чтобы он всегда уведомлял при повышении привилегий"
        },
        "Windows Network Security": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LmCompatibilityLevel", 
            "expected": "5",
            "remediation": "Установите уровень совместимости LM равным 5 (отправить только NTLMv2, отклонить LM и NTLM)"
        },
        "Windows PowerShell": {
            "command": "$ProgressPreference = 'SilentlyContinue'; Get-ExecutionPolicy", 
            "expected": "RemoteSigned",
            "remediation": "Установите политику выполнения PowerShell на RemoteSigned: Set-ExecutionPolicy RemoteSigned"
        }
    }
    
    # Обновляем команды для соответствующих критериев
    for name, data in real_commands.items():
        criterion = db.query(models.Criterion).filter(models.Criterion.name == name).first()
        if criterion:
            criterion.check_command = data["command"]
            criterion.expected_output = data["expected"]
            criterion.remediation = data["remediation"]
            logger.info(f"Обновлен критерий: {name}")
        else:
            logger.warning(f"Критерий '{name}' не найден")
    
    db.commit()
    logger.info("Критерии успешно обновлены")
    
except Exception as e:
    db.rollback()
    logger.error(f"Ошибка при обновлении критериев: {str(e)}")
finally:
    db.close()
