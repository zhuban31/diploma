import sys
import logging
from database import SessionLocal
from windows_scanner import WindowsScanner
import models

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("windows_debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("windows-fix")

def fix_windows_scan():
    logger.info("Запуск отладки Windows-сканера")
    db = SessionLocal()
    
    try:
        # Получаем последний Windows-скан
        last_scan = db.query(models.Scan).filter(models.Scan.connection_type == "winrm").order_by(models.Scan.id.desc()).first()
        
        if last_scan:
            logger.info(f"Последний Windows-скан (ID: {last_scan.id}): сервер {last_scan.server_ip}, статус {last_scan.status}")
            
            # Создаем новый объект WindowsScanner с заведомо рабочими учетными данными
            scanner = WindowsScanner(last_scan.server_ip, "Gaming", "ВАШ_ПАРОЛЬ") # Замените на рабочий пароль
            
            # Попытка подключения (метод connect должен вызываться в perform_scan)
            logger.info("Попытка явного вызова метода connect")
            success = scanner.connect()
            logger.info(f"Подключение: {'успешно' if success else 'неудачно'}")
            
            if success:
                # Для каждого Windows-критерия пытаемся выполнить команду
                windows_criteria = db.query(models.Criterion).filter(models.Criterion.category_id >= 13).all()
                logger.info(f"Найдено {len(windows_criteria)} Windows-критериев")
                
                fixed_commands = []
                for criterion in windows_criteria:
                    logger.info(f"Критерий {criterion.id}: {criterion.name}")
                    logger.info(f"  Команда: {criterion.check_command}")
                    
                    # Исправляем команду проверки на более конкретную
                    new_command = get_fixed_command(criterion.name)
                    
                    if new_command:
                        logger.info(f"  Новая команда: {new_command}")
                        # Обновляем команду в базе
                        criterion.check_command = new_command
                        
                        # Если есть специальный ожидаемый вывод для этой команды, обновляем его
                        expected_output = get_expected_output(criterion.name)
                        if expected_output:
                            criterion.expected_output = expected_output
                            logger.info(f"  Новый ожидаемый вывод: {expected_output}")
                        
                        fixed_commands.append(criterion.id)
                
                if fixed_commands:
                    db.commit()
                    logger.info(f"Исправлено {len(fixed_commands)} Windows-критериев")
                else:
                    logger.info("Нет критериев для исправления")
                
                # Тестируем на одной базовой команде
                try:
                    logger.info("Тестирование базовой команды")
                    result = scanner.run_powershell_command("Get-ComputerInfo | Select-Object OSName, OSVersion")
                    logger.info(f"Результат: {result['output']}")
                    logger.info("Базовая команда выполнена успешно")
                except Exception as e:
                    logger.error(f"Ошибка при выполнении базовой команды: {str(e)}")
            
            # Закрываем сканер
            scanner.close()
            logger.info("Сканер закрыт")
        else:
            logger.warning("Windows-сканирования не найдены")
    
    except Exception as e:
        logger.error(f"Ошибка при отладке: {str(e)}")
        db.rollback()
    finally:
        db.close()

def get_fixed_command(criterion_name):
    """Возвращает исправленную команду для критерия на основе его имени"""
    commands = {
        "Windows Automatic Updates": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -Name 'AUOptions' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'AUOptions' -ErrorAction SilentlyContinue",
        "Windows Remote Desktop": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'fDenyTSConnections' -ErrorAction SilentlyContinue",
        "Windows Firewall": "$ProgressPreference = 'SilentlyContinue'; Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json",
        "Windows User Accounts": "$ProgressPreference = 'SilentlyContinue'; Get-LocalUser Guest | Select-Object Name, Enabled | ConvertTo-Json",
        "Windows Security Policy": "$ProgressPreference = 'SilentlyContinue'; Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue",
        "Windows Services": "$ProgressPreference = 'SilentlyContinue'; Get-Service -Name 'WinDefend' | Select-Object Name, Status | ConvertTo-Json",
    }
    
    # Возвращаем команду или None, если не найдена для этого критерия
    return commands.get(criterion_name)

def get_expected_output(criterion_name):
    """Возвращает ожидаемый вывод для критерия на основе его имени"""
    expected = {
        "Windows Automatic Updates": "4",
        "Windows Remote Desktop": "0",
        "Windows Firewall": "True",
        "Windows User Accounts": "False",
        "Windows Security Policy": "5",
        "Windows Services": "Running",
    }
    
    return expected.get(criterion_name)

if __name__ == "__main__":
    fix_windows_scan()
