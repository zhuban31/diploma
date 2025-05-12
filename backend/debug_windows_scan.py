import winrm
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("windows-debug")

server = "25.13.178.117"  # IP Windows-сервера  
username = "Gaming"       # Используйте успешное имя пользователя
password = "Mirage0909_!"   # Используйте успешный пароль

try:
    logger.info(f"Подключение к {server} с пользователем {username}...")
    session = winrm.Session(
        server, 
        auth=(username, password),
        transport='ntlm',
        server_cert_validation='ignore'
    )
    
    # Проверяем базовую команду
    logger.info("Выполнение базовой команды hostname")
    result = session.run_ps("hostname")
    logger.info(f"Результат: {result.std_out.decode('utf-8', errors='replace').strip()}")
    
    # Тестируем команду Get-ComputerInfo
    logger.info("Выполнение команды Get-ComputerInfo")
    result = session.run_ps("Get-ComputerInfo | Select-Object OSName, OSVersion")
    logger.info(f"Результат: {result.std_out.decode('utf-8', errors='replace')}")
    
    # Проверяем команду для реестра
    logger.info("Проверка доступа к реестру")
    result = session.run_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name ProductName")
    logger.info(f"Результат: {result.std_out.decode('utf-8', errors='replace')}")
    
    logger.info("Все тесты завершены успешно!")
    
except Exception as e:
    logger.error(f"Ошибка: {str(e)}")
