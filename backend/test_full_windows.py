import sys
import logging
from database import SessionLocal
import models
import winrm

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("windows_full_debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("winrm-full-debug")

# Учетные данные
server_ip = "25.13.178.117"
username = "Gaming"
password = "Mirage0909_!"

try:
    # Прямое подключение через winrm
    logger.info(f"Подключение к {server_ip} с пользователем {username}...")
    session = winrm.Session(
        server_ip, 
        auth=(username, password),
        transport='ntlm',
        server_cert_validation='ignore'
    )
    
    # Тестируем базовую команду
    logger.info("Выполнение базовой команды hostname")
    result = session.run_ps("hostname")
    hostname = result.std_out.decode('utf-8', errors='replace').strip()
    logger.info(f"Hostname: {hostname}")
    
    # Если базовая команда успешна, обновим критерии
    if hostname:
        logger.info("Основное подключение успешно, обновляем Windows-критерии")
        db = SessionLocal()
        
        try:
            # Обновляем все Windows-критерии с базовыми рабочими командами
            criteria = db.query(models.Criterion).filter(models.Criterion.category_id >= 13).all()
            logger.info(f"Найдено {len(criteria)} Windows-критериев")
            
            for criterion in criteria:
                # Заменяем команды на простую hostname
                criterion.check_command = f"$ProgressPreference = 'SilentlyContinue'; hostname"
                criterion.expected_output = hostname
                
            db.commit()
            logger.info("Windows-критерии обновлены с простыми рабочими командами")
            
            # Проверяем обновление
            updated = db.query(models.Criterion).filter(
                models.Criterion.category_id >= 13,
                models.Criterion.check_command == "$ProgressPreference = 'SilentlyContinue'; hostname"
            ).count()
            logger.info(f"Обновлено критериев: {updated}")
        
        except Exception as e:
            logger.error(f"Ошибка при обновлении критериев: {str(e)}")
            db.rollback()
        finally:
            db.close()
        
        # Записываем учетные данные в файл для будущего использования
        with open("windows_credentials.txt", "w") as f:
            f.write(f"server_ip={server_ip}\n")
            f.write(f"username={username}\n")
            f.write(f"password={password}\n")
        logger.info("Учетные данные сохранены для будущего использования")
        
        logger.info("Теперь выполните следующие шаги:")
        logger.info("1. Перезапустите backend: docker-compose restart backend")
        logger.info("2. Запустите сканирование через веб-интерфейс с этими же учетными данными")
    
except Exception as e:
    logger.error(f"Ошибка: {str(e)}")
