"""
Добавление пояснений к результатам проверок Linux-критериев безопасности
"""

import logging
from database import SessionLocal
import models
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("linux-explanations")

# Словарь с пояснениями к результатам проверок Linux
linux_explanations = {
    # System Updates
    "unattended-upgrades": "unattended-upgrades (Пакет автоматических обновлений установлен)",
    
    # Filesystem
    "noexec": "noexec (Запрещено выполнение файлов - безопасно)",
    "nodev": "nodev (Запрещены файлы устройств - безопасно)",
    "nosuid": "nosuid (Запрещены SUID биты - безопасно)",
    
    # Bootloader
    "password": "password (Пароль загрузчика установлен)",
    
    # Core dumps
    "* hard core 0": "* hard core 0 (Дампы памяти ограничены - безопасно)",
    
    # IP forwarding
    "net.ipv4.ip_forward = 0": "net.ipv4.ip_forward = 0 (IP-перенаправление отключено - безопасно)",
    "net.ipv4.ip_forward = 1": "net.ipv4.ip_forward = 1 (IP-перенаправление включено - небезопасно)",
    
    # IPv6
    "net.ipv6.conf.all.disable_ipv6 = 1": "net.ipv6.conf.all.disable_ipv6 = 1 (IPv6 отключен - безопасно)",
    "net.ipv6.conf.all.disable_ipv6 = 0": "net.ipv6.conf.all.disable_ipv6 = 0 (IPv6 включен - потенциально небезопасно)",
    
    # Wireless
    "Soft blocked: yes": "Soft blocked: yes (Беспроводные интерфейсы отключены - безопасно)",
    "Soft blocked: no": "Soft blocked: no (Беспроводные интерфейсы включены - потенциальный риск)",
    
    # Audit
    "active": "active (Служба аудита активна)",
    
    # Password expiration
    "90": "90 (Срок действия пароля 90 дней - рекомендуемое значение)",
    "99999": "99999 (Пароли никогда не истекают - небезопасно)",
    
    # SSH banner
    "/etc/issue.net": "/etc/issue.net (Баннер SSH настроен)",
    
    # File permissions
    "644 0 0": "644 0 0 (Права 644, владелец root:root - правильная конфигурация)",
    "640 0 42": "640 0 42 (Права 640, владелец root:shadow - правильная конфигурация)",
    
    # PATH
    "1": "1 (PATH не содержит пустых директорий - безопасно)",
    "Empty Directory": "Empty Directory (PATH содержит пустые директории - небезопасно)",
    
    # HTTP server
    "disabled": "disabled (Веб-сервер отключен - безопасно)",
    "enabled": "enabled (Веб-сервер включен - потребуется дополнительная настройка)",
    
    # ASLR
    "kernel.randomize_va_space = 2": "kernel.randomize_va_space = 2 (ASLR включен полностью - безопасно)",
    "kernel.randomize_va_space = 1": "kernel.randomize_va_space = 1 (ASLR включен частично - недостаточно безопасно)",
    "kernel.randomize_va_space = 0": "kernel.randomize_va_space = 0 (ASLR отключен - небезопасно)",
    
    # Firewall
    "Firewall active": "Firewall active (Файервол активен - безопасно)",
    
    # Password security
    "No empty passwords": "No empty passwords (Пустые пароли не обнаружены - безопасно)",
    
    # Syslog
    "Status: install ok installed": "Status: install ok installed (Служба журналирования установлена)",
    
    # SSH security
    "PermitRootLogin no": "PermitRootLogin no (Вход root через SSH отключен - безопасно)",
    "Protocol 2": "Protocol 2 (Используется безопасный протокол SSH)",
    
    # AppArmor/SELinux
    "No unconfined daemons": "No unconfined daemons (Все службы ограничены политиками безопасности)",
    
    # Common empty results (good)
    "No world-writable files found": "No world-writable files found (Нет файлов с правами записи для всех - безопасно)",
    "No unowned files found": "No unowned files found (Нет файлов без владельца - безопасно)",
    "No .netrc files found": "No .netrc files found (Нет файлов .netrc - безопасно)",
    "No .forward files found": "No .forward files found (Нет файлов .forward - безопасно)",
    "No world-writable directories without sticky bit found": "No world-writable directories without sticky bit found (Нет небезопасных общих директорий - безопасно)",
    
    # Common failure patterns
    "not set": "not set (Настройка не установлена - требуется исправление)",
    "Not properly configured": "Not properly configured (Настройка неправильная - требуется исправление)",
    "not properly configured": "not properly configured (Настройка неправильная - требуется исправление)",
    "not enabled": "not enabled (Служба не активирована - требуется исправление)",
    "Not enabled": "Not enabled (Служба не активирована - требуется исправление)",
    "incorrect": "incorrect (Настройка некорректна - требуется исправление)",
    "Incorrect": "Incorrect (Настройка некорректна - требуется исправление)",
    "Permissions incorrect": "Permissions incorrect (Неправильные права доступа - требуется исправление)",
}

def add_linux_explanation_function():
    """Добавляет функцию объяснения Linux-вывода в main.py"""
    
    # Читаем текущий файл main.py
    with open("main.py", "r") as f:
        main_code = f.read()
    
    # Создаем функцию add_linux_explanation
    linux_explanation_function = """
def add_linux_explanation(criterion_id: int, output: str) -> str:
    \"\"\"
    Добавляет пояснения к выводу Linux-команд для более понятных результатов
    
    Args:
        criterion_id: ID критерия
        output: Исходный вывод команды
        
    Returns:
        Вывод с добавленными пояснениями
    \"\"\"
    # Словарь с пояснениями к результатам проверок Linux
    linux_explanations = {
        # System Updates
        "unattended-upgrades": "unattended-upgrades (Пакет автоматических обновлений установлен)",
        
        # Filesystem
        "noexec": "noexec (Запрещено выполнение файлов - безопасно)",
        "nodev": "nodev (Запрещены файлы устройств - безопасно)",
        "nosuid": "nosuid (Запрещены SUID биты - безопасно)",
        
        # Bootloader
        "password": "password (Пароль загрузчика установлен)",
        
        # Core dumps
        "* hard core 0": "* hard core 0 (Дампы памяти ограничены - безопасно)",
        
        # IP forwarding
        "net.ipv4.ip_forward = 0": "net.ipv4.ip_forward = 0 (IP-перенаправление отключено - безопасно)",
        "net.ipv4.ip_forward = 1": "net.ipv4.ip_forward = 1 (IP-перенаправление включено - небезопасно)",
        
        # IPv6
        "net.ipv6.conf.all.disable_ipv6 = 1": "net.ipv6.conf.all.disable_ipv6 = 1 (IPv6 отключен - безопасно)",
        "net.ipv6.conf.all.disable_ipv6 = 0": "net.ipv6.conf.all.disable_ipv6 = 0 (IPv6 включен - потенциально небезопасно)",
        
        # Wireless
        "Soft blocked: yes": "Soft blocked: yes (Беспроводные интерфейсы отключены - безопасно)",
        "Soft blocked: no": "Soft blocked: no (Беспроводные интерфейсы включены - потенциальный риск)",
        
        # Audit
        "active": "active (Служба аудита активна)",
        
        # Password expiration
        "90": "90 (Срок действия пароля 90 дней - рекомендуемое значение)",
        "99999": "99999 (Пароли никогда не истекают - небезопасно)",
        
        # SSH banner
        "/etc/issue.net": "/etc/issue.net (Баннер SSH настроен)",
        
        # File permissions
        "644 0 0": "644 0 0 (Права 644, владелец root:root - правильная конфигурация)",
        "640 0 42": "640 0 42 (Права 640, владелец root:shadow - правильная конфигурация)",
        
        # PATH
        "1": "1 (PATH не содержит пустых директорий - безопасно)",
        "Empty Directory": "Empty Directory (PATH содержит пустые директории - небезопасно)",
        
        # HTTP server
        "disabled": "disabled (Веб-сервер отключен - безопасно)",
        "enabled": "enabled (Веб-сервер включен - потребуется дополнительная настройка)",
        
        # ASLR
        "kernel.randomize_va_space = 2": "kernel.randomize_va_space = 2 (ASLR включен полностью - безопасно)",
        "kernel.randomize_va_space = 1": "kernel.randomize_va_space = 1 (ASLR включен частично - недостаточно безопасно)",
        "kernel.randomize_va_space = 0": "kernel.randomize_va_space = 0 (ASLR отключен - небезопасно)",
        
        # Firewall
        "Firewall active": "Firewall active (Файервол активен - безопасно)",
        
        # Password security
        "No empty passwords": "No empty passwords (Пустые пароли не обнаружены - безопасно)",
        
        # Syslog
        "Status: install ok installed": "Status: install ok installed (Служба журналирования установлена)",
        
        # SSH security
        "PermitRootLogin no": "PermitRootLogin no (Вход root через SSH отключен - безопасно)",
        "Protocol 2": "Protocol 2 (Используется безопасный протокол SSH)",
        
        # AppArmor/SELinux
        "No unconfined daemons": "No unconfined daemons (Все службы ограничены политиками безопасности)",
        
        # Common empty results (good)
        "No world-writable files found": "No world-writable files found (Нет файлов с правами записи для всех - безопасно)",
        "No unowned files found": "No unowned files found (Нет файлов без владельца - безопасно)",
        "No .netrc files found": "No .netrc files found (Нет файлов .netrc - безопасно)",
        "No .forward files found": "No .forward files found (Нет файлов .forward - безопасно)",
        "No world-writable directories without sticky bit found": "No world-writable directories without sticky bit found (Нет небезопасных общих директорий - безопасно)",
        
        # Common failure patterns
        "not set": "not set (Настройка не установлена - требуется исправление)",
        "Not properly configured": "Not properly configured (Настройка неправильная - требуется исправление)",
        "not properly configured": "not properly configured (Настройка неправильная - требуется исправление)",
        "not enabled": "not enabled (Служба не активирована - требуется исправление)",
        "Not enabled": "Not enabled (Служба не активирована - требуется исправление)",
        "incorrect": "incorrect (Настройка некорректна - требуется исправление)",
        "Incorrect": "Incorrect (Настройка некорректна - требуется исправление)",
        "Permissions incorrect": "Permissions incorrect (Неправильные права доступа - требуется исправление)",
    }
    
    # Проверяем наличие пояснений для конкретных строк вывода
    for key, explanation in linux_explanations.items():
        if key in output:
            # Заменяем все совпадения ключа на объяснение
            output = output.replace(key, explanation)
            
    return output
"""
    
    # Добавляем функцию перед функцией perform_scan
    if "async def perform_scan" in main_code:
        main_code = main_code.replace("async def perform_scan", linux_explanation_function + "\n\nasync def perform_scan")
    
    # Модифицируем код добавления результатов
    old_results_line = '                    "details": output,'
    new_results_line = '                    "details": add_linux_explanation(criterion.id, output),'
    
    if old_results_line in main_code:
        main_code = main_code.replace(old_results_line, new_results_line)
    
    # Сохраняем изменения
    with open("main.py.new", "w") as f:
        f.write(main_code)
    
    logger.info("Функция add_linux_explanation добавлена в main.py.new")
    logger.info("Для применения изменений выполните: mv main.py.new main.py && docker-compose restart backend")
    
    return True

# Обновляем также уже существующие результаты сканирования
def update_existing_results():
    """Обновляем существующие результаты сканирования с пояснениями"""
    db = SessionLocal()
    
    try:
        # Получаем все результаты для Linux-сканирований
        linux_scans = db.query(models.Scan).filter(models.Scan.connection_type == "ssh").all()
        
        updated_count = 0
        for scan in linux_scans:
            # Получаем результаты сканирования
            results = db.query(models.ScanResult).filter(models.ScanResult.scan_id == scan.id).all()
            
            for result in results:
                original_details = result.details
                
                # Добавляем пояснения ко всем ключевым словам
                for key, explanation in linux_explanations.items():
                    if key in original_details:
                        result.details = original_details.replace(key, explanation)
                        updated_count += 1
                        break
        
        db.commit()
        logger.info(f"Обновлено {updated_count} существующих результатов с пояснениями")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при обновлении существующих результатов: {str(e)}")
    finally:
        db.close()

if __name__ == "__main__":
    # Добавляем функцию в main.py
    add_linux_explanation_function()
    
    # Опционально: обновляем существующие результаты
    # update_existing_results()