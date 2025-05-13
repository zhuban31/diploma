"""
Исправленная версия добавления пояснений к Linux-критериям безопасности
"""

import logging
import re
from database import SessionLocal
import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("linux-explanations-fix")

# Функция для замены скрипта в main.py
def fix_linux_explanations():
    """Создает новую функцию add_linux_explanation и заменяет старую в main.py"""
    
    # Читаем текущий файл main.py
    with open("main.py", "r") as f:
        main_code = f.read()
    
    # Удаляем старую функцию add_linux_explanation, если она есть
    # Ищем начало и конец функции
    start_pattern = "def add_linux_explanation"
    end_pattern = "async def perform_scan"
    
    if start_pattern in main_code:
        # Находим позиции начала и конца
        start_pos = main_code.find(start_pattern)
        end_pos = main_code.find(end_pattern, start_pos)
        
        # Если нашли обе позиции, удаляем функцию
        if start_pos != -1 and end_pos != -1:
            # Ищем начало определения функции (def)
            def_pos = main_code.rfind("def ", 0, start_pos)
            if def_pos != -1:
                start_pos = def_pos
            
            # Вырезаем старую функцию, оставляя async def perform_scan
            before_function = main_code[:start_pos]
            after_function = main_code[end_pos:]
            main_code = before_function + after_function
    
    # Создаем новую улучшенную функцию
    improved_function = """
def add_linux_explanation(criterion_id: int, output: str) -> str:
    \"\"\"
    Добавляет пояснения к выводу Linux-команд, учитывая ID критерия
    и обрабатывая только нужные части вывода
    
    Args:
        criterion_id: ID критерия
        output: Исходный вывод команды
        
    Returns:
        Вывод с добавленными пояснениями
    \"\"\"
    # Если вывод пустой, не меняем его
    if not output:
        return output
    
    # Разделяем вывод на секции, чтобы обрабатывать только результаты,
    # а не команды и структурные элементы вывода
    command_section = ""
    result_section = ""
    
    # Проверяем, содержит ли вывод структурированные секции
    if "=== НАЧАЛО ВЫПОЛНЕНИЯ КОМАНДЫ ===" in output and "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===" in output:
        parts = output.split("=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===")
        if len(parts) > 1:
            command_section = parts[0]
            result_section = "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===" + parts[1]
            
            # Проверяем, есть ли завершающая секция
            if "=== КОНЕЦ ВЫПОЛНЕНИЯ ===" in result_section:
                result_parts = result_section.split("=== КОНЕЦ ВЫПОЛНЕНИЯ ===")
                if len(result_parts) > 1:
                    result_section = result_parts[0]
                    end_section = "=== КОНЕЦ ВЫПОЛНЕНИЯ ===" + result_parts[1]
                else:
                    end_section = ""
            else:
                end_section = ""
    else:
        # Если нет структурированных секций, обрабатываем весь вывод
        result_section = output
        command_section = ""
        end_section = ""
    
    # Словарь с соответствиями ID критерия и пояснений
    explanations_by_id = {
        # System Updates (110-199)
        110: {
            "unattended-upgrades": "unattended-upgrades (Пакет автоматических обновлений установлен)",
        },
        120: {
            "No upgrades needed": "No upgrades needed (Система обновлена)",
            "Upgrades needed": "Upgrades needed (Требуются обновления)",
        },
        130: {
            "All transports secure": "All transports secure (Все репозитории используют безопасные протоколы)",
        },
        
        # Filesystem (210-299)
        210: {
            "noexec": "noexec (Запрещено выполнение файлов в /tmp - безопасно)",
        },
        220: {
            "nodev set": "nodev set (Запрещены файлы устройств в /tmp - безопасно)",
            "nodev not set": "nodev not set (Разрешены файлы устройств в /tmp - небезопасно)",
        },
        230: {
            "nosuid set": "nosuid set (Запрещены SUID биты в /tmp - безопасно)",
            "nosuid not set": "nosuid not set (Разрешены SUID биты в /tmp - небезопасно)",
        },
        
        # Bootloader (310-399)
        310: {
            "password": "password (Пароль загрузчика установлен - безопасно)",
        },
        320: {
            "Permissions correct": "Permissions correct (Права доступа к файлу загрузчика корректны)",
            "Permissions incorrect": "Permissions incorrect (Неправильные права доступа к файлу загрузчика)",
        },
        330: {
            "Authentication required": "Authentication required (Аутентификация для однопользовательского режима настроена)",
            "No authentication required": "No authentication required (Аутентификация для однопользовательского режима не настроена)",
        },
        
        # Process Hardening (409-499)
        409: {
            "* hard core 0": "* hard core 0 (Дампы памяти отключены - безопасно)",
        },
        412: {
            "kernel.randomize_va_space = 2": "kernel.randomize_va_space = 2 (ASLR включен полностью - безопасно)",
            "kernel.randomize_va_space = 1": "kernel.randomize_va_space = 1 (ASLR включен частично - недостаточно безопасно)",
            "kernel.randomize_va_space = 0": "kernel.randomize_va_space = 0 (ASLR отключен - небезопасно)",
        },
        420: {
            "Prelink not installed": "Prelink not installed (Prelink не установлен - безопасно)",
            "Prelink installed": "Prelink installed (Prelink установлен - небезопасно)",
        },
        430: {
            "Core dumps protected": "Core dumps protected (Дампы памяти защищены от чтения)",
            "Core dumps may be exposed": "Core dumps may be exposed (Дампы памяти могут быть доступны другим пользователям)",
        },
        
        # Network Configuration (509-599)
        509: {
            "net.ipv4.ip_forward = 0": "net.ipv4.ip_forward = 0 (IP-перенаправление отключено - безопасно)",
            "net.ipv4.ip_forward = 1": "net.ipv4.ip_forward = 1 (IP-перенаправление включено - небезопасно)",
        },
        520: {
            "disabled": "disabled (Веб-сервер отключен - безопасно)",
            "enabled": "enabled (Веб-сервер включен - требует настройки)",
        },
        530: {
            "Correctly configured": "Correctly configured (MaxAuthTries настроен правильно)",
            "Not properly configured": "Not properly configured (MaxAuthTries не настроен правильно)",
        },
        540: {
            "Correctly configured": "Correctly configured (SSH LogLevel настроен правильно)",
            "Not properly configured": "Not properly configured (SSH LogLevel не настроен правильно)",
        },
        550: {
            "PermitRootLogin no": "PermitRootLogin no (Вход root через SSH отключен - безопасно)",
        },
        552: {
            "Protocol 2": "Protocol 2 (Используется безопасный протокол SSH v2)",
        },
        560: {
            "Correctly configured": "Correctly configured (PermitEmptyPasswords отключен - безопасно)",
            "Not properly configured": "Not properly configured (PermitEmptyPasswords не отключен - небезопасно)",
        },
        570: {
            "X11 forwarding disabled": "X11 forwarding disabled (Перенаправление X11 отключено - безопасно)",
            "X11 forwarding not disabled": "X11 forwarding not disabled (Перенаправление X11 не отключено - небезопасно)",
        },
        
        # Network Hardening (610-699)
        610: {
            "Soft blocked: yes": "Soft blocked: yes (Беспроводные интерфейсы отключены - безопасно)",
            "Soft blocked: no": "Soft blocked: no (Беспроводные интерфейсы включены - потенциальный риск)",
        },
        615: {
            "net.ipv6.conf.all.disable_ipv6 = 1": "net.ipv6.conf.all.disable_ipv6 = 1 (IPv6 отключен - безопасно)",
            "net.ipv6.conf.all.disable_ipv6 = 0": "net.ipv6.conf.all.disable_ipv6 = 0 (IPv6 включен - потенциально небезопасно)",
        },
        620: {
            "No unconfined daemons": "No unconfined daemons (Все службы ограничены политиками безопасности - безопасно)",
        },
        630: {
            "Firewall active": "Firewall active (Файервол активен - безопасно)",
        },
        640: {
            "Outbound filtering active": "Outbound filtering active (Фильтрация исходящего трафика включена - безопасно)",
            "No outbound filtering": "No outbound filtering (Фильтрация исходящего трафика отключена - потенциально небезопасно)",
        },
        650: {
            "No active wireless interfaces": "No active wireless interfaces (Нет активных беспроводных интерфейсов - безопасно)",
        },
        
        # Logging and Auditing (710-799)
        710: {
            "active": "active (Служба аудита активна - безопасно)",
            "inactive": "inactive (Служба аудита неактивна - небезопасно)",
        },
        720: {
            "Enabled": "Enabled (Служба аудита включена автоматически)",
            "Not enabled": "Not enabled (Служба аудита не включена автоматически)",
        },
        730: {
            "Status: install ok installed": "Status: install ok installed (Служба журналирования установлена - безопасно)",
        },
        740: {
            "Logrotate configured": "Logrotate configured (Ротация журналов настроена - безопасно)",
            "Logrotate not configured": "Logrotate not configured (Ротация журналов не настроена - небезопасно)",
        },
        750: {
            "Remote logging configured": "Remote logging configured (Удалённое журналирование настроено - безопасно)",
            "Remote logging not configured": "Remote logging not configured (Удалённое журналирование не настроено)",
        },
        
        # User Account Settings (810-899)
        810: {
            "PASS_MAX_DAYS\t99999": "PASS_MAX_DAYS\t99999 (Пароли никогда не истекают - небезопасно)",
            "PASS_MAX_DAYS\t90": "PASS_MAX_DAYS\t90 (Срок действия пароля 90 дней - рекомендуемое значение)",
        },
        820: {
            "No empty passwords": "No empty passwords (Пустые пароли не обнаружены - безопасно)",
        },
        830: {
            "Correctly configured": "Correctly configured (Минимальное время между сменами пароля настроено корректно)",
            "Not properly configured": "Not properly configured (Минимальное время между сменами пароля не настроено корректно)",
        },
        840: {
            "SHA-512 enabled": "SHA-512 enabled (Используется сильное хеширование паролей - безопасно)",
            "SHA-512 not enabled": "SHA-512 not enabled (Не используется сильное хеширование паролей - небезопасно)",
        },
        
        # Warning Banners (910-999)
        910: {
            "/etc/issue.net": "/etc/issue.net (Баннер SSH настроен)",
        },
        920: {
            "Warning exists": "Warning exists (Предупреждающий баннер настроен - безопасно)",
            "No appropriate warning": "No appropriate warning (Предупреждающий баннер не настроен)",
        },
        930: {
            "Warning exists": "Warning exists (Предупреждающий баннер настроен - безопасно)",
            "No appropriate warning": "No appropriate warning (Предупреждающий баннер не настроен)",
        },
        
        # File Permissions (1010-1099)
        1010: {
            "644 0 0": "644 0 0 (Права 644, владелец root:root - правильная конфигурация)",
        },
        1020: {
            "640 0 42": "640 0 42 (Права 640, владелец root:shadow - правильная конфигурация)",
        },
        1030: {
            "Permissions correct": "Permissions correct (Права на /etc/group настроены правильно)",
            "Permissions incorrect": "Permissions incorrect (Права на /etc/group настроены неправильно)",
        },
        1040: {
            "Permissions correct": "Permissions correct (Права на /etc/gshadow настроены правильно)",
            "Permissions incorrect": "Permissions incorrect (Права на /etc/gshadow настроены неправильно)",
        },
        1050: {
            "No world-writable directories without sticky bit found": "No world-writable directories without sticky bit found (Нет директорий с небезопасными правами доступа)",
        },
        
        # User Settings (1110-1199)
        1110: {
            "1": "1 (PATH не содержит пустых директорий - безопасно)",
            "Empty Directory": "Empty Directory (PATH содержит пустые директории - небезопасно)",
        },
        1120: {
            "No world-writable files found": "No world-writable files found (Нет файлов с правами записи для всех - безопасно)",
        },
        1130: {
            "No unowned files found": "No unowned files found (Нет файлов без владельца - безопасно)",
        },
        
        # Account Settings (1210-1299)
        1210: {
            "No .forward files found": "No .forward files found (Нет файлов .forward - безопасно)",
        },
        1220: {
            "No .netrc files found": "No .netrc files found (Нет файлов .netrc - безопасно)",
        },
        1230: {
            "Permissions correct": "Permissions correct (Права на домашние директории настроены правильно)",
            "Permissions incorrect": "Permissions incorrect (Права на домашние директории настроены неправильно)",
        },
        1240: {
            "Umask properly configured": "Umask properly configured (Umask настроен правильно - безопасно)",
            "Umask not configured": "Umask not configured (Umask не настроен - потенциально небезопасно)",
        },
    }
    
    # Общие пояснения для всех критериев
    general_explanations = {
        "not set": "not set (Настройка не установлена - требуется исправление)",
        "Not properly configured": "Not properly configured (Настройка неправильная - требуется исправление)",
        "not properly configured": "not properly configured (Настройка неправильная - требуется исправление)",
        "not enabled": "not enabled (Служба не активирована - требуется исправление)",
        "Not enabled": "Not enabled (Служба не активирована - требуется исправление)",
        "incorrect": "incorrect (Настройка некорректна - требуется исправление)",
        "Incorrect": "Incorrect (Настройка некорректна - требуется исправление)",
        "Permissions incorrect": "Permissions incorrect (Неправильные права доступа - требуется исправление)",
    }
    
    # Получаем словарь пояснений для текущего критерия
    specific_explanations = explanations_by_id.get(criterion_id, {})
    
    # Функция для безопасного применения замен (только для полных слов, не внутри других слов)
    def safe_replace(text, old, new):
        # Проверяем, что текст или заменяемое слово не пустые
        if not text or not old:
            return text
            
        # Проверяем, что заменяемое слово не содержит уже пояснение (в скобках)
        if "(" in old and ")" in old:
            return text
            
        # Используем регулярное выражение для замены только целых слов или фраз
        # \\b - граница слова, escape-последовательность для re.sub
        # (?<!\\() - отрицательный просмотр назад, убеждаемся что перед old нет открывающей скобки
        # (?!\\)) - отрицательный просмотр вперед, убеждаемся что после old нет закрывающей скобки
        pattern = f"(?<!\\()\\b{re.escape(old)}\\b(?!\\))"
        return re.sub(pattern, new, text)
    
    # Сначала применяем замены для конкретного критерия
    result_text = result_section
    for old, new in specific_explanations.items():
        result_text = safe_replace(result_text, old, new)
    
    # Затем общие замены (только если не были применены специфичные)
    for old, new in general_explanations.items():
        result_text = safe_replace(result_text, old, new)
    
    # Собираем обратно вывод
    if command_section and end_section:
        return command_section + result_text + end_section
    else:
        return result_text
"""
    
    # Добавляем новую функцию перед perform_scan
    if "async def perform_scan" in main_code:
        main_code = main_code.replace("async def perform_scan", improved_function + "\n\nasync def perform_scan")
    
    # Меняем вызов в perform_scan
    old_details_line = '                    "details": output,'
    new_details_line = '                    "details": add_linux_explanation(criterion.id, output),'
    
    if old_details_line in main_code:
        main_code = main_code.replace(old_details_line, new_details_line)
    
    # Сохраняем изменения в новый файл
    with open("main.py.fixed", "w") as f:
        f.write(main_code)
    
    logger.info("Создан файл main.py.fixed с исправленной функцией add_linux_explanation")
    logger.info("Для применения изменений выполните:")
    logger.info("docker-compose exec backend mv main.py.fixed main.py")
    logger.info("docker-compose restart backend")
    
    return True

if __name__ == "__main__":
    # Исправляем функцию пояснений
    fix_linux_explanations()