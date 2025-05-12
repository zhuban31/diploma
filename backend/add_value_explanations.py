import logging
from database import SessionLocal
import models
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("add-explanations")

db = SessionLocal()

try:
    # Словарь с пояснениями к числовым значениям для различных проверок
    explanations = {
        "Windows Firewall": {
            "1": "1 (Включен 1 профиль брандмауэра из 3)",
            "2": "2 (Включены 2 профиля брандмауэра из 3)",
            "3": "3 (Включены все 3 профиля брандмауэра)",
            "0": "0 (Все профили брандмауэра отключены)"
        },
        "Windows UAC": {
            "1": "1 (UAC включен)",
            "0": "0 (UAC отключен)"
        },
        "Windows Authentication": {
            "0": "0 (Анонимный доступ разрешен)",
            "1": "1 (Базовое ограничение анонимного доступа)",
            "2": "2 (Строгое ограничение анонимного доступа)"
        },
        "Windows Remote Desktop": {
            "1": "1 (Безопасная авторизация RDP включена)",
            "0": "0 (Безопасная авторизация RDP отключена)"
        },
        "Windows Security Policy": {
            "0": "0 (UAC отключен)", 
            "1": "1 (UAC в режиме без уведомлений)",
            "2": "2 (UAC с уведомлениями)",
            "3": "3 (UAC в режиме запроса учетных данных)",
            "4": "4 (UAC в режиме запроса с затемнением рабочего стола)",
            "5": "5 (UAC в максимально строгом режиме)"
        },
        "Windows Registry": {
            "1": "1 (UAC включен в реестре)",
            "0": "0 (UAC отключен в реестре)"
        },
        "Windows User Rights": {
            "0": "0 (Группа не найдена)",
            "1": "1 (1 пользователь в группе Администраторы)",
            "2": "2 (2 пользователя в группе Администраторы)"
        },
        "Windows Basic Test": {
            "0": "0 (Не установлено ни одного обновления)",
            "1": "1 (Установлено 1 обновление)",
            "2": "2 (Установлено 2 обновления)",
            "3": "3 (Установлено 3 обновления)",
            "4": "4 (Установлено 4 обновления)"
        },
        "Windows Automatic Updates": {
            "0": "0 (Автоматическое обновление отключено)",
            "1": "1 (Только уведомления о доступных обновлениях)",
            "2": "2 (Автоматическая загрузка, ручная установка)",
            "3": "3 (Автоматическая загрузка и установка)",
            "4": "4 (Полностью автоматическое обновление)",
            "5": "5 (Настройка по умолчанию)"
        }
    }
    
    # Обновляем файл windows_scanner.py, чтобы он мог добавлять пояснения к цифрам
    with open("windows_scanner.py", "r") as f:
        scanner_code = f.read()
    
    # Ищем метод determine_status и модифицируем его
    original_determine_status = """
    def determine_status(self, criterion_id: int, output: str, expected: str) -> str:
        \"\"\"Determine if a check passes or fails based on the output and expected value\"\"\"
        logger.info(f"Determining status for criterion {criterion_id}: Output='{output[:50]}...', Expected='{expected}'")
        
        # If output contains the expected string, it passes
        if expected and expected in output:
            logger.info(f"Criterion {criterion_id} PASSED (expected string found)")
            return "Pass"
        
        # For Windows hostname command (our simple test)
        if "DESKTOP-" in output or "WIN-" in output:
            logger.info(f"Criterion {criterion_id} PASSED (hostname check)")
            return "Pass"
            
        # Default case - if no conditions are met, it's a fail
        logger.info(f"Criterion {criterion_id} FAILED - Output doesn't match expected value")
        return "Fail"
    """

    enhanced_determine_status = """
    def determine_status(self, criterion_id: int, output: str, expected: str) -> str:
        \"\"\"Determine if a check passes or fails based on the output and expected value\"\"\"
        logger.info(f"Determining status for criterion {criterion_id}: Output='{output[:50]}...', Expected='{expected}'")
        
        # If output contains the expected string, it passes
        if expected and expected in output:
            logger.info(f"Criterion {criterion_id} PASSED (expected string found)")
            return "Pass"
        
        # For Windows hostname command (our simple test)
        if "DESKTOP-" in output or "WIN-" in output:
            logger.info(f"Criterion {criterion_id} PASSED (hostname check)")
            return "Pass"
            
        # Default case - if no conditions are met, it's a fail
        logger.info(f"Criterion {criterion_id} FAILED - Output doesn't match expected value")
        return "Fail"
    
    def add_explanation(self, criterion_name: str, output: str) -> str:
        \"\"\"Add explanation to numeric outputs\"\"\"
        # Словарь с пояснениями к числовым значениям
        explanations = {
            "Windows Firewall": {
                "1": "1 (Включен 1 профиль брандмауэра из 3)",
                "2": "2 (Включены 2 профиля брандмауэра из 3)",
                "3": "3 (Включены все 3 профиля брандмауэра)",
                "0": "0 (Все профили брандмауэра отключены)"
            },
            "Windows UAC": {
                "1": "1 (UAC включен)",
                "0": "0 (UAC отключен)"
            },
            "Windows Authentication": {
                "0": "0 (Анонимный доступ разрешен)",
                "1": "1 (Базовое ограничение анонимного доступа)",
                "2": "2 (Строгое ограничение анонимного доступа)"
            },
            "Windows Remote Desktop": {
                "1": "1 (Безопасная авторизация RDP включена)",
                "0": "0 (Безопасная авторизация RDP отключена)"
            },
            "Windows Security Policy": {
                "0": "0 (UAC отключен)", 
                "1": "1 (UAC в режиме без уведомлений)",
                "2": "2 (UAC с уведомлениями)",
                "3": "3 (UAC в режиме запроса учетных данных)",
                "4": "4 (UAC в режиме запроса с затемнением рабочего стола)",
                "5": "5 (UAC в максимально строгом режиме)"
            },
            "Windows Registry": {
                "1": "1 (UAC включен в реестре)",
                "0": "0 (UAC отключен в реестре)"
            },
            "Windows User Rights": {
                "0": "0 (Группа не найдена)",
                "1": "1 (1 пользователь в группе Администраторы)",
                "2": "2 (2 пользователя в группе Администраторы)"
            },
            "Windows Basic Test": {
                "0": "0 (Не установлено ни одного обновления)",
                "1": "1 (Установлено 1 обновление)",
                "2": "2 (Установлено 2 обновления)",
                "3": "3 (Установлено 3 обновления)",
                "4": "4 (Установлено 4 обновления)"
            },
            "Windows Automatic Updates": {
                "0": "0 (Автоматическое обновление отключено)",
                "1": "1 (Только уведомления о доступных обновлениях)",
                "2": "2 (Автоматическая загрузка, ручная установка)",
                "3": "3 (Автоматическая загрузка и установка)",
                "4": "4 (Полностью автоматическое обновление)",
                "5": "5 (Настройка по умолчанию)"
            },
            "Windows Services": {
                "Running": "Running (Служба запущена)",
                "Stopped": "Stopped (Служба остановлена)"
            },
            "Windows SMB": {
                "True": "True (SMBv1 включен - небезопасно)",
                "False": "False (SMBv1 отключен - безопасно)"
            }
        }
        
        # Проверяем, есть ли пояснения для этого критерия
        if criterion_name in explanations:
            # Ищем числовое значение в выводе
            # Если вывод состоит только из одного числа или одного слова
            output_stripped = output.strip()
            if output_stripped in explanations[criterion_name]:
                return explanations[criterion_name][output_stripped]
        
        # Если пояснения не найдены, возвращаем исходный вывод
        return output
    """

    # Заменяем метод determine_status на улучшенную версию
    if original_determine_status.strip() in scanner_code:
        updated_code = scanner_code.replace(original_determine_status.strip(), enhanced_determine_status.strip())
        
        # Обновляем и строку с добавлением output в результаты
        updated_code = updated_code.replace(
            'details": f"Command: ```powershell\\n{criterion.check_command}\\n```\\n\\nOutput:\\n{output}"',
            'details": f"Command: ```powershell\\n{criterion.check_command}\\n```\\n\\nOutput:\\n{self.add_explanation(criterion.name, output)}"'
        )
        
        # Если предыдущая замена не сработала, пробуем другой вариант
        if 'details": f"Command: ```powershell\\n{criterion.check_command}\\n```\\n\\nOutput:\\n{output}"' not in updated_code:
            updated_code = updated_code.replace(
                '"details": output,',
                '"details": f"Command: ```powershell\\n{criterion.check_command}\\n```\\n\\nOutput:\\n{self.add_explanation(criterion.name, output)}",'
            )
            
        # Сохраняем обновленный файл
        with open("windows_scanner.py", "w") as f:
            f.write(updated_code)
        
        logger.info("Файл windows_scanner.py успешно обновлен с добавлением пояснений к цифрам")
    else:
        logger.warning("Не удалось найти метод determine_status в файле windows_scanner.py")
    
except Exception as e:
    logger.error(f"Ошибка при обновлении: {str(e)}")
finally:
    db.close()

print("Файл windows_scanner.py обновлен с пояснениями к числовым значениям.")
print("Перезапустите backend для применения изменений:")
print("docker-compose restart backend")
