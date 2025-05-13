"""
Исправляем отсутствие импорта модуля re
"""

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix-re-import")

def add_re_import():
    """Добавляет импорт модуля re в main.py"""
    
    # Читаем main.py
    with open("main.py", "r") as f:
        content = f.read()
    
    # Проверяем, есть ли уже импорт re
    if "import re" not in content:
        # Находим блок импортов
        import_section_end = content.find("# Инициализируем логгер")
        if import_section_end == -1:
            import_section_end = content.find("Base.metadata.create_all")
        
        if import_section_end > 0:
            # Добавляем импорт re перед концом блока импортов
            updated_content = content[:import_section_end] + "import re\n" + content[import_section_end:]
            
            # Записываем обновленный файл
            with open("main.py", "w") as f:
                f.write(updated_content)
            
            logger.info("Добавлен импорт 're' в main.py")
            return True
        else:
            logger.error("Не удалось найти подходящее место для импорта")
            return False
    else:
        logger.info("Импорт 're' уже существует в main.py")
        return True

if __name__ == "__main__":
    add_re_import()