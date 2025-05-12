"""
Скрипт для реорганизации Windows-критериев по разным категориям.
Вместо одной категории 'Windows Security' создает несколько подкатегорий.
"""

from database import SessionLocal, engine, Base
import models
import logging
import re

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("reorganize_windows_criteria.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("reorganize-windows-criteria")

# Новые категории для Windows критериев
windows_categories = [
    {"id": 13, "name": "Windows Updates", "description": "Критерии обновления Windows и защиты от вредоносных программ"},
    {"id": 14, "name": "Windows Services", "description": "Критерии настройки и безопасности служб Windows"},
    {"id": 15, "name": "Windows Registry", "description": "Критерии настройки реестра Windows"},
    {"id": 16, "name": "Windows User Security", "description": "Критерии безопасности учетных записей и UAC"},
    {"id": 17, "name": "Windows Network", "description": "Критерии сетевой безопасности Windows"},
    {"id": 18, "name": "Windows Remote Access", "description": "Критерии безопасности удаленного доступа (RDP, WinRM)"}
]

# Правила для распределения критериев по категориям
category_rules = {
    "13": ["Update", "Обновлен", "телеметр", "Adobe Flash", "SmartScreen"],
    "14": ["служб", "Service", "Служба", "Факс", "отключен", "Disable"],
    "15": ["реестр", "HKLM", "Registry", "значение Start", "value"],
    "16": ["Account", "учетн", "UAC", "password", "пароль", "Guest", "Administrator", "Admin"],
    "17": ["Network", "Multicast", "NetBIOS", "IP", "Firewall", "SNMP", "WDigest", "сет"],
    "18": ["RDP", "Remote", "удален", "WinRM", "SSH", "WebClient"]
}

def reorganize_windows_criteria():
    """Реорганизация Windows-критериев по разным категориям"""
    db = SessionLocal()
    
    try:
        # 1. Получаем все существующие Windows-критерии (категория 13)
        windows_criteria = db.query(models.Criterion).filter(models.Criterion.category_id == 13).all()
        if not windows_criteria:
            logger.warning("Windows-критерии не найдены")
            return 0
        
        logger.info(f"Найдено {len(windows_criteria)} Windows-критериев для реорганизации")
        
        # 2. Создаем новые категории
        existing_categories = []
        for category in windows_categories:
            existing_cat = db.query(models.CriterionCategory).filter(models.CriterionCategory.id == category["id"]).first()
            if existing_cat:
                logger.info(f"Категория {category['name']} (id: {category['id']}) уже существует")
                existing_categories.append(existing_cat.id)
            else:
                new_category = models.CriterionCategory(
                    id=category["id"],
                    name=category["name"],
                    description=category["description"]
                )
                db.add(new_category)
                db.commit()
                logger.info(f"Создана новая категория: {category['name']} (id: {category['id']})")
                existing_categories.append(category["id"])
        
        # 3. Распределяем критерии по категориям
        for criterion in windows_criteria:
            assigned = False
            
            # Определяем категорию по ключевым словам
            for cat_id, keywords in category_rules.items():
                if any(keyword.lower() in criterion.name.lower() or 
                       keyword.lower() in criterion.description.lower() for keyword in keywords):
                    criterion.category_id = int(cat_id)
                    assigned = True
                    logger.info(f"Критерий '{criterion.name}' (id: {criterion.id}) назначен категории {cat_id}")
                    break
            
            # Если категория не определена, оставляем в Windows Updates (13)
            if not assigned:
                criterion.category_id = 13
                logger.info(f"Критерий '{criterion.name}' (id: {criterion.id}) оставлен в категории 13 (по умолчанию)")
        
        db.commit()
        logger.info(f"Реорганизация Windows-критериев успешно завершена")
        return len(windows_criteria)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при реорганизации Windows-критериев: {str(e)}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    # Создаем таблицы, если они не существуют
    Base.metadata.create_all(bind=engine)
    
    # Реорганизуем Windows-критерии
    criteria_count = reorganize_windows_criteria()
    print(f"Реорганизовано {criteria_count} Windows-критериев")