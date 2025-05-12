"""
Скрипт для исправления категоризации критериев и проверки их корректности.
Также восстанавливает имена Windows-критериев.
"""

from database import SessionLocal, engine, Base
import models
import logging
import sys

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fix_criteria_categories.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("fix-criteria-categories")

# Линукс и Windows категории
linux_category_ids = range(1, 13)  # от 1 до 12
windows_category_ids = range(13, 19)  # от 13 до 18

def check_criteria_categories():
    """Проверка и вывод информации о категориях и их критериях"""
    db = SessionLocal()
    try:
        logger.info("Проверка категорий критериев:")
        
        # Проверка Linux-категорий
        linux_categories = db.query(models.CriterionCategory).filter(
            models.CriterionCategory.id.in_(linux_category_ids)
        ).all()
        
        logger.info(f"Найдено {len(linux_categories)} Linux-категорий:")
        for cat in linux_categories:
            criteria_count = db.query(models.Criterion).filter(
                models.Criterion.category_id == cat.id
            ).count()
            logger.info(f"ID: {cat.id}, Название: {cat.name}, Критериев: {criteria_count}")
        
        # Проверка Windows-категорий
        windows_categories = db.query(models.CriterionCategory).filter(
            models.CriterionCategory.id.in_(windows_category_ids)
        ).all()
        
        logger.info(f"Найдено {len(windows_categories)} Windows-категорий:")
        for cat in windows_categories:
            criteria_count = db.query(models.Criterion).filter(
                models.Criterion.category_id == cat.id
            ).count()
            logger.info(f"ID: {cat.id}, Название: {cat.name}, Критериев: {criteria_count}")
        
        # Проверка на странные критерии
        strange_criteria = db.query(models.Criterion).filter(
            models.Criterion.name.in_(["Check", "Expected", "Remediation", "Description"])
        ).all()
        
        if strange_criteria:
            logger.warning(f"Найдено {len(strange_criteria)} критериев с неправильными именами:")
            for c in strange_criteria:
                logger.warning(f"ID: {c.id}, Имя: {c.name}, Категория: {c.category_id}")
                
        return linux_categories, windows_categories, strange_criteria
        
    except Exception as e:
        logger.error(f"Ошибка при проверке критериев: {str(e)}")
        return [], [], []
    finally:
        db.close()

def fix_strange_criteria_names():
    """Исправление странных имен критериев (Check, Expected и т.д.)"""
    db = SessionLocal()
    try:
        # Находим критерии с проблемными именами
        strange_criteria = db.query(models.Criterion).filter(
            models.Criterion.name.in_(["Check", "Expected", "Remediation", "Description"])
        ).all()
        
        if not strange_criteria:
            logger.info("Странных критериев не найдено")
            return 0
            
        logger.info(f"Найдено {len(strange_criteria)} критериев с неправильными именами, исправляем...")
        
        # Имена замены для проблемных критериев
        replacement_names = {
            "Check": "Windows Security Check",
            "Expected": "Windows Security Expected",
            "Remediation": "Windows Security Remediation",
            "Description": "Windows Security Description"
        }
        
        # Порядковый номер для уникализации имен
        counter = 1
        
        # Исправляем имена
        for criterion in strange_criteria:
            old_name = criterion.name
            if old_name in replacement_names:
                new_name = f"{replacement_names[old_name]} #{counter}"
                criterion.name = new_name
                counter += 1
                logger.info(f"Имя критерия изменено: '{old_name}' -> '{new_name}'")
        
        db.commit()
        logger.info(f"Исправлено {len(strange_criteria)} критериев")
        return len(strange_criteria)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при исправлении имен критериев: {str(e)}")
        return 0
    finally:
        db.close()

def ensure_criteria_in_correct_categories():
    """Проверка и исправление принадлежности критериев к правильным категориям"""
    db = SessionLocal()
    try:
        # Находим Linux-критерии в Windows-категориях
        misplaced_linux = db.query(models.Criterion).filter(
            ~models.Criterion.name.like("Windows%"),
            models.Criterion.category_id.in_(windows_category_ids)
        ).all()
        
        # Находим Windows-критерии в Linux-категориях
        misplaced_windows = db.query(models.Criterion).filter(
            models.Criterion.name.like("Windows%"), 
            models.Criterion.category_id.in_(linux_category_ids)
        ).all()
        
        fixed_count = 0
        
        # Исправляем Linux-критерии
        if misplaced_linux:
            logger.info(f"Найдено {len(misplaced_linux)} Linux-критериев в Windows-категориях")
            for criterion in misplaced_linux:
                old_category = criterion.category_id
                criterion.category_id = 1  # Перемещаем в категорию "System Updates"
                logger.info(f"Критерий '{criterion.name}' перемещен из категории {old_category} в категорию 1")
                fixed_count += 1
        
        # Исправляем Windows-критерии
        if misplaced_windows:
            logger.info(f"Найдено {len(misplaced_windows)} Windows-критериев в Linux-категориях")
            for criterion in misplaced_windows:
                old_category = criterion.category_id
                criterion.category_id = 13  # Перемещаем в категорию "Windows Updates"
                logger.info(f"Критерий '{criterion.name}' перемещен из категории {old_category} в категорию 13")
                fixed_count += 1
        
        db.commit()
        logger.info(f"Исправлено {fixed_count} критериев")
        return fixed_count
        
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при исправлении категорий критериев: {str(e)}")
        return 0
    finally:
        db.close()

if __name__ == "__main__":
    # Проверяем категории критериев
    linux_cats, windows_cats, strange_crits = check_criteria_categories()
    
    # Исправляем странные имена критериев
    fixed_names = fix_strange_criteria_names()
    print(f"Исправлено {fixed_names} критериев с неправильными именами")
    
    # Исправляем критерии в неправильных категориях
    fixed_categories = ensure_criteria_in_correct_categories()
    print(f"Исправлено {fixed_categories} критериев в неправильных категориях")
    
    # Проверяем результаты
    if fixed_names > 0 or fixed_categories > 0:
        print("\nИзменения внесены. Проверяем результаты:")
        check_criteria_categories()
    else:
        print("\nНет изменений. Все критерии в порядке.")