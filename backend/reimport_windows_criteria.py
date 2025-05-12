"""
Скрипт для переимпорта Windows-критериев.
Удаляет существующие Windows-критерии и импортирует их заново.
"""

from database import SessionLocal, engine, Base
import models
from import_windows_criteria import import_windows_criteria_to_db
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("reimport_windows_criteria.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("reimport-windows-criteria")

def clean_windows_criteria():
    """Удаляет все существующие Windows-критерии"""
    db = SessionLocal()
    
    try:
        # Находим все Windows-критерии
        windows_criteria = db.query(models.Criterion).filter(models.Criterion.category_id == 13).all()
        
        if not windows_criteria:
            logger.info("Windows-критерии не найдены в базе данных")
            return 0
            
        count = len(windows_criteria)
        logger.info(f"Найдено {count} Windows-критериев для удаления")
        
        # Удаляем все Windows-критерии
        for criterion in windows_criteria:
            db.delete(criterion)
        
        # Удаляем результаты сканирования для Windows-критериев
        deleted_results = db.query(models.ScanResult).filter(
            models.ScanResult.criterion_id.in_([c.id for c in windows_criteria])
        ).delete(synchronize_session=False)
        
        logger.info(f"Удалено {deleted_results} результатов сканирования для Windows-критериев")
        
        db.commit()
        logger.info(f"Успешно удалено {count} Windows-критериев")
        return count
        
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при удалении Windows-критериев: {str(e)}")
        raise
    finally:
        db.close()

def main():
    """Переимпорт Windows-критериев"""
    try:
        # Создаем таблицы, если они не существуют
        Base.metadata.create_all(bind=engine)
        
        # Очищаем существующие Windows-критерии
        deleted_count = clean_windows_criteria()
        logger.info(f"Удалено {deleted_count} существующих Windows-критериев")
        
        # Импортируем Windows-критерии заново
        imported_count = import_windows_criteria_to_db()
        logger.info(f"Импортировано {imported_count} Windows-критериев")
        
        print(f"Переимпорт завершен: удалено {deleted_count}, добавлено {imported_count} Windows-критериев")
        
    except Exception as e:
        logger.error(f"Ошибка при переимпорте Windows-критериев: {str(e)}")
        print(f"Ошибка: {str(e)}")

if __name__ == "__main__":
    main()