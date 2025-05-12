"""
Скрипт для проверки импорта Windows-критериев.
Показывает количество Windows-критериев и информацию о них.
"""

from database import SessionLocal
import models
import sys

def check_windows_criteria():
    db = SessionLocal()
    
    try:
        # Проверяем наличие категории Windows Security
        windows_category = db.query(models.CriterionCategory).filter(models.CriterionCategory.id == 13).first()
        if not windows_category:
            print("ОШИБКА: Категория 'Windows Security' (id=13) не найдена!")
            return False
            
        print(f"Категория '{windows_category.name}' (id={windows_category.id}) найдена")
        
        # Проверяем наличие Windows-критериев
        windows_criteria = db.query(models.Criterion).filter(models.Criterion.category_id == 13).all()
        print(f"Найдено {len(windows_criteria)} Windows-критериев")
        
        if len(windows_criteria) == 0:
            print("ОШИБКА: Windows-критерии не найдены! Запустите скрипт import_windows_criteria.py")
            return False
            
        # Выводим информацию о первых 5 критериях
        print("\nПримеры Windows-критериев:")
        for i, criterion in enumerate(windows_criteria[:5]):
            print(f"{i+1}. ID: {criterion.id}, Имя: {criterion.name}")
            print(f"   Команда: {criterion.check_command[:70]}..." if len(criterion.check_command) > 70 else f"   Команда: {criterion.check_command}")
            print(f"   Ожидаемый вывод: {criterion.expected_output}")
            print()
        
        return True
        
    except Exception as e:
        print(f"Ошибка при проверке Windows-критериев: {str(e)}")
        return False
    finally:
        db.close()

if __name__ == "__main__":
    print("Проверка Windows-критериев в базе данных:")
    if check_windows_criteria():
        print("Проверка успешно завершена. Windows-критерии найдены.")
        sys.exit(0)
    else:
        print("Проверка не пройдена. Windows-критерии отсутствуют или некорректны.")
        sys.exit(1)