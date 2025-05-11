import argparse
import sys
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import models, schemas
from auth import get_password_hash

def create_admin_user(username, email, password):
    """Создает пользователя с административными правами"""
    db = SessionLocal()
    
    try:
        # Проверяем, существует ли уже пользователь с таким именем
        existing_user = db.query(models.User).filter(models.User.username == username).first()
        if existing_user:
            print(f"Пользователь с именем '{username}' уже существует.")
            return False
        
        # Создаем нового пользователя
        hashed_password = get_password_hash(password)
        new_user = models.User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            is_active=True
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        print(f"Пользователь '{username}' успешно создан.")
        return True
        
    except Exception as e:
        db.rollback()
        print(f"Ошибка при создании пользователя: {e}")
        return False
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Создание первого пользователя для системы')
    parser.add_argument('--username', default='admin', help='Имя пользователя (по умолчанию: admin)')
    parser.add_argument('--email', default='admin@example.com', help='Email (по умолчанию: admin@example.com)')
    parser.add_argument('--password', default='admin123', help='Пароль (по умолчанию: admin123)')
    
    args = parser.parse_args()
    
    # Проверка минимальной длины пароля
    if len(args.password) < 8:
        print("Пароль должен содержать не менее 8 символов")
        sys.exit(1)
    
    # Создаем таблицы в базе данных, если они еще не созданы
    Base.metadata.create_all(bind=engine)
    
    success = create_admin_user(args.username, args.email, args.password)
    
    if not success:
        sys.exit(1)
