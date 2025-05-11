from sqlalchemy.orm import Session
import models, schemas
from auth import get_password_hash
from typing import List, Optional

# User operations
def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Criteria operations
def get_criterion(db: Session, criterion_id: int):
    return db.query(models.Criterion).filter(models.Criterion.id == criterion_id).first()

def get_criteria(db: Session, skip: int = 0, limit: int = 1000):
    return db.query(models.Criterion).offset(skip).limit(limit).all()

def get_criteria_by_category(db: Session, category_id: int):
    return db.query(models.Criterion).filter(models.Criterion.category_id == category_id).all()

def create_criterion(db: Session, criterion: schemas.CriterionCreate):
    db_criterion = models.Criterion(**criterion.dict())
    db.add(db_criterion)
    db.commit()
    db.refresh(db_criterion)
    return db_criterion

def update_criterion(db: Session, criterion_id: int, criterion_data: dict):
    db_criterion = db.query(models.Criterion).filter(models.Criterion.id == criterion_id).first()
    for key, value in criterion_data.items():
        setattr(db_criterion, key, value)
    db.commit()
    db.refresh(db_criterion)
    return db_criterion

def delete_criterion(db: Session, criterion_id: int):
    db_criterion = db.query(models.Criterion).filter(models.Criterion.id == criterion_id).first()
    db.delete(db_criterion)
    db.commit()
    return db_criterion

# Category operations
def get_criterion_category(db: Session, category_id: int):
    return db.query(models.CriterionCategory).filter(models.CriterionCategory.id == category_id).first()

def get_criteria_categories(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.CriterionCategory).offset(skip).limit(limit).all()

def create_criterion_category(db: Session, category: schemas.CriterionCategoryCreate):
    db_category = models.CriterionCategory(**category.dict())
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    return db_category

# Scan operations
def get_scan(db: Session, scan_id: int):
    return db.query(models.Scan).filter(models.Scan.id == scan_id).first()

def get_user_scans(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(models.Scan).filter(models.Scan.user_id == user_id).offset(skip).limit(limit).all()

def create_scan(db: Session, user_id: int, server_ip: str, connection_type: str):
    db_scan = models.Scan(user_id=user_id, server_ip=server_ip, connection_type=connection_type)
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

def update_scan_status(db: Session, scan_id: int, status: str):
    db_scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    db_scan.status = status
    db.commit()
    db.refresh(db_scan)
    return db_scan

# Scan result operations
def get_scan_result(db: Session, result_id: int):
    return db.query(models.ScanResult).filter(models.ScanResult.id == result_id).first()

def get_scan_results(db: Session, scan_id: int):
    return db.query(models.ScanResult).filter(models.ScanResult.scan_id == scan_id).all()

def create_scan_result(db: Session, scan_id: int, criterion_id: int, status: str, details: Optional[str] = None, remediation: Optional[str] = None):
    db_result = models.ScanResult(
        scan_id=scan_id,
        criterion_id=criterion_id,
        status=status,
        details=details,
        remediation=remediation
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return db_result
