from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import models, schemas, crud, auth
from database import SessionLocal, engine, Base
import paramiko
import json
import csv
from io import StringIO
import asyncio
import logging
import os
from datetime import datetime, timedelta

# Инициализируем логгер
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("server-audit")

# Создаем базу данных
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Server Security Audit", version="1.0.0")

# Добавляем CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене нужно ограничить до реальных доменов
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 для аутентификации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Endpoint для аутентификации и получения токена
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Dependency для получения текущего пользователя
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return auth.get_current_user(db, token)

# API endpoints

@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user

@app.get("/criteria/", response_model=List[schemas.Criterion])
def get_criteria(db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    return crud.get_criteria(db)

@app.get("/criteria_categories/", response_model=List[schemas.CriterionCategory])
def get_criteria_categories(db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    return crud.get_criteria_categories(db)

@app.post("/scan/", response_model=schemas.ScanResponse)
async def run_scan(scan_request: schemas.ScanRequest, db: Session = Depends(get_db), 
                  current_user: schemas.User = Depends(get_current_user)):
    """
    Запускает сканирование указанного сервера на соответствие выбранным критериям
    """
    logger.info(f"Начало сканирования сервера {scan_request.server_ip}")
    
    # Создаем запись о сканировании
    scan_record = crud.create_scan(db, 
                                  user_id=current_user.id, 
                                  server_ip=scan_request.server_ip,
                                  connection_type=scan_request.connection_type)
    
    try:
        # Получаем выбранные критерии
        selected_criteria = []
        for criterion_id in scan_request.criteria_ids:
            criterion = crud.get_criterion(db, criterion_id)
            if criterion:
                selected_criteria.append(criterion)
        
        # Выполняем сканирование
        results = await perform_scan(scan_request.server_ip, 
                                    scan_request.username,
                                    scan_request.password, 
                                    scan_request.ssh_key,
                                    scan_request.connection_type,
                                    selected_criteria)
        
        # Сохраняем результаты сканирования
        for result in results:
            crud.create_scan_result(db, scan_id=scan_record.id, **result)
        
        # Обновляем статус сканирования
        crud.update_scan_status(db, scan_record.id, "completed")
        
        return {
            "scan_id": scan_record.id,
            "results": results,
            "status": "completed",
            "message": f"Сканирование сервера {scan_request.server_ip} успешно завершено."
        }
        
    except Exception as e:
        # В случае ошибки обновляем статус и возвращаем сообщение об ошибке
        crud.update_scan_status(db, scan_record.id, "failed")
        logger.error(f"Ошибка при сканировании сервера {scan_request.server_ip}: {str(e)}")
        
        return {
            "scan_id": scan_record.id,
            "results": [],
            "status": "failed",
            "message": f"Ошибка при сканировании: {str(e)}"
        }

async def perform_scan(server_ip, username, password, ssh_key, connection_type, criteria):
    """
    Выполняет сканирование сервера на соответствие указанным критериям.
    Возвращает список результатов сканирования.
    """
    results = []
    
    try:
        # Подключаемся к серверу по SSH
        if connection_type == "ssh":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_key:
                private_key = paramiko.RSAKey.from_private_key_file(ssh_key)
                client.connect(server_ip, username=username, pkey=private_key)
            else:
                client.connect(server_ip, username=username, password=password)
                
            # Для каждого критерия выполняем проверку
            for criterion in criteria:
                try:
                    # Выполняем команду аудита
                    cmd = criterion.check_command
                    stdin, stdout, stderr = client.exec_command(cmd)
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    
                    # Анализируем результат и определяем статус
                    if criterion.expected_output in output:
                        status = "Pass"
                    else:
                        status = "Fail"
                    
                    # Добавляем результат
                    results.append({
                        "criterion_id": criterion.id,
                        "status": status,
                        "details": output if status == "Pass" else error or output,
                        "remediation": criterion.remediation if status == "Fail" else ""
                    })
                    
                except Exception as e:
                    # В случае ошибки при выполнении проверки
                    results.append({
                        "criterion_id": criterion.id,
                        "status": "Error",
                        "details": f"Ошибка при выполнении проверки: {str(e)}",
                        "remediation": criterion.remediation
                    })
            
            client.close()
            
        # Для WinRM (Windows Remote Management)
        elif connection_type == "winrm":
            # Здесь можно реализовать подключение к Windows-серверам через WinRM
            # Пример кода для WinRM будет отличаться от SSH
            pass
        
    except Exception as e:
        logger.error(f"Ошибка при сканировании: {str(e)}")
        raise
    
    return results

@app.get("/scans/", response_model=List[schemas.Scan])
def get_user_scans(db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    """
    Возвращает список всех сканирований пользователя
    """
    return crud.get_user_scans(db, current_user.id)

@app.get("/scans/{scan_id}", response_model=schemas.ScanDetail)
def get_scan_details(scan_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    """
    Возвращает детали сканирования по ID
    """
    scan = crud.get_scan(db, scan_id)
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    results = crud.get_scan_results(db, scan_id)
    
    return {
        "scan": scan,
        "results": results
    }

@app.get("/scans/{scan_id}/export/{format}")
def export_scan_results(scan_id: int, format: str, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    """
    Экспортирует результаты сканирования в выбранном формате (json или csv)
    """
    scan = crud.get_scan(db, scan_id)
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    results = crud.get_scan_results(db, scan_id)
    
    if format.lower() == "json":
        # Экспорт в JSON
        export_data = []
        for result in results:
            criterion = crud.get_criterion(db, result.criterion_id)
            export_data.append({
                "id": result.id,
                "criterion": criterion.name,
                "status": result.status,
                "severity": criterion.severity,
                "details": result.details,
                "remediation": result.remediation
            })
        
        return export_data
    
    elif format.lower() == "csv":
        # Экспорт в CSV
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Criterion", "Status", "Severity", "Details", "Remediation"])
        
        for result in results:
            criterion = crud.get_criterion(db, result.criterion_id)
            writer.writerow([
                result.id,
                criterion.name,
                result.status,
                criterion.severity,
                result.details,
                result.remediation
            ])
        
        return output.getvalue()
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'json' or 'csv'.")

# Запуск приложения
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
