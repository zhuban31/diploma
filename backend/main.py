from fastapi import FastAPI, Depends, HTTPException, status, Form
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

# Добавляем CORS middleware с расширенными настройками
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешаем запросы от любых источников
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
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
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # Логирование попытки входа для отладки
    logger.info(f"Попытка входа с именем пользователя: {form_data.username}")
    
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.warning(f"Неудачная попытка входа для пользователя: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    logger.info(f"Успешный вход для пользователя: {form_data.username}")
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
                                    selected_criteria,
                                    scan_request.use_sudo)
        
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

async def perform_scan(server_ip, username, password, ssh_key, connection_type, criteria, use_sudo=False):
    """
    Выполняет сканирование сервера на соответствие указанным критериям.
    Возвращает список результатов сканирования.
    """
    results = []
    
    try:
        # Подключаемся к серверу по SSH
        if connection_type == "ssh":
            logger.info(f"Подключение к серверу {server_ip} по SSH с пользователем {username}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_key:
                logger.info(f"Используется SSH-ключ: {ssh_key}")
                private_key = paramiko.RSAKey.from_private_key_file(ssh_key)
                client.connect(server_ip, username=username, pkey=private_key)
            else:
                logger.info("Используется аутентификация по паролю")
                client.connect(server_ip, username=username, password=password)
                
            logger.info(f"Успешное подключение к {server_ip}. Начинаем выполнение проверок.")
            
            # Проверка доступности sudo, если требуется
            if use_sudo:
                logger.info("Проверка работоспособности sudo...")
                # Тест без sudo
                stdin, stdout, stderr = client.exec_command("id")
                output_without_sudo = stdout.read().decode('utf-8')
                error_without_sudo = stderr.read().decode('utf-8')
                logger.info(f"Тест без sudo: {output_without_sudo}")
                
                # Тест с sudo -n (проверка без пароля)
                stdin, stdout, stderr = client.exec_command("sudo -n id")
                output_with_sudo_n = stdout.read().decode('utf-8')
                error_with_sudo_n = stderr.read().decode('utf-8')
                logger.info(f"Тест с sudo -n: {output_with_sudo_n}, ошибки: {error_with_sudo_n}")
                
                # Если sudo -n не работает, настраиваем временный доступ
                if "password is required" in error_with_sudo_n:
                    logger.info("Sudo -n не работает, пробуем настроить временный sudo доступ")
                    # Создаем временный файл sudoers
                    sudo_command = f'echo "{password}" | sudo -S echo "Настройка временного sudo"'
                    stdin, stdout, stderr = client.exec_command(sudo_command)
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    logger.info(f"Настройка временного sudo: {error}")
                
                    # Создаем временное sudoers правило
                    temp_sudoers_cmd = f"""echo "{password}" | sudo -S bash -c 'echo "{username} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/temp_{username}'"""
                    stdin, stdout, stderr = client.exec_command(temp_sudoers_cmd)
                    
                    # Убедимся, что правило применилось
                    stdin, stdout, stderr = client.exec_command("sudo -n id")
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    
                    if "password is required" in error:
                        logger.warning("Не удалось настроить sudo без пароля, будем использовать обычный sudo")
                        use_sudo_command = f'echo "{password}" | sudo -S'
                    else:
                        use_sudo_command = "sudo -n"
                else:
                    use_sudo_command = "sudo -n"
            
            # Для каждого критерия выполняем проверку
            for criterion in criteria:
                try:
                    # Получаем команду проверки
                    cmd = criterion.check_command
                    
                    logger.info(f"Выполнение команды для критерия {criterion.id} ({criterion.name}): {cmd}")
                    
                    # Проверяем, что команда не пустая
                    if not cmd:
                        logger.warning(f"Пустая команда для критерия {criterion.id}. Пропускаем.")
                        results.append({
                            "criterion_id": criterion.id,
                            "status": "Error",
                            "details": "Команда проверки не определена",
                            "remediation": criterion.remediation
                        })
                        continue
                    
                    # Если нужно использовать sudo, добавляем его к команде
                    if use_sudo and not cmd.startswith("sudo "):
                        original_cmd = cmd
                        cmd = f"{use_sudo_command} {cmd}"
                    
                    # Создаем скрипт для выполнения команды с дополнительным контекстом
                    script_content = f"""#!/bin/bash
echo "=== НАЧАЛО ВЫПОЛНЕНИЯ КОМАНДЫ ==="
echo "Команда: {cmd}"
echo "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ==="
{cmd} 2>&1 || echo "Команда завершилась с ошибкой: $?"
echo "=== КОНЕЦ ВЫПОЛНЕНИЯ ==="
"""
                    # Создаем временный скрипт на удаленном сервере
                    create_script_cmd = f"cat > /tmp/scan_cmd.sh << 'EOF'\n{script_content}\nEOF\nchmod +x /tmp/scan_cmd.sh"
                    stdin, stdout, stderr = client.exec_command(create_script_cmd)
                    
                    # Выполняем скрипт
                    stdin, stdout, stderr = client.exec_command("bash /tmp/scan_cmd.sh")
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')
                    
                    # Удаляем временный скрипт
                    client.exec_command("rm -f /tmp/scan_cmd.sh")
                    
                    # Логируем вывод команды
                    logger.info(f"Результат выполнения команды для критерия {criterion.id}:")
                    logger.info(f"STDOUT: {output}")
                    if error:
                        logger.info(f"STDERR: {error}")
                    
                    # Проверка на ошибки sudo
                    if use_sudo and "sudo:" in error and "command not found" in error:
                        logger.error(f"Ошибка sudo для критерия {criterion.id}: {error}")
                        results.append({
                            "criterion_id": criterion.id,
                            "status": "Error",
                            "details": f"Ошибка выполнения sudo команды: {error}",
                            "remediation": criterion.remediation
                        })
                        continue
                    
                    # Добавляем более очевидные сообщения для пустого вывода
                    if not output.strip() and not error.strip():
                        output = "Команда выполнена, но не вернула никакого вывода"
                    
                    # Анализируем результат и определяем статус
                    expected = criterion.expected_output
                    logger.info(f"Сравниваем с ожидаемым результатом: '{expected}'")
                    
                    if expected and expected in output:
                        status = "Pass"
                        logger.info(f"Критерий {criterion.id} ПРОЙДЕН")
                    else:
                        status = "Fail"
                        logger.info(f"Критерий {criterion.id} НЕ ПРОЙДЕН")
                    
                    # Добавляем результат
                    results.append({
                        "criterion_id": criterion.id,
                        "status": status,
                        "details": output,
                        "remediation": criterion.remediation if status == "Fail" else ""
                    })
                    
                except Exception as e:
                    # В случае ошибки при выполнении проверки
                    logger.error(f"Ошибка при выполнении команды для критерия {criterion.id}: {str(e)}")
                    results.append({
                        "criterion_id": criterion.id,
                        "status": "Error",
                        "details": f"Ошибка при выполнении проверки: {str(e)}",
                        "remediation": criterion.remediation
                    })
            
            # Удаляем временный файл sudoers, если он был создан
            if use_sudo and "temp_sudoers_cmd" in locals():
                cleanup_cmd = f'echo "{password}" | sudo -S rm -f /etc/sudoers.d/temp_{username}'
                stdin, stdout, stderr = client.exec_command(cleanup_cmd)
                logger.info("Временный файл sudoers удален")
            
            logger.info(f"Сканирование сервера {server_ip} завершено. Закрываем SSH-соединение.")
            client.close()
            
        # Для WinRM (Windows Remote Management)
        elif connection_type == "winrm":
            logger.info(f"Подключение к серверу {server_ip} по WinRM пока не реализовано")
            # Здесь можно реализовать подключение к Windows-серверам через WinRM
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