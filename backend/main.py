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
import winrm
from windows_scanner import WindowsScanner

import re
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
        # Определяем правильные категории для типа соединения
        allowed_categories = []
        if scan_request.connection_type == "ssh":
            # Linux категории (1-12)
            allowed_categories = list(range(1, 13))
        elif scan_request.connection_type == "winrm":
            # Windows категории (13-18)
            allowed_categories = list(range(13, 19))
        
        logger.info(f"Разрешенные категории для типа {scan_request.connection_type}: {allowed_categories}")
        
        # Получаем выбранные критерии с фильтрацией по разрешенным категориям
        selected_criteria = []
        for criterion_id in scan_request.criteria_ids:
            criterion = crud.get_criterion(db, criterion_id)
            if criterion and criterion.category_id in allowed_categories:
                selected_criteria.append(criterion)
        
        logger.info(f"Отфильтровано {len(selected_criteria)} критериев для сканирования")
        
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

def determine_status(criterion_id, output, expected):
    """
    Correctly determines the status of a security check based on the output.
    Fixed logic that properly handles all cases from the scan results.
    """
    logger.info(f"STATUS CHECK: criterion={criterion_id}, output='{output.strip()[:100]}...'")
    
    # Очищаем вывод от служебной информации
    clean_output = output.strip()
    
    # Извлекаем только результат выполнения между маркерами
    if "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===" in clean_output:
        parts = clean_output.split("=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===")
        if len(parts) > 1:
            result_part = parts[1]
            if "=== КОНЕЦ ВЫПОЛНЕНИЯ ===" in result_part:
                result_part = result_part.split("=== КОНЕЦ ВЫПОЛНЕНИЯ ===")[0]
            clean_output = result_part.strip()
    
    logger.info(f"Clean output for {criterion_id}: '{clean_output}'")
    
    # СПЕЦИАЛЬНЫЕ ПРАВИЛА ДЛЯ КАЖДОГО ТИПА ПРОВЕРКИ
    
    # 1. Проверки с четкими паттернами успеха
    success_indicators = [
        "Correctly configured",
        "correctly configured",
        "Permissions correct", 
        "permissions correct",
        "Firewall active",
        "Logrotate configured",
        "SHA-512 enabled",
        "Warning exists",
        "Core dumps protected",
        "Outbound filtering active",
        "X11 forwarding disabled",
        "Umask properly configured",
        "Remote logging configured",
        "All transports secure",
        "No upgrades needed",
        "Authentication required"
    ]
    
    for indicator in success_indicators:
        if indicator in clean_output:
            logger.info(f"SUCCESS: Found '{indicator}' for criterion {criterion_id}")
            return "Pass"
    
    # 2. Проверки "No X found" - это успех
    no_found_success = [
        "No empty passwords",
        "No world-writable files found",
        "No unowned files found", 
        "No .netrc files found",
        "No .forward files found",
        "No world-writable directories without sticky bit found",
        "No unconfined daemons",
        "No active wireless interfaces"
    ]
    
    for pattern in no_found_success:
        if pattern in clean_output:
            logger.info(f"SUCCESS: Found '{pattern}' for criterion {criterion_id}")
            return "Pass"
    
    # 3. Проверки "not installed/disabled" - это тоже успех для некоторых случаев
    not_installed_success = [
        "Prelink not installed",
        "disabled not-found disabled",  # HTTP server disabled
        "not-found"
    ]
    
    for pattern in not_installed_success:
        if pattern in clean_output:
            logger.info(f"SUCCESS: Found '{pattern}' for criterion {criterion_id}")
            return "Pass"
    
    # 4. Числовые проверки
    numeric_checks = {
        # IP forwarding должен быть 0
        509: lambda out: "net.ipv4.ip_forward = 0" in out,
        # IPv6 должен быть 1 (отключен)
        615: lambda out: "net.ipv6.conf.all.disable_ipv6 = 1" in out,
        # ASLR должен быть 2
        412: lambda out: "kernel.randomize_va_space = 2" in out,
        # Правильные права доступа
        1010: lambda out: "644 0 0" in out,
        1020: lambda out: "640 0 42" in out,
        # SSH checks
        550: lambda out: "PermitRootLogin no" in out,
        552: lambda out: "Protocol 2" in out,
        # Audit active
        710: lambda out: "active" in out.lower(),
        # Services running  
        720: lambda out: "enabled" in out.lower(),
        730: lambda out: "Status: install ok installed" in out,
        # Password max days not 99999
        810: lambda out: "99999" not in out and "PASS_MAX_DAYS" in out
    }
    
    if criterion_id in numeric_checks:
        if numeric_checks[criterion_id](clean_output):
            logger.info(f"SUCCESS: Numeric check passed for criterion {criterion_id}")
            return "Pass"
    
    # 5. Пустой вывод = успех для find команд
    empty_success_criteria = [1210, 1220, 1050, 1120, 1130]  # find команды
    if criterion_id in empty_success_criteria and not clean_output:
        logger.info(f"SUCCESS: Empty output for find command {criterion_id}")
        return "Pass"
    
    # 6. Проверяем ожидаемый результат
    if expected and expected in clean_output:
        logger.info(f"SUCCESS: Expected '{expected}' found for criterion {criterion_id}")
        return "Pass"
    
    # 7. СПЕЦИАЛЬНЫЕ ИСКЛЮЧЕНИЯ ДЛЯ КОНКРЕТНЫХ ПРОБЛЕМНЫХ КРИТЕРИЕВ
    
    # Критерий 5.7 (X11 forwarding) - "X11 forwarding not disabled" = FAIL
    if criterion_id == 570 and "X11 forwarding not disabled" in clean_output:
        logger.info(f"FAIL: X11 forwarding not disabled for criterion {criterion_id}")
        return "Fail"
    
    # Критерий 6.4 (outbound filtering) - "No outbound filtering" = FAIL  
    if criterion_id == 640 and "No outbound filtering" in clean_output:
        logger.info(f"FAIL: No outbound filtering for criterion {criterion_id}")
        return "Fail"
        
    # Критерий 4.4 (core dumps) - "Core dumps may be exposed" = FAIL
    if criterion_id == 430 and "Core dumps may be exposed" in clean_output:
        logger.info(f"FAIL: Core dumps exposed for criterion {criterion_id}")
        return "Fail"
    
    # Критерий 7.5 (remote syslog) - "Remote logging not configured" = FAIL
    if criterion_id == 750 and "Remote logging not configured" in clean_output:
        logger.info(f"FAIL: Remote logging not configured for criterion {criterion_id}")
        return "Fail"
    
    # Критерий 8.4 (SHA-512) - "SHA-512 not enabled" = FAIL
    if criterion_id == 840 and "SHA-512 not enabled" in clean_output:
        logger.info(f"FAIL: SHA-512 not enabled for criterion {criterion_id}")
        return "Fail"
    
    # Критерий 9.2, 9.3 (warnings) - "No appropriate warning" = FAIL
    if criterion_id in [920, 930] and "No appropriate warning" in clean_output:
        logger.info(f"FAIL: No appropriate warning for criterion {criterion_id}")
        return "Fail"
    
    # Критерий 12.4 (umask) - "Umask not configured" = FAIL
    if criterion_id == 1240 and "Umask not configured" in clean_output:
        logger.info(f"FAIL: Umask not configured for criterion {criterion_id}")
        return "Fail"
    
    # 8. Критерии с "Not properly configured" = FAIL
    not_configured_patterns = [
        "Not properly configured",
        "not properly configured", 
        "not set",
        "not enabled",
        "not disabled",
        "Permissions incorrect",
        "No authentication required"
    ]
    
    for pattern in not_configured_patterns:
        if pattern in clean_output:
            logger.info(f"FAIL: Found '{pattern}' for criterion {criterion_id}")
            return "Fail"
    
    # 9. Ошибки команд = FAIL (кроме find команд)
    if ("Команда завершилась с ошибкой" in clean_output or 
        "command not found" in clean_output) and criterion_id not in empty_success_criteria:
        logger.info(f"FAIL: Command error for criterion {criterion_id}")
        return "Fail"
    
    # 10. Пустой вывод на обычных командах = FAIL
    if not clean_output and criterion_id not in empty_success_criteria:
        logger.info(f"FAIL: Empty output for criterion {criterion_id}")
        return "Fail"
    
    # 11. По умолчанию = FAIL если ничего не подошло
    logger.info(f"FAIL: No success condition met for criterion {criterion_id}")
    return "Fail"


def add_linux_explanation(criterion_id: int, output: str) -> str:
    """
    Добавляет пояснения к выводу Linux-команд, учитывая ID критерия
    и обрабатывая только нужные части вывода
    
    Args:
        criterion_id: ID критерия
        output: Исходный вывод команды
        
    Returns:
        Вывод с добавленными пояснениями
    """
    # Если вывод пустой, не меняем его
    if not output:
        return output
    
    # Разделяем вывод на секции, чтобы обрабатывать только результаты,
    # а не команды и структурные элементы вывода
    command_section = ""
    result_section = ""
    
    # Проверяем, содержит ли вывод структурированные секции
    if "=== НАЧАЛО ВЫПОЛНЕНИЯ КОМАНДЫ ===" in output and "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===" in output:
        parts = output.split("=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===")
        if len(parts) > 1:
            command_section = parts[0]
            result_section = "=== РЕЗУЛЬТАТ ВЫПОЛНЕНИЯ ===" + parts[1]
            
            # Проверяем, есть ли завершающая секция
            if "=== КОНЕЦ ВЫПОЛНЕНИЯ ===" in result_section:
                result_parts = result_section.split("=== КОНЕЦ ВЫПОЛНЕНИЯ ===")
                if len(result_parts) > 1:
                    result_section = result_parts[0]
                    end_section = "=== КОНЕЦ ВЫПОЛНЕНИЯ ===" + result_parts[1]
                else:
                    end_section = ""
            else:
                end_section = ""
    else:
        # Если нет структурированных секций, обрабатываем весь вывод
        result_section = output
        command_section = ""
        end_section = ""
    
    # Словарь с соответствиями ID критерия и пояснений
    explanations_by_id = {
        # System Updates (110-199)
        110: {
            "unattended-upgrades": "unattended-upgrades (Пакет автоматических обновлений установлен)",
        },
        120: {
            "No upgrades needed": "No upgrades needed (Система обновлена)",
            "Upgrades needed": "Upgrades needed (Требуются обновления)",
        },
        130: {
            "All transports secure": "All transports secure (Все репозитории используют безопасные протоколы)",
        },
        
        # Filesystem (210-299)
        210: {
            "noexec": "noexec (Запрещено выполнение файлов в /tmp - безопасно)",
        },
        220: {
            "nodev set": "nodev set (Запрещены файлы устройств в /tmp - безопасно)",
            "nodev not set": "nodev not set (Разрешены файлы устройств в /tmp - небезопасно)",
        },
        230: {
            "nosuid set": "nosuid set (Запрещены SUID биты в /tmp - безопасно)",
            "nosuid not set": "nosuid not set (Разрешены SUID биты в /tmp - небезопасно)",
        },
        
        # Bootloader (310-399)
        310: {
            "password": "password (Пароль загрузчика установлен - безопасно)",
        },
        320: {
            "Permissions correct": "Permissions correct (Права доступа к файлу загрузчика корректны)",
            "Permissions incorrect": "Permissions incorrect (Неправильные права доступа к файлу загрузчика)",
        },
        330: {
            "Authentication required": "Authentication required (Аутентификация для однопользовательского режима настроена)",
            "No authentication required": "No authentication required (Аутентификация для однопользовательского режима не настроена)",
        },
        
        # Process Hardening (409-499)
        409: {
            "* hard core 0": "* hard core 0 (Дампы памяти отключены - безопасно)",
        },
        412: {
            "kernel.randomize_va_space = 2": "kernel.randomize_va_space = 2 (ASLR включен полностью - безопасно)",
            "kernel.randomize_va_space = 1": "kernel.randomize_va_space = 1 (ASLR включен частично - недостаточно безопасно)",
            "kernel.randomize_va_space = 0": "kernel.randomize_va_space = 0 (ASLR отключен - небезопасно)",
        },
        420: {
            "Prelink not installed": "Prelink not installed (Prelink не установлен - безопасно)",
            "Prelink installed": "Prelink installed (Prelink установлен - небезопасно)",
        },
        430: {
            "Core dumps protected": "Core dumps protected (Дампы памяти защищены от чтения)",
            "Core dumps may be exposed": "Core dumps may be exposed (Дампы памяти могут быть доступны другим пользователям)",
        },
        
        # Network Configuration (509-599)
        509: {
            "net.ipv4.ip_forward = 0": "net.ipv4.ip_forward = 0 (IP-перенаправление отключено - безопасно)",
            "net.ipv4.ip_forward = 1": "net.ipv4.ip_forward = 1 (IP-перенаправление включено - небезопасно)",
        },
        520: {
            "disabled": "disabled (Веб-сервер отключен - безопасно)",
            "enabled": "enabled (Веб-сервер включен - требует настройки)",
        },
        530: {
            "Correctly configured": "Correctly configured (MaxAuthTries настроен правильно)",
            "Not properly configured": "Not properly configured (MaxAuthTries не настроен правильно)",
        },
        540: {
            "Correctly configured": "Correctly configured (SSH LogLevel настроен правильно)",
            "Not properly configured": "Not properly configured (SSH LogLevel не настроен правильно)",
        },
        550: {
            "PermitRootLogin no": "PermitRootLogin no (Вход root через SSH отключен - безопасно)",
        },
        552: {
            "Protocol 2": "Protocol 2 (Используется безопасный протокол SSH v2)",
        },
        560: {
            "Correctly configured": "Correctly configured (PermitEmptyPasswords отключен - безопасно)",
            "Not properly configured": "Not properly configured (PermitEmptyPasswords не отключен - небезопасно)",
        },
        570: {
            "X11 forwarding disabled": "X11 forwarding disabled (Перенаправление X11 отключено - безопасно)",
            "X11 forwarding not disabled": "X11 forwarding not disabled (Перенаправление X11 не отключено - небезопасно)",
        },
        
        # Network Hardening (610-699)
        610: {
            "Soft blocked: yes": "Soft blocked: yes (Беспроводные интерфейсы отключены - безопасно)",
            "Soft blocked: no": "Soft blocked: no (Беспроводные интерфейсы включены - потенциальный риск)",
        },
        615: {
            "net.ipv6.conf.all.disable_ipv6 = 1": "net.ipv6.conf.all.disable_ipv6 = 1 (IPv6 отключен - безопасно)",
            "net.ipv6.conf.all.disable_ipv6 = 0": "net.ipv6.conf.all.disable_ipv6 = 0 (IPv6 включен - потенциально небезопасно)",
        },
        620: {
            "No unconfined daemons": "No unconfined daemons (Все службы ограничены политиками безопасности - безопасно)",
        },
        630: {
            "Firewall active": "Firewall active (Файервол активен - безопасно)",
        },
        640: {
            "Outbound filtering active": "Outbound filtering active (Фильтрация исходящего трафика включена - безопасно)",
            "No outbound filtering": "No outbound filtering (Фильтрация исходящего трафика отключена - потенциально небезопасно)",
        },
        650: {
            "No active wireless interfaces": "No active wireless interfaces (Нет активных беспроводных интерфейсов - безопасно)",
        },
        
        # Logging and Auditing (710-799)
        710: {
            "active": "active (Служба аудита активна - безопасно)",
            "inactive": "inactive (Служба аудита неактивна - небезопасно)",
        },
        720: {
            "Enabled": "Enabled (Служба аудита включена автоматически)",
            "Not enabled": "Not enabled (Служба аудита не включена автоматически)",
        },
        730: {
            "Status: install ok installed": "Status: install ok installed (Служба журналирования установлена - безопасно)",
        },
        740: {
            "Logrotate configured": "Logrotate configured (Ротация журналов настроена - безопасно)",
            "Logrotate not configured": "Logrotate not configured (Ротация журналов не настроена - небезопасно)",
        },
        750: {
            "Remote logging configured": "Remote logging configured (Удалённое журналирование настроено - безопасно)",
            "Remote logging not configured": "Remote logging not configured (Удалённое журналирование не настроено)",
        },
        
        # User Account Settings (810-899)
        810: {
            "PASS_MAX_DAYS	99999": "PASS_MAX_DAYS	99999 (Пароли никогда не истекают - небезопасно)",
            "PASS_MAX_DAYS	90": "PASS_MAX_DAYS	90 (Срок действия пароля 90 дней - рекомендуемое значение)",
        },
        820: {
            "No empty passwords": "No empty passwords (Пустые пароли не обнаружены - безопасно)",
        },
        830: {
            "Correctly configured": "Correctly configured (Минимальное время между сменами пароля настроено корректно)",
            "Not properly configured": "Not properly configured (Минимальное время между сменами пароля не настроено корректно)",
        },
        840: {
            "SHA-512 enabled": "SHA-512 enabled (Используется сильное хеширование паролей - безопасно)",
            "SHA-512 not enabled": "SHA-512 not enabled (Не используется сильное хеширование паролей - небезопасно)",
        },
        
        # Warning Banners (910-999)
        910: {
            "/etc/issue.net": "/etc/issue.net (Баннер SSH настроен)",
        },
        920: {
            "Warning exists": "Warning exists (Предупреждающий баннер настроен - безопасно)",
            "No appropriate warning": "No appropriate warning (Предупреждающий баннер не настроен)",
        },
        930: {
            "Warning exists": "Warning exists (Предупреждающий баннер настроен - безопасно)",
            "No appropriate warning": "No appropriate warning (Предупреждающий баннер не настроен)",
        },
        
        # File Permissions (1010-1099)
        1010: {
            "644 0 0": "644 0 0 (Права 644, владелец root:root - правильная конфигурация)",
        },
        1020: {
            "640 0 42": "640 0 42 (Права 640, владелец root:shadow - правильная конфигурация)",
        },
        1030: {
            "Permissions correct": "Permissions correct (Права на /etc/group настроены правильно)",
            "Permissions incorrect": "Permissions incorrect (Права на /etc/group настроены неправильно)",
        },
        1040: {
            "Permissions correct": "Permissions correct (Права на /etc/gshadow настроены правильно)",
            "Permissions incorrect": "Permissions incorrect (Права на /etc/gshadow настроены неправильно)",
        },
        1050: {
            "No world-writable directories without sticky bit found": "No world-writable directories without sticky bit found (Нет директорий с небезопасными правами доступа)",
        },
        
        # User Settings (1110-1199)
        1110: {
            "1": "1 (PATH не содержит пустых директорий - безопасно)",
            "Empty Directory": "Empty Directory (PATH содержит пустые директории - небезопасно)",
        },
        1120: {
            "No world-writable files found": "No world-writable files found (Нет файлов с правами записи для всех - безопасно)",
        },
        1130: {
            "No unowned files found": "No unowned files found (Нет файлов без владельца - безопасно)",
        },
        
        # Account Settings (1210-1299)
        1210: {
            "No .forward files found": "No .forward files found (Нет файлов .forward - безопасно)",
        },
        1220: {
            "No .netrc files found": "No .netrc files found (Нет файлов .netrc - безопасно)",
        },
        1230: {
            "Permissions correct": "Permissions correct (Права на домашние директории настроены правильно)",
            "Permissions incorrect": "Permissions incorrect (Права на домашние директории настроены неправильно)",
        },
        1240: {
            "Umask properly configured": "Umask properly configured (Umask настроен правильно - безопасно)",
            "Umask not configured": "Umask not configured (Umask не настроен - потенциально небезопасно)",
        },
    }
    
    # Общие пояснения для всех критериев
    general_explanations = {
        "not set": "not set (Настройка не установлена - требуется исправление)",
        "Not properly configured": "Not properly configured (Настройка неправильная - требуется исправление)",
        "not properly configured": "not properly configured (Настройка неправильная - требуется исправление)",
        "not enabled": "not enabled (Служба не активирована - требуется исправление)",
        "Not enabled": "Not enabled (Служба не активирована - требуется исправление)",
        "incorrect": "incorrect (Настройка некорректна - требуется исправление)",
        "Incorrect": "Incorrect (Настройка некорректна - требуется исправление)",
        "Permissions incorrect": "Permissions incorrect (Неправильные права доступа - требуется исправление)",
    }
    
    # Получаем словарь пояснений для текущего критерия
    specific_explanations = explanations_by_id.get(criterion_id, {})
    
    # Функция для безопасного применения замен (только для полных слов, не внутри других слов)
    def safe_replace(text, old, new):
        # Проверяем, что текст или заменяемое слово не пустые
        if not text or not old:
            return text
            
        # Проверяем, что заменяемое слово не содержит уже пояснение (в скобках)
        if "(" in old and ")" in old:
            return text
            
        # Используем регулярное выражение для замены только целых слов или фраз
        # \b - граница слова, escape-последовательность для re.sub
        # (?<!\() - отрицательный просмотр назад, убеждаемся что перед old нет открывающей скобки
        # (?!\)) - отрицательный просмотр вперед, убеждаемся что после old нет закрывающей скобки
        pattern = f"(?<!\()\b{re.escape(old)}\b(?!\))"
        return re.sub(pattern, new, text)
    
    # Сначала применяем замены для конкретного критерия
    result_text = result_section
    for old, new in specific_explanations.items():
        result_text = safe_replace(result_text, old, new)
    
    # Затем общие замены (только если не были применены специфичные)
    for old, new in general_explanations.items():
        result_text = safe_replace(result_text, old, new)
    
    # Собираем обратно вывод
    if command_section and end_section:
        return command_section + result_text + end_section
    else:
        return result_text


async def perform_scan(server_ip, username, password, ssh_key, connection_type, criteria, use_sudo=False):
    """
    Performs a security scan on a server, supporting both Linux (SSH) and Windows (WinRM) servers.
    
    Args:
        server_ip: IP address of the server to scan
        username: Username for authentication
        password: Password for authentication
        ssh_key: SSH key for Linux authentication (ignored for Windows)
        connection_type: "ssh" for Linux or "winrm" for Windows
        criteria: List of security criteria to check
        use_sudo: Whether to use sudo for Linux commands (ignored for Windows)
        
    Returns:
        List of scan results
    """
    results = []
    
    try:
        # Linux server scanning via SSH
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
                    
                    # ПОЛНОСТЬЮ ПЕРЕРАБОТАННАЯ ЛОГИКА ОПРЕДЕЛЕНИЯ СТАТУСА
                    # Используем отдельную функцию для определения статуса
                    status = determine_status(criterion.id, output, expected)
                    
                    # Логируем определенный статус
                    if status == "Pass":
                        logger.info(f"Критерий {criterion.id} ПРОЙДЕН")
                    else:
                        logger.info(f"Критерий {criterion.id} НЕ ПРОЙДЕН")
                    
                    # Добавляем результат с правильно определенным статусом
                    results.append({
                        "criterion_id": criterion.id,
                        "status": status,
                        "details": add_linux_explanation(criterion.id, output),
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
            
        # Windows server scanning via WinRM
        elif connection_type == "winrm":
            logger.info(f"Connecting to Windows server {server_ip} with WinRM")
            
            try:
                # Create scanner instance
                scanner = WindowsScanner(server_ip, username, password)
                
                # Perform the scan
                results = scanner.perform_scan(criteria)
                
                # Close the connection
                scanner.close()
                
                logger.info(f"Windows scan completed for server {server_ip}")
                
            except Exception as e:
                logger.error(f"Error scanning Windows server: {str(e)}")
                raise
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
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
    Экспортирует результаты сканирования в формате JSON
    """
    scan = crud.get_scan(db, scan_id)
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    # Проверяем, что запрошен JSON формат
    if format.lower() != "json":
        raise HTTPException(status_code=400, detail="Only JSON format is supported")
    
    # Получаем результаты сканирования
    scan_results = crud.get_scan_results(db, scan_id)
    
    # Подготавливаем данные для экспорта
    export_data = []
    for result in scan_results:
        criterion = crud.get_criterion(db, result.criterion_id)
        export_data.append({
            "id": result.id,
            "criterion": criterion.name,
            "status": result.status,
            "severity": criterion.severity,
            "details": result.details.replace("\n", " ").replace("\r", " ") if result.details else "",
            "remediation": result.remediation.replace("\n", " ").replace("\r", " ") if result.remediation else ""
        })
    
    return export_data

# Запуск приложения
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
