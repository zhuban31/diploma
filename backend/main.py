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
    Directly determine status by looking for explicit failure patterns in output.
    
    Args:
        criterion_id: The ID of the criterion being checked
        output: The actual output from the command
        expected: The expected output for a passing check
    
    Returns:
        "Pass" if the check passes, "Fail" if it fails
    """
    # First, log the check details for debugging
    logger.info(f"STATUS CHECK: criterion={criterion_id}, output='{output.strip()}'")
    
    # Explicit failure patterns - if any of these are in the output, the check fails
    failure_patterns = [
        "not set",
        "Not properly configured", 
        "not properly configured",
        "not enabled", 
        "Not enabled",
        "incorrect",
        "Incorrect",
        "Permissions incorrect",
        "not disabled",
        "not installed",
        "No appropriate warning",
        "may be exposed",
        "X11 forwarding not disabled",
        "No outbound filtering",
        "Remote logging not configured",
        "SHA-512 not enabled",
        "Core dumps may be exposed"
    ]
    
    # Command errors usually indicate a fail
    if "Команда завершилась с ошибкой" in output and criterion_id != 1210 and criterion_id != 1220:
        logger.info(f"Command error detected for criterion {criterion_id}, marking as FAIL")
        return "Fail"
    
    # For output patterns that indicate failure
    for pattern in failure_patterns:
        if pattern in output:
            logger.info(f"Failure pattern '{pattern}' found in output for criterion {criterion_id}, marking as FAIL")
            return "Fail"
    
    # Special case for empty output on non-find commands
    # Skip these specific find commands where empty output is good
    if not output.strip() and "find /home -name" not in str(criterion_id) and criterion_id != 1210 and criterion_id != 1220:
        logger.info(f"Empty output for non-find command {criterion_id}, marking as FAIL")
        return "Fail"
    
    # IPv6 disabled check needs special handling
    if criterion_id == 615 and "disable_ipv6 = 0" in output:
        logger.info(f"IPv6 not disabled for criterion {criterion_id}, marking as FAIL")
        return "Fail"
    
    # IP forwarding check
    if criterion_id == 509 and "ip_forward = 1" in output:
        logger.info(f"IP forwarding enabled for criterion {criterion_id}, marking as FAIL")
        return "Fail"
    
    # Password max days check
    if criterion_id == 810 and "99999" in output:
        logger.info(f"Password max days too high for criterion {criterion_id}, marking as FAIL")
        return "Fail"
    
    # Special case for find commands - empty output is a pass
    if (criterion_id == 1210 or criterion_id == 1220 or "find /home -name" in output) and not output.strip():
        logger.info(f"Empty output for find command {criterion_id}, marking as PASS")
        return "Pass"
    
    # For "No X found" patterns
    no_found_patterns = [
        "No world-writable files found",
        "No unowned files found",
        "No empty passwords",
        "No .netrc files found",
        "No active wireless interfaces",
        "No world-writable directories without sticky bit found",
        "No unconfined daemons"
    ]
    
    for pattern in no_found_patterns:
        if pattern in output:
            logger.info(f"'No found' pattern '{pattern}' found in output for criterion {criterion_id}, marking as PASS")
            return "Pass"
    
    # Special case for Prelink
    if "Prelink not installed" in output:
        logger.info(f"Prelink not installed for criterion {criterion_id}, marking as PASS")
        return "Pass"
    
    # If the expected output is in the actual output, it passes
    if expected and expected in output:
        logger.info(f"Expected output '{expected}' found in output for criterion {criterion_id}, marking as PASS")
        return "Pass"
    
    # Default case - if we're unsure, fail
    logger.info(f"No clear pass condition met for criterion {criterion_id}, defaulting to FAIL")
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