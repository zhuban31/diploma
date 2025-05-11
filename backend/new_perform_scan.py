
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
