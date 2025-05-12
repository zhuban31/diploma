import winrm
import sys

server = "25.13.178.117"  # IP Windows-сервера
username = "Gaming"  # Замените на актуальное имя пользователя
password = "Mirage0909_!"  # Замените на актуальный пароль

try:
    print(f"Подключение к {server} с пользователем {username}...")
    session = winrm.Session(
        server, 
        auth=(username, password),
        transport='ntlm',
        server_cert_validation='ignore'
    )
    result = session.run_ps("hostname")
    print("\nРезультат:")
    print(result.std_out.decode('utf-8', errors='replace'))
    print("Exit code:", result.status_code)
    print("\nПодключение успешно!")
except Exception as e:
    print(f"Ошибка: {str(e)}")
