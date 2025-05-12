"""
Тестирование команд PowerShell для Windows.
Этот скрипт напрямую тестирует выполнение PowerShell команд на целевом Windows-сервере.
"""

import winrm
import argparse
import sys

def test_windows_command(ip, username, password, command=None):
    """
    Тестирование подключения к Windows-серверу и выполнения команды.
    
    Args:
        ip: IP-адрес Windows-сервера
        username: Имя пользователя
        password: Пароль
        command: PowerShell команда для выполнения (если не указана, будет выполнен простой тест)
    """
    print(f"Тестирование подключения к {ip} с пользователем {username}...")
    
    try:
        # Создаем сессию
        session = winrm.Session(
            ip, 
            auth=(username, password),
            transport='ntlm',  # NTLM auth
            server_cert_validation='ignore'  # Отключаем проверку сертификата
        )
        
        # Настраиваем тестовую команду
        if not command:
            command = """
            $ProgressPreference = 'SilentlyContinue'
            $ErrorActionPreference = 'Continue'
            
            Write-Output "WinRM подключение работает!"
            Write-Output "Hostname: $env:COMPUTERNAME"
            Write-Output "Windows Version: $((Get-WmiObject Win32_OperatingSystem).Caption)"
            Write-Output "Current user: $env:USERNAME"
            """
        
        print("\nВыполнение команды PowerShell:")
        print("-" * 50)
        print(command)
        print("-" * 50)
        
        # Выполняем команду
        result = session.run_ps(command)
        
        # Выводим результаты
        print("\nРезультаты:")
        print(f"Status Code: {result.status_code}")
        
        if result.status_code == 0:
            print("\nOutput:")
            print("-" * 50)
            print(result.std_out.decode('utf-8', errors='replace'))
            print("-" * 50)
            
            if result.std_err:
                print("\nErrors:")
                print("-" * 50)
                print(result.std_err.decode('utf-8', errors='replace'))
                print("-" * 50)
                
            print("\nТест успешно выполнен!")
            return True
        else:
            print("\nCommand failed with non-zero exit code")
            print("\nOutput:")
            print(result.std_out.decode('utf-8', errors='replace'))
            print("\nErrors:")
            print(result.std_err.decode('utf-8', errors='replace'))
            return False
        
    except Exception as e:
        print(f"\nОшибка подключения к Windows-серверу: {str(e)}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test Windows PowerShell command execution')
    parser.add_argument('--ip', required=True, help='IP address of Windows server')
    parser.add_argument('--username', required=True, help='Windows username')
    parser.add_argument('--password', required=True, help='Windows password')
    parser.add_argument('--command', help='PowerShell command to execute')
    
    args = parser.parse_args()
    
    if test_windows_command(args.ip, args.username, args.password, args.command):
        sys.exit(0)
    else:
        sys.exit(1)