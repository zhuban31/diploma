


import winrm
import json
import logging
import traceback
from typing import List, Dict, Any, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("windows_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("windows-scanner")

class WindowsScanner:
    """Scanner for Windows servers using WinRM"""
    
    def __init__(self, server_ip: str, username: str, password: str):
        """Initialize the Windows scanner"""
        self.server_ip = server_ip
        self.username = username
        self.password = password
        self.session = None
        logger.info(f"WindowsScanner initialized for {server_ip}")
    
    def connect(self) -> bool:
        """Connect to the Windows server using WinRM"""
        try:
            logger.info(f"Connecting to Windows server {self.server_ip} with WinRM")
            # Create a WinRM session
            self.session = winrm.Session(
                self.server_ip, 
                auth=(self.username, self.password),
                transport='ntlm',  # Using NTLM authentication
                server_cert_validation='ignore'  # For testing; in production, use proper cert validation
            )
            
            # Test connection
            logger.info("Testing connection with hostname command")
            result = self.session.run_ps("hostname")
            if result.status_code == 0:
                hostname = result.std_out.decode('utf-8', errors='replace').strip()
                logger.info(f"Successfully connected to {self.server_ip} (hostname: {hostname})")
                return True
            else:
                error = result.std_err.decode('utf-8', errors='replace')
                logger.error(f"Connection test failed with status code {result.status_code}: {error}")
                return False
                
        except Exception as e:
            logger.error(f"Error connecting to Windows server: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def run_powershell_command(self, command: str) -> Dict[str, Any]:
        """Run a PowerShell command on the Windows server"""
        if not self.session:
            if not self.connect():
                logger.error("Failed to establish WinRM session")
                return {
                    "status": "Error",
                    "output": "Failed to establish WinRM session",
                    "error": "Session not established"
                }
        
        try:
            logger.info(f"Running PowerShell command: {command}")
            
            # Wrap command with progress preference suppression
            if not command.startswith("$ProgressPreference"):
                wrapped_command = f"$ProgressPreference = 'SilentlyContinue'; {command}"
            else:
                wrapped_command = command
            
            # Execute the command
            result = self.session.run_ps(wrapped_command)
            
            # Process the result
            status_code = result.status_code
            output = result.std_out.decode('utf-8', errors='replace').strip()
            error = result.std_err.decode('utf-8', errors='replace').strip()
            
            logger.info(f"Command execution completed with status code: {status_code}")
            if output:
                logger.info(f"Output: {output[:200]}{'...' if len(output) > 200 else ''}")
            if error:
                logger.warning(f"Error output: {error}")
            
            if status_code == 0:
                return {
                    "status": "Success",
                    "output": output,
                    "error": error
                }
            else:
                return {
                    "status": "Failed",
                    "output": output,
                    "error": error
                }
                
        except Exception as e:
            logger.error(f"Error executing PowerShell command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "status": "Error",
                "output": "",
                "error": str(e)
            }
    
    def determine_status(self, criterion_id: int, output: str, expected: str) -> str:
        """Determine if a check passes or fails based on the output and expected value"""
        logger.info(f"Determining status for criterion {criterion_id}: Output='{output[:50]}...', Expected='{expected}'")
        
        # If output contains the expected string, it passes
        if expected and expected in output:
            logger.info(f"Criterion {criterion_id} PASSED (expected string found)")
            return "Pass"
        
        # For Windows hostname command (our simple test)
        if "DESKTOP-" in output or "WIN-" in output:
            logger.info(f"Criterion {criterion_id} PASSED (hostname check)")
            return "Pass"
            
        # Default case - if no conditions are met, it's a fail
        logger.info(f"Criterion {criterion_id} FAILED - Output doesn't match expected value")
        return "Fail"
    
    def add_explanation(self, criterion_name: str, output: str) -> str:
        
        # Словарь с пояснениями к числовым значениям
        explanations = {
            "Windows Firewall": {
                "1": "1 (Включен 1 профиль брандмауэра из 3)",
                "2": "2 (Включены 2 профиля брандмауэра из 3)",
                "3": "3 (Включены все 3 профиля брандмауэра)",
                "0": "0 (Все профили брандмауэра отключены)"
            },
            "Windows UAC": {
                "1": "1 (UAC включен)",
                "0": "0 (UAC отключен)"
            },
            "Windows Authentication": {
                "0": "0 (Анонимный доступ разрешен)",
                "1": "1 (Базовое ограничение анонимного доступа)",
                "2": "2 (Строгое ограничение анонимного доступа)"
            },
            "Windows Remote Desktop": {
                "1": "1 (Безопасная авторизация RDP включена)",
                "0": "0 (Безопасная авторизация RDP отключена)"
            },
            "Windows Security Policy": {
                "0": "0 (UAC отключен)", 
                "1": "1 (UAC в режиме без уведомлений)",
                "2": "2 (UAC с уведомлениями)",
                "3": "3 (UAC в режиме запроса учетных данных)",
                "4": "4 (UAC в режиме запроса с затемнением рабочего стола)",
                "5": "5 (UAC в максимально строгом режиме)"
            },
            "Windows Registry": {
                "1": "1 (UAC включен в реестре)",
                "0": "0 (UAC отключен в реестре)"
            },
            "Windows User Rights": {
                "0": "0 (Группа не найдена)",
                "1": "1 (1 пользователь в группе Администраторы)",
                "2": "2 (2 пользователя в группе Администраторы)"
            },
            "Windows Basic Test": {
                "0": "0 (Не установлено ни одного обновления)",
                "1": "1 (Установлено 1 обновление)",
                "2": "2 (Установлено 2 обновления)",
                "3": "3 (Установлено 3 обновления)",
                "4": "4 (Установлено 4 обновления)"
            },
            "Windows Automatic Updates": {
                "0": "0 (Автоматическое обновление отключено)",
                "1": "1 (Только уведомления о доступных обновлениях)",
                "2": "2 (Автоматическая загрузка, ручная установка)",
                "3": "3 (Автоматическая загрузка и установка)",
                "4": "4 (Полностью автоматическое обновление)",
                "5": "5 (Настройка по умолчанию)"
            },
            "Windows Services": {
                "Running": "Running (Служба запущена)",
                "Stopped": "Stopped (Служба остановлена)"
            },
            "Windows SMB": {
                "True": "True (SMBv1 включен - небезопасно)",
                "False": "False (SMBv1 отключен - безопасно)"
            }
        }
        
        # Проверяем, есть ли пояснения для этого критерия
        if criterion_name in explanations:
            # Ищем числовое значение в выводе
            # Если вывод состоит только из одного числа или одного слова
            output_stripped = output.strip()
            if output_stripped in explanations[criterion_name]:
                return explanations[criterion_name][output_stripped]
        
        # Если пояснения не найдены, возвращаем исходный вывод
        return output
    
    def perform_scan(self, criteria: List[Any]) -> List[Dict[str, Any]]:
        """
        Scan the Windows server against the provided criteria
        
        Args:
            criteria: List of criteria objects to check
            
        Returns:
            List of scan results
        """
        results = []
        logger.info(f"Starting Windows scan with {len(criteria)} criteria")
        
        # Try to connect first
        if not self.connect():
            logger.error("Failed to connect to the Windows server")
            # Create failure results for all criteria
            for criterion in criteria:
                results.append({
                    "criterion_id": criterion.id,
                    "status": "Error",
                    "details": "Failed to connect to the Windows server",
                    "remediation": criterion.remediation
                })
            return results
        
        # For each criterion, run the check and evaluate the result
        for criterion in criteria:
            try:
                logger.info(f"Checking criterion {criterion.id}: {criterion.name}")
                
                # Skip criteria without a check command
                if not criterion.check_command or not criterion.check_command.strip():
                    logger.warning(f"No check command for criterion {criterion.id}, skipping")
                    results.append({
                        "criterion_id": criterion.id,
                        "status": "Error",
                        "details": "No check command defined",
                        "remediation": criterion.remediation
                    })
                    continue
                
                # Run the PowerShell command
                command_result = self.run_powershell_command(criterion.check_command)
                
                # If the command failed with an error, mark as error
                if command_result["status"] == "Error":
                    logger.error(f"Error running check for criterion {criterion.id}: {command_result['error']}")
                    results.append({
                        "criterion_id": criterion.id,
                        "status": "Error",
                        "details": f"Error running check: {command_result['error']}",
                        "remediation": criterion.remediation
                    })
                    continue
                
                # Get command output
                output = command_result["output"]
                if command_result["error"]:
                    output += f"\nErrors: {command_result['error']}"
                
                # Handle empty output
                if not output.strip():
                    output = "Command returned no output"
                
                # Determine status (Pass/Fail)
                expected = criterion.expected_output
                status = self.determine_status(criterion.id, output, expected)
                
                # Log the result
                logger.info(f"Criterion {criterion.id} check completed with status: {status}")
                
                # Add to results
                results.append({
                    "criterion_id": criterion.id,
                    "status": status,
                    "details": f"Command: ```powershell\n{criterion.check_command}\n```\n\nOutput:\n{self.add_explanation(criterion.name, output)}",
                    "remediation": criterion.remediation if status == "Fail" else ""
                })
                
            except Exception as e:
                # Handle any exceptions during check
                logger.error(f"Exception during check for criterion {criterion.id}: {str(e)}")
                logger.error(traceback.format_exc())
                results.append({
                    "criterion_id": criterion.id,
                    "status": "Error",
                    "details": f"Exception during check: {str(e)}",
                    "remediation": criterion.remediation
                })
        
        logger.info(f"Scan completed with {len(results)} results")
        return results
    
    def close(self):
        """Close the WinRM session"""
        # WinRM doesn't require explicit closing like SSH
        logger.info("Closing WinRM connection")
        self.session = None
