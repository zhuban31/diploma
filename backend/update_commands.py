import os
from database import SessionLocal, engine
import models
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("update_commands.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("update-commands")

def update_check_commands():
    """Обновляет команды проверки в базе данных"""
    db = SessionLocal()
    
    try:
        # Обновляем команды и ожидаемые выводы для критериев
        updates = {
            110: {'cmd': 'dpkg -l | grep unattended-upgrades', 'output': 'unattended-upgrades'},
            210: {'cmd': 'findmnt -n /tmp', 'output': 'noexec'},
            310: {'cmd': 'grep "^password" /boot/grub/grub.cfg', 'output': 'password'},
            409: {'cmd': 'grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf', 'output': '* hard core 0'},
            509: {'cmd': 'sysctl net.ipv4.ip_forward', 'output': '0'},
            610: {'cmd': 'rfkill list', 'output': 'Soft blocked: yes'},
            710: {'cmd': 'systemctl is-active auditd', 'output': 'active'},
            810: {'cmd': 'grep PASS_MAX_DAYS /etc/login.defs', 'output': '90'},
            910: {'cmd': 'grep Banner /etc/ssh/sshd_config', 'output': '/etc/issue.net'},
            1010: {'cmd': 'stat -c "%a %u %g" /etc/passwd', 'output': '644 0 0'},
            1110: {'cmd': 'echo $PATH | grep -q "::" && echo "Empty Directory" || echo "1"', 'output': '1'},
            1210: {'cmd': 'find /home -name .forward', 'output': ''}
        }
        
        for crit_id, data in updates.items():
            criterion = db.query(models.Criterion).filter(models.Criterion.id == crit_id).first()
            if criterion:
                criterion.check_command = data['cmd']
                criterion.expected_output = data['output']
                logger.info(f'Обновлен критерий {crit_id}: {data["cmd"]}')
            else:
                logger.warning(f'Критерий {crit_id} не найден')
        
        db.commit()
        logger.info('Команды проверок успешно обновлены')
        
    except Exception as e:
        db.rollback()
        logger.error(f'Ошибка при обновлении команд: {str(e)}')
    finally:
        db.close()

if __name__ == "__main__":
    update_check_commands()