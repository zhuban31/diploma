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
            1210: {'cmd': 'find /home -name .forward', 'output': ''},
            615: {'cmd': 'sysctl net.ipv6.conf.all.disable_ipv6', 'output': '1'},
            520: {'cmd': 'systemctl is-enabled apache2 2>/dev/null || systemctl is-enabled nginx 2>/dev/null || echo disabled', 'output': 'disabled'},
            412: {'cmd': 'sysctl kernel.randomize_va_space', 'output': '2'},
            630: {'cmd': 'ufw status | grep -E "Status:\\s*active" || iptables -L -n | grep -q "REJECT\\|DROP" && echo "Firewall active"', 'output': 'Firewall active'},
            820: {'cmd': 'cat /etc/shadow | awk -F: \'($2 == "" ) { print $1 " has no password" ; exit 1 }\' || echo "No empty passwords"', 'output': 'No empty passwords'},
            730: {'cmd': 'dpkg -s rsyslog || dpkg -s syslog-ng || echo "No syslog service installed"', 'output': 'Status: install ok installed'},
            1020: {'cmd': 'stat -c "%a %u %g" /etc/shadow', 'output': '640 0 42'},
            550: {'cmd': 'grep -i "^PermitRootLogin" /etc/ssh/sshd_config | grep -i "no"', 'output': 'PermitRootLogin no'},
            552: {'cmd': 'grep -i "^Protocol" /etc/ssh/sshd_config', 'output': 'Protocol 2'},
            620: {'cmd': 'ps -eZ | grep -v "^\\w\\{1,\\}-[\\w\\{1,\\}_]\\{1,\\} " | grep -v "^system_u:system_r:initrc_t:s0 " | grep -v "^unconfined_u:unconfined_r:unconfined_t:s0 " | grep -v "^unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 " | tr -s " " | cut -d " " -f2 | sort -u || echo "No unconfined daemons"', 'output': 'No unconfined daemons'}
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