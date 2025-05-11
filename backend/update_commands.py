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
            # Original criteria
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
            
            # Existing additional criteria
            615: {'cmd': 'sysctl net.ipv6.conf.all.disable_ipv6', 'output': '1'},
            520: {'cmd': 'systemctl is-enabled apache2 2>/dev/null || systemctl is-enabled nginx 2>/dev/null || echo disabled', 'output': 'disabled'},
            412: {'cmd': 'sysctl kernel.randomize_va_space', 'output': '2'},
            630: {'cmd': 'ufw status | grep -E "Status:\\s*active" || iptables -L -n | grep -q "REJECT\\|DROP" && echo "Firewall active"', 'output': 'Firewall active'},
            820: {'cmd': 'cat /etc/shadow | awk -F: \'($2 == "" ) { print $1 " has no password" ; exit 1 }\' || echo "No empty passwords"', 'output': 'No empty passwords'},
            730: {'cmd': 'dpkg -s rsyslog || dpkg -s syslog-ng || echo "No syslog service installed"', 'output': 'Status: install ok installed'},
            1020: {'cmd': 'stat -c "%a %u %g" /etc/shadow', 'output': '640 0 42'},
            550: {'cmd': 'grep -i "^PermitRootLogin" /etc/ssh/sshd_config | grep -i "no"', 'output': 'PermitRootLogin no'},
            552: {'cmd': 'grep -i "^Protocol" /etc/ssh/sshd_config', 'output': 'Protocol 2'},
            620: {'cmd': 'ps -eZ | grep -v "^\\w\\{1,\\}-[\\w\\{1,\\}_]\\{1,\\} " | grep -v "^system_u:system_r:initrc_t:s0 " | grep -v "^unconfined_u:unconfined_r:unconfined_t:s0 " | grep -v "^unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 " | tr -s " " | cut -d " " -f2 | sort -u || echo "No unconfined daemons"', 'output': 'No unconfined daemons'},
            
            # New criteria
            120: {'cmd': 'apt list --upgradable | grep -q \'upgradable\' && echo \'Upgrades needed\' || echo \'No upgrades needed\'', 'output': 'No upgrades needed'},
            130: {'cmd': 'grep -E \'^deb\\s+[^http:|file:]\' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || echo \'All transports secure\'', 'output': 'All transports secure'},
            220: {'cmd': 'findmnt -n /tmp | grep -q \'nodev\' && echo \'nodev set\' || echo \'nodev not set\'', 'output': 'nodev set'},
            230: {'cmd': 'findmnt -n /tmp | grep -q \'nosuid\' && echo \'nosuid set\' || echo \'nosuid not set\'', 'output': 'nosuid set'},
            320: {'cmd': 'stat -L -c \"%a %u %g\" /boot/grub/grub.cfg | grep -q \'400 0 0\' && echo \'Permissions correct\' || echo \'Permissions incorrect\'', 'output': 'Permissions correct'},
            330: {'cmd': 'grep -q \'^root:[*!]:\' /etc/shadow && echo \'Authentication required\' || echo \'No authentication required\'', 'output': 'Authentication required'},
            420: {'cmd': 'dpkg -s prelink 2>/dev/null | grep -q \'Status: install\' && echo \'Prelink installed\' || echo \'Prelink not installed\'', 'output': 'Prelink not installed'},
            430: {'cmd': 'grep -q \'fs.suid_dumpable = 0\' /etc/sysctl.conf /etc/sysctl.d/* && echo \'Core dumps protected\' || echo \'Core dumps may be exposed\'', 'output': 'Core dumps protected'},
            530: {'cmd': 'grep -E \'^MaxAuthTries\\s+[1-4]\' /etc/ssh/sshd_config && echo \'Correctly configured\' || echo \'Not properly configured\'', 'output': 'Correctly configured'},
            540: {'cmd': 'grep -i \"^LogLevel INFO\" /etc/ssh/sshd_config && echo \'Correctly configured\' || echo \'Not properly configured\'', 'output': 'Correctly configured'},
            560: {'cmd': 'grep -i \"^PermitEmptyPasswords\" /etc/ssh/sshd_config | grep -i \"no\" && echo \'Correctly configured\' || echo \'Not properly configured\'', 'output': 'Correctly configured'},
            570: {'cmd': 'grep -i \"^X11Forwarding\" /etc/ssh/sshd_config | grep -i \"no\" && echo \'X11 forwarding disabled\' || echo \'X11 forwarding not disabled\'', 'output': 'X11 forwarding disabled'},
            640: {'cmd': 'iptables -L OUTPUT -v -n | grep -q \'REJECT\\|DROP\' && echo \'Outbound filtering active\' || echo \'No outbound filtering\'', 'output': 'Outbound filtering active'},
            650: {'cmd': 'ip link | grep -i \'state UP\' | grep -i wireless || echo \'No active wireless interfaces\'', 'output': 'No active wireless interfaces'},
            720: {'cmd': 'systemctl is-enabled auditd && echo \'Enabled\' || echo \'Not enabled\'', 'output': 'Enabled'},
            740: {'cmd': 'grep -r \"^rotate\" /etc/logrotate.d/ /etc/logrotate.conf | grep -v \"^#\" && echo \'Logrotate configured\' || echo \'Logrotate not configured\'', 'output': 'Logrotate configured'},
            750: {'cmd': 'grep -E \'^[^#].*@.*\' /etc/rsyslog.conf /etc/rsyslog.d/*.conf && echo \'Remote logging configured\' || echo \'Remote logging not configured\'', 'output': 'Remote logging configured'},
            830: {'cmd': 'grep -E \'^PASS_MIN_DAYS\\s+[7-9]|^PASS_MIN_DAYS\\s+[1-9][0-9]+\' /etc/login.defs && echo \'Correctly configured\' || echo \'Not properly configured\'', 'output': 'Correctly configured'},
            840: {'cmd': 'grep -E \'^password\\s+[^\\s]+\\s+pam_unix.so\\s+.*sha512\' /etc/pam.d/common-password && echo \'SHA-512 enabled\' || echo \'SHA-512 not enabled\'', 'output': 'SHA-512 enabled'},
            920: {'cmd': 'grep -E \'Authorized users only|authorized use only|unauthorized access prohibited\' /etc/issue && echo \'Warning exists\' || echo \'No appropriate warning\'', 'output': 'Warning exists'},
            930: {'cmd': 'grep -E \'Authorized users only|authorized use only|unauthorized access prohibited\' /etc/issue.net && echo \'Warning exists\' || echo \'No appropriate warning\'', 'output': 'Warning exists'},
            1030: {'cmd': 'stat -c \"%a %u %g\" /etc/group | grep -q \'644 0 0\' && echo \'Permissions correct\' || echo \'Permissions incorrect\'', 'output': 'Permissions correct'},
            1040: {'cmd': 'stat -c \"%a %u %g\" /etc/gshadow | grep -q \'640 0 42\' && echo \'Permissions correct\' || echo \'Permissions incorrect\'', 'output': 'Permissions correct'},
            1050: {'cmd': 'df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type d -perm -0002 -not -perm -1000 -print 2>/dev/null || echo \'No world-writable directories without sticky bit found\'', 'output': 'No world-writable directories without sticky bit found'},
            1120: {'cmd': 'df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -0002 -print 2>/dev/null || echo \'No world-writable files found\'', 'output': 'No world-writable files found'},
            1130: {'cmd': 'df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser -ls 2>/dev/null || echo \'No unowned files found\'', 'output': 'No unowned files found'},
            1220: {'cmd': 'find /home -name .netrc 2>/dev/null || echo \'No .netrc files found\'', 'output': 'No .netrc files found'},
            1230: {'cmd': 'for dir in $(cut -d: -f6 /etc/passwd | grep -v \'^/$\'); do [ -d \"$dir\" ] && stat -L -c \'%A\' \"$dir\" | cut -c6-10 | grep -q \'^-----$\' && echo \'Permissions correct\' || echo \'Permissions incorrect\'; done', 'output': 'Permissions correct'},
            1240: {'cmd': 'grep -E \'^\\s*umask\\s+([0-7][0-7]27|[0-7]22)\' /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh && echo \'Umask properly configured\' || echo \'Umask not configured\'', 'output': 'Umask properly configured'},
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