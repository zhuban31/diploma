"""
Script to add new security criteria to the database.
This should be run before update_commands.py
"""

import os
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import models
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("add_criteria.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("add-criteria")

def add_new_criteria():
    """Add new security criteria to the database"""
    db = SessionLocal()
    
    try:
        # Define the new criteria to add
        new_criteria = [
            # System Updates
            {
                "category_id": 1,
                "id": 120,
                "name": "1.2. Ensure system packages are up to date",
                "description": "Description: Keeping system packages up to date ensures the latest security patches are applied",
                "check_command": "apt list --upgradable | grep -q 'upgradable' && echo 'Upgrades needed' || echo 'No upgrades needed'",
                "expected_output": "No upgrades needed",
                "remediation": "Run 'apt update && apt upgrade' to update all packages",
                "severity": "High",
                "automated": True
            },
            {
                "category_id": 1,
                "id": 130,
                "name": "1.3. Ensure APT repositories use secure transports",
                "description": "Description: APT repositories should use secure transport methods to prevent MITM attacks",
                "check_command": "grep -E '^deb\\s+[^http:|file:]' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || echo 'All transports secure'",
                "expected_output": "All transports secure",
                "remediation": "Edit repository configurations to use HTTPS transport instead of HTTP",
                "severity": "Medium",
                "automated": True
            },
            
            # Filesystem Configuration
            {
                "category_id": 2,
                "id": 220,
                "name": "2.2. Ensure nodev option set on /tmp partition",
                "description": "Description: The nodev mount option prevents execution of device files from temporary directories",
                "check_command": "findmnt -n /tmp | grep -q 'nodev' && echo 'nodev set' || echo 'nodev not set'",
                "expected_output": "nodev set",
                "remediation": "Edit /etc/fstab and add the nodev option to the /tmp mount",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 2,
                "id": 230,
                "name": "2.3. Ensure nosuid option set on /tmp partition",
                "description": "Description: The nosuid mount option prevents SUID bits from working in temporary directories",
                "check_command": "findmnt -n /tmp | grep -q 'nosuid' && echo 'nosuid set' || echo 'nosuid not set'",
                "expected_output": "nosuid set",
                "remediation": "Edit /etc/fstab and add the nosuid option to the /tmp mount",
                "severity": "Medium",
                "automated": True
            },
            
            # Bootloader Configuration
            {
                "category_id": 3,
                "id": 320,
                "name": "3.2. Ensure permissions on bootloader config are configured",
                "description": "Description: Bootloader configuration files should have secure permissions",
                "check_command": "stat -L -c \"%a %u %g\" /boot/grub/grub.cfg | grep -q '400 0 0' && echo 'Permissions correct' || echo 'Permissions incorrect'",
                "expected_output": "Permissions correct",
                "remediation": "Run 'chmod 0400 /boot/grub/grub.cfg' and 'chown root:root /boot/grub/grub.cfg'",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 3,
                "id": 330,
                "name": "3.3. Ensure authentication required for single user mode",
                "description": "Description: System should be configured to require authentication for single user mode",
                "check_command": "grep -q '^root:[*!]:' /etc/shadow && echo 'Authentication required' || echo 'No authentication required'",
                "expected_output": "Authentication required",
                "remediation": "Set a password for the root account",
                "severity": "Medium",
                "automated": True
            },
            
            # Process Hardening
            {
                "category_id": 4,
                "id": 420,
                "name": "4.3. Ensure prelink is disabled",
                "description": "Description: Prelink alters binaries to speed loading times, but complicates security measures like ASLR",
                "check_command": "dpkg -s prelink 2>/dev/null | grep -q 'Status: install' && echo 'Prelink installed' || echo 'Prelink not installed'",
                "expected_output": "Prelink not installed",
                "remediation": "Run 'apt purge prelink' to remove prelink",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 4,
                "id": 430,
                "name": "4.4. Ensure core dumps are not readable by all users",
                "description": "Description: Core dumps may contain sensitive data and should not be readable by all users",
                "check_command": "grep -q 'fs.suid_dumpable = 0' /etc/sysctl.conf /etc/sysctl.d/* && echo 'Core dumps protected' || echo 'Core dumps may be exposed'",
                "expected_output": "Core dumps protected",
                "remediation": "Add 'fs.suid_dumpable = 0' to /etc/sysctl.conf and run 'sysctl -p'",
                "severity": "Medium",
                "automated": True
            },
            
            # Network Configuration
            {
                "category_id": 5,
                "id": 530,
                "name": "5.3. Ensure SSH MaxAuthTries is set to 4 or less",
                "description": "Description: Limiting authentication attempts per connection reduces brute force risk",
                "check_command": "grep -E '^MaxAuthTries\\s+[1-4]' /etc/ssh/sshd_config && echo 'Correctly configured' || echo 'Not properly configured'",
                "expected_output": "Correctly configured",
                "remediation": "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 5,
                "id": 540,
                "name": "5.4. Ensure SSH LogLevel is set to INFO",
                "description": "Description: Proper logging level enables monitoring of potential break-in attempts",
                "check_command": "grep -i \"^LogLevel INFO\" /etc/ssh/sshd_config && echo 'Correctly configured' || echo 'Not properly configured'",
                "expected_output": "Correctly configured",
                "remediation": "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'",
                "severity": "Low",
                "automated": True
            },
            {
                "category_id": 5,
                "id": 560,
                "name": "5.6. Ensure SSH PermitEmptyPasswords is disabled",
                "description": "Description: SSH should not allow authentication with empty passwords",
                "check_command": "grep -i \"^PermitEmptyPasswords\" /etc/ssh/sshd_config | grep -i \"no\" && echo 'Correctly configured' || echo 'Not properly configured'",
                "expected_output": "Correctly configured",
                "remediation": "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'",
                "severity": "High",
                "automated": True
            },
            {
                "category_id": 5,
                "id": 570,
                "name": "5.7. Ensure SSH X11 forwarding is disabled",
                "description": "Description: X11 forwarding can present a security risk if not properly secured",
                "check_command": "grep -i \"^X11Forwarding\" /etc/ssh/sshd_config | grep -i \"no\" && echo 'X11 forwarding disabled' || echo 'X11 forwarding not disabled'",
                "expected_output": "X11 forwarding disabled",
                "remediation": "Edit /etc/ssh/sshd_config and set 'X11Forwarding no'",
                "severity": "Medium",
                "automated": True
            },
            
            # Network Hardening
            {
                "category_id": 6,
                "id": 640,
                "name": "6.4. Ensure outbound connections are restricted",
                "description": "Description: Outbound connections should be restricted to prevent data exfiltration",
                "check_command": "iptables -L OUTPUT -v -n | grep -q 'REJECT\\|DROP' && echo 'Outbound filtering active' || echo 'No outbound filtering'",
                "expected_output": "Outbound filtering active",
                "remediation": "Configure iptables OUTPUT chain to restrict outbound connections",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 6,
                "id": 650,
                "name": "6.5. Ensure wireless network interfaces are disabled",
                "description": "Description: Disable wireless interfaces on servers to reduce attack surface",
                "check_command": "ip link | grep -i 'state UP' | grep -i wireless || echo 'No active wireless interfaces'",
                "expected_output": "No active wireless interfaces",
                "remediation": "Disable wireless interfaces using 'ip link set dev <interface> down'",
                "severity": "Medium",
                "automated": True
            },
            
            # Logging and Auditing
            {
                "category_id": 7,
                "id": 720,
                "name": "7.2. Ensure auditd service is enabled",
                "description": "Description: The auditd service should be enabled to ensure audit records are preserved at boot",
                "check_command": "systemctl is-enabled auditd && echo 'Enabled' || echo 'Not enabled'",
                "expected_output": "Enabled",
                "remediation": "Run 'systemctl enable auditd'",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 7,
                "id": 740,
                "name": "7.4. Ensure logrotate is configured",
                "description": "Description: The logrotate utility should be properly configured to manage log files",
                "check_command": "grep -r \"^rotate\" /etc/logrotate.d/ /etc/logrotate.conf | grep -v \"^#\" && echo 'Logrotate configured' || echo 'Logrotate not configured'",
                "expected_output": "Logrotate configured",
                "remediation": "Configure logrotate to properly manage your log files",
                "severity": "Low",
                "automated": True
            },
            {
                "category_id": 7,
                "id": 750,
                "name": "7.5. Ensure remote syslog is configured",
                "description": "Description: System logs should be sent to a remote syslog server for better security",
                "check_command": "grep -E '^[^#].*@.*' /etc/rsyslog.conf /etc/rsyslog.d/*.conf && echo 'Remote logging configured' || echo 'Remote logging not configured'",
                "expected_output": "Remote logging configured",
                "remediation": "Configure rsyslog to send logs to a remote syslog server",
                "severity": "Medium",
                "automated": True
            },
            
            # User Account Settings
            {
                "category_id": 8,
                "id": 830,
                "name": "8.3. Ensure minimum days between password changes is 7 or more",
                "description": "Description: The PASS_MIN_DAYS parameter should be set to prevent password churning",
                "check_command": "grep -E '^PASS_MIN_DAYS\\s+[7-9]|^PASS_MIN_DAYS\\s+[1-9][0-9]+' /etc/login.defs && echo 'Correctly configured' || echo 'Not properly configured'",
                "expected_output": "Correctly configured",
                "remediation": "Edit /etc/login.defs and set PASS_MIN_DAYS to 7 or more",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 8,
                "id": 840,
                "name": "8.4. Ensure password hashing algorithm is SHA-512",
                "description": "Description: Strong password hashing algorithms should be used",
                "check_command": "grep -E '^password\\s+[^\\s]+\\s+pam_unix.so\\s+.*sha512' /etc/pam.d/common-password && echo 'SHA-512 enabled' || echo 'SHA-512 not enabled'",
                "expected_output": "SHA-512 enabled",
                "remediation": "Edit /etc/pam.d/common-password and add 'sha512' option to pam_unix.so line",
                "severity": "Medium",
                "automated": True
            },
            
            # Warning Banners
            {
                "category_id": 9,
                "id": 920,
                "name": "9.2. Ensure /etc/issue contains appropriate warning",
                "description": "Description: Login warning banners should contain appropriate legal text",
                "check_command": "grep -E 'Authorized users only|authorized use only|unauthorized access prohibited' /etc/issue && echo 'Warning exists' || echo 'No appropriate warning'",
                "expected_output": "Warning exists",
                "remediation": "Edit /etc/issue to include appropriate unauthorized access warning",
                "severity": "Low",
                "automated": True
            },
            {
                "category_id": 9,
                "id": 930,
                "name": "9.3. Ensure remote login warning banner is configured",
                "description": "Description: Remote login services should display warning banners",
                "check_command": "grep -E 'Authorized users only|authorized use only|unauthorized access prohibited' /etc/issue.net && echo 'Warning exists' || echo 'No appropriate warning'",
                "expected_output": "Warning exists",
                "remediation": "Edit /etc/issue.net to include appropriate unauthorized access warning",
                "severity": "Low",
                "automated": True
            },
            
            # File Permissions
            {
                "category_id": 10,
                "id": 1030,
                "name": "10.3. Ensure permissions on /etc/group are configured",
                "description": "Description: The /etc/group file contains group account information and should be properly secured",
                "check_command": "stat -c \"%a %u %g\" /etc/group | grep -q '644 0 0' && echo 'Permissions correct' || echo 'Permissions incorrect'",
                "expected_output": "Permissions correct",
                "remediation": "Run 'chmod 644 /etc/group' and 'chown root:root /etc/group'",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 10,
                "id": 1040,
                "name": "10.4. Ensure permissions on /etc/gshadow are configured",
                "description": "Description: The /etc/gshadow file contains group password hashes and should be properly secured",
                "check_command": "stat -c \"%a %u %g\" /etc/gshadow | grep -q '640 0 42' && echo 'Permissions correct' || echo 'Permissions incorrect'",
                "expected_output": "Permissions correct",
                "remediation": "Run 'chmod 640 /etc/gshadow' and 'chown root:shadow /etc/gshadow'",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 10,
                "id": 1050,
                "name": "10.5. Ensure no unauthorized world-writable directories exist",
                "description": "Description: World-writable directories without proper sticky bits are a security risk",
                "check_command": "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 -not -perm -1000 -print 2>/dev/null || echo 'No world-writable directories without sticky bit found'",
                "expected_output": "No world-writable directories without sticky bit found",
                "remediation": "Set the sticky bit or remove world-writable permissions from directories",
                "severity": "High",
                "automated": True
            },
            
            # User Settings
            {
                "category_id": 11,
                "id": 1120,
                "name": "11.2. Ensure no world-writable files exist",
                "description": "Description: World-writable files are a security risk as they can be modified by any user",
                "check_command": "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print 2>/dev/null || echo 'No world-writable files found'",
                "expected_output": "No world-writable files found",
                "remediation": "Remove write permissions for others from identified files",
                "severity": "High",
                "automated": True
            },
            {
                "category_id": 11,
                "id": 1130,
                "name": "11.3. Ensure no unowned files or directories exist",
                "description": "Description: Files without an owner can indicate compromised files",
                "check_command": "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls 2>/dev/null || echo 'No unowned files found'",
                "expected_output": "No unowned files found",
                "remediation": "Assign ownership to unowned files or remove them",
                "severity": "Medium",
                "automated": True
            },
            
            # Account Settings
            {
                "category_id": 12,
                "id": 1220,
                "name": "12.2. Ensure no users have .netrc files",
                "description": "Description: .netrc files may contain unencrypted passwords which could be used to access remote systems",
                "check_command": "find /home -name .netrc 2>/dev/null || echo 'No .netrc files found'",
                "expected_output": "No .netrc files found",
                "remediation": "Remove .netrc files or ensure they're properly secured",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 12,
                "id": 1230,
                "name": "12.3. Ensure all user home directories have proper permissions",
                "description": "Description: User home directories should be readable and executable only by the user",
                "check_command": "for dir in $(cut -d: -f6 /etc/passwd | grep -v '^/$'); do [ -d \"$dir\" ] && stat -L -c '%A' \"$dir\" | cut -c6-10 | grep -q '^-----$' && echo 'Permissions correct' || echo 'Permissions incorrect'; done",
                "expected_output": "Permissions correct",
                "remediation": "Run 'chmod 0750' on user home directories",
                "severity": "Medium",
                "automated": True
            },
            {
                "category_id": 12,
                "id": 1240,
                "name": "12.4. Ensure default user umask is 027 or more restrictive",
                "description": "Description: The default umask determines the permissions of files created by users",
                "check_command": "grep -E '^\\s*umask\\s+([0-7][0-7]27|[0-7]22)' /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh && echo 'Umask properly configured' || echo 'Umask not configured'",
                "expected_output": "Umask properly configured",
                "remediation": "Edit /etc/profile and /etc/bash.bashrc to set umask 027",
                "severity": "Medium",
                "automated": True
            }
        ]
        
        # Add each new criterion to the database
        for criterion_data in new_criteria:
            # Check if criterion already exists
            existing = db.query(models.Criterion).filter(models.Criterion.id == criterion_data["id"]).first()
            if existing:
                logger.info(f"Criterion {criterion_data['id']} already exists, skipping")
                continue
                
            # Create new criterion
            new_criterion = models.Criterion(
                id=criterion_data["id"],
                category_id=criterion_data["category_id"],
                name=criterion_data["name"],
                description=criterion_data["description"],
                check_command=criterion_data["check_command"],
                expected_output=criterion_data["expected_output"],
                remediation=criterion_data["remediation"],
                severity=criterion_data["severity"],
                automated=criterion_data["automated"]
            )
            
            db.add(new_criterion)
            logger.info(f"Added new criterion: {criterion_data['id']} - {criterion_data['name']}")
        
        # Commit changes
        db.commit()
        logger.info(f"Successfully added {len(new_criteria)} new criteria to the database")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error adding criteria: {str(e)}")
    finally:
        db.close()

if __name__ == "__main__":
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    add_new_criteria()