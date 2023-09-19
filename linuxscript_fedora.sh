#!/bin/bash

# TODO add firewalld check and respective rule additions

Main(){
	clear

	if [[ $EUID -ne 0 ]]; then
		echo "You must be root to run this script."
		exit 1
	fi

	printf "\033[1;31mChange the password to CyberPatriot1! to begin.\033[0m\n"
	passwd
	
	clear
	ServiceCheck
	Dnf
	PasswordsAccounts
	Apache
	SQL
	Nginx
	Samba
	PHP
	SSH
	VSFTPD
	PureFTPD
	ProFTP
	File
	Misc
	Firewall
	Sysctl
	Auditctl        
	clear

	printf "\e[1;34mThe script is finished. Y to delete media files, n to exit \e[0m"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
		find / -iname '*.mp3' -delete
		find / -iname '*.mp4' -delete
		find / -iname '*.png' -delete
		find / -iname '*.jpeg' -delete
		echo "SSH set."
	else
        exit 1
		fi
	exit 1
}

ServiceCheck() {
	clear

	printf "\033[1;31mChecking services. PUT EITHER y OR n\033[0m\n"
	echo " "
	echo "Need SSH?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        dnf install openssh-server -y
		HasSSH=true
		echo "SSH set."
	else
        echo "SSH skipped for some reason"
		fi

	echo "Need SQL?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
	dnf install mysql-server -y
        echo "SQL Set."
		HasSQL=true 
	else
		dnf remove mysql-server -y 
		fi

	echo "Need VSFTPD?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
				dnf install ftp vsftpd -y
        echo "VSFTPD Set."
		HasVSFTPD=true
	else
        dnf remove vsftpd -y
		fi

	echo "Need PureFTPD?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
	   echo "PureFTPD set." 
	   dnf install ftp pure-ftpd -y
	   HasPureFTPD=true
	else
	   dnf remove pure-ftpd -y
	fi
#Really weird formatting, I know, but at least it works.
			echo "Need ProFTP?"
			read input
			if [[ $input == "Y" || $input == "y" ]]; then
		        dnf install ftp -y
						dnf install proftpd -y
						echo "FTP set."
				HasProFTP=true
			else
		        dnf remove proftpd -y
						dnf remove proftpd -y
					fi

			echo "Need FTP at all?"
			read input
			if [[ $input == "Y" || $input == "y" ]]; then
						dnf install ftp -y
						echo "FTP set."
			else
				 		dnf remove ftp -y
							fi

	echo "Need Samba?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "Samba set."
		HasSamba=true
	else
        dnf remove samba -y
		fi

	echo "Need Apache?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "Apache set."
		HasApache=true
	else
        dnf remove httpd -y
		fi 
		
	echo "Need PHP?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        dnf install php-cli -y
		dnf install php-mysqli
		echo "PHP set."
		HasPHP=true
	else
        dnf remove php-cli -y
		dnf remove php-mysqli -y
		fi

	echo "Need nginx?"
	read input
	if [[ $input == "Y" || $input == "y" ]]; then
        echo "nginx set."
				HasNginx=true
	else
        dnf remove nginx -y
		fi

	printf "\e[1;34mFinished ServiceCheck() function!\e[0m"
}

Dnf() {
	clear 
	printf "\e[1;34mStarted Dnf() function!\e[0m"
	printf "\033[1;31mUpdating computer...\033[0m\n"

	#Sets automatic updates
	yum install dnf-automatic -y
	sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
	sudo systemctl enable --now dnf-automatic.timer

	echo "Downloading and removing packages..."
	dnf install gedit -y
	dnf install sudo -y
	dnf install ufw -y
	dnf install unhide -y
	dnf install clamav -y 
	dnf install htop -y
	dnf install iptables -y
	dnf install audit -y
	dnf install openssh-server -y
	dnf install ranger -y
	dnf install fail2ban -y

	dnf remove john -y
	dnf remove abc -y
	dnf remove aria2 -y 
	dnf remove bitcomet -y 
	dnf remove bitlet -y 
	dnf remove bitspirit -y 
	dnf remove endless-sky -y
	dnf remove zenmap -y
	dnf remove minetest -y
	dnf remove minetest-server -y
	dnf remove armitage -y
	dnf remove crack -y
	dnf remove aircrack-ng -y
	dnf remove hunt -y
	dnf remove airbase-ng -y
	dnf remove hydra -y
	dnf remove freeciv -y
	dnf remove hydra-gtk -y
	dnf remove netcat -y
	dnf remove netcat-traditional -y
	dnf remove netcat-openbsd -y
	dnf remove netcat-ubuntu -y
	dnf remove netcat-minimal -y
	dnf remove qbittorrent -y
	dnf remove ctorrent -y
	dnf remove ktorrent -y
	dnf remove rtorrent -y
	dnf remove deluge -y
	dnf remove transmission-common -y
	dnf remove transmission-bittorrent-client -y
	dnf remove tixati -y
	dnf remove frostwise -y
	dnf remove vuse -y
	dnf remove irssi -y
	dnf remove transmission-gtk -y
	dnf remove utorrent -y
	dnf remove kismet -y
	dnf remove medusa -y
	dnf remove telnet -y
	dnf remove exim4 -y
	dnf remove telnetd -y
	dnf remove bind9 -y
	dnf remove crunch -y
	dnf remove tcpdump -y
	dnf remove tomcat -y
	dnf remove tomcat6 -y
	dnf remove vncserver -y
	dnf remove tightvnc -y
	dnf remove tightvnc-common -y
	dnf remove tightvncserver -y
	dnf remove vnc4server -y
	dnf remove nmdb -y
	dnf remove dhclient -y
	dnf remove telnet-server -y
	dnf remove ophcrack -y
	dnf remove cryptcat -y
	dnf remove cups -y
	dnf remove cupsd -y
	dnf remove tcpspray -y
	dnf remove dsniff -y
	dnf remove ettercap -y
	dnf remove netcat -y
	dnf remove wesnoth -y
	dnf remove snort -y
	dnf remove pryit -y
	dnf remove weplab -y
	dnf remove wireshark -y
	dnf remove nikto -y
	dnf remove lcrack -y
	dnf remove postfix -y
	dnf remove snmp -y
	dnf remove icmp -y
	dnf remove dovecot -y
	dnf remove pop3 -y
	dnf remove p0f -y
	dnf remove dsniff -y
	dnf remove hunt -y
	dnf remove ember -y
	dnf remove nbtscan -y
	dnf remove rsync -y
	dnf remove freeciv-client-extras -y
	dnf remove freeciv-data -y
	dnf remove freeciv-server -y
	dnf remove freeciv-client-gtk -y
	rm -rf /usr/lib/games
	rm -rf /usr/local/games
	rm -rf /usr/share/games
	rm -rf /var/games
	rm -rf /var/lib/games
	echo "Finished."

	echo "Echoing all packages to a Desktop text file for examination."
	dnf list >> allpackages.txt

	echo "Printed root processes to desktop"
	ps Zaux >> rootprocesses.txt

	echo "Printed services to desktop"
	service --status-all >> services.txt

	echo "Printed network scan to desktop"
	netstat -tulpn >> networkscan.txt

	echo "Printing NMAP scan to desktop"
	dnf install nmap -y
	nmap -T4 -A -v localhost >> nmapscan.txt
	dnf remove nmap -y
	
	echo "Printed file locations to desktop"
	mkdir /home/configbackup
	#excutables
	mkdir /home/configbackup/executables
	find / -name ".py" -print >> /home/configbackup/executables/py.txt
	find / -name "*.exe" -print >> /home/configbackup/executables/exe.txt
	find / -name "*.bat" -print >> /home/configbackup/executables/bat.txt
	find / -name "*.sh" -print >> /home/configbackup/executables/sh.txt
	find / -name "*.c" -print >> /home/configbackup/executables/c.txt
	find / -name "*.pl" -print >> /home/configbackup/executables/perl.txt
	find / -name "*.php" -print >> /home/configbackup/executables/php.txt

	#text files
	mkdir /home/configbackup/textfiles
	find / -name "*.txt" -print >> /home/configbackup/textfiles/txt.txt
	find / -name "*.xlsx" -print >> /home/configbackup/textfiles/xlsx.txt
	find / -name "*.csv" -print >> /home/configbackup/textfiles/csv.txt

	#media file
	mkdir /home/configbackup/mediafiles
	find / -name "*.jpg" -print >> /home/configbackup/mediafiles/jpg.txt
	find / -name "*.jpeg" -print >> /home/configbackup/mediafiles/jpeg.txt
	find / -name "*.png" -print >> /home/configbackup/mediafiles/png.txt
	find / -name "*.mp3" -print >> /home/configbackup/mediafiles/mp3.txt
	find / -name "*.mp4" -print >> /home/configbackup/mediafiles/mp4.txt
	find / -name "*.wav" -print >> /home/configbackup/mediafiles/wav.txt
	find / -name "*.avi" -print >> /home/configbackup/mediafiles/avi.txt
	find / -name "*.mov" -print >> /home/configbackup/mediafiles/mov.txt

	find / -name "*password.txt" -type f -delete
    find / -name "*passwords.txt" -type f -delete

	echo "Done printing stuff to desktop."

	printf "\e[1;34mFinished Dnf() function!\e[0m"
}

PasswordsAccounts(){
	clear
	printf "\e[1;34mStarted PasswordsAccounts() function!\e[0m"
	echo "Using chattr -i on files."
	chattr -i /etc/passwd
    	chattr -i /etc/passwd
	chattr -i /etc/profile
	chattr -i /etc/bash.bashrc
	chattr -i /etc/login.defs
	chattr -i /etc/pam.d/common-auth
	chattr -i /etc/pam.d/common-password
	chattr -i /etc/group
	chattr -i /etc/shadow
	chattr -i /etc/ssh/sshd_config
	chattr -i /etc/host.conf
	chattr -i /etc/hosts.deny
	chattr -i /etc/hosts.allow
	chattr -i /etc/hosts
	chattr -i /etc/resolv.conf
	chattr -i /etc/default/grub
	chattr -i /etc/grub.d/40_custom
	chattr -i /etc/ers
	chattr -i ~/.mozilla/firefox/*.default/prefs.js
	chattr -i /etc/sysctl.conf
	chattr -i /etc/dnf/sources.list

	#removing nopasswdlogon group
	echo "Removing nopasswdlogon group"
	sed -i -e '/nopasswdlogin/d' /etc/group

	echo "Changing all user passwords"
	for user in $( sed 's/:.*//' /etc/passwd);
	do
	  if [[ $( id -u $user) -ge 999 && "$user" != "nobody" ]]
	  then
		(echo "CyberPatriot1!"; echo "CyberPatriot1!") |  passwd "$user"
	  fi
	done

	echo "Enabling auditing."
	#Enables auditing
	systemctl start auditd
	auditctl -e 1

	echo "Setting login.defs"
	# Configure Password Aging Controls
	sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
	sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
	sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs
	sed -i '/^PASS_MIN_LEN/ c\PASS_MIN_LEN 8' /etc/login.defs
	sed -i 's/FAILLOG_ENAB		no/FAILLOG_ENAB		yes/g' /etc/login.defs
	sed -i 's/LOG_UNKFAIL_ENAB		no/LOG_UNKFAIL_ENAB		yes/g' /etc/login.defs
	sed -i 's/SYSLOG_SU_ENAB		no/SYSLOG_SU_ENAB		yes/g' /etc/login.defs
	sed -i 's/SYSLOG_SG_ENAB		no/SYSLOG_SG_ENAB		yes/g' /etc/login.defs
	echo "PASS_MAX_DAYS   90" >> /etc/login.defs
	echo "PASS_MIN_DAYS   10" >> /etc/login.defs
	echo "PASS_WARN_AGE   7" >> /etc/login.defs
	echo "FAILLOG_ENAB   yes" >> /etc/login.defs
	echo "LOG_UNKFAIL_ENAB   yes" >> /etc/login.defs
	echo "LOG_OK_LOGINS		no" >> /etc/login.defs
	echo "SYSLOG_SU_ENAB   yes" >> /etc/login.defs
	echo "SYSLOG_SG_ENAB   yes" >> /etc/login.defs
	echo "LOGIN_RETRIES	  5" >> /etc/login.defs
	echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
	echo "SU_NAME	  su" >> /etc/login.defs
	echo "MD5_CRYPT_ENAB yes" >> /etc/login.defs
	echo "LOGIN_TIMEOUT		60" >> /etc/login.defs

	echo "Setting password authentication"
	# Password Authentication
	sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
	sed -i 's/sha512\+/sha512 remember=5/' /etc/pam.d/common-password

	echo "Setting up libpam"
	# Force Strong Passwords
	sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password

	echo "Removing nullok"
	sed -i 's/nullok//g' /etc/pam.d/common-password
	sed -i 's/nullok//g' /etc/pam.d/common-auth

	echo "Rejecting passwords which contain more than 2 same consecutive characters"
	# Reject passwords which contain more than 2 same consecutive characters
	sed -i "s/\bminclass=4\b/& maxrepeat=2/" /etc/pam.d/common-password

	echo "Protecting root"
	# Prevent root-owned files from accidentally becoming accessible to non-privileged users
	usermod -g 0 root

	echo "Increasing login prompt delay"
	# Increase the delay time between login prompts (10sec)
	sed -i "s/delay=[[:digit:]]\+/delay=10000000/" /etc/pam.d/login

	# Disables Root
	echo "Disabling root"
	passwd -l root

	printf "\e[1;34mFinished PasswordsAccounts() function!\e[0m"
}

Apache(){
	if [[ $HasApache ]]; then
		clear
		printf "\033[1;31mRunning Apache()\033[0m\n"
		#--------- Securing Apache ----------------#
		#This might break by the way. But you can just fix it during comp.
		ufw allow apache
		ufw allow http
		ufw allow https 
		chattr -i /etc/httpd/conf/httpd.conf
		dnf install mod_security

		# echo "HostnameLookups Off" >> /etc/httpd/conf/httpd.conf
		# echo "LogLevel warn" >> /etc/httpd/conf/httpd.conf
		# echo "ServerTokens Prod" >> /etc/httpd/conf/httpd.conf
		# echo "ServerSignature Off"  >> /etc/httpd/conf/httpd.conf
		# echo "Options all -Indexes" >> /etc/httpd/conf/httpd.conf
		# echo "Header unset ETag" >> /etc/httpd/conf/httpd.conf
		# echo "Header always unset X-Powered-By" >> /etc/httpd/conf/httpd.conf
    	        # echo "FileETag None" >> /etc/httpd/conf/httpd.conf
 		# echo "TraceEnable off" >> /etc/httpd/conf/httpd.conf
		# echo "Timeout 30" >> /etc/httpd/conf/httpd.conf

		# echo "<Directory />" >> /etc/httpd/conf/httpd.conf
		# echo "        AllowOverride None" >> /etc/httpd/conf/httpd.conf
		# echo "        Order Deny,Allow" >> /etc/httpd/conf/httpd.conf
		# echo "        Options None" >> /etc/httpd/conf/httpd.conf
		# echo "        Deny from all" >> /etc/httpd/conf/httpd.conf
		# echo "</Directory>" >> /etc/httpd/conf/httpd.conf

		# echo "<Directory /var/www/html>" >> /etc/httpd/conf/httpd.conf
		# echo "    Options -Indexes" >> /etc/httpd/conf/httpd.conf
		# echo "</Directory>" >> /etc/httpd/conf/httpd.conf

		# echo "<IfModule mod_headers.c>" >> /etc/httpd/conf/httpd.conf
		# echo "Header set X-XSS-Protection 1; mode=block" >> /etc/httpd/conf/httpd.conf
		# echo "</IfModule>" >> /etc/httpd/conf/httpd.conf

		# echo "RewriteEngine On" >> /etc/httpd/conf/httpd.conf

				# Secure root directory
		# echo "<Directory />" >> /etc/httpd/conf-available/security.conf
		# echo "Options -Indexes" >> /etc/httpd/conf-available/security.conf
		# echo "AllowOverride None" >> /etc/httpd/conf-available/security.conf
		# echo "Order Deny,Allow" >> /etc/httpd/conf-available/security.conf
		# echo "Deny from all" >> /etc/httpd/conf-available/security.conf
		# echo "</Directory>" >> /etc/httpd/conf-available/security.conf

		# Secure html directory
		# echo "<Directory /var/www/html>" >> /etc/httpd/conf-available/security.conf
		# echo "Options -Indexes -Includes" >> /etc/httpd/conf-available/security.conf
		# echo "AllowOverride None" >> /etc/httpd/conf-available/security.conf
		# echo "Order Allow,Deny" >> /etc/httpd/conf-available/security.conf
		# echo "Allow from All" >> /etc/httpd/conf-available/security.conf
		# echo "</Directory>" >> /etc/httpd/conf-available/security.conf

		# Use TLS only
		# sed -i "s/SSLProtocol all -SSLv3/SSLProtocol –ALL +TLSv1 +TLSv1.1 +TLSv1.2/" /etc/httpd/mods-available/ssl.conf

		# Use strong cipher suites
		sed -i "s/SSLCipherSuite HIGH:\!aNULL/SSLCipherSuite HIGH:\!MEDIUM:\!aNULL:\!MD5:\!RC4/" /etc/httpd/mods-available/ssl.conf

		# Enable HttpOnly and Secure flags
		echo "Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure" >> /etc/httpd/conf-available/security.conf

		# Clickjacking Attack Protection
		echo "Header always append X-Frame-Options SAMEORIGIN" >> /etc/httpd/conf-available/security.conf

		# XSS Protection
		echo "Header set X-XSS-Protection \"1; mode=block\"" >> /etc/httpd/conf-available/security.conf

		# Enforce secure connections to the server
		echo "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"" >> /etc/httpd/conf-available/security.conf

		# MIME sniffing Protection
		echo "Header set X-Content-Type-Options: \"nosniff\"" >> /etc/httpd/conf-available/security.conf

		# Prevent Cross-site scripting and injections
		echo "Header set Content-Security-Policy \"default-src 'self';\"" >> /etc/httpd/conf-available/security.conf

		# Prevent DoS attacks - Limit timeout
		sed -i "s/Timeout/Timeout 60/" /etc/httpd/conf/httpd.conf
		echo "Timeout 60" >> /etc/httpd/conf/httpd.conf

		# chown -R root:root /etc/httpd

		printf "\e[1;34mFinished Apache() function!\e[0m"
		echo ""
	fi
	
}

SQL(){
	if [[ $HasSQL ]]; then
		clear
		printf "\033[1;31mRunning SQL()\033[0m\n"
		ufw allow mysql
		echo "Look up mysql secure installation"

		sed -i 's/root/mysql/g' /etc/mysql/my.cnf
		chown root:root /root/.my.cnf
		chown -R root:root /etc/mysql/
		chmod 0644 /etc/mysql/my.cnf
		chmod 0600 /root/.my.cnf

		#Disables LOCAL INFILE
		echo "local-infile=0" >> /etc/mysql/my.cnf

		#Lowers database privileges
		echo "skip-show-database" >> /etc/mysql/my.cnf

		# Disable remote access
		echo "bind-address=127.0.0.1" >> /etc/mysql/my.cnf
		sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf

		#Disables symbolic links
		echo "symbolic-links=0" >> /etc/mysql/my.cnf

		#Sets password expiration
		echo "default_password_lifetime = 90" >> /etc/mysql/my.cnf

		#Sets root account password
		echo "[mysqladmin]" >> /etc/mysql/my.cnf
		echo "user = root" >> /etc/mysql/my.cnf
		echo "password = CyberPatriot1!" >> /etc/mysql/my.cnf

		#Sets packet restrictions
		echo "key_buffer_size         = 16M" >> /etc/mysql/my.cnf
		echo "max_allowed_packet      = 16M" >> /etc/mysql/my.cnf

		printf "\e[1;34mFinished SQL() function!\e[0m"
		
	fi
	
}

Nginx() {
	if [[ $HasNginx ]]; then
		clear
		printf "\e[1;34mRunning Nginx()\e[0m"
		
		# Hide nginx version
		sed -i "s/# server_tokens off;/server_tokens off;/g" /etc/nginx/nginx.conf

		# Remove ETags
		sed -i 's/server_tokens off;/server_tokens off;\netag off;/' /etc/nginx/nginx.conf

		# Remove default page
		echo "" > /var/www/html/index.html

		# Use strong cipher suites
		sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;/" /etc/nginx/nginx.conf

		# Set ssl session timeout
		sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

		# Set ssl session cache
		sed -i "s/ssl_session_timeout 5m;/ssl_session_cache shared:SSL:10m;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

		# Enable HttpOnly and Secure flags
		sed -i "s|^\s*try_files \\\$uri \\\$uri/ =404;|try_files \\\$uri \\\$uri/ =404;\nproxy_cookie_path / \"/; secure; HttpOnly\";|" /etc/nginx/sites-available/default

		# Clickjacking Attack Protection
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Frame-Options DENY;|" /etc/nginx/sites-available/default

		# XSS Protection
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-XSS-Protection \"1; mode=block\";|" /etc/nginx/sites-available/default

		# Enforce secure connections to the server
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubdomains;\";|" /etc/nginx/sites-available/default

		# MIME sniffing Protection
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Content-Type-Options nosniff;|" /etc/nginx/sites-available/default

		# Prevent Cross-site scripting and injections
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Content-Security-Policy \"default-src 'self';\";|" /etc/nginx/sites-available/default

		# Set X-Robots-Tag
		sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Robots-Tag none;|" /etc/nginx/sites-available/default
	fi

}

Samba() {
	if [[ $HasSamba ]]; then
		clear
		printf "\033[1;31mRunning Samba()\033[0m\n"

		dnf install samba -y 
		chattr -i /etc/samba/smb.conf
	    ufw allow samba
		chmod 600 /etc/samba/smb.conf

		echo "restrict anonymous = 2" >> /etc/samba/smb.conf
		echo "encrypt passwords = True" >> /etc/samba/smb.conf
		echo "encrypt passwords = yes" >> /etc/samba/smb.conf
		echo "read only = Yes" >> /etc/samba/smb.conf
		echo "ntlm auth = no" >> /etc/samba/smb.conf
		echo "obey pam restrictions = yes" >> /etc/samba/smb.conf
		echo "server signing = mandatory" >> /etc/samba/smb.conf
		echo "smb encrypt = mandatory" >> /etc/samba/smb.conf
		echo "min protocol = SMB2" >> /etc/samba/smb.conf
		echo "protocol = SMB2" >> /etc/samba/smb.conf
		echo "guest ok = no" >> /etc/samba/smb.conf
		echo "max log size = 24" >> /etc/samba/smb.conf


		echo "Make sure to read the /etc/samba/smb.conf file and check whats inside!"

		printf "\e[1;34mFinished Samba() function!\e[0m"
	fi

}

PHP() {
	if [[ $HasPHP ]]; then
		clear
		printf "\033[1;31mRunning PHP()\033[0m\n"

		ufw allow php

		chattr -i /etc/php.ini
		chattr -i /etc/php.d/
		chattr -i /etc/my.cnf
		chattr -i /etc/httpd/conf/httpd.conf

		#Enables safe mode in php.ini
		echo "sql.safe_mode=on" >> /etc/php.ini
		echo "safe_mode = On" >> /etc/php.ini
		echo "safe_mode_gid = On" >> /etc/php.ini

		#Disables Global variables
		echo "register_globals=off" >> /etc/php.ini

		#Disables tracking, HTML, and display errors
		sed -i '/^track_errors = On/ c\track_errors = Off' /etc/php.ini
		sed -i '/^html_errors = On/ c\html_errors = Off' /etc/php.ini
		sed -i '/^display_errors = On/ c\display_errors = Off' /etc/php.ini
		echo "expose_php = Off" >> /etc/php.ini
		echo "track_errors = Off" >> /etc/php.ini
		echo "html_errors = Off" >> /etc/php.ini
		echo "display_errors = Off" >> /etc/php.ini

		#Disables Remote File Includes
		sed -i '/^allow_url_fopen = On/ c\allow_url_fopen = Off' /etc/php.ini
		sed -i '/^allow_url_include = On/ c\allow_url_include = Off' /etc/php.ini
		echo "allow_url_fopen = Off" >> /etc/php.ini
		echo "allow_url_include = Off" >> /etc/php.ini

		#Restrict File Uploads
		sed -i '/^file_uploads = On/ c\file_uploads = Off' /etc/php.ini
		echo "file_uploads = Off" >> /etc/php.ini

		#Control POST size
		sed -i '/^post_max_size = 8M/ c\post_max_size = 1K' /etc/php.ini

		#Protect sessions
		sed -i '/^session.cookie_httponly =/ c\session.cookie_httponly = 1' /etc/php.ini

		#Disables a metric fuck ton of functionality
		echo "disable_functions = php_uname, getmyuid, getmypid, passthru, leak, listen, diskfreespace, tmpfile, link, ignore_user_abord,
		shell_exec, dl, set_time_limit, exec, system, highlight_file, source, show_source, fpaththru, virtual, posix_ctermid, posix_getcwd,
		posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid,
		posix_getpgrp, posix_getpid, posix, _getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty,
		posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname,
		posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo" >> /etc/php.ini

		echo "magic_quotes_gpc=Off" >> /etc/php.ini
		echo "session.cookie_httponly = 1" >> /etc/php.ini
		echo "expose_php = Off" >> /etc/php.ini
		echo "session.use_strict_mode = On" >> /etc/php.ini
		echo "allow_url_fopen=Off" >> /etc/php.ini
		echo "allow_url_include=Off" >> /etc/php.ini
		echo "disable_functions =exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec" >> /etc/php.ini
		echo "upload_max_filesize = 2M" >> /etc/php.ini
		echo "max_execution_time = 30" >> /etc/php.ini
		echo "max_input_time = 30 " >> /etc/php.ini
		echo "open_basedir="/home/user/public_html"" >> /etc/php.ini
		echo "display_errors = Off" >> /etc/php.ini
		echo "memory_limit = 40M" >> /etc/php.ini
		echo "mail.add_x_header = Off" >> /etc/php.ini
		echo "fle_uploads=Off" >> /etc/php.ini
		echo "max_input_time = 60" >> /etc/php.ini
		printf "\e[1;34mFinished PHP() function!\e[0m"
		echo ""
}

SSH() {
	if [[ $HasSSH ]]; then
		clear
		printf "\033[1;31mRunning SSH()\033[0m\n"
		ufw allow 22
		
		# echo "Port 22" > /etc/ssh/sshd_config
		# echo "PermitRootLogin no" >> /etc/ssh/sshd_config
		# echo "Protocol 2" >> /etc/ssh/sshd_config
		# echo "LoginGRaceTime 2m" >> /etc/ssh/sshd_config
		# echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
		# echo "HostbasedAUthentication no" >> /etc/ssh/sshd_config
		# echo "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
		# echo "UsePrivilegeSeparation yes" >> /etc/ssh/sshd_config
		# echo "StrictModes yes" >> /etc/ssh/sshd_config
		# echo "VerifyReverseMapping yes" >> /etc/ssh/sshd_config
		# echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
		# echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
		# echo "ChallengeResponseAuthentication yes" >> /etc/ssh/sshd_config
		# echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
		# echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
		# echo "X11Forwarding no" >> /etc/ssh/sshd_config
		# echo "SyslogFacility AUTH" >> /etc/ssh/sshd_config
		# echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
		# echo "MaxStartups 2" >> /etc/ssh/sshd_config
		# echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
		# echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
		# echo "UseDNS no" >> /etc/ssh/sshd_config
		# echo "PermitTunnel no" >> /etc/ssh/sshd_config
		# echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
		# echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
		# echo "PrintLastLog no" >> /etc/ssh/sshd_config
		# echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
		# sed -i "s/#Banner none/Banner \/etc\/issue\.net/g" /etc/ssh/sshd_config
		# echo "Welcome!" > /etc/issue.net

		printf "\e[1;34mFinished SSH() function!\e[0m"
		echo ""

	fi

}

VSFTPD() {
	if [[ $HasVSFTPD ]]; then
		clear
		printf "\033[1;31mRunning VSFTPD()\033[0m\n"

		ufw allow 21
		chattr -i /etc/vsftpd.conf

		echo "anonymous_enable=NO" >> /etc/vsftpd.conf
		echo "chroot_local_user=YES" >> /etc/vsftpd.conf
		echo "local_enable=YES" >> /etc/vsftpd.conf
		echo "write_enable=YES" >> /etc/vsftpd.conf
		echo "use_localtime=YES" >> /etc/vsftpd.conf
		echo "dirmessage_enable=YES" >> /etc/vsftpd.conf
		echo "xferlog_enable=YES" >> /etc/vsftpd.conf
		echo "connect_from_port_20=YES" >> /etc/vsftpd.conf
		echo "ascii_upload_enable=NO" >> /etc/vsftpd.conf
		echo "ascii_download_enable=NO" >> /etc/vsftpd.conf
		
# example conf or some shit
# Jail users to home directory (user will need a home dir to exist)
#chroot_local_user=YES
#chroot_list_enable=YES
#chroot_list_file=/etc/vsftpd.chroot_list
#allow_writeable_chroot=YES # Only enable if you want files to be editable
# Allow or deny users
#userlist_enable=YES
#userlist_file=/etc/vsftpd.userlist
#userlist_deny=NO
# General config
#anonymous_enable=NO # disable anonymous login
#ocal_enable=YES # permit local logins
#write_enable=YES # enable FTP commands which change the filesystem
#local_umask=022 # value of umask for file creation for local users
#dirmessage_enable=YES # enable showing of messages when users first enter a
#new directory
#xferlog_enable=YES # a log file will be maintained detailing uploads and
#downloads
#connect_from_port_20=YES # use port 20 (ftp-data) on the server machine for PORT
#style connections
#xferlog_std_format=YES # keep standard log file format
#listen=NO # prevent vsftpd from running in standalone mode
#listen_ipv6=YES # vsftpd will listen on an IPv6 socket instead of an
#IPv4 one
#pam_service_name=vsftpd # name of the PAM service vsftpd will use
#userlist_enable=YES # enable vsftpd to load a list of usernames
#tcp_wrappers=YES # turn on tcp wrappers

		printf "\e[1;34mFinished VSFTPD() function!\e[0m"
		echo ""
	fi
}

PureFTPD() {
	if [[ $HasPureFTPD ]]; then
		clear
		printf "\e[1;34mRunning PureFTPD()\e[0m"
		chattr -i /etc/pure-ftpd/conf
		echo "yes" >> /etc/pure-ftpd/conf/NoAnonymous
		echo "yes" >> /etc/pure-ftpd/conf/ChrootEveryone
		echo "yes" >> /etc/pure-ftpd/conf/IPV4Only
		echo "yes" >> /etc/pure-ftpd/conf/ProhibitDotFilesWrite
		echo "2" > /etc/pure-ftpd/conf/TLS
		echo 2 |  tee /etc/pure-ftpd/conf/TLS
		echo 1 |  tee /etc/pure-ftpd/conf/NoAnonymous

		printf "\e[1;34mFinished PureFTPD() function!\e[0m"
	fi
	
}

ProFTP() {
	if [[ $HasProFTP ]]; then
		clear
		printf "\e[1;34mRunning ProFTP()\e[0m"
		echo "DelayEngine on" >> /etc/proftpd/proftpd.conf
		echo "UseLastLog on" >> /etc/proftpd/proftpd.conf
		echo "ServerIndent Off" >> /etc/proftpd/proftpd.conf
		echo "IdentLookups off" >> /etc/proftpd/proftpd.conf
		echo "TLSEngine on" >> /etc/proftpd/proftpd.conf
		echo "TLSProtocol SSLv23" >> /etc/proftpd/proftpd.conf
		echo "TLSRequired On" >> /etc/proftpd/proftpd.conf
		echo "UseReverseDNS On" >> /etc/proftpd/proftpd.conf
		printf "\e[1;34mFinished ProFTP() function!\e[0m"
	fi
	
}

File(){
	clear
	printf "\033[1;31mSetting file permissions...\033[0m\n"

	echo "exit 0" > /etc/rc.local

	chown root:root /etc/fstab
	chmod 644 /etc/fstab
	chown root:root /etc/group
	chmod 644 /etc/group
	chown root:root /etc/shadow
	chmod 400 /etc/shadow
	chown root:root /etc/apache2
	chmod 755 /etc/apache2
	chmod 0600 /etc/securetty
	chmod 644 /etc/crontab
	chmod 640 /etc/ftpusers
	chmod 440 /etc/inetd.conf
	chmod 440 /etc/xinetd.conf
	chmod 400 /etc/inetd.d
	chmod 644 /etc/hosts.allow
	chmod 440 /etc/ers
	chmod 640 /etc/shadow
	chmod 600 /boot/grub/grub.cfg
	chmod 600 /etc/ssh/sshd_config
	chmod 600 /etc/gshadow-
	chmod 600 /etc/group-
	chmod 600 /etc/passwd-
	chown root:root /etc/ssh/sshd_config
	chown root:root /etc/passwd-
	chown root:root /etc/group-
	chown root:root /etc/shadow
	chown root:root /etc/securetty
	chown root:root /boot/grub/grub.cfg
	chmod og-rwx /boot/grub/grub.cfg
	chown root:shadow /etc/shadow-
	chmod o-rwx,g-rw /etc/shadow-
	chown root:shadow /etc/gshadow-
	chmod o-rwx,g-rw /etc/gshadow-
	touch /etc/cron.allow
	touch /etc/at.allow
	chmod og-rwx /etc/cron.allow
	chmod og-rwx /etc/at.allow
	chown root:root /etc/cron.allow
	chown root:root /etc/at.allow
	chown root:root /etc/cron.d
	chmod og-rwx /etc/cron.d
	chown root:root /etc/crontab
	chmod og-rwx /etc/crontab
	chmod -R g-wx,o-rwx /var/log/

	printf "\e[1;34mFinished File() function!\e[0m"

}

Misc(){	
	clear
	printf "\033[1;31mRunning Misc()\033[0m\n"

	#Disable automounting
	systemctl disable autofs
	service autofs stop

	# set users umask
	sed -i "s/UMASK.*022/UMASK   077/" /etc/login.defs

	# set root umask
	sed -i "s/#.*umask.*022/umask 077/" /root/.bashrc
	
	#Restricts umask
    sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc

	#Disables ctrl-alt-delete
	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload

	#Disables cups
	systemctl disable cups
	systemctl disable cupsd
	service cups stop
	service cupsd stop

	#Hardening /proc with hidepid
	mount -o remount,rw,hidepid=2 /proc

	#Secure sudoers
	sed -i 's/NOPASSWD://g' /etc/ers
	sed -i 's/!authenticate//g' /etc/ers
	sed -i 's/!authenticate//g' /etc/ers.d/*
	sed -i 's/NOPASSWD://g' /etc/ers.d/*

	#IP Spoofing
	echo "order bind,hosts" >> /etc/host.conf
	echo "nospoof on" >> /etc/host.conf

	#Secured shared memory
	echo "none     /run/shm    tmpfs    ro,noexec,nosuid,nodev,defaults    0    0" >> /etc/fstab

	#Changes the nameserver to 8.8.8.8, Google's DNS.
	echo "nameserver 8.8.8.8 " >> /etc/resolv.conf

	chown root:root /etc/motd
	chmod 644 /etc/motd
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd

	chown root:root /etc/issue
	chmod 644 /etc/issue
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

	chown root:root /etc/issue.net
	chmod 644 /etc/issue.net
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

	printf "\e[1;34mFinished Misc() function!\e[0m"
}

Firewall(){
	clear
	printf "\033[1;31mSetting up firewall...\033[0m\n"
	#--------- Setup Firewall ----------------
	# Flush/Delete firewall rules
	iptables -F
	iptables -X
	iptables -Z

	ufw reset
	ufw enable
	ufw logging full
	ufw default deny incoming
	ufw deny 23		#Block Telnet
	ufw deny 2049	#Block NFS
	ufw deny 515	#Block printer port
	ufw deny 111 #Block Sun rpc/NFS
	ufw status verbose > ufwrules.txt

	#Disables IPV6
	sed -i '/^IPV6=yes/ c\IPV6=no\' /etc/default/ufw
	echo 'blacklist ipv6' >> /etc/modprobe.d/blacklist

	# Block null packets (DoS)
	iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

	# Block syn-flood attacks (DoS)
	iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

	#Drop incoming packets with fragments
	iptables -A INPUT -f -j DROP

	# Block XMAS packets (DoS)
	iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

	# Allow internal traffic on the loopback device
	iptables -A INPUT -i lo -j ACCEPT

	# Allow ssh access
	iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

	# Allow established connections
	iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# Allow outgoing connections
	iptables -P OUTPUT ACCEPT

	# Set default deny firewall policy
	iptables -P INPUT DROP

	#Block Telnet
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP

	#Block NFS
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP

	#Block X-Windows
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP

	#Block X-Windows font server
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP

	#Block printer port
	iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP

	#Block Sun rpc/NFS
	iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP

	 #Deny outside packets from internet which claim to be from your loopback interface.
	iptables -A INPUT -p all -s localhost  -i eth0 -j DROP

	# Save rules
	iptables-save > /etc/iptables/rules.v4

	#If you ever need to block an IP address - http://bookofzeus.com/harden-ubuntu/hardening/protect-ddos-attacks/
	printf "\e[1;34mFinished Firewall() function!\e[0m"
}

Sysctl(){
	clear
	printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
	#--------- Secure /etc/sysctl.conf ----------------
	echo "net.ipv4.tcp_syncookies=1
kernel.dmesg_restrict=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv6.conf.default.accept_redirects=0
fs.suid_dumpable=0
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.sysrq = 0
kernel.maps_protect=1
kernel.core_uses_pid=1
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv6.conf.all.accept_redirects=0
net.ipv4.icmp_echo_ignore_all=1
kernel.exec-shield=1
kernel.panic=10
kernel.kptr_restrict=2
vm.panic_on_oom=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.randomize_va_space=2
net.ipv6.conf.default.router_solicitations=0
net.ipv6.conf.default.accept_ra_rtr_pref=0
net.ipv6.conf.default.accept_ra_pinfo=0
net.ipv6.conf.default.accept_ra_defrtr=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.dad_transmits=0
net.ipv6.conf.default.max_addresses=1
net.ipv4.tcp_rfc1337=1
kernel.unprivileged_userns_clone=0
kernel.ctrl-alt-del=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1


	" > /etc/sysctl.conf

	sysctl -p

	printf "\e[1;34mFinished Sysctl() function!\e[0m"
}

Auditctl() { #This is most likely useless.
	clear
	printf "\e[1;34mRunning Auditctl()\e[0m"
	echo "
	# First rule - delete all
	-D

	#Ensure events that modify date and time information are collected

	-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
	-a always,exit -F arch=b64 -S clock_settime -k time-change
	-a always,exit -F arch=b32 -S clock_settime -k time-change
	-w /etc/localtime -p wa -k time-change

	#Ensure events that modify user/group information are collected

	-w /etc/group -p wa -k identity
	-w /etc/passwd -p wa -k identity
	-w /etc/gshadow -p wa -k identity
	-w /etc/shadow -p wa -k identity
	-w /etc/security/opasswd -p wa -k identity

	#Ensure events that modify the system's network environment are collected

	-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
	-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
	-w /etc/issue -p wa -k system-locale
	-w /etc/issue.net -p wa -k system-locale
	-w /etc/hosts -p wa -k system-locale
	-w /etc/network -p wa -k system-locale
	-w /etc/networks -p wa -k system-locale

	#Ensure events that modify system's MAC are collected

	-w /etc/apparmor/ -p wa -k MAC-policy
	-w /etc/apparmor.d/ -p wa -k MAC-policy

	#Ensure login and logouts events are collected

	-w /var/log/faillog -p wa -k logins
	-w /var/log/lastlog -p wa -k logins
	-w /var/log/tallylog -p wa -k logins

	#Ensure session initiation information is collected

	-w /var/run/utmp -p wa -k session
	-w /var/run/wtmp -p wa -k session
	-w /var/run/btmp -p wa -k session

	#Ensure discretionary access control permission modification events are collected

	-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

	#Ensure unsuccessful unauthorized file access attempts are collected

	-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
	-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
	-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
	-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

	#Ensure successful file system mounts are collected

	-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
	-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

	#Ensure file deletion events by users are collected

	-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
	-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

	#Ensure changes to system administration scope (ers) is collected

	-w /etc/ers -p wa -k scope
	-w /etc/ers.d -p wa -k scope

	#Ensure system administrator actions (log) are collected

	-w /var/log/.log -p wa -k actions

	#Ensure kernel module loading and unloading is collected

	-w /sbin/insmod -p x -k modules
	-w /sbin/rmmod -p x -k modules
	-w /sbin/modprobe -p x -k modules
	-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

	# increase the buffers to survive stress events. make this bigger for busy systems.
	-b 1024

	# monitor unlink() and rmdir() system calls.
	-a exit,always -S unlink -S rmdir

	# monitor open() system call by Linux UID 1001.
	-a exit,always -S open -F loginuid=1001

	" >> /etc/audit/audit.rules
		
	printf "\e[1;34mFinished Sysctl() function!\e[0m"
}
	clear

	dnf autoremove -y
	
Main
