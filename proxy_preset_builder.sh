#!/bin/bash
# enable debug
#set -x -v
#set -e -o verbose
#pipefail | verbose

# fixing paths
export PATH=$PATH:/usr/sbin:/usr/sbin:/usr/local/sbin

# set colors
GCV="\033[0;92m"
LRV="\033[1;91m"
YCV="\033[01;33m"
NCV="\033[0m"

# show script version
self_current_version="1.0.22"
printf "\n${YCV}Hello${NCV}, my version is ${YCV}$self_current_version\n${NCV}"

# check privileges
if [[ $EUID -ne 0 ]]
then
	printf "\n${LRV}ERROR - This script must be run as root.${NCV}" 
	exit 1
fi

#check tools
WE_NEED=('/usr/local/mgr5/sbin/mgrctl' 'nginx' 'sed' 'awk' 'perl' 'cp' 'grep' 'printf' 'cat' 'rm' 'test' 'openssl' 'getent' 'mkdir' 'timeout')

for needitem in "${WE_NEED[@]}"
do
	if ! command -v $needitem &> /dev/null
	then 
		printf "\n${LRV}ERROR - $needitem could not be found. Please install it first or export correct \$PATH.${NCV}"
	exit 1
	fi
done

# check OS
shopt -s nocasematch
REL=$(cat /etc/*release* | head -n 1)
case "$REL" in
        *cent*) distr="rhel";;
	*alma*) distr="rhel";;
        *cloud*) distr="rhel";;
        *rhel*) distr="rhel";;
        *debian*) distr="debian";;
        *ubuntu*) distr="debian";;
        *) distr="unknown";;
esac;
shopt -u nocasematch

# RHEL
if [[ $distr == "rhel" ]]
then
        printf "\n${GCV}Looks like this is some RHEL (or derivative) OS${NCV}\n"
# DEBIAN
elif [[ $distr == "debian" ]]
then
        printf "\n${GCV}Looks like this is some Debian (or derivative) OS${NCV}\n"
# UNKNOWN
elif [[ $distr == "unknown" ]]
then
        printf "\n${LRV}Sorry, cannot detect this OS${NCV}\n"
        EXIT_STATUS=1
        exit 1
fi

#check env
if [[ -f /usr/bin/hostnamectl ]] || [[ -f /bin/hostnamectl ]]
then
	PLATFROM_CHASSIS=$(hostnamectl status | grep Chassis | awk '{print $2}')
	PLATFROM_VIRT=$(hostnamectl status | grep Virtualization | awk '{print $2}')
	
	if [[ $PLATFROM_CHASSIS == "server" || $PLATFROM_CHASSIS == "laptop" ]]
	then
		DEDICATED="yes"
		VIRTUAL="no"
	else
		DEDICATED="no"
	fi
	
	if [[ $PLATFROM_CHASSIS == "vm" || $PLATFROM_CHASSIS == "container" ]]
	then
		VIRTUAL="yes"
		if [[ $PLATFROM_VIRT == "kvm" ]]
		then
			PLATFROM_VIRT="kvm"
		elif [[ $PLATFROM_VIRT == "openvz" ]]
		then
			PLATFROM_VIRT="openvz"
		elif [[ $PLATFROM_VIRT == "xen" ]]
		then
			PLATFROM_VIRT="xen"
		else
			PLATFROM_VIRT="unknown"
		fi 
	else
		PLATFROM_VIRT="none"
		VIRTUAL="no"
	fi
elif [[ -f /usr/sbin/dmidecode ]] || [[ -f /bin/dmidecode ]]
then
	PLATFROM_CHASSIS=$(dmidecode -t memory | grep -iA 10 "Physical Memory Array" | grep Location | awk '{print $2}')
	if [[ $PLATFROM_CHASSIS == "Other" ]]
	then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="unknown"
	elif [[ $PLATFROM_CHASSIS == "System" ]]
	then
		VIRTUAL="no"
		DEDICATED="yes"
		PLATFROM_VIRT="none"
	fi

	if [[ -f /usr/bin/systemd-detect-virt ]]
	then
		PLATFROM_VIRT=$(systemd-detect-virt)
		if [[ $PLATFROM_VIRT == "openvz" ]]
		then
			VIRTUAL="yes"
			DEDICATED="no"
			PLATFROM_VIRT="openvz"
		elif [[ $PLATFROM_VIRT == "kvm" ]]
		then
			VIRTUAL="yes"
			DEDICATED="no"
			PLATFROM_VIRT="kvm"
		elif [[ $PLATFROM_VIRT == "xen" ]]
		then
			VIRTUAL="yes"
			DEDICATED="no"
			PLATFROM_VIRT="xen"
		elif [[ $PLATFROM_VIRT == "none" ]]
		then
			VIRTUAL="no"
			DEDICATED="yes"
			PLATFROM_VIRT="none"
		else
			VIRTUAL="unknown"
			DEDICATED="unknown"
			PLATFROM_VIRT="unknown"
		fi
	fi	
elif [[ -f /usr/bin/systemd-detect-virt ]]
then
	PLATFROM_VIRT=$(systemd-detect-virt)
	if [[ $PLATFROM_VIRT == "openvz" ]]
	then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="openvz"
	elif [[ $PLATFROM_VIRT == "kvm" ]]
	then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="kvm"
	elif [[ $PLATFROM_VIRT == "xen" ]]
	then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="xen"
	elif [[ $PLATFROM_VIRT == "none" ]]
	then
		VIRTUAL="no"
		DEDICATED="yes"
		PLATFROM_VIRT="none"
	else
		VIRTUAL="unknown"
		DEDICATED="unknown"
		PLATFROM_VIRT="unknown"
	fi
else
	PLATFROM_VIRT="unknown"
	DEDICATED="unknown"
	VIRTUAL="unknown"
fi

# isp vars
MGR_PATH="/usr/local/mgr5"
MGRCTL="$MGR_PATH/sbin/mgrctl -m ispmgr"

# allowed script actions
ALLOWED_ACTIONS="(^add$|^del$|^reset$|^tweak$|^recompile$|^setstatus$)"

# paths to ISP manager nginx templates
NGINX_DEFAULT_TEMPLATE="$MGR_PATH/etc/templates/default/nginx-vhosts.template"
NGINX_DEFAULT_SSL_TEMPLATE="$MGR_PATH/etc/templates/default/nginx-vhosts-ssl.template"
NGINX_TEMPLATE="$MGR_PATH/etc/templates/nginx-vhosts.template"
NGINX_SSL_TEMPLATE="$MGR_PATH/etc/templates/nginx-vhosts-ssl.template"
NGINX_MAIN_CONF_FILE="/etc/nginx/nginx.conf"
NGX_RECOMPILE_SCRIPT_NAME="recompile_nginx.sh"

# global randrom number
RANDOM_N=$RANDOM

# proxy prefix may be changed here
PROXY_PREFIX="proxy_to_"

# GIT repo
SCRIPT_GIT_REPO="https://github.com/attaattaatta/proxy_preset_builder"
SCRIPT_GIT_BACKUP_REPO="https://gitlab.hoztnode.net/admins/scripts"

# GIT script raw path to proxy_preset_builder.sh folder
SCRIPT_GIT_PATH="https://raw.githubusercontent.com/attaattaatta/proxy_preset_builder/master"
SCRIPT_GIT_BACKUP_PATH="https://gitlab.hoztnode.net/admins/scripts/-/raw/master"

# extract domain names of GIT urls
GIT_DOMAIN_NAME="$(printf "$SCRIPT_GIT_PATH" | awk -F[/:] '{print $4}')"
GIT_BACKUP_DOMAIN_NAME="$(printf "$SCRIPT_GIT_BACKUP_PATH" | awk -F[/:] '{print $4}')"

# extract request uri of GIT urls
GIT_REQ_URI="${SCRIPT_GIT_PATH#https://*/}"
GIT_BACKUP_REQ_URI="${SCRIPT_GIT_BACKUP_PATH#https://*/}"

# show script version and check gits
script_git_name="proxy_preset_builder.sh"
git_version="$(printf "GET $SCRIPT_GIT_PATH/$script_git_name HTTP/1.1\nHost:$GIT_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_DOMAIN_NAME:443 -quiet | grep -o -P '(?<=self_current_version=")\d+\.?\d+?\.?\d+?')"
git_backup_version="$(printf "GET $SCRIPT_GIT_BACKUP_PATH/$script_git_name HTTP/1.1\nHost:$GIT_BACKUP_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_BACKUP_DOMAIN_NAME:443 -quiet | grep -o -P '(?<=self_current_version=")\d+\.?\d+?\.?\d+?')"

if [[ $git_version ]] && [[ $self_current_version < $git_version ]]
then
	printf "\nVersion ${YCV}$git_version${NCV} at $SCRIPT_GIT_PATH/$script_git_name \n"
	printf "You may use it like this:\n# bash <(printf \"GET /$GIT_REQ_URI/$script_git_name HTTP/1.1\\\nHost:$GIT_DOMAIN_NAME\\\nConnection:Close\\\n\\\n\" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_DOMAIN_NAME:443 -quiet | sed \'1,/^\s\$/d\')\n"
fi

if [[ $git_backup_version ]] && [[ $self_current_version < $git_backup_version ]]
then
	printf "\nVersion ${YCV}$git_backup_version${NCV} at $SCRIPT_GIT_BACKUP_PATH/$script_git_name\n"
	printf "You may use it like this:\n# bash <(printf \"GET /$GIT_BACKUP_REQ_URI/$script_git_name HTTP/1.1\\\nHost:$GIT_BACKUP_DOMAIN_NAME\\\nConnection:Close\\\n\\\n\" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_BACKUP_DOMAIN_NAME:443 -quiet | sed \'1,/^\s\$/d\')\n"
fi

# check panel version and release name
printf "\n${GCV}ISP Manager version checking${NCV}\n"

panel_required_version="6.82.0"

panel_current_version="$($MGRCTL license.info | grep -o -P '(?<=panel_info=)\d+\.?\d+\.?\d+')"
panel_release_name="$($MGRCTL license.info |  grep -o -P '(?<=panel_name=)\w+\s\w+')"

if [[ -z $panel_release_name ]] || [[ -z $panel_current_version ]]
then
	printf "\n${LRV}ERROR - Cannot get ISP Manager panel version or release name.\nPlease check \"$MGRCTL license.info\" command${NCV}\n"
	exit 1
fi

# set case insence for regexp
shopt -s nocasematch
if [[ $panel_release_name =~ .*busines.* ]]
then 
	printf "\n${LRV}ISP Manager Business detected. Not yet supported.${NCV}\n"
	shopt -u nocasematch
	exit 1
else
	if [[ $panel_current_version < $panel_required_version ]]
	then 
		printf "\n${LRV}ERROR - ISP Manager panel version must not be less than $panel_required_version (current version is $panel_current_version)${NCV}\n${GCV}You may update it to $panel_required_version\nor check out this link - https://gitlab.hoztnode.net/admins/scripts/-/blob/12c70d7c370959f9f8a2c45b3b72c0a9aade914c/proxy_preset_builder.sh\nfor older panel release version of this script${NCV}\n"
		exit 1
	else
		printf "ISP Manager version ($panel_current_version) suits\n"
	fi
		printf "ISP Manager release ($panel_release_name) suits\n"
fi
# unset case insence for regexp
shopt -u nocasematch

# validate first argument 
if ! [[ $1 =~ $ALLOWED_ACTIONS ]]  && ! [[ -z "$1" ]]
then
	printf "\n\n${LRV}ERROR - Not valid argument - $1${NCV}\n"
	exit 1
fi

# restart ISP panel func
isp_panel_graceful_restart_func() {

printf "\n${LRV}ISP panel restarting${NCV}"
EXIT_STATUS=0
trap 'EXIT_STATUS=1' ERR
$MGRCTL -R
check_exit_and_restore_func
printf " - ${GCV}OK${NCV}\n"
exit 0

}

# backing up /etc and existing presets
backup_func() {
	BACKUP_ROOT_DIR="/root/support"
	current_ispmgr_backup_directory="/root/support/ispmgr_templates.$(date '+%d-%b-%Y-%H-%M')"
	current_etc_backup_directory="/root/support/etc_preset_builder_$(date '+%d-%b-%Y-%H-%M')"

	NGINX_TEMPLATE_BACKUP="$current_ispmgr_backup_directory/nginx-vhosts.template"
	NGINX_SSL_TEMPLATE_BACKUP="$current_ispmgr_backup_directory/nginx-vhosts-ssl.template"
	NGINX_MAIN_CONF_BACKUP_PATH="${NGINX_MAIN_CONF_FILE#*etc/}"
	NGINX_MAIN_CONF_BACKUP_FILE="$current_etc_backup_directory/$NGINX_MAIN_CONF_BACKUP_PATH"
	
	printf "\n${GCV}Backing up etc and templates${NCV}\n"
	\mkdir -p "$BACKUP_ROOT_DIR"
	\cp -rp --reflink=auto "$MGR_PATH/etc/templates" "$current_ispmgr_backup_directory"
	\cp -rp --reflink=auto "/etc" "$current_etc_backup_directory"
	printf "/etc and templates are backed up to $current_ispmgr_backup_directory and $current_etc_backup_directory\n"
}
  
# if proxy target to fastcgi format fastcgi_pass string
fastcgi_pass_format_func() {
	sed -i -E 's@(.*fastcgi_pass.+):;$@\1;@gi' $NGINX_TEMPLATE
	sed -i -E 's@(.*fastcgi_pass.+):;$@\1;@gi' $NGINX_SSL_TEMPLATE
}

# remove ssl port number from 301 redirect
seo_fix_ssl_port_func() {
	sed -i -E 's@(.*return 301 https:\/\/\$host)\:\{\% \$SSL_PORT \%\}(\$request_uri;)@\{\% if $PRESET == proxy_to_bitrix_fpm \%\}\n\tif ($request_uri !~ ^\(/robots.txt|/bitrix/admin/site_checker.*|/bitrix/admin/1c_exchange.*\)\) {\n\t\1\2\n\t}\n{% else %}\n\1\2\n{% endif %}@gi' $NGINX_TEMPLATE
}

# set ssl tune options
ssl_tune_func() {
	# todo (isp manager 6 bug / ignoring ssl server { ... }  at nginx ssl template parsing if  ssl_prefer_server_ciphers not exists or off /)
	#sed -i -E 's@^.*ssl_prefer_server_ciphers.*on;@\tssl_session_timeout 10m;\n\tssl_session_cache shared:SSL:10m;@gi' $NGINX_SSL_TEMPLATE 
	sed -i '/ssl_protocols/a \\tssl_session_timeout 10m;\n \tssl_session_cache shared:SSL:10m;' $NGINX_SSL_TEMPLATE 
}

# git availability check and set the choosen one
git_check() {
	printf "\n\n${YCV}Here we need some network for download${NCV}"
	
	# resolve 
	if [[ ! -z $GIT_DOMAIN_NAME ]] || [[ ! -z $GIT_BACKUP_DOMAIN_NAME ]]
	then
		EXIT_STATUS=0
		trap 'EXIT_STATUS=1' ERR
		
		getent hosts $GIT_DOMAIN_NAME &> /dev/null || getent hosts $GIT_BACKUP_DOMAIN_NAME &> /dev/null
		
		# check result and restore if error
		printf "\nResolving $GIT_DOMAIN_NAME and $GIT_BACKUP_DOMAIN_NAME"
		if [[ $1 == "no_check_exit" ]] 
		then
			exit 1
		else
			check_exit_and_restore_func
		fi
		printf " - ${GCV}OK${NCV}\n"
	else
		printf "\n${LRV}ERROR - Variables \$GIT_DOMAIN_NAME or \$GIT_BACKUP_DOMAIN_NAME are empty\n${NCV}"
		EXIT_STATUS=1
		if [[ $1 == "no_check_exit" ]] 
		then
			exit 1
		else
			check_exit_and_restore_func
		fi
		exit 1
	fi
	
	# choosing which git to use
	if [[ $git_version ]]
	then
		GIT_THE_CHOSEN_ONE_REPO="$SCRIPT_GIT_REPO"
		GIT_THE_CHOSEN_ONE_PATH="$SCRIPT_GIT_PATH"
		GIT_THE_CHOSEN_ONE_DOMAIN_NAME="$(printf "$SCRIPT_GIT_PATH" | awk -F[/:] '{print $4}')"
		GIT_THE_CHOSEN_ONE_REQ_URI="${SCRIPT_GIT_PATH#https://*/}"
		
		printf "$GIT_THE_CHOSEN_ONE_REPO will be used\n"
	else
		if [[ $git_backup_version ]]
		then
			GIT_THE_CHOSEN_ONE_REPO="$SCRIPT_GIT_BACKUP_REPO"
			GIT_THE_CHOSEN_ONE_PATH="$SCRIPT_GIT_BACKUP_PATH"
			GIT_THE_CHOSEN_ONE_DOMAIN_NAME="$(printf "$SCRIPT_GIT_BACKUP_PATH" | awk -F[/:] '{print $4}')"
			GIT_THE_CHOSEN_ONE_REQ_URI="${SCRIPT_GIT_BACKUP_PATH#https://*/}"
			
			printf "$GIT_THE_CHOSEN_ONE_REPO will be used\n"
		else
			printf "\n${LRV}ERROR - $SCRIPT_GIT_PATH and $SCRIPT_GIT_BACKUP_PATH both not available\n${NCV}"
			EXIT_STATUS=1
			if [[ $1 == "no_check_exit" ]] 
			then
				exit 1
			else
				check_exit_and_restore_func
			fi
			exit 1
		fi
	fi
}

# check last exit code =>1 and restore panel nginx configuration templates
check_exit_and_restore_func() {
	if test $EXIT_STATUS != 0
	then
		printf "\n${LRV}Last command(s) has failed.\nRemoving preset $PROXY_PREFIX$proxy_target${NCV}"
		
		{
		\rm -f "$NGINX_TEMPLATE" "$NGINX_SSL_TEMPLATE"
		\rm -f /etc/nginx/vhosts-includes/apache_status_[0-9]*.conf
		\rm -f /etc/nginx/vhosts-includes/nginx_status_[0-9]*.conf
		} &> /dev/null
		
		if $MGRCTL preset.delete elid=$PROXY_PREFIX$proxy_target elname=$PROXY_PREFIX$proxy_target  &> /dev/null
		then
			printf " - ${GCV}OK${NCV}\n"
		else
			printf " - ${LRV}FAIL${NCV}\n"
		fi
		
		printf "\n${LRV}Restoring last templates backup${NCV}\n"
		if [[ -d "$current_ispmgr_backup_directory" ]] || [[ -d "$current_etc_backup_directory" ]]
		then
			\cp -f -p --reflink=auto "$NGINX_TEMPLATE_BACKUP" "$NGINX_TEMPLATE" &> /dev/null && printf "${GCV}$NGINX_TEMPLATE_BACKUP restore was successful.\n${NCV}"
			\cp -f -p --reflink=auto "$NGINX_SSL_TEMPLATE_BACKUP" "$NGINX_SSL_TEMPLATE" &> /dev/null && printf "${GCV}$NGINX_SSL_TEMPLATE_BACKUP restore was successful.\n${NCV}"
			\cp -f -p --reflink=auto "$NGINX_MAIN_CONF_BACKUP_FILE" "$NGINX_MAIN_CONF_FILE" &> /dev/null && printf "${GCV}$NGINX_MAIN_CONF_BACKUP_FILE restore was successful.\n${NCV}"
			# panel graceful restart
			isp_panel_graceful_restart_func
			exit 1
		else 
			printf "\n${LRV}ERROR - $current_etc_backup_directory or $current_ispmgr_backup_directory was not found\n"
			exit 1
		fi
	fi
}

# tweaking all installed php versions and mysql through ISP Manager panel API
ispmanager_tweak_php_and_mysql_settings_func() {

if [[ $DEDICATED == "yes" ]]
then
	printf "\nSeems like a ${GCV}dedicated${NCV} server here\n"
elif [[ $VIRTUAL == "yes" ]]
then
	printf "\nSeems like a ${GCV}virtual${NCV} server here"
	if [[ -n $PLATFROM_VIRT ]]
	then
		printf " with ${GCV}$PLATFROM_VIRT${NCV} virtualization\n"
	else
		printf " with ${LRV}unknown${NCV} virtualization\n"
	fi
else
	printf "\nSeems like a ${LRV}unknown${NCV} server\n"
fi

# check swap file exists if this is virtual server
if [[ $VIRTUAL == "yes" ]]
then

	#Checking swap file exists and its settings
	if ! grep -i "swap" /etc/fstab &> /dev/null
	then
		echo
		read -p "No swap detected. Skip fix ? [Y/n]" -n 1 -r
		echo
		if ! [[ $REPLY =~ ^[Nn]$ ]]
		then
			# user chose not to fix swap
			printf "Fix was canceled by user choice\n"
		else
			VFS_CACHE_PRESSURE=$(cat /proc/sys/vm/vfs_cache_pressure)
			SWAPPINESS=$(cat /proc/sys/vm/swappiness)
		
			printf "Current vfs_cache_pressure - $VFS_CACHE_PRESSURE ( ${GCV}echo \"vm.vfs_cache_pressure = 100\" >> /etc/sysctl.conf && sysctl -p ${NCV})\n"
			printf "Current swappiness - $SWAPPINESS ( ${GCV}echo \"vm.swappiness = 60\" >> /etc/sysctl.conf && sysctl -p ${NCV})\n"
	
			TOTAL_RAM_IN_GB=$(awk '/MemTotal/ { printf "%.1f\n", $2/1024/1024 }' /proc/meminfo)
			FREE_RAM_IN_MB=$(awk '/MemAvailable/ { printf "%i\n", $2/1024 }' /proc/meminfo)
	
			printf "\n${LRV}There is no swap file in /etc/fstab${NCV} and total ${GCV}$TOTAL_RAM_IN_GB GB RAM${NCV} size. Free RAM size - ${GCV}$FREE_RAM_IN_MB MB${NCV} \n\n"
			swapsizes=("1GB" "2GB" "3GB" "4GB" "5GB" "10GB")
			swapsizes+=('Skip')
			PS3='Choose swap size to set:'
			select swapsize_choosen_version in "${swapsizes[@]}"
			do
				if [[ $swapsize_choosen_version == Skip || -z $swapsize_choosen_version ]] 
				then
					break
				else
					printf "\nRunning"
					{
					DD_COUNT=$(($(echo $swapsize_choosen_version | grep -o [[:digit:]])*1024*1024))
					\swapoff /swapfile
					\rm -f /swapfile
					\dd if=/dev/zero of=/swapfile bs=1024 count=$DD_COUNT
					\mkswap /swapfile
					\chmod 600 /swapfile
					\swapon /swapfile
					} &> /dev/null


					if swapon --show | grep -i "/swapfile" &> /dev/null
					then
						echo "/swapfile                                 none                    swap    sw              0 0" >> /etc/fstab
						printf " - ${GCV}DONE${NCV}\n"
						break
					else
						printf " - ${LRV}ERROR. Cannot add /swapfile to /etc/fstab${NCV}\n"
						break
					fi
				fi
			
			done
		fi
	fi
fi

echo
read -p "Skip PHP and MySQL tweak? [Y/n]" -n 1 -r
echo
if ! [[ $REPLY =~ ^[Nn]$ ]]
then
	# user chose not to tweak PHP nor MySQL
	EXIT_STATUS=0
	printf "Tweak was canceled by user choice\n"
else
	# fix ISP panel mysql include bug
	if [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]] && ! grep "^\!includedir /etc/mysql/mysql.conf.d/" /etc/mysql/my.cnf &> /dev/null
		then
		printf "\n${GCV}ISP panel MySQL 8 no include path bug was fixed${NCV}\n"
		echo '!'"includedir /etc/mysql/mysql.conf.d/" >> /etc/mysql/my.cnf
		systemctl restart mysql mysqld mariadb &> /dev/null
		sleep 5s
	fi

	printf "\n${GCV}PHP${NCV}\n"
	# get isp panel installed php versions into the array phpversions
	phpversions=(); while IFS= read -r version; do phpversions+=( "$version" ); done < <( $MGRCTL phpversions | grep -E 'apache=on|fpm=on' | awk '{print $1}' | grep -o -P '(?<=key=).*')
	phpversions+=('Skip')
	
	# check that array not empty
	if [[ ${#phpversions[@]} -eq 0 ]]
	then
		EXIT_STATUS=1
		printf "\n${LRV}ERROR - Array phpversions empty. Check that PHP versions exists in ISP Manager panel.${NCV}\n"
	else
		# generating menu from array and user choosen php version to $php_choosen_version and apply
		PS3='Choose PHP version to tweak:'
		select php_choosen_version in "${phpversions[@]}"
		do
			if [[ $php_choosen_version == Skip || -z $php_choosen_version ]] 
			then
				break
			else
				printf "I can tweak PHP $php_choosen_version: max_execution_time to 300s, post_max_size to 1024m, upload_max_filesize to 1024m, memory_limit to 1024m, opcache.revalidate_freq to 0, max_input_vars to 150000, opcache.memory_consumption to 300MB\nand enable PHP extensions: opcache, memcached, ioncube, imagick, bcmath, xsl\n"
				printf "${GCV}"
				read -p "Should I tweak these PHP settings? [Y/n]" -n 1 -r
				printf "${NCV}"
				if ! [[ $REPLY =~ ^[Nn]$ ]]
				then
					printf "\nRunning"
					EXIT_STATUS=0
					trap 'EXIT_STATUS=1' ERR
					{
					$MGRCTL phpconf.settings plid=$php_choosen_version elid=$php_choosen_version max_execution_time=300 memory_limit=1024  post_max_size=1024 upload_max_filesize=1024 sok=ok
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=opcache elname=opcache sok=ok
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=bcmath elname=bcmath sok=ok
					$MGRCTL phpextensions.install plid=$php_choosen_version elid=imagick elname=imagick sok=ok
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=imagick elname=imagick sok=ok
					$MGRCTL phpextensions.install plid=$php_choosen_version elid=ioncube elname=ioncube sok=ok
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=ioncube elname=ioncube sok=ok
					$MGRCTL phpextensions.install plid=$php_choosen_version elid=memcache elname=memcache sok=ok 
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=memcache elname=memcache sok=ok
					$MGRCTL phpextensions.install plid=$php_choosen_version elid=memcached elname=memcached sok=ok
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=memcached elname=memcached sok=ok
					$MGRCTL phpextensions.install plid=$php_choosen_version elid=xsl elname=xsl sok=ok
					$MGRCTL phpextensions.resume plid=$php_choosen_version elid=xsl elname=xsl sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=opcache.revalidate_freq apache_value=0 cgi_value=0 fpm_value=0 sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=opcache.revalidate_freq value=0 sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=opcache.memory_consumption apache_value=300 cgi_value=300 fpm_value=300 sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=opcache.memory_consumption value=300 sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=max_input_vars apache_value=150000 cgi_value=150000 fpm_value=150000 sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=max_input_vars apache_value=150000 cgi_value=150000 fpm_value=150000 sok=ok
					$MGRCTL phpconf.edit plid=$php_choosen_version elid=max_input_vars value=150000 sok=ok
					} &> /dev/null
					
					# todo
					#check_exit_and_restore_func
					printf " - ${GCV}DONE${NCV}\n"
					break
				else
					printf "\n${YCV}PHP tweaking canceled${NCV}\n"
					EXIT_STATUS=1
					break
				fi
			fi
		done
	fi

	# get isp panel installed mysql versions into the array mysqlversions
	mysqlversions=(); while IFS= read -r version; do mysqlversions+=( "$version" ); done < <( $MGRCTL db.server | grep -E 'type=mysql' | awk '{print $2}' | grep -o -P '(?<=name=).*')
	mysqlversions+=('Skip')
	
	# check that array not empty
	if [[ ${#mysqlversions[@]} -eq 0 ]]
	then
		EXIT_STATUS=1
		printf "\n${LRV}ERROR - Array mysqlversions empty. Check that MySQL versions exists in ISP Manager panel.${NCV}\n"
	else
		printf "\n${GCV}MySQL${NCV}\n"
	
		# generating menu from array and user choosen mysql version to $mysql_choosen_version and apply
		PS3='Choose MySQL version to tweak:'
		select mysql_choosen_version in "${mysqlversions[@]}"
		do
			if [[ $mysql_choosen_version == Skip || -z $mysql_choosen_version ]] 
			then
				break
			else
				printf "I can tweak MySQL - $mysql_choosen_version:\ninnodb_strict_mode to OFF, sql_mode to '', innodb_flush_method to O_DIRECT, transaction_isolation to READ-COMMITTED, innodb_flush_log_at_trx_commit to 2, disable binlog if no replicas exists\n"
				printf "${GCV}"
				read -p "Should I tweak these MySQL settings? [Y/n]" -n 1 -r
				printf "${NCV}"
				if ! [[ $REPLY =~ ^[Nn]$ ]]
				then
					printf "\nRunning"
					EXIT_STATUS=0
					trap 'EXIT_STATUS=1' ERR
					{

					# check docker or not
					if $MGRCTL db.server | grep "$mysql_choosen_version" | grep "docker=on" &> /dev/null
					then
						MYSQL_CHOOSEN_VERSION_DOCKER="in_docker"
					else
						MYSQL_CHOOSEN_VERSION_DOCKER="not_in_docker"
					fi

					#native mysql version disable binlog if no replicas exists
					if [[ $MYSQL_CHOOSEN_VERSION_DOCKER == "not_in_docker" ]] && mysql -e "show slave status;" -vv | grep -i "Empty set" &> /dev/null && ! grep -RIiE "disable_log_bin|skip-log-bin|skip_log_bin" /etc/my* &> /dev/null
					then
						# RHEL
						if [[ $distr == "rhel" ]] && [[ -f /etc/my.cnf.d/mysql-server.cnf ]]
						then
							{
						        	echo "skip-log-bin" >> /etc/my.cnf.d/mysql-server.cnf
								systemctl restart mysql mysqld mariadb &> /dev/null
								\rm -Rf /var/lib/mysql/binlog.* &> /dev/null
							} &> /dev/null

						elif [[ $distr == "rhel" ]] && [[ -f /etc/my.cnf.d/mariadb-server.cnf ]]
						then
							{
								echo "skip-log-bin" >> /etc/my.cnf.d/mariadb-server.cnf
								systemctl restart mysql mysqld mariadb &> /dev/null
								\rm -Rf /var/lib/mysql/binlog.* &> /dev/null
							} &> /dev/null

						# DEBIAN
						elif [[ $distr == "debian" ]] && [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]]
						then
							{
						        	echo "skip-log-bin" >> /etc/mysql/mysql.conf.d/mysqld.cnf
								systemctl restart mysql mysqld mariadb
								\rm -Rf /var/lib/mysql/binlog.* 
							} &> /dev/null
						elif [[ $distr == "debian" ]] && [[-f /etc/mysql/mariadb.conf.d/50-server.cnf ]]
						then
							{
								echo "skip-log-bin" >> /etc/mysql/mariadb.conf.d/50-server.cnf
								systemctl restart mysql mysqld mariadb
								\rm -Rf /var/lib/mysql/binlog.* 
							} &> /dev/null

						# UNKNOWN
						elif [[ $distr == "unknown" ]]
						then
						        printf "\n${LRV}Sorry, cannot detect this OS, add skip-log-bin to cnf file in [mysqld] section by hands${NCV}\n"
						fi
					fi

					if [[ $MYSQL_CHOOSEN_VERSION_DOCKER == "in_docker" ]]
					then
						echo "skip-log-bin" >> /etc/ispmysql/$mysql_choosen_version/custom.cnf
					fi

					$MGRCTL db.server.settings.edit plid=$mysql_choosen_version elid=innodb-strict-mode name=innodb-strict-mode bool_value=FALSE value=FALSE sok=ok
					$MGRCTL db.server.settings.edit plid=$mysql_choosen_version elid=sql-mode name=sql-mode value='' str_value='' sok=ok
					$MGRCTL db.server.settings.edit plid=$mysql_choosen_version elid=innodb-flush-method name=innodb-flush-method value=O_DIRECT str_value=O_DIRECT sok=ok
					$MGRCTL db.server.settings.edit plid=$mysql_choosen_version elid=innodb-flush-log-at-trx-commit name=innodb-flush-log-at-trx-commit value=2 int_value=2 str_value=2 sok=ok
					$MGRCTL db.server.settings.edit plid=$mysql_choosen_version elid=transaction-isolation name=transaction-isolation value=READ-COMMITTED str_value=READ-COMMITTED sok=ok

					} &> /dev/null
					sleep 10s
					#todo
					#check_exit_and_restore_func

					sleep 5s

					printf " - ${GCV}DONE${NCV}\n"
					break
				else
					printf "\n${YCV}MySQL tweaking canceled${NCV}\n"
					EXIT_STATUS=1
					break
				fi
			fi
		done
	fi
fi
}

# check nginx conf and reload configuration
nginx_conf_sanity_check_and_reload_func() {
printf "\n${YCV}Making nginx configuration check${NCV}"
if nginx_test_output=$({ nginx -t; } 2>&1)
then
	printf " - ${GCV}OK${NCV}\n"
	nginx -s reload &> /dev/null
	EXIT_STATUS=0
else
	printf " - ${LRV}FAIL${NCV}\n$nginx_test_output\n"
	EXIT_STATUS=1
	for file in "${BITRIX_REQ_NGINX_HTTP_FILES[@]}"
	do
	\rm -f "$BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file"
	done
	for file in "${BITRIX_REQ_NGINX_SERVER_FILES[@]}"
	do
	\rm -f "$BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR/$file"
	done
	check_exit_and_restore_func
fi
}

# detecting nginx push & pull support
nginx_push_pull_module_support() {

if 2>&1 nginx -V | grep -i "push-stream" &> /dev/null
then 
	NGINX_HAVE_PUSH_PULL=1
else
	NGINX_HAVE_PUSH_PULL=0
fi

}

# bitrix_fpm special inject download nginx conf files function
bitrix_fpm_download_files_func() {

BITRIX_REQ_NGINX_HTTP_FILES=("$BITRIX_NGX_PUSH" "nginx_bitrix_http_context.conf")
BITRIX_REQ_NGINX_SERVER_FILES=("nginx_bitrix_server_context.conf")

# http context
printf "\n${YCV}Downloading bitrix nginx http context files to $BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR${NCV}\n"
for file in "${BITRIX_REQ_NGINX_HTTP_FILES[@]}"
do
	EXIT_STATUS=0
	trap 'EXIT_STATUS=1' ERR
	printf "GET $GIT_THE_CHOSEN_ONE_REQ_URI/$BITRIX_REQ_NGINX_FOLDER_URL$file HTTP/1.1\nHost:$GIT_THE_CHOSEN_ONE_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_THE_CHOSEN_ONE_DOMAIN_NAME:443 -quiet | sed '1,/^\s$/d' > "$BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file"
	# check download result and restore if error
	printf "Verifying download status of $BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file"
	check_exit_and_restore_func
	if [[ -f "$BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file" ]]
	then
		# file exists after download and total size more than 30 bytes
		FILE_SIZE=$(ls -l "$BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file" | awk '{print $5}' 2> /dev/null)
		if [[ $FILE_SIZE -gt 30 ]]
		then 
			printf " - ${GCV}OK${NCV}\n"
		else
			# file size less than 30 bytes
			printf " - ${LRV}FAIL (Filesize less than 30 bytes)${NCV}\n"
			EXIT_STATUS=1
			check_exit_and_restore_func
		fi
	else
		# file doesnt exists after download
		printf " - ${LRV}FAIL (File not exist after download)${NCV}\n"
		EXIT_STATUS=1
		check_exit_and_restore_func
	fi
done

# server context
printf "\n${YCV}Downloading bitrix nginx server context files to $BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR${NCV}\n"
for file in "${BITRIX_REQ_NGINX_SERVER_FILES[@]}"
do
	EXIT_STATUS=0
	trap 'EXIT_STATUS=1' ERR
	printf "GET $GIT_THE_CHOSEN_ONE_REQ_URI/$BITRIX_REQ_NGINX_FOLDER_URL$file HTTP/1.1\nHost:$GIT_THE_CHOSEN_ONE_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_THE_CHOSEN_ONE_DOMAIN_NAME:443 -quiet | sed '1,/^\s$/d' > "$BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR/$file"
	# check download result and restore if error
	printf "Verifying download status of $BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR/$file"
	check_exit_and_restore_func
	if [[ -f "$BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR/$file" ]]
	then
		# file exists after download and total size more than 30 bytes
		FILE_SIZE=$(ls -l "$BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR/$file" | awk '{print $5}' 2> /dev/null)
		if [[ $FILE_SIZE -gt 30 ]]
		then 
			printf " - ${GCV}OK${NCV}\n"
		else
			# file size less than 30 bytes
			printf " - ${LRV}FAIL (Filesize less than 30 bytes)${NCV}\n"
			EXIT_STATUS=1
			check_exit_and_restore_func
		fi
	else
		# file doesnt exists after download
		printf " - ${LRV}FAIL (File not exist after download)${NCV}\n"
		EXIT_STATUS=1
		check_exit_and_restore_func
	fi
done

# run nginx conf sanity check
nginx_conf_sanity_check_and_reload_func

}

# backward compatibility injection and check
backward_copmat_func() {

	# NGINX_TEMPLATE injection 
	perl -i -p0e "$BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_APACHE" "$NGINX_TEMPLATE" 
	perl -i -p0e "$BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_PHPFPM" "$NGINX_TEMPLATE"
	perl -i -p0e "$BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_BEGIN" "$NGINX_TEMPLATE"
	perl -i -p0e "$BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_END" "$NGINX_TEMPLATE"		
	# NGINX_SSL_TEMPLATE injection
	perl -i -p0e "$BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_APACHE" "$NGINX_SSL_TEMPLATE" 
	perl -i -p0e "$BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_PHPFPM" "$NGINX_SSL_TEMPLATE"
	perl -i -p0e "$BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_BEGIN" "$NGINX_SSL_TEMPLATE"
	perl -i -p0e "$BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_END" "$NGINX_SSL_TEMPLATE"

	# check for success backward comaptibility injection, restore from backup and exit
	EXIT_STATUS=0
	trap 'EXIT_STATUS=1' ERR

	grep -q 'apache_backward_compatibility_condition_start_DO_NOT_(RE)MOVE' "$NGINX_TEMPLATE"
	grep -q 'apache_backward_compatibility_condition_stop_DO_NOT_(RE)MOVE' "$NGINX_TEMPLATE"
	grep -q "phpfpm_backward_compatibility_condition_start_DO_NOT_(RE)MOVE" "$NGINX_TEMPLATE"
	grep -q "phpfpm_backward_compatibility_condition_stop_DO_NOT_(RE)MOVE" "$NGINX_TEMPLATE"
	grep -q "php_off_backward_compatibility_condition_start_DO_NOT_(RE)MOVE" "$NGINX_TEMPLATE"
	grep -q "php_off_backward_compatibility_condition_stop_DO_NOT_(RE)MOVE" "$NGINX_TEMPLATE"

	grep -q 'apache_backward_compatibility_condition_start_DO_NOT_(RE)MOVE' "$NGINX_SSL_TEMPLATE"
	grep -q 'apache_backward_compatibility_condition_stop_DO_NOT_(RE)MOVE' "$NGINX_SSL_TEMPLATE"
	grep -q "phpfpm_backward_compatibility_condition_start_DO_NOT_(RE)MOVE" "$NGINX_SSL_TEMPLATE"
	grep -q "phpfpm_backward_compatibility_condition_stop_DO_NOT_(RE)MOVE" "$NGINX_SSL_TEMPLATE"
	grep -q "php_off_backward_compatibility_condition_start_DO_NOT_(RE)MOVE" "$NGINX_SSL_TEMPLATE"
	grep -q "php_off_backward_compatibility_condition_stop_DO_NOT_(RE)MOVE" "$NGINX_SSL_TEMPLATE"

	# check result and restore if error
	printf "Backward comatibility injection verification"
	check_exit_and_restore_func
	printf " - ${GCV}OK${NCV}"
}
  
# removing presets if defined
if [[ $1 = "del" ]]
then
	if [[ $2 = "all" ]]
	then
		echo
		printf "${LRV}"
		read -p "This will delete all $PROXY_PREFIX presets. Are you sure? [Y/n]" -n 1 -r
		echo
		printf "${NCV}"
		if ! [[ $REPLY =~ ^[Nn]$ ]]
		then
			# backup
			backup_func
			
			# removing all $PROXY_PREFIX presets
			preset_list=$($MGRCTL preset | awk -F '=' '{print $3}' | grep -E "$PROXY_PREFIX.+")
			for plist in $preset_list; do $MGRCTL preset.delete elid=$plist elname=$plist; done
			printf "\n${LRV}All ISP panel %%$PROXY_PREFIX%% presets was removed${NCV}\n"
		
			# removing all $PROXY_PREFIX  injects
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_TEMPLATE
			sed -i '/^[[:space:]]*$/d' $NGINX_TEMPLATE
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_SSL_TEMPLATE
			sed -i '/^[[:space:]]*$/d' $NGINX_SSL_TEMPLATE
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_MAIN_CONF_FILE
			sed -i '/^[[:space:]]*$/d' $NGINX_MAIN_CONF_FILE
			
			# panel graceful restart
			isp_panel_graceful_restart_func
		else
			printf "\n${LRV}Deletion canceled${NCV}\n"
			exit 0
		fi
	# check that this preset exists in panel, and if exists delete it with inject
	elif [[ ! -z "$2"  ]]  && [[  ! -z $($MGRCTL preset | awk -F '=' '{print $3}' | grep -E "$2") ]]
		then
			echo
			printf "${LRV}"
			read -p "This will delete $2 preset. Are you sure? [Y/n]" -n 1 -r
			echo
			printf "${NCV}"
			if ! [[ $REPLY =~ ^[Nn]$ ]]
			then
				# backup
				backup_func
				
				# removing $2 preset
				printf "\n${LRV}Deleting preset $2 ${NCV}\n"
				
				EXIT_STATUS=0
				trap 'EXIT_STATUS=1' ERR
				
				$MGRCTL preset.delete elid=$2 elname=$2 &> /dev/null
				
				# removing $2 inject
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_TEMPLATE &> /dev/null
				sed -i '/^[[:space:]]*$/d' $NGINX_TEMPLATE &> /dev/null
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_SSL_TEMPLATE &> /dev/null
				sed -i '/^[[:space:]]*$/d' $NGINX_SSL_TEMPLATE &> /dev/null
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_MAIN_CONF_FILE &> /dev/null
				sed -i '/^[[:space:]]*$/d' $NGINX_MAIN_CONF_FILE &> /dev/null
				
				#check result
				check_exit_and_restore_func
				
				# panel graceful restart
				isp_panel_graceful_restart_func
			else
				printf "\n${LRV}Deletion canceled${NCV}\n"
				exit 0
			fi
	# del was supplied without preset
	elif [[ ! -z "$1"  ]] && [[ -z "$2"  ]]
		then
			printf "\n${LRV}ERROR - Preset not defined.\n\nExample: $BASH_SOURCE del $PROXY_PREFIXwordpress_fpm${NCV}\n"
			exit 1
	
	else	
		printf "\n${LRV}ERROR - Preset $2 not found in panel.\nNothing to delete.${NCV}\n"
		exit 1
	fi
fi

# delete all presets and injects and restore defaults
if [[ $1 = "reset" ]]
then
	echo
	printf "${LRV}"
	read -p "This will delete all presets. Are you sure? [y/N]" -n 1 -r
	echo
	printf "${NCV}"
	if [[ $REPLY =~ ^[Yy]$ ]]
		then
			backup_func
			# removing all presets 
			preset_list=$($MGRCTL preset | awk -F '=' '{print $3}')
			for plist in $preset_list; do $MGRCTL preset.delete elid=$plist elname=$plist; done
			printf "\n${LRV}All ISP panel presets removed${NCV}\n"
			# removing nginx templates
			\rm -f $NGINX_SSL_TEMPLATE &> /dev/null
			\rm -f $NGINX_TEMPLATE &> /dev/null
			printf "\n${LRV}Custom nginx templates removed${NCV}\n"
			# removing injects in $NGINX_MAIN_CONF_FILE
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_MAIN_CONF_FILE &> /dev/null
			sed -i '/^[[:space:]]*$/d' $NGINX_MAIN_CONF_FILE &> /dev/null
			# panel graceful restart
			isp_panel_graceful_restart_func
		else
			printf "\n${LRV}Reset canceled${NCV}\n"
			exit 0
		fi
fi

# set web servers status pages func
set_status_pages() {

#todo
#FPM_POOL=
printf "\n${GCV}This option will try to set up status pages for the web servers:\nnginx - /nginx-status-$RANDOM_N\napache - /apache-status-$RANDOM_N and /apache-info-$RANDOM_N\n${NCV}\n"
#todo
#php-fpm - /fpm-status-$FPM_POOL$RANDOM_N

# nginx
NGX_STATUS_PAGE_FILE="/etc/nginx/vhosts-includes/nginx_status_$RANDOM_N.conf"
APACHE_STATUS_PAGE_FILE="/etc/nginx/vhosts-includes/apache_status_$RANDOM_N.conf"
#todo
#FPM_STATUS_PAGE_FILE="/etc/nginx/vhosts-includes/fpm_status.conf"

if nginx -t &> /dev/null
then
	printf "\n${GCV}Injecting nginx status page at\n$NGX_STATUS_PAGE_FILE\n$APACHE_STATUS_PAGE_FILE\n$FPM_STATUS_PAGE_FILE${NCV}\n"
	if 

	{
	if [[ -z BITRIX_FPM_STATUS_SET ]]
	then
		printf "\nlocation ^~ /nginx-status-$RANDOM_N { stub_status on; allow all; }\n" > "$NGX_STATUS_PAGE_FILE"
		printf "\nlocation ~* /apache-(status|info)-$RANDOM_N { allow all; proxy_pass http://127.0.0.1:8080; }\n" > "$APACHE_STATUS_PAGE_FILE"
		#todo
		#printf "\nlocation ~* /fpm-status-$RANDOM_N { allow all; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; include fastcgi_params; fastcgi_pass unix:/replace_with_fpm_pool_socket_file_path }\n" > "$FPM_STATUS_PAGE_FILE"
	fi
	} &> /dev/null
	
	then
		if nginx -t &> /dev/null
		then
			printf "\n${GCV}OK${NCV}\n"
			nginx -s reload &> /dev/null
			EXIT_STATUS=0
		else
			printf "\n${LRV}FAIL (nginx -t)${NCV}\n"
			\rm -f "$NGX_STATUS_PAGE_FILE"
			exit 1
		fi
	else
		printf " - ${LRV}Cannot write $NGX_STATUS_PAGE_FILE${NCV}\n"
		exit 1
	fi
else
	printf "n${LRV}Nginx configtest failed${NCV}\n"
	exit 1
fi

# apache
APACHE_STATUS_PAGE_INJECT="<Location \"/apache-status-$RANDOM_N\">\nSetHandler server-status\n</Location>\n<Location \"/apache-info-$RANDOM_N\">\nSetHandler server-info\n</Location>\nExtendedStatus On\n"
APACHE_STATUS_PAGE_INJECT_FILE_DEB="/etc/apache2/apache2.conf"
APACHE_STATUS_PAGE_INJECT_FILE_RHEL="/etc/httpd/conf/httpd.conf"

if [[ -f "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" ]] && [[ -f "$APACHE_STATUS_PAGE_INJECT_FILE_RHEL" ]]
then
	printf "\n${LRV}Something strange.\n $APACHE_STATUS_PAGE_INJECT_FILE_DEB and $APACHE_STATUS_PAGE_INJECT_FILE_RHEL co-exist${NCV}\n"
	exit 1
fi

if apachectl configtest  &> /dev/null
then
	if [[ -f "$APACHE_STATUS_PAGE_INJECT_FILE_RHEL" ]]
	then
		printf "\n${GCV}Injecting apache status page at $APACHE_STATUS_PAGE_INJECT_FILE_RHEL${NCV}"
		printf "$APACHE_STATUS_PAGE_INJECT" >> "$APACHE_STATUS_PAGE_INJECT_FILE_RHEL"
		if apachectl configtest &> /dev/null
		then
			printf " - ${GCV}OK${NCV}\n"
			apachectl graceful  &> /dev/null
		else
			printf " - ${LRV}FAIL (apachectl configtest)${NCV}\n"
			sed -i "s|$APACHE_STATUS_PAGE_INJECT||gi" "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" &> /dev/null
			exit 1
		fi
	elif [[ -f "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" ]]
	then
		printf "\n${GCV}Injecting apache status page at $APACHE_STATUS_PAGE_INJECT_FILE_DEB${NCV}"
		printf "$APACHE_STATUS_PAGE_INJECT" >> "$APACHE_STATUS_PAGE_INJECT_FILE_DEB"
		if apachectl configtest &> /dev/null
		then
			printf " - ${GCV}OK${NCV}\n"
			apachectl graceful  &> /dev/null
		else
			printf " - ${LRV}FAIL (apachectl configtest)${NCV}\n"
			sed -i "s|$APACHE_STATUS_PAGE_INJECT||gi" "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" &> /dev/null
			exit 1
		fi
	else
		printf "\n${LRV}Nor $APACHE_STATUS_PAGE_INJECT_FILE_RHEL or $APACHE_STATUS_PAGE_INJECT_FILE_DEB files found${NCV}\n"
		exit 1
	fi
else
	printf "\n${LRV}Apache configtest failed${NCV}\n"
	exit 1
fi

#todo
# fpm
}

# recompile nginx function
recompile_nginx_func() {

# check gits
git_check

# download recompilation script
if printf "GET $GIT_THE_CHOSEN_ONE_REQ_URI/$NGX_RECOMPILE_SCRIPT_NAME HTTP/1.1\nHost:$GIT_THE_CHOSEN_ONE_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_THE_CHOSEN_ONE_DOMAIN_NAME:443 -quiet | sed '1,/^\s$/d' > "/tmp/$NGX_RECOMPILE_SCRIPT_NAME"
then
	# execute recompilation script
	bash "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" 
	\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" &> /dev/null
	exit 0
else
	printf "\n${RLV}Download $GIT_THE_CHOSEN_ONE_DOMAIN_NAME$GIT_THE_CHOSEN_ONE_REQ_URI/$NGX_RECOMPILE_SCRIPT_NAME failed${NCV}\n"
	\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" &> /dev/null
	EXIT_STATUS=1
	exit 1
fi
}

# run set up web servers set status pages function
if [[ $1 = "setstatus" ]]
then
	set_status_pages
	exit 0
fi


# run tweak function
if [[ $1 = "tweak" ]]
then
	ispmanager_tweak_php_and_mysql_settings_func
	exit 0
fi

# run recompile nginx function
if [[ $1 = "recompile" ]]
then
	recompile_nginx_func
	exit 0
fi

main_func() {

# enabling ISP PHP-FPM FastCGI feature
if ! [[ $($MGRCTL feature | grep "name=web" | grep -i fpm) ]]
then
	printf "\n${GCV}Enabling ISP Manager PHP-FPM FastCGI feature${NCV}"
	EXIT_STATUS=0
	$MGRCTL feature.edit elid=web package_php-fpm=on sok=ok &> /dev/null
	check_exit_and_restore_func
	printf " - ${GCV}OK${NCV}\n"
	# feature.edit return OK but actual install continues, so we need to sleep some time
	printf "\n${GCV}Waiting 60 seconds for ISP Panel PHP-FPM FastCGI feature install${NCV}"
	sleep 60
	if ! [[ $($MGRCTL feature | grep "name=web" | grep -i fpm) ]]
	then
		printf "\n${LRV}ISP Manager PHP-FPM FastCGI feature still not exists\nCheck /usr/local/mgr5/var/pkg.log logfile${NCV}"
		exit 1
	fi
fi

# enought arguments check and if nothing in the list of presets show help
if [[ "$#" -lt 1 ]]
then
	# check if any presets exist
	if [[ $($MGRCTL preset) ]]
	then
		printf "\n${GCV}Listing existing templates:${NCV}\n---------------\n"
		$MGRCTL preset | awk -F '=' '{print $3}'
		echo "---------------"
	else
		printf "\n${GCV}There is no existing templates in the ISP panel${NCV}\n"
	fi
	printf "\n${GCV}Example for 1 preset:${NCV} $BASH_SOURCE add wordpress_fpm OR $BASH_SOURCE add 127.0.0.1:8088\n"
	printf "${GCV}Example for 4 presets:${NCV} $BASH_SOURCE add wordpress_fpm 127.0.0.1:8000 1.1.1.1 /path/to/unix/socket\n"
	printf "\n${GCV}Delete all existing %%$PROXY_PREFIX*%% presets and injects:${NCV} $BASH_SOURCE del all $PROXY_PREFIX"
	printf "\n${GCV}Delete one existing preset and inject:${NCV} $BASH_SOURCE del proxy_to_wordpress_fpm OR $BASH_SOURCE del proxy_to_127.0.0.1:8000"
	printf "\n${GCV}Restore default templates and delete all presets:${NCV} $BASH_SOURCE reset\n"
	printf "\n${GCV}Tweak some general PHP and MySQL options:${NCV} $BASH_SOURCE tweak"
	printf "\n${GCV}Recompile nginx (add/remove modules | update/change SSL):${NCV} $BASH_SOURCE recompile\n"
	printf "\n${YCV}Current special templates list:${NCV} wordpress_fpm, bitrix_fpm, opencart_fpm, moodle_fpm, webassyst_fpm, magento2_fpm, cscart_fpm\n"
	printf "\n\n${LRV}ERROR - Not enough arguments, please specify proxy target/targets${NCV}\n"
	exit 1
fi

# check $NGINX_TEMPLATE and $NGINX_SSL_TEMPLATE exists, copy. If not, error on no default template files exist
if [[ ! -f "$NGINX_TEMPLATE" ]]
then
	if [[ ! -f "$NGINX_DEFAULT_TEMPLATE" ]]
	then
		printf "\n${LRV}No NGINX default template exists in $MGR_PATH/etc/templates/default/.\nExiting.${NCV}\n"
		exit 1
	else
		printf "\nNGINX default template exists. Copying it to $NGINX_TEMPLATE\n"
		\cp -p --reflink=auto "$NGINX_DEFAULT_TEMPLATE" "$NGINX_TEMPLATE" &> /dev/null
		# fix importing default ssl template
		sed -i 's@import etc/templates/default/@import etc/templates/@gi' "$NGINX_TEMPLATE" &> /dev/null
	fi
fi

if [[ ! -f "$NGINX_SSL_TEMPLATE" ]]
then
	if [[ ! -f "$NGINX_DEFAULT_SSL_TEMPLATE" ]]
	then
		printf "\n${LRV}No NGINX default ssl template exists in $MGR_PATH/etc/templates/default/. \nExiting.${NCV}\n"
		exit 1
	else
		printf "NGINX default ssl template exists. Copying it to $NGINX_SSL_TEMPLATE\n"
		\cp -p --reflink=auto "$NGINX_DEFAULT_SSL_TEMPLATE" "$NGINX_SSL_TEMPLATE" &> /dev/null
	fi
fi

# check for sockets in target list (for nginx proxy_pass and fastcgi_pass to unix socket)
for proxy_target in "$@"
do
	if [[ "${proxy_target#*'/'}" != "$proxy_target" ]]
	then
		proxy_target="unix:$proxy_target:"
	fi
	proxy_targets="$proxy_targets $proxy_target"
	
done
printf "\n${GCV}Proxy target list: $proxy_targets${NCV}\n"

# creating backup
backup_func

# creating presets if defined
for proxy_target in $proxy_targets
do
	# get date & time
	current_date_time=$(date)
	
	# regular nginx templates injections (using comma sign as separator) variables
	# backward compatibility for panel's variables and #custom template and also it's the hook for replacements
	BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR="\n\\{#\\} apache_backward_compatibility_condition_start_DO_NOT_\(RE\)MOVE\n\{% if \\\$PRESET == #custom %\}\n\t\tproxy_pass \{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %}\ /;\n\{% endif %\}\n\\{#\\} apache_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE\n"
	
	BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_APACHE="s,(\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\tlocation \@fallback \{\n)\t\tinclude \{% \\\$INCLUDE_DYNAMIC_RESOURCE_PATH %\};\n\t\tproxy_pass \{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n,\$1$BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_APACHE="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass http://$proxy_target;\n\t\tproxy_redirect http://$proxy_target /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
	
	BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR="\n\\{#\\} phpfpm_backward_compatibility_condition_start_DO_NOT_\(RE\)MOVE\n\{% if \\\$PRESET == #custom %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\{% endif %\}\n\\{#\\} phpfpm_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE\n"
	
	BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_PHPFPM="s,(\{% if \\\$REDIRECT_TO_PHPFPM == on %\}\n\tlocation \@php \{\n\t\tinclude \{% \\\$INCLUDE_DYNAMIC_RESOURCE_PATH %\};\n\t\tfastcgi_index index.php;\n\t\tfastcgi_param PHP_ADMIN_VALUE \"sendmail_path = /usr/sbin/sendmail -t -i -f \{% \\\$EMAIL %\}\";\n)\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n,\$1$BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_PHPFPM="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass $proxy_target;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
	
	BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_BEGIN="s,(\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n)(\tlocation / \{\n\{% if \\\$PHP == on %}\n),\$1\n\\{#\\} php_off_backward_compatibility_condition_start_DO_NOT_(RE)MOVE\n{% if \\\$PRESET == #custom %}\n\$2,gi"
	
	BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_END="s,(\t\t\ttry_files /does_not_exists \@fallback;\n\t\t}\n\{% endif %\}\n\t\}\n\{% endif %\}\n)(\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\tlocation \@fallback \{),\$1\n\{% endif %\}\n\\{#\\} php_off_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE\n\n\$2,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF="s,(\{#\\} php_off_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE),\$1\n\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_IF_PHPOFF_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\tlocation / \{\n\{% if \\\$PHP == off %\}\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@backend;\n\{% endif %\}\n\\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$  \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\\{% endif %\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\t\tindex index.html;\n\t\t\tlocation ~ \[^/\].ph\(p\\\d*|tml\)\\\$ \{\n\t\t\t\ttry_files \\\$uri \\\$uri/ \@backend;\n\t\t\t\}\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$PHP == off %\}\n\tlocation \@backend \{\n\t\tproxy_pass http://$proxy_target;\n\t\tproxy_redirect http://$proxy_target /;\n\t\tproxy_set_header Host \\\$host;\n\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\tproxy_set_header X-Forwarded-Proto \\\$scheme;\n\t\tproxy_set_header X-Forwarded-Port \\\$server_port;\n\t}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_IF_PHPOFF_STOP_DO_NOT_REMOVE\n,gi"

	SPECIAL_INJECTIONS_VAR="\{% if THIS_BLOCK_FOR_REMOVE_EXPIRES %\}\n\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n"
	
	# creating user defined ISP manager presets
	printf "\n\n>>>>> ${GCV}$PROXY_PREFIX$proxy_target${NCV}\nCreating ISP panel preset"
	
	# $limit_dirindex_var
	if [[ $proxy_target = "opencart_fpm" ]] || [[ $proxy_target = "wordpress_fpm" ]] || [[ $proxy_target = "bitrix_fpm" ]] || [[ $proxy_target = "moodle_fpm" ]] || [[ $proxy_target = "webassyst_fpm" ]] || [[ $proxy_target = "magento2_fpm" ]] || [[ $proxy_target = "cscart_fpm" ]]

	then
		limit_dirindex_var=index.php
	fi
	# check for error / success
	if $MGRCTL preset.edit backup=on limit_php_mode=php_mode_fcgi_nginxfpm limit_php_fpm_version=native limit_php_mode_fcgi_nginxfpm=on limit_cgi=on limit_php_cgi_enable=on limit_php_mode_cgi=on limit_php_mode_mod=on limit_shell=on limit_ssl=on name=$PROXY_PREFIX$proxy_target limit_dirindex=$limit_dirindex_var sok=ok &> /dev/null
	then
		printf " - ${GCV}OK${NCV}\n"
		preset_raise_error="0"
			#if wordpress_fpm in preset name create special template
			if [[ $proxy_target = "wordpress_fpm" ]]
			then
				# WORDPRESS_FPM nginx templates injections variables
				WORDPRESS_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$args;\n\{% endif %\}\n\t\tlocation ~ \[^/\]\\\\.ph(p\d*|tml)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER != "" %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\\.ph\(p\\\d*|tml\)\\\$ {\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
				WORDPRESS_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$WORDPRESS_FPM_NGINX_PERL_INJECTION_LOCATIONS"
				
				WORDPRESS_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass \\{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
				
				WORDPRESS_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
				
				# create & check comaptibility
				backward_copmat_func
				
				# wordpress_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				
				# wordpress_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$WORDPRESS_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func
				
				continue
				
			elif [[ $proxy_target = "opencart_fpm" ]]
			then
				# OPENCART_FPM nginx templates injections variables
				OPENCART_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\tif \(!-e \\\$request_filename\) \{\n\t\t\trewrite ^/\(.+\)\\\$ /index.php?_route_=\\\$1 last;\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\tlog_not_found off;\n\t\tadd_header Pragma public;\n\t\tadd_header Cache-Control \"public\, must-revalidate\, proxy-revalidate\";\n\t\ttry_files \\\$uri \\\$uri/ \@static;\n\t\}\n\tlocation ~* \\\.\(eot|otf|ttf|woff\)\\\$ \{\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\}\n\n\tlocation ~* \(\\\.\(tpl|ini\)\)\\\$ \{\n\t\tdeny all; \n\t\}\n\n\tlocation ~* \\\.\(engine|inc|info|ini|install|log|make|module|profile|test|po|sh|.*sql|theme|tpl\(\\\.php\)?|xtmpl\)\\\$|^\(\\\..*|Entries.*|Repository|Root|Tag|Template\)\\\$|\\\.php_ \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~ /\\\. \{\n\t\taccess_log off;\n\t\tlog_not_found off;\n\t\tdeny all;\n\t\}\n\n\tlocation ~ ~\\\$ \{\n\t\taccess_log off;\n\t\tlog_not_found off;\n\t\tdeny all;\n\t\}\n\n\tlocation ~* /\(?:cache|logs|image|download\)/.*\\\.php\\\$ \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~ /\\\.ht \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~* \(\\\.\(svn|hg|git\)\)\\\$ \{\n\t\tdeny all; \n\t\}\n\n\tlocation ~ /\\\.tpl/ \{\n\t\tdeny all;\n\t\}\n\n\tlocation \@static \{\n\t\terror_log /dev/null crit;\n\t\taccess_log off ;\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
				OPENCART_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$OPENCART_FPM_NGINX_PERL_INJECTION_LOCATIONS"
				
				OPENCART_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass \\{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
				
				OPENCART_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_connect_timeout 60;\n\t\tfastcgi_send_timeout 180;\n\t\tfastcgi_read_timeout 180;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
	
				# create & check comaptibility
				backward_copmat_func
				
				# opencart_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$OPENCART_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$OPENCART_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$OPENCART_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				
				# opencart_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$OPENCART_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$OPENCART_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$OPENCART_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func
				
				continue

			elif [[ $proxy_target = "cscart_fpm" ]]
			then
				# CSCART_FPM nginx templates injections variables
				CSCART_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t#\n\t# https://www.cs-cart.ru/docs/4.14.x/install/nginx.html \n\t#\n\tclient_max_body_size 100m;\n\tclient_body_buffer_size 128k;\n\tclient_header_timeout 3m;\n\tclient_body_timeout 3m;\n\tsend_timeout 3m;\n\tclient_header_buffer_size 1k;\n\tlarge_client_header_buffers 4 16k;\n\t#\n\terror_page 598 = \@backend;\n\t#\n\tlocation \@backend \{\n\t\ttry_files \\\$uri \\\$uri/ /\\\$2\\\$3 /\\\$3 /index.php  =404;\n\t\t#\tPHP-FPM\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\t#\n\t\tfastcgi_index index.php;\n\t\tfastcgi_read_timeout 360;\n\t\tfastcgi_send_timeout 360;\n\t\t#\tfastcgi_params\\\.conf\n\t\t################################################################################\n\t\t\tfastcgi_param PHP_ADMIN_VALUE \"sendmail_path = /usr/sbin/sendmail -t -i -f \{% \\\$EMAIL %\}\";\n\t\tfastcgi_param QUERY_STRING \\\$query_string;\n\t\tfastcgi_param REQUEST_METHOD \\\$request_method;\n\t\tfastcgi_param CONTENT_TYPE \\\$content_type;\n\t\tfastcgi_param CONTENT_LENGTH \\\$content_length;\n\t\tfastcgi_param SCRIPT_NAME \\\$fastcgi_script_name;\n\t\tfastcgi_param REQUEST_URI \\\$request_uri;\n\t\tfastcgi_param DOCUMENT_URI \\\$document_uri;\n\t\tfastcgi_param DOCUMENT_ROOT \\\$document_root;\n\t\tfastcgi_param SERVER_PROTOCOL \\\$server_protocol;\n\t\tfastcgi_param HTTPS \\\$https if_not_empty;\n\t\tfastcgi_param GATEWAY_INTERFACE CGI/1\\\.1;\n\t\tfastcgi_param SERVER_SOFTWARE nginx/\\\$nginx_version;\n\t\tfastcgi_param REMOTE_ADDR \\\$remote_addr;\n\t\tfastcgi_param REMOTE_PORT \\\$remote_port;\n\t\tfastcgi_param SERVER_ADDR \\\$server_addr;\n\t\tfastcgi_param SERVER_PORT \\\$server_port;\n\t\tfastcgi_param SERVER_NAME \\\$server_name;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_param REDIRECT_STATUS 200;\n\t\t################################################################################\n\t\}\t\n\{% endif %\}\n\tlocation / \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\tindex  index.php index.html index.htm;\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$args;\n\{% endif %\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\treturn 598;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\treturn 598;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\tlog_not_found off;\n\t\tadd_header Pragma public;\n\t\tadd_header Cache-Control \"public\, must-revalidate\, proxy-revalidate\";\n\t\ttry_files \\\$uri \\\$uri/ /\\\$2\\\$3 /\\\$3 /index.php?\\\$args;\n\t\}\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?api/ \{\n\t\trewrite ^/\(\\\\w+/\)?\(\\\\w+/\)?api/\(.*\)\\\$ /api.php?_d=\\\$3&ajax_custom=1&\\\$args last;\n\t\trewrite_log off;\n\t\}\n\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?var/database/ \{\n\t\treturn 404;\n\t\}\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?var/backups/ \{\n\t\treturn 404;\n\t\}\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?var/restore/ \{\n\t\treturn 404;\n\t\}\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?var/themes_repository/ \{\n\t\tallow all;\n\t\tlocation ~* \\\\.\(tpl|php.?\)\\\$ \{\n\t\t\treturn 404;\n\t\t\}\n\t\}\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?var/ \{\n\t\treturn 404;\n\t\tlocation ~* /\(\\\\w+/\)?\(\\\\w+/\)?\(.+\\\\.\(js|css|png|jpe?g|gz|yml|xml|svg\)\)\\\$ \{\n\t\t\ttry_files \\\$uri \\\$uri/ /\\\$2\\\$3 /\\\$3 /index.php?\\\$args;\n\t\t\tallow all;\n\t\t\taccess_log off;\n\t\t\texpires 1M;\n\t\t\tadd_header Cache-Control public;\n\t\t\tadd_header Access-Control-Allow-Origin *;\n\t\t\}\n\t\}\n\t\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?app/payments/ \{\n\t\treturn 404;\n\t\tlocation ~ \\\\.php\\\$ \{\n\t\t\treturn 598;\n\t\t\}\n\t\}\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?app/addons/rus_exim_1c/ \{\n\t\treturn 404;\n\t\tlocation ~ \\\\.php\\\$ \{\n\t\t\treturn 598;\n\t\t\}\n\t\}\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?app/ \{\n\t\treturn 404;\n\t\}\n\n\t############################################################################\n\n\tlocation ~ ^/\(favicon|apple-touch-icon|homescreen-|firefox-icon-|coast-icon-|mstile-\).*\\\\.\(png|ico\)\\\$  \{\n\t\taccess_log off;\n\t\ttry_files \\\$uri =404;\n\t\texpires max;\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\tadd_header Cache-Control public;\n\t\}\n\n\tlocation ~* /\(\\\\w+/\)?\(\\\\w+/\)?\(.+\\\\.\(jpe?g|jpg|webp|ico|gif|png|css|js|pdf|txt|tar|woff|woff2|svg|ttf|eot|csv|zip|xml|yml\)\)\\\$ \{\n\t\taccess_log off;\n\t\ttry_files \\\$uri \\\$uri/ /\\\$2\\\$3 /\\\$3 /index.php?\\\$args;\n\t\texpires max;\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\tadd_header Cache-Control public;\n\t\}\n\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?design/ \{\n\t\tallow all;\n\t\tlocation ~* \\\\.\(tpl|php.?\)\\\$ \{\n\t\t\treturn 404;\n\t\t\}\n\t\}\n\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?images/ \{\n\t\tallow all;\n\t\tlocation ~* \\\\.\(php.?\)\\\$ \{\n\t\t\treturn 404;\n\t\t\}\n\t\}\n\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?js/ \{\n\t\tallow all;\n\t\tlocation ~* \\\\.\(php.?\)\\\$ \{\n\t\t\treturn 404;\n\t\t\}\n\t\}\n\n\t############################################################################\n\n\tlocation ~ ^/\(\\\\w+/\)?\(\\\\w+/\)?init.php \{\n\t\treturn 404;\n\t\}\n\n\tlocation ~* \\\\.\(tpl.?\)\\\$ \{\n\t\treturn 404;\n\t\}\n\n\tlocation ~ /\\\\.\(ht|git\) \{\n\t\treturn 404;\n\t\}\n\n\tlocation ~* \\\\.php\\\$ \{\n\t\treturn 598 ;\n\t\}\n\n\t################################################################################\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
				CSCART_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$CSCART_FPM_NGINX_PERL_INJECTION_LOCATIONS"
				
				CSCART_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass \\{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
				
				CSCART_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_connect_timeout 60;\n\t\tfastcgi_send_timeout 180;\n\t\tfastcgi_read_timeout 180;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
	
				# create & check comaptibility
				backward_copmat_func
				
				# cscart_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$CSCART_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$CSCART_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$CSCART_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				
				# cscart_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$CSCART_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$CSCART_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$CSCART_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func
				
				continue
			
			elif [[ $proxy_target = "moodle_fpm" ]]
			then
				# MOODLE_FPM nginx templates injections variables
				MOODLE_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www\\\.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^\\\.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index\\\.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tlocation ~* \(/lib/classes/|/doesnotexist|/vendor/|/node_modules/|composer\\\\.json|/readme|/README|readme\\\\.txt|/upgrade\\\\.txt|db/install\\\\.xml|\/fixtures\/|/behat/|phpunit\\\\.xml|\\\\.lock|environment\\\\.xml\) \{\n\t\tdeny all;\n\t\treturn 404;\n\t\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\tlocation ~* /\\\\.\(?!well-known\).* \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\tlocation ~* \\\\.\(eot|otf|ttf|woff\)\\\$ \{\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\}\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index\\\.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\tlog_not_found off;\n\t\tadd_header Pragma public;\n\t\tadd_header Cache-Control \"public\, must-revalidate\, proxy-revalidate\";\n\t\ttry_files \\\$uri \\\$uri/ \@static;\n\t\}\n\tlocation ~* \\\.\(eot|otf|ttf|woff\)\\\$ \{\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\}\n\tlocation ~ \[^/\]\\\\.php\(/|\\\$\) \{\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(/.+\)\\\$;\n\t\tfastcgi_index index.php;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tinclude fastcgi_params;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\}\n\tlocation ~ ^\(.+\\\\.php\)\(.*\)\\\$ \{\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(.*\)\\\$;\n\t\tfastcgi_index index.php;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tinclude /etc/nginx/mime.types;\n\t\tinclude fastcgi_params;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\}\n\tlocation \@static \{\n\t\terror_log /dev/null crit;\n\t\taccess_log off ;\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} \\\$PROXY_PREFIX\\\$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
				MOODLE_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$MOODLE_FPM_NGINX_PERL_INJECTION_LOCATIONS"
				
				MOODLE_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass \\{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
				
				MOODLE_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\ttry_files \\\$uri =404;\n\t\tinclude fastcgi_params;\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(/.+\)\\\$;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
				
				MOODLE_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2="s,(\t\tfastcgi_split_path_info \^\(\(\?U\).+\.ph\(\?:p\\\d\*\|tml\)\)\(\/\?\.\+\)\\$\;),\{% if \\\$PRESET != $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\$1\n\{% endif %\},gi"
	
				# create & check comaptibility
				backward_copmat_func
				
				# moodle_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_TEMPLATE"
				
				# moodle_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$MOODLE_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$MOODLE_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func
				
				continue

			elif [[ $proxy_target = "webassyst_fpm" ]]
			then
				# WEBASSYST_FPM nginx templates injections variables
				WEBASSYST_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www\\\.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^\\\.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index\\\.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t#\n\ttry_files \\\$uri \\\$uri/ /index.php?\\\$query_string;\n\t#\n\tlocation /index.php \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\n\t\n\t# for install only\n\tlocation /install.php \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\t\n\t\n\tlocation /api.php \{\n\t\tfastcgi_split_path_info  ^\(.+\.php\)\(.*\)\\\$;\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\n\t\n\tlocation ~ /\(oauth.php|link.php|payments.php\) \{\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$query_string;\n\t\}\t\n\n\tlocation ^~ /wa-data/protected/ \{\n\t\tinternal;\n\t\}\n\t\n\tlocation ~ /wa-content \{\n\t\tallow all;\n\t\}\n\n\tlocation ^~ /\(wa-apps|wa-plugins|wa-system|wa-widgets\)/.*/\(lib|locale|templates\)/ \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~* ^/wa-\(cache|config|installer|log|system\)/ \{\n\t\treturn 403;\n\t\}\n\n\tlocation ~* ^/wa-data/public/contacts/photos/\[0-9\]+/ \{\n\t\t root\t\t\\\$root_path;\n\t\t access_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t error_page\t404 = \@contacts_thumb;\n\t\}\n\n\tlocation \@contacts_thumb \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/contacts/photos/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/contacts/photos/thumb.php;\n\t\}\n\t\n\t# photos app\n\tlocation ~* ^/wa-data/public/photos/\[0-9\]+/ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page\t404 = \@photos_thumb;\n\t\}\n\n\tlocation \@photos_thumb \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/photos/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/photos/thumb.php;\n\t\}\n\t# end photos app\n\t\n\t# shop app\n\tlocation ~* ^/wa-data/public/shop/products/\[0-9\]+/ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page\t404 = \@shop_thumb;\n\t\}\n\tlocation \@shop_thumb \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/shop/products/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/shop/products/thumb.php;\n\t\}\n\t\n\tlocation ~* ^/wa-data/public/shop/promos/\[0-9\]+ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page\t404 = \@shop_promo;\n\t\}\n\tlocation \@shop_promo \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/shop/promos/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/shop/promos/thumb.php;\n\t\}\n\t# end shop app\n\t\n\t# mailer app\n\tlocation ~* ^/wa-data/public/mailer/files/\[0-9\]+/ \{\n\t\taccess_log\toff;\n\t\terror_page\t404 = \@mailer_file;\n\t\}\n\tlocation \@mailer_file \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/mailer/files/file.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/mailer/files/file.php;\n\t\}\n\t# end mailer app\n\n\tlocation ~* ^.+\\\\.\(jpg|jpeg|gif|png|webp|js|css\)\\\$ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} \\\$PROXY_PREFIX\\\$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
				WEBASSYST_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$WEBASSYST_FPM_NGINX_PERL_INJECTION_LOCATIONS"
				
				WEBASSYST_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass \\{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
				
				WEBASSYST_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\ttry_files \\\$uri =404;\n\t\tinclude fastcgi_params;\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(/.+\)\\\$;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
	
				# create & check comaptibility
				backward_copmat_func
				
				# webassyst_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_TEMPLATE"
				
				# webassyst_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$WEBASSYST_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$WEBASSYST_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func
				
				continue

			elif [[ $proxy_target = "magento2_fpm" ]]
			then
				# MAGENTO2_FPM nginx templates injections variables
				MAGENTO2_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# wwww prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www\\\.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index\\\.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation / \{\n\{% if \\\$PHP == on %\}\n\t\t\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\t\t\}\n\{% endif %\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\t\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\t\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\t\tlocation / \{\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\t\t\}\n\{% endif %\}\n\t\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\t\t\tindex index\\\.html;\n\{% if \\\$PHP == on %\}\n\t\t\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\t\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\t\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\t\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\t\t\}\n\t\t\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\t\t\}\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tset \\\$root_root \\\$root_path;\n\tset \\\$root_path \\\$root_path/pub;\n\t#\n\tlocation /.user.ini \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation ~* ^/admin_.+\(\\\$|/\) \{\n\t\ttry_files \\\$uri \\\$uri/ /index.php\\\$is_args\\\$args;\n\t\}\n\t#\n\tlocation ~* ^/setup\(\\\$|/\) \{\n\t\troot \\\$root_root;\n\t\tlocation ~ ^/setup/index.php \{\n\t\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\t\tfastcgi_param  PHP_FLAG  \"session.auto_start=off \\\n suhosin.session.cryptua=off\";\n\t\t\tfastcgi_param  PHP_VALUE \"memory_limit=756M \\\n max_execution_time=600\";\n\t\t\tfastcgi_read_timeout 600s;\n\t\t\tfastcgi_connect_timeout 600s;\n\t\t\tfastcgi_index  index.php;\n\t\t\tfastcgi_param  SCRIPT_FILENAME  \\\$document_root\\\$fastcgi_script_name;\n\t\t\tinclude\t\tfastcgi_params;\n\t\t\}\n\t\tlocation ~ ^/setup/\(?!pub/\). \{\n\t\t\tdeny all;\n\t\t\}\n\t\tlocation ~ ^/setup/pub/ \{\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\}\n\t\}\n\t#\n\tlocation ~* ^/update\(\\\$|/\) \{\n\t\troot \\\$root_root;\n\t\tlocation ~ ^/update/index.php \{\n\t\t\tfastcgi_split_path_info ^\(/update/index.php\)\(/.+\)\\\$;\n\t\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\t\tfastcgi_index  index.php;\n\t\t\tfastcgi_param  SCRIPT_FILENAME  \\\$document_root\\\$fastcgi_script_name;\n\t\t\tfastcgi_param  PATH_INFO\t\t\\\$fastcgi_path_info;\n\t\t\tinclude\t\tfastcgi_params;\n\t\t\}\n\t\t# Deny everything but index.php\n\t\tlocation ~ ^/update/\(?!pub/\). \{\n\t\t\tdeny all;\n\t\t\}\n\t\tlocation ~ ^/update/pub/ \{\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\}\n\t\}\n\t#\n\tlocation /pub/ \{\n\t\tlocation ~ ^/pub/media/\(downloadable|customer|import|custom_options|theme_customization/.*\\\\.xml\) \{\n\t\t\tdeny all;\n\t\t\}\n\t\talias \\\$root_root/pub/;\n\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\}\n\t#\n\tlocation /static/ \{\n\t\t# Uncomment the following line in production mode\n\t\t# expires max;\n\n\t\t# Remove signature of the static files that is used to overcome the browser cache\n\t\tlocation ~ ^/static/version\\\\d*/ \{\n\t\t\trewrite ^/static/version\\\\d*/\(.*\)\\\$ /static/\\\$1 last;\n\t\t\}\n\n\t\tlocation ~* \\\\.\(ico|jpg|jpeg|png|gif|svg|svgz|webp|avif|avifs|js|css|eot|ttf|otf|woff|woff2|html|json|webmanifest\)\\\$ \{\n\t\t\tadd_header Cache-Control \"public\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\n\t\t\tif \(!-f \\\$request_filename\) \{\n\t\t\t\trewrite ^/static/\(version\\\\d*/\)?\(.*\)\\\$ /static.php?resource=\\\$2 last;\n\t\t\t\}\n\t\t\}\n\t\tlocation ~* \\\\.\(zip|gz|gzip|bz2|csv|xml\)\\\$ \{\n\t\t\tadd_header Cache-Control \"no-store\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\texpires\toff;\n\n\t\t\tif \(!-f \\\$request_filename\) \{\n\t\t\t\trewrite ^/static/\(version\\\\d*/\)?\(.*\)\\\$ /static.php?resource=\\\$2 last;\n\t\t\t\}\n\t\t\}\n\t\tif \(!-f \\\$request_filename\) \{\n\t\t\trewrite ^/static/\(version\\\\d*/\)?\(.*\)\\\$ /static.php?resource=\\\$2 last;\n\t\t\}\n\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\}\n\t#\n\tlocation /media/ \{\n\t\n\t## The following section allows to offload image resizing from Magento instance to the Nginx.\n\t## Catalog image URL format should be set accordingly.\n\t## See https://docs\\\.magento\\\.com/user-guide/configuration/general/web\\\.html#url-options\n\t#\tlocation ~* ^/media/catalog/.* \{\n\t#\n\t#\t\t# Replace placeholders and uncomment the line below to serve product images from public S3\n\t#\t\t# See examples of S3 authentication at https://github\\\.com/anomalizer/ngx_aws_auth\n\t#\t\t# resolver 8\\\.8\\\.8\\\.8;\n\t#\t\t# proxy_pass https://<bucket-name>\\\.<region-name>\\\.amazonaws\\\.com;\n\t#\n\t#\t\tset \\\$width \"-\";\n\t#\t\tset \\\$height \"-\";\n\t#\t\tif \(\\\$arg_width != ''\) \{\n\t#\t\t\tset \\\$width \\\$arg_width;\n\t#\t\t\}\n\t#\t\tif \(\\\$arg_height != ''\) \{\n\t#\t\t\tset \\\$height \\\$arg_height;\n\t#\t\t\}\n\t#\t\timage_filter resize \\\$width \\\$height;\n\t#\t\timage_filter_jpeg_quality 90;\n\t#\t\}\n\n\t\ttry_files \\\$uri \\\$uri/ /get.php\\\$is_args\\\$args;\n\n\t\tlocation ~ ^/media/theme_customization/.*\\\\.xml \{\n\t\t\tdeny all;\n\t\t\}\n\n\t\tlocation ~* \\\\.\(ico|jpg|jpeg|png|gif|svg|svgz|webp|avif|avifs|js|css|eot|ttf|otf|woff|woff2\)\\\$ \{\n\t\t\tadd_header Cache-Control \"public\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ /get.php\\\$is_args\\\$args;\n\t\t\}\n\n\t\tlocation ~* \\\\.\(zip|gz|gzip|bz2|csv|xml\)\\\$ \{\n\t\t\tadd_header Cache-Control \"no-store\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\texpires\toff;\n\t\t\ttry_files \\\$uri \\\$uri/ /get.php\\\$is_args\\\$args;\n\t\t\}\n\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\}\n\t#\n\tlocation /media/customer/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /media/downloadable/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /media/import/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /media/custom_options/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /errors/ \{\n\t\tlocation ~* \\\\.xml\\\$ \{\n\t\t\tdeny all;\n\t\t\}\n\t\}\n\t# PHP entry point for main application\n\tlocation ~ ^/\(index|get|static|errors/report|errors/404|errors/503|health_check\)\\\\.php\\\$ \{\n\t\ttry_files \\\$uri =404;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_buffers 16 16k;\n\t\tfastcgi_buffer_size 32k;\n\n\t\tfastcgi_param  PHP_FLAG  \"session.auto_start=off \\\n suhosin.session.cryptua=off\";\n\t\tfastcgi_param  PHP_VALUE \"memory_limit=756M \\\n max_execution_time=18000\";\n\t\tfastcgi_read_timeout 600s;\n\t\tfastcgi_connect_timeout 600s;\n\n\t\tfastcgi_index  index.php;\n\t\tfastcgi_param  SCRIPT_FILENAME  \\\$document_root\\\$fastcgi_script_name;\n\t\tinclude\t\tfastcgi_params;\n\t\}\n\t#\n\{% endif %\}\n\{% endif %\} \n\\{#\\} \\\$PROXY_PREFIX\\\$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
				MAGENTO2_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$MAGENTO2_FPM_NGINX_PERL_INJECTION_LOCATIONS"
				
				MAGENTO2_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass \\{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
				
				MAGENTO2_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\ttry_files \\\$uri =404;\n\t\tinclude fastcgi_params;\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(/.+\)\\\$;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
	
				# create & check comaptibility
				backward_copmat_func
				
				# magento2_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_TEMPLATE"
				
				# magento2_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$MAGENTO2_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_APACHE_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$MAGENTO2_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func
				
				continue
				
			#if bitrix_fpm in preset name create special template
			elif [[ $proxy_target = "bitrix_fpm" ]]
			then
			# set bitrix_fpm local vars
			BITRIX_REQ_NGINX_FOLDER_URL="isp_templates/bitrix/nginx/"
			BITRIX_REQ_ERROR_PAGES_URL="bitrix_error_pages/"
			BITRIX_REQ_ERROR_PAGES_FILES=('403.html' '404.html' '500.html' '502.html' '503.html' '504.html')
			BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR="/etc/nginx/conf.d"
			BITRIX_FPM_LOCAL_INCLUDE_SERVER_DIR="/etc/nginx/vhosts-includes"
			BITRIX_FPM_LOCAL_ERRORS_DIR="/etc/nginx/vhosts-includes/bitrix_fpm/errors"
				
			# BITRIX_FPM nginx templates injections variables
			BITRIX_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\n\{#\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\{#\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\{% if \\\$PHP == on %\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\tdeny all; \n\t\}\n\{#\}\n\{#\} CGI_APACHE_MODULE_config_start\n\{#\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t# errors handlers\n\terror_page 403 /403.html;\n\t#error_page 404 /404.php;\n\terror_page 404 = \@fallback;\n\terror_page 412 = \@fallback;\n\terror_page 497 https://\\\$host\\\$request_uri;\n\terror_page 500 /500.html;\n\terror_page 502 /502.html;\n\terror_page 503 /503.html;\n\terror_page 504 /504.html;\n\t#\n\t# errors custom pages\n\tlocation ^~ /500.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /502.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /503.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /504.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /403.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /404.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\t#ssi_last_modified on;\n\t# memcached options\n\tmemcached_connect_timeout 1s;\n\tmemcached_read_timeout 1s;\n\tmemcached_send_timeout 1s;\n\tmemcached_gzip_flag 65536;\n\t#\n\t# variables\n\tset \\\$proxyserver \"\{% \\\$BACKEND_BIND_URI %\}\";\n\tset \\\$memcached_key \"/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_cache \"bitrix/html_pages/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_file \"\\\$root_path/\\\$\{composite_cache\}\";\n\tset \\\$use_composite_cache \"\";\n\t#\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\t# aspro max sitemap\n\t# location ~ ^/sitemap.*\\\.xml\\\$ \{ rewrite \"/\(sitemap.*\)\\\.xml\" /aspro_regions/sitemap/\\\$1_\\\$host.xml break; \}\n\t#\n\t# composite cache\n\t# if no composite checks file exist then NULL-ing variables\n\tif \(!-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$composite_key \"\"; set \\\$is_global_composite \"\"; \}\n\t# if bitrix html cache .enabled file exist then set A\n\tset \\\$composite_enabled  \"\\\$root_path/bitrix/html_pages/.enabled\";\n\tif \(-f \\\$composite_enabled\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}A\"; \}\n\t#\n\t# if bitrix html cache mappings file exist then set B\n\tif \(-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}B\"; \}\n\t#\n\t# if global check success then set C\n\tif \(\\\$is_global_composite = 1\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}C\"; \}\n\t#\n\t# if composite cache file exist then set D\n\tif \(-f \\\$composite_file\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}D\"; \}\n\t#\n\tclient_max_body_size 1024m;\n\tclient_body_buffer_size 4m;\n\t#\n\tkeepalive_timeout 70;\n\tkeepalive_requests 150;\n\t#\n\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\tproxy_set_header X-Real-IP \\\$remote_addr;\n\tproxy_set_header Host \\\$host;\n\tproxy_set_header X-Forwarded-Host \\\$host;\n\tproxy_set_header X-Forwarded-Scheme \\\$scheme;\n\n\t#### bx/conf/general-add_header.conf\n\tadd_header \"X-Content-Type-Options\" \"nosniff\";\n\tset \\\$frame_options \"\";\n\tif \(\\\$http_referer !~ '^https?:\/\/\(\[^\/\]+\\\.\)?\(webvisor\\\.com\)\/'\) \{ set \\\$frame_options \"SAMEORIGIN\"; \}\n\tadd_header \"X-Frame-Options\" \"\\\$frame_options\";\n\t#\n\t# Nginx server status page\n\tlocation ^~ /nginx-status-$RANDOM_N \{\n\t\tstub_status on;\n\t\tallow all;\n\t\}\n\t# Apache server status page\n\tlocation ~* /apache-\(status|info\)-$RANDOM_N \{\n\t\tallow all;\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\t#### bx/site_settings/default/bx_temp.conf\n\tlocation ~* ^/bx_tmp_download/ \{\n\t\tinternal;\n\t\trewrite /bx_tmp_download/\(.+\) /.bx_temp/sitemanager/\\\$1 last;\n\t\}\n\tlocation ~* ^/.bx_temp/sitemanager/ \{\n\t\tinternal;\n\t\troot \\\$root_path;\n\t\}\n\n\t#### bx/conf/bitrix_block.conf\n\t# ht\(passwd|access\)\n\tlocation ~* /\\\.ht \{ deny all; \}\n\n\t# repositories\n\tlocation ~* /\\\.\(svn|hg|git\) \{ deny all; \}\n\n\t# bitrix internal locations\n\tlocation ~* ^/bitrix/\(modules|local_cache|stack_cache|managed_cache|php_interface\) \{ deny all; \}\n\tlocation = /bitrix/.settings.php \{ deny all; \}\n\n\t# 1C upload files\n\tlocation ~* ^/upload/1c_\[^/\]+/ \{ deny all; \}\n\n\t# use the file system to access files outside the site \(cache\)\n\tlocation ~* /\\\.\\\./ \{ deny all; \}\n\tlocation = /bitrix/html_pages/.config.php \{ deny all; \}\n\tlocation = /bitrix/html_pages/.enabled \{ deny all; \}\n\n\t#### bx/conf/bitrix_general.conf\n\t# Intenal locations\n\tlocation ^~ /upload/support/not_image \{ internal; \}\n\t\t\n\n\t# Player options\ disable no-sniff\n\tlocation ~* ^/bitrix/components/bitrix/player/mediaplayer/player\\\$ \{ add_header Access-Control-Allow-Origin *; \}\n\n\t# Process dav request on\n\t# main company\n\t# extranet\n\t# additional departments\n\t# locations that ends with / => directly to apache \n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\).*/\\\$ \{ proxy_pass \\\$proxyserver; \}\n\n\t# Add / to request\n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\) \{\n\t\tset \\\$addslash \"\";\n\t\tif \(-d \\\$request_filename\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$is_args != '?'\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$addslash = \"YY\" \) \{ proxy_pass \\\$proxyserver\\\$request_uri/; \}\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\n\t# Accept access for merged css and js\n\tlocation ~* ^/bitrix/cache/\(css/.+\\\.css|js/.+\\\.js\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page 404 /404.html;\n\t\}\n\n\t# Disable access for other assets in cache location\n\tlocation ~* ^/bitrix/cache \{ deny all; \}\n\n\t# Excange and Outlook\n\tlocation ~ ^/bitrix/tools/ws_.*/_vti_bin/.*\\\.asmx\\\$ \{ proxy_pass \\\$proxyserver; \}\n\n\t# Groupdav\n\tlocation ^~ /bitrix/groupdav.php \{ proxy_pass \\\$proxyserver; \}\n\n\t# Use nginx to return static content from s3 cloud storage\n\t# /upload/bx_cloud_upload/<schema>.<backet_name>.<s3_point>.amazonaws.com/<path/to/file>\n\tlocation ^~ /upload/bx_cloud_upload/ \{\n\t\t# Amazon\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(s3|us-east-2|us-east-1|us-west-1|us-west-2|af-south-1|ap-east-1|ap-south-1|ap-northeast-3|ap-northeast-2|ap-southeast-1|ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|eu-south-1|eu-west-3|eu-north-1|me-south-1|sa-east-1\)\\\.amazonaws\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.amazonaws.com/\\\$4;\n\t\t\}\n\n\t\t# Rackspace\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.rackcdn\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.\\\$4.rackcdn.com/\\\$5;\n\t\t\}\n\n\t\t# Clodo\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.clodo\\\.ru:\(80|443\)/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.clodo.ru:\\\$3/\\\$4;\n\t\t\}\n\n\t\t# Google\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.commondatastorage\\\.googleapis\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.commondatastorage.googleapis.com/\\\$3;\n\t\t\}\n\n\t\t# Selectel\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.selcdn\\\.ru/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.selcdn.ru/\\\$3;\n\t\t\}\n\n\t\t# Yandex\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.storage\\\.yandexcloud\\\.net/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.storage.yandexcloud.net/\\\$3;\n\t\t\}\n\n\t\tlocation ~* .*\\\$ \{ deny all; \}\n\t\}\n\n\t# Static content\n\tlocation ~* ^/\(upload|bitrix/images|bitrix/tmp\) \{\n\t\tif \( \\\$upstream_http_x_accel_redirect = \"\"  \) \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\}\n\t\}\n\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\t\tadd_header Cache-Control \"public\";\n\t\terror_page 404 /404.html;\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\}\n\n\t# pub & online\n\t# telephony and voximplant\n\tlocation ~* ^/\(pub/|online/|services/telephony/info_receiver\\\.php|/bitrix/tools/voximplant/\) \{\n\t\tadd_header X-Frame-Options \"always\";\n\t\tlocation ~* ^/\(pub/imconnector/|pub/imbot.php|services/telephony/info_receiver\\\.php|bitrix/tools/voximplant/\) \{\n\t\t\tproxy_ignore_client_abort on;\n\t\t\tproxy_pass \\\$proxyserver;\n\t\t\}\n\tproxy_pass \\\$proxyserver;\n\t\}\n\n\t# Bitrix setup script\n\tlocation ^~ ^\(/bitrixsetup\\\.php\)\\\$ \{ \n\t\tproxy_pass \\\$proxyserver; \n\t\tproxy_buffering off;\n\t\}\n\n\t# Upload location\n\tlocation ~ /upload/ \{\n\t\tclient_body_buffer_size 1024m;\n\t\}\n\n\tlocation = /robots.txt \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\t# aspro robots.txt rewrite\n\t\t#rewrite \"robots.txt\" /aspro_regions/robots/robots_\\\$host.txt break;\n\t\}\n\n\tlocation = /favicon.png \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\}\n\n\tlocation  = /restore.php \{\n\t\tclient_body_buffer_size 8192m;\n\t\tclient_max_body_size 8192m;\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\n\tlocation = /bitrix/admin/1c_exchange.php \{\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\{% if \\\$LOG_ERROR == on %\}\n\t\terror_log \{% \\\$ERROR_LOG_PATH %\} notice;\n\{% else %\}\n\t\terror_log /dev/null crit;\n\{% endif %\}\n\t\tproxy_pass \\\$proxyserver;\n\t\tsend_timeout 3600;\n\t\tproxy_connect_timeout 3600;\n\t\tproxy_send_timeout 3600;\n\t\tproxy_read_timeout 3600;\n\t\tfastcgi_read_timeout 3600;\n\t\tfastcgi_send_timeout 3600;\n\t\tfastcgi_connect_timeout 3600;\n\t\tclient_body_timeout 3600;\n\t\tkeepalive_timeout 3600;\n\t\tkeepalive_requests 100;\n\t\tfastcgi_param REMOTE_USER \\\$http_authorization;\n\t\tfastcgi_param HTTP_IF_NONE_MATCH \\\$http_if_none_match;\n\t\tfastcgi_param HTTP_IF_MODIFIED_SINCE \\\$http_if_modified_since;\n\t\}\n\n\tlocation / \{\n\t\tdefault_type text/html;\n\t\t# slow \- Bitrix php composite html processing \- if bitrix/.bxfile_composite_enabled then go to Cache \(200\)\n\t\t# backend php headers \+ client headers \+ nginx headers works\n\t\tset \\\$bxfile_composite_enabled \"\\\$root_path/bitrix/.bxfile_composite_enabled\";\n\t\tif \(-f \\\$bxfile_composite_enabled\) \{ return 412; \}\n\n\t\t# fast \- Nginx html processing \- if ABCD then go to Nginx \(file\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABCD\"\) \{ rewrite .* /\\\$composite_cache last; \}\n\t\tlocation ~* \@.*\\\\.html\\\$ \{\n\t\t\tinternal;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(file\)\";\n\t\t\t# disable browser cache php manage file\n\t\t\texpires -1y;\n\t\t\tadd_header Cache-Control \"no\-store\, no\-cache\";\n\t\t\}\n\t\t# fastest - Memcached html processing - if ABC then go to Nginx \(memcached\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABC\"\) \{\n\t\t\terror_page 404 405 412 502 504 = \@bitrix;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(memcached\)\";\n\t\t\t# use memcached tcp\n\t\t\tmemcached_pass 127.0.0.1:11211;\n\t\t\t# use memcached socket\n\t\t\t#memcached_pass unix:/tmp/memcached.socket;\n\t\t\}\n\t\t# no composite cache \- if NOT ABC then go to \@bitrix\n\t\tif \(\\\$use_composite_cache != \"ABC\"\) \{ return 412; \}\n\t\t# php go to apache\n\t\t#\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\n\tlocation \@fallback \{\n\t\tproxy_set_header Host \\\$host;\n\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\tproxy_set_header X-Forwarded-Proto \\\$scheme;\n\t\tproxy_set_header X-Forwarded-Port \\\$server_port;\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\t\tproxy_pass \{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\t\}\n\{% endif %\}\n\{#\}\n\{#\} CGI_APACHE_MODULE_config_stop\n\{#\}\n\{#\}\n\{#\} FPM_config_start\n\{#\}\n\{% if \\\$REDIRECT_TO_PHPFPM == on %\}\n\t# errors handlers\n\terror_page 403 /403.html;\n\t#error_page 404 /404.php;\n\terror_page 404 = \@bitrix;\n\terror_page 412 = \@bitrix;\n\terror_page 497 https://\\\$host\\\$request_uri;\n\terror_page 500 /500.html;\n\terror_page 502 /502.html;\n\terror_page 503 /503.html;\n\terror_page 504 /504.html;\n\t#\n\t# errors custom pages\n\tlocation ^~ /500.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /502.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /503.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /504.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /403.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /404.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\t# memcached options\n\tmemcached_connect_timeout 1s;\n\tmemcached_read_timeout 1s;\n\tmemcached_send_timeout 1s;\n\tmemcached_gzip_flag 65536;\n\t#\n\t# variables\n\tset \\\$memcached_key \"/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_cache \"bitrix/html_pages/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_file \"\\\$root_path/\\\$\{composite_cache\}\";\n\tset \\\$use_composite_cache \"\";\n\t#\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\t# aspro max sitemap\n\t# location ~ ^/sitemap.*\\\.xml\\\$ \{ rewrite \"/\(sitemap.*\)\\\.xml\" /aspro_regions/sitemap/\\\$1_\\\$host.xml break; \}\n\t#\n\t# composite cache\n\t# if no composite checks file exist then NULL-ing variables\n\tif \(!-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$composite_key \"\"; set \\\$is_global_composite \"\"; \}\n\t# if bitrix html cache .enabled file exist then set A\n\tset \\\$composite_enabled  \"\\\$root_path/bitrix/html_pages/.enabled\";\n\tif \(-f \\\$composite_enabled\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}A\"; \}\n\t#\n\t# if bitrix html cache mappings file exist then set B\n\tif \(-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}B\"; \}\n\t#\n\t# if global check success then set C\n\tif \(\\\$is_global_composite = 1\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}C\"; \}\n\t#\n\t# if composite cache file exist then set D\n\tif \(-f \\\$composite_file\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}D\"; \}\n\t#\n\tclient_max_body_size 1024m;\n\tclient_body_buffer_size 4m;\n\t#\n\tkeepalive_timeout 70;\n\tkeepalive_requests 150;\n\t#\n\tadd_header \"X-Content-Type-Options\" \"nosniff\";\n\tset \\\$frame_options \"\";\n\tif \(\\\$http_referer !~ '^https?:\/\/\(\[^\/\]+\\\.\)?\(webvisor\\\.com\)\/'\) \{ set \\\$frame_options \"SAMEORIGIN\"; \}\n\tadd_header X-Frame-Options \"\\\$frame_options\";\n\t#\n\t# Nginx server status page\n\tlocation ^~ /nginx-status-$RANDOM_N \{\n\t\tstub_status on;\n\t\tallow all;\n\t\}\n\t#\n\t#### bx/site_settings/default/bx_temp.conf\n\tlocation ~* ^/bx_tmp_download/ \{\n\t\tinternal;\n\t\trewrite /bx_tmp_download/\(.+\) /.bx_temp/sitemanager/\\\$1 last;\n\t\}\n\tlocation ~* ^/.bx_temp/sitemanager/ \{\n\t\tinternal;\n\t\troot \\\$root_path;\n\t\}\n\t#\n\t#### bx/conf/bitrix_block.conf\n\t# ht\(passwd|access\)\n\tlocation ~* /\\\.ht \{ deny all; \}\n\t#\n\t# repositories\n\tlocation ~* /\\\.\(svn|hg|git\) \{ deny all; \}\n\t#\n\t# bitrix internal locations\n\tlocation ~* ^/bitrix/\(modules|local_cache|stack_cache|managed_cache|php_interface\) \{ deny all; \}\n\tlocation = /bitrix/php_interface/dbconn.php \{ deny all; \}\n\t\n\tlocation = /bitrix/.settings.php \{ deny all; \}\n\t#\n\t# 1C upload files\n\tlocation ~* ^/upload/1c_\[^/\]+/ \{ deny all; \}\n\t#\n\t# use the file system to access files outside the site \(cache\)\n\tlocation ~* /\\\.\\\./ \{ deny all; \}\n\tlocation = /bitrix/html_pages/.config.php \{ deny all; \}\n\tlocation = /bitrix/html_pages/.enabled \{ deny all; \}\n\t#### bx/conf/bitrix_general.conf\n\t# Intenal locations\n\tlocation ^~ /upload/support/not_image \{ internal; \}\n\t\t\n\n\t# Player options\ disable no-sniff\n\tlocation ~* ^/bitrix/components/bitrix/player/mediaplayer/player\\\$ \{ add_header Access-Control-Allow-Origin *; \}\n\n\t# Process dav request on\n\t# main company\n\t# extranet\n\t# additional departments\n\t# locations that ends with / => directly to fpm \n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\).*/\\\$ \{\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\t#\n\t# Add / to request\n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\) \{\n\t\tset \\\$addslash \"\";\n\t\tif \(-d \\\$request_filename\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$is_args != '?'\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$addslash = \"YY\" \) \{ rewrite ^\(.*\[^/\]\)\\\$ \\\$1/ permanent; \}\n\t\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\t# Accept access for merged css and js\n\tlocation ~* ^/bitrix/cache/\(css/.+\\\.css|js/.+\\\.js\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page 404 = \@bitrix;\n\t\t#error_page 404 /404.html;\n\t\t#error_page 404 /404.php;\n\t\}\n\n\t# Disable access for other assets in cache location\n\tlocation ~* ^/bitrix/cache \{ deny all; \}\n\n\t# Excange and Outlook\n\tlocation ~ ^/bitrix/tools/ws_.*/_vti_bin/.*\\\.asmx\\\$ \{ try_files \\\$uri \@bitrix; \}\n\n\t# Groupdav\n\tlocation ^~ /bitrix/groupdav.php \{ try_files try_files \\\$uri \@bitrix; \}\n\n\t# Use nginx to return static content from s3 cloud storage\n\t# /upload/bx_cloud_upload/<schema>.<backet_name>.<s3_point>.amazonaws.com/<path/to/file>\n\tlocation ^~ /upload/bx_cloud_upload/ \{\n\t\t# Amazon\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(s3|us-east-2|us-east-1|us-west-1|us-west-2|af-south-1|ap-east-1|ap-south-1|ap-northeast-3|ap-northeast-2|ap-southeast-1|ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|eu-south-1|eu-west-3|eu-north-1|me-south-1|sa-east-1\)\\\.amazonaws\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.amazonaws.com/\\\$4;\n\t\t\}\n\n\t\t# Rackspace\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.rackcdn\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.\\\$4.rackcdn.com/\\\$5;\n\t\t\}\n\n\t\t# Clodo\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.clodo\\\.ru:\(80|443\)/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.clodo.ru:\\\$3/\\\$4;\n\t\t\}\n\n\t\t# Google\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.commondatastorage\\\.googleapis\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.commondatastorage.googleapis.com/\\\$3;\n\t\t\}\n\n\t\t# Selectel\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.selcdn\\\.ru/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.selcdn.ru/\\\$3;\n\t\t\}\n\n\t\t# Yandex\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.storage\\\.yandexcloud\\\.net/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.storage.yandexcloud.net/\\\$3;\n\t\t\}\n\n\t\tlocation ~* .*\\\$ \{ deny all; \}\n\t\}\n\n\t# Static content\n\tlocation ~* ^/\(bitrix/images|bitrix/tmp\) \{\n\t\tclient_body_buffer_size 1024m;\n\t\tif \( \\\$upstream_http_x_accel_redirect = \"\"  \) \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\}\n\t\tlocation ~* ^.+\\\\.(ph(p\\\\d*|tml)|pl|asp|aspx|cgi|dll|exe|shtm|shtml|fcg|fcgi|fpl|asmx|pht|py|psp|rb|var)\\\$ \{\n\t\t\tadd_header Content-Type text/plain;\n\t\t\tdefault_type text/plain;\n\t\t\}\n\t\}\n\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\t\tadd_header Cache-Control \"public\";\n\t\terror_page 404 = \@bitrix;\n\t\t#error_page 404 /404.html;\n\t\t#error_page 404 /404.php;\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\}\n\n\t# pub & online\n\t# telephony and voximplant\n\tlocation ~* ^/\(pub/|online/|services/telephony/info_receiver\\\.php|/bitrix/tools/voximplant/\) \{\n\t\tadd_header X-Frame-Options \"always\";\n\t\tlocation ~* ^/\(pub/imconnector/|pub/imbot.php|services/telephony/info_receiver\\\.php|bitrix/tools/voximplant/\) \{\n\t\t\ttry_files \\\$uri \@bitrix;\n\t\t\}\n\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\t# Bitrix setup script\n\tlocation ^~ ^\(/bitrixsetup\\\.php\)\\\$ \{\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\t# Upload location\n\tlocation ~* ^/upload/ \{\n\t\tclient_body_buffer_size 1024m;\n\t\tif \( \\\$upstream_http_x_accel_redirect = \"\"  \) \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\}\n\t\tlocation ~* ^.+\\\\.(ph(p\\\\d*|tml)|pl|asp|aspx|cgi|dll|exe|shtm|shtml|fcg|fcgi|fpl|asmx|pht|py|psp|rb|var)\\\$ \{\n\t\t\tadd_header Content-Type text/plain;\n\t\t\tdefault_type text/plain;\n\t\t\}\n\t\}\n\n\tlocation = /robots.txt \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\t# aspro robots.txt rewrite\n\t\t#rewrite \"robots.txt\" /aspro_regions/robots/robots_\\\$host.txt break;\n\t\}\n\n\tlocation = /favicon.png \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\}\n\n\tlocation = /restore.php \{\n\t\tinclude fastcgi_params;\n\t\tclient_body_buffer_size 8192m;\n\t\tclient_max_body_size 8192m;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\n\n\t# 1C exchange\n\tlocation = /bitrix/admin/1c_exchange.php \{\n\t\tinclude fastcgi_params;\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\{% if \\\$LOG_ERROR == on %\}\n\t\terror_log \{% \\\$ERROR_LOG_PATH %\} notice;\n\{% else %\}\n\t\terror_log /dev/null crit;\n\{% endif %\}\n\t\tfastcgi_read_timeout 3600;\n\t\tfastcgi_send_timeout 3600;\n\t\tfastcgi_connect_timeout 3600;\n\t\tclient_body_timeout 3600;\n\t\tkeepalive_timeout 3600;\n\t\tkeepalive_requests 100;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\tlocation / \{\n\t\tdefault_type text/html;\n\t\t# slow \- Bitrix php composite html processing \- if bitrix/.bxfile_composite_enabled then go to Cache \(200\)\n\t\t# backend php headers \+ client headers \+ nginx headers works\n\t\tset \\\$bxfile_composite_enabled \"\\\$root_path/bitrix/.bxfile_composite_enabled\";\n\t\tif \(-f \\\$bxfile_composite_enabled\) \{ return 412; \}\n\n\t\t# fast \- Nginx html processing \- if ABCD then go to Nginx \(file\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABCD\"\) \{ rewrite .* /\\\$composite_cache last; \}\n\t\tlocation ~* \@.*\\\\.html\\\$ \{\n\t\t\tinternal;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(file\)\";\n\t\t\t# disable browser cache php manage file\n\t\t\texpires -1y;\n\t\t\tadd_header Cache-Control \"no\-store\, no\-cache\";\n\t\t\}\n\t\t# fastest - Memcached html processing - if ABC then go to Nginx \(memcached\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABC\"\) \{\n\t\t\terror_page 404 405 412 502 504 = \@bitrix;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(memcached\)\";\n\t\t\t# use memcached tcp\n\t\t\tmemcached_pass 127.0.0.1:11211;\n\t\t\t# use memcached socket\n\t\t\t#memcached_pass unix:/tmp/memcached.socket;\n\t\t\}\n\t\t# no composite cache \- if NOT ABC then go to \@bitrix\n\t\tif \(\\\$use_composite_cache != \"ABC\"\) \{ return 412; \}\n\t\}\n\t# php go to php-fpm\n\t#\n\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\t\tinclude fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_param PHP_ADMIN_VALUE \"sendmail_path = /usr/sbin/sendmail -t -i -f \{% \\\$EMAIL %\}\";\n\t\tfastcgi_param SERVER_NAME \\\$host;\n\t\tfastcgi_param REMOTE_USER \\\$http_authorization;\n\t\tfastcgi_param HTTP_IF_NONE_MATCH \\\$http_if_none_match;\n\t\tfastcgi_param HTTP_IF_MODIFIED_SINCE \\\$http_if_modified_since;\n\t\tfastcgi_read_timeout 180;\n\t\tfastcgi_send_timeout 180;\n\t\tfastcgi_connect_timeout 180;\n\t\tclient_body_timeout 180;\n\t\tkeepalive_timeout 180;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 8 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 10m;\n\t\tkeepalive_requests 100;\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\tlocation \@bitrix \{\n\t\ttry_files \\\$uri \\\$uri/ /bitrix/urlrewrite.php\\\$is_args\\\$args;\n\t\}\n\{% endif %\}\n\{#\}\n\{#\} FPM_config_stop\n\{#\}\n\{% endif %\}\n\{% endif %\}\n\{#\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n,gi"
	
				BITRIX_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS="$BITRIX_FPM_NGINX_PERL_INJECTION_LOCATIONS"
	
				BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_send_timeout 180;\n\t\tfastcgi_read_timeout 180;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 8 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 10m;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root/bitrix/urlrewrite.php;\n\t\tfastcgi_param REMOTE_USER \\\$http_authorization;\n\t\tfastcgi_param HTTP_IF_NONE_MATCH \\\$http_if_none_match;\n\t\tfastcgi_param HTTP_IF_MODIFIED_SINCE \\\$http_if_modified_since;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
				
				BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2="s,\t\ttry_files \\\$uri =404;\n\t\tinclude fastcgi_params;\n\t\}\n\{% endif %\}\n\},\{% if \\\$PRESET != $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\ttry_files \\\$uri =404;\n\{% endif %\}\n\t\}\n\{% endif %\}\n\},gi"
				
				BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_3="s,\{% if \\\$REDIRECT_TO_PHPFPM == on %\}\n\tlocation \@php \{\n\t\tfastcgi_index index.php;,\{% if \\\$REDIRECT_TO_PHPFPM == on %\}\n\tlocation \@php \{\n\t\tinclude fastcgi_params;\n\t\tfastcgi_index index.php;\n,gi"
	
				# check current nginx conf sanity
				if ! nginx_test_output=$({ nginx -t; } 2>&1)
				then 
					printf "\n${LRV}ERROR - current nginx configuration check has failed (nginx -t)${NCV}\n$nginx_test_output"
					EXIT_STATUS=1
					check_exit_and_restore_func
				fi
				# create & check comaptibility
				backward_copmat_func
				
				# check gits
				git_check
				
				# installed nginx check
				nginx_push_pull_module_support
				
				# user select nginx push pull stream Y/N
				if [[ $NGINX_HAVE_PUSH_PULL = "1" ]]
				then 
					BITRIX_NGX_PUSH="nginx_bitrix_http_context_push.conf"
				else
					printf "\n${YCV}Warning: nginx compiled without push and pull stream module\nI can recompile it with nginx-push-stream (and also with brotli, headers-more-nginx-module, latest openssl) OR you may just continue without it (modern bitrix core using own node.js or cloud stream server)\n${NCV}\n"
					read -p "Continue without nginx recompilation ? [Y/n]" -n 1 -r
					echo
					if ! [[ $REPLY =~ ^[Nn]$ ]]
					then
						# no push and pull stream
						BITRIX_NGX_PUSH="nginx_bitrix_http_context_push.conf.disabled"
					else
						# recompilation of nginx was selected
						printf "\n${GCV}You have chosen to recompile nginx with modules needed\nDo not forget manually uncomment the more_clear_input_headers directives in bitrix nginx configuration if recompilation succeed like this:\nsed -i 's@#more_clear_input_headers@more_clear_input_headers@gi' $NGINX_TEMPLATE && sed -i 's@#more_clear_input_headers@more_clear_input_headers@gi' $NGINX_SSL_TEMPLATE${NCV}\n"
						BITRIX_NGX_PUSH="nginx_bitrix_http_context_push.conf"
						EXIT_STATUS=0
						trap 'EXIT_STATUS=1' ERR
							
						# download recompilation script
						if printf "GET $GIT_THE_CHOSEN_ONE_REQ_URI/$NGX_RECOMPILE_SCRIPT_NAME HTTP/1.1\nHost:$GIT_THE_CHOSEN_ONE_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_THE_CHOSEN_ONE_DOMAIN_NAME:443 -quiet | sed '1,/^\s$/d' > "/tmp/$NGX_RECOMPILE_SCRIPT_NAME"
						then
							# execute recompilation script
							printf "This will take some time\nRecompiling"
							
							if printf "1\n" | bash "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" &> /dev/null
							then
								printf " - ${GCV}OK${NCV}\n"
								\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" &> /dev/null
							else
								printf " - ${LRV}FAIL${NCV}\n"
								\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" &> /dev/null
								EXIT_STATUS=1
								check_exit_and_restore_func
							fi
						else
							printf "\n${RLV}Download $GIT_THE_CHOSEN_ONE_DOMAIN_NAME$GIT_THE_CHOSEN_ONE_REQ_URI/$NGX_RECOMPILE_SCRIPT_NAME failed${NCV}\n"
							\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" &> /dev/null
							EXIT_STATUS=1
							check_exit_and_restore_func
						fi
					fi
				fi
				
				# download bitrix_fpm error files
				printf "\n${YCV}Downloading bitrix error files to $BITRIX_FPM_LOCAL_ERRORS_DIR${NCV}\n"
				if mkdir -p "$BITRIX_FPM_LOCAL_ERRORS_DIR"
				then
					for file in "${BITRIX_REQ_ERROR_PAGES_FILES[@]}"
					do
						EXIT_STATUS=0
						trap 'EXIT_STATUS=1' ERR
						
						printf "GET $GIT_THE_CHOSEN_ONE_REQ_URI/$BITRIX_REQ_NGINX_FOLDER_URL$BITRIX_REQ_ERROR_PAGES_URL$file HTTP/1.1\nHost:$GIT_THE_CHOSEN_ONE_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_THE_CHOSEN_ONE_DOMAIN_NAME:443 -quiet | sed '1,/^\s$/d' > "$BITRIX_FPM_LOCAL_ERRORS_DIR/$file"
						# check result and restore if error
						printf "Verifying download status of $BITRIX_FPM_LOCAL_ERRORS_DIR/$file"
						if [[ -f "$BITRIX_FPM_LOCAL_ERRORS_DIR/$file" ]]
						then
							# file exists after download and total size more than 30 bytes
							FILE_SIZE=$(ls -l "$BITRIX_FPM_LOCAL_ERRORS_DIR/$file" | awk '{print $5}' 2> /dev/null)
							if [[ $FILE_SIZE -gt 30 ]]
							then 
								printf " - ${GCV}OK${NCV}\n"
							else
								# file size less than 30 bytes
								printf " - ${LRV}FAIL (Filesize less than 30 bytes)${NCV}\n"
								EXIT_STATUS=1
								check_exit_and_restore_func
							fi
						else
							# file doesnt exists after download
							printf " - ${LRV}FAIL (File not exist after download)${NCV}\n"
							EXIT_STATUS=1
							check_exit_and_restore_func
						fi
					done
				else
					printf "\n${LRV}ERROR - Cannot create $BITRIX_FPM_LOCAL_ERRORS_DIR${NCV}\n"
					EXIT_STATUS=1
					check_exit_and_restore_func
				fi
				
				# download bitrix_fpm nginx files
				if [[ -f "$NGINX_MAIN_CONF_FILE" ]]
				then 
					# we have main conf, check includes
					if ! grep -v "#" $NGINX_MAIN_CONF_FILE | grep "include /etc/nginx/conf.d/\*.conf.*;" &> /dev/null
					then
						# nginx's include /etc/nginx/conf.d/*.conf.* was not found
						# check that we already have bitrix_fpm $NGINX_MAIN_CONF_FILE inject
						if ! grep "$PROXY_PREFIX$proxy_target" $NGINX_MAIN_CONF_FILE &> /dev/null
						then
							sed -i "s@http {@&\n# $PROXY_PREFIX$proxy_target\_START_DO_NOT_REMOVE\n# date added - $current_date_time\n# $PROXY_PREFIX$proxy_target\_STOP_DO_NOT_REMOVE\n@g" $NGINX_MAIN_CONF_FILE
							# download
							bitrix_fpm_download_files_func
							
							# adding inject if /etc/nginx/conf.d/*.conf.* was not found
							printf "Updating $NGINX_MAIN_CONF_FILE\n"
							sed -i "s@# $PROXY_PREFIX$proxy_target\_STOP_DO_NOT_REMOVE@    include\t$BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file;\n&@g" $NGINX_MAIN_CONF_FILE &> /dev/null
						else
							# we already have bitrix_fpm $NGINX_MAIN_CONF_FILE inject
							printf "\n${LRV}ERROR - $existing $PROXY_PREFIX$proxy_target found in $NGINX_MAIN_CONF_FILE\nUse \"$BASH_SOURCE del $PROXY_PREFIX$proxy_target\" to remove it${NCV}\n"
							EXIT_STATUS=1
							check_exit_and_restore_func
						fi
					else
						# nginx's include /etc/nginx/conf.d/*.conf.* was found
						# just download
						bitrix_fpm_download_files_func
					fi
				else
					# we cannot find $NGINX_MAIN_CONF_FILE
					printf "\n${LRV}ERROR - file $NGINX_MAIN_CONF_FILE was not found${NCV}\n"
					EXIT_STATUS=1
					check_exit_and_restore_func
				fi
				
				# bitrix_fpm nginx-vhosts.template
				printf "${YCV}Injecting $PROXY_PREFIX$proxy_target${NCV}"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_LOCATIONS" "$NGINX_TEMPLATE"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_TEMPLATE"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_TEMPLATE"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_3" "$NGINX_TEMPLATE"
				
				# bitrix_fpm nginx-vhosts-ssl.template
				perl -i -p0e "$BITRIX_FPM_NGINX_SSL_PERL_INJECTION_LOCATIONS" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_2" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$BITRIX_FPM_NGINX_PERL_INJECTION_PHPFPM_BACKEND_3" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
				
				# set status pages for nginx and apache
				BITRIX_FPM_STATUS_SET=1
				#set_status_pages &> /dev/null
				
				# tweak php and mysql
				ispmanager_tweak_php_and_mysql_settings_func

				continue
			else
				
				# create & check comaptibility
				backward_copmat_func
				
				# not special injections comes here
				printf "\nInjecting $PROXY_PREFIX$proxy_target"
				
				# $NGINX_TEMPLATE injection
				perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_APACHE" "$NGINX_TEMPLATE"
				perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_PHPFPM" "$NGINX_TEMPLATE"
				perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF" "$NGINX_TEMPLATE"
				
				# $NGINX_SSL_TEMPLATE injection
				perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_APACHE" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_PHPFPM" "$NGINX_SSL_TEMPLATE"
				perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF" "$NGINX_SSL_TEMPLATE"
				
				check_exit_and_restore_func
				printf " - ${GCV}OK${NCV}\n"
			fi
	else
		printf "\n${LRV}Error on adding preset - $PROXY_PREFIX$proxy_target${NCV}\n"
		printf "${LRV}Skipping template injection.${NCV}\n"
		printf "${LRV}Check $MGR_PATH/var/ispmgr.log for errors${NCV}\n" 
		preset_raise_error="1"
		continue
	fi
done

# fix fastcgi_pass
fastcgi_pass_format_func

# fix seo 301
seo_fix_ssl_port_func

# ssl tune
ssl_tune_func

# panel graceful restart
isp_panel_graceful_restart_func

}

main_func "${@:2}"
