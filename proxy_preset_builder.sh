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
self_current_version="1.0.72"
printf "\n${YCV}Hello${NCV}, this is proxy_preset_builder.sh - ${YCV}$self_current_version\n${NCV}"

# check privileges
if [[ $EUID -ne 0 ]]; then
	printf "\n${LRV}ERROR - This script must be run as root.${NCV}" 
	exit 1
fi

# isp vars
MGR_PATH="/usr/local/mgr5"
MGR_BIN="$MGR_PATH/sbin/mgrctl"
MGR_CTL="$MGR_PATH/sbin/mgrctl -m ispmgr"
MGR_MAIN_CONF_FILE="$MGR_PATH/etc/ispmgr.conf"
SITES_TWEAKS_NEEDED=""
SITES_TWEAKS_NEEDED_SITES=()
NO_MOD_PHP=()

# bitrix vars
ADMIN_SH_BITRIX_FILE_LOCAL="/root/admin.sh"
ADMIN_SH_BITRIX_FILE_URL=""
ADMIN_SH_BITRIX_FILE_LOCAL_SIZE=""
ADMIN_SH_BITRIX_FILE_REMOTE_SIZE=""

# other var
NGINX_CONF_DIR="/etc/nginx"
NGINX_CONF_FILE="$NGINX_CONF_DIR/nginx.conf"
NGINX_TWEAKS_INCLUDE_FILE="$NGINX_CONF_DIR/custom.conf"
NGINX_TWEAKS_SUCCESS_ADDED=()
NGINX_BAD_ROBOT_FILE_URL=""
SHARED_BASH_FUNCTIONS_URL="https://raw.githubusercontent.com/attaattaatta/proxy_preset_builder/refs/heads/master/bash_shared_functions.sh"

# allowed script actions
ALLOWED_ACTIONS="(^add$|^del$|^reset$|^tweak$|^recompile$|^setstatus$|^-?-?help$)"

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

load_shared_functions_func() {

# check args n
if [[ $# -ne 1 ]]; then
	printf "\n${LRV}Error:${NCV} Not enouth args.\n"
	printf "\n${LRV}1:${NCV}$1\n"
	return 1
fi

# check args not empty
for arg in "$@"; do
	if [[ -z "$arg" ]]; then
		printf "\n${LRV}Error:${NCV} Empty arg.\n"
		printf "\n${LRV}1:${NCV}$1\n"
		return 1
	fi
done

local shared_func_url="$1"

local remote_hostname=$(echo "$1" | awk -F[/:] '{print $4}')

if command -v wget >/dev/null 2>/dev/null; then 
	if source <(timeout 4 \wget --timeout 4 --no-check-certificate -q -O- ${shared_func_url}); then 
		return 0
	else
		printf "\nSource shared functions from ${shared_func_url} to RAM - ${LRV}FAIL${NCV}\n"
		return 1
	fi

elif command -v openssl > /dev/null 2>/dev/null; then
	if source <(printf "GET ${shared_func_url} HTTP/1.1\nHost:${remote_hostname}\nConnection:Close\n\n" | timeout 5 \openssl 2>/dev/null s_client -crlf -connect ${remote_hostname}:443 -quiet | sed '1,/^\s$/d');then
		return 0
	else
		printf "\nSource shared functions from ${shared_func_url} to RAM - ${LRV}FAIL${NCV}\n"
		return 1
	fi
else
	printf "\nDownloading shared functions from ${shared_func_url} to RAM - ${LRV}FAIL${NCV}\n"
	return 1
fi

}

if ! load_shared_functions_func "${SHARED_BASH_FUNCTIONS_URL}" >/dev/null 2>/dev/null; then
	printf "\n${LRV}Error${NCV} from load_shared_functions_func. Check internet access and name resolv.\n"
	exit 1
fi

show_help_func() {

printf "\n\n${YCV}Usage help:${NCV}\n"
printf "\n${GCV}Tweak${NCV} this box: $BASH_SOURCE tweak\n"
printf "\nExample for ${GCV}1 preset:${NCV} $BASH_SOURCE add wordpress_fpm OR $BASH_SOURCE add 127.0.0.1:8088\n"
printf "Example for ${GCV}4 presets:${NCV} $BASH_SOURCE add wordpress_fpm 127.0.0.1:8000 1.1.1.1 /path/to/unix/socket\n"
printf "\n${GCV}Delete all${NCV} existing %%$PROXY_PREFIX*%% presets and injects: $BASH_SOURCE del all $PROXY_PREFIX"
printf "\n${GCV}Delete one${NCV} existing preset and inject: $BASH_SOURCE del proxy_to_wordpress_fpm OR $BASH_SOURCE del proxy_to_127.0.0.1:8000"
printf "\n${GCV}Restore${NCV} default templates and ${GCV}delete all presets${NCV}:${NCV} $BASH_SOURCE reset\n"
printf "\n${GCV}Recompile nginx${NCV} (add/remove modules | update/change SSL): $BASH_SOURCE recompile\n"
printf "\nCurrent special ${YCV}templates list${NCV}: wordpress_fpm, bitrix_fpm, opencart_fpm, moodle_fpm, webassyst_fpm, magento2_fpm, cscart_fpm\n"

}

#check tools
WE_NEED=('sed' 'awk' 'perl' 'cp' 'grep' 'printf' 'cat' 'rm' 'test' 'openssl' 'getent' 'mkdir' 'timeout')

for needitem in "${WE_NEED[@]}"
do
	if ! command -v $needitem >/dev/null 2>&1; then 
		if ! apt-get update >/dev/null 2>&1 && apt-get install -y "$needitem" >/dev/null 2>&1 || ! yum install -y "$needitem" >/dev/null 2>&1; then
			printf "\n${LRV}Error:${NCV} cannot install ${needitem}. Please install it first or export correct \$PATH.\n"
			show_help_func
			exit 1
		fi
	fi
done

# check OS
if ! check_os_func >/dev/null 2>/dev/null; then
	printf "\n${LRV}Error${NCV} from check_os_func. Check internet access and name resolv.\n"
	exit 1
fi

#check env
if [[ -f /usr/bin/hostnamectl ]] || [[ -f /bin/hostnamectl ]]; then
	PLATFROM_CHASSIS=$(hostnamectl status | grep Chassis | awk '{print $2}')
	PLATFROM_VIRT=$(hostnamectl status | grep Virtualization | awk '{print $2}')
	
	if [[ $PLATFROM_CHASSIS == "server" || $PLATFROM_CHASSIS == "laptop" || $PLATFROM_CHASSIS == "desktop" ]]; then
		DEDICATED="yes"
		VIRTUAL="no"
	else
		DEDICATED="no"
	fi
	
	if [[ $PLATFROM_CHASSIS == "vm" || $PLATFROM_CHASSIS == "container" ]]; then
		VIRTUAL="yes"
		if [[ $PLATFROM_VIRT == "kvm" ]]; then
			PLATFROM_VIRT="kvm"
		elif [[ $PLATFROM_VIRT == "openvz" ]]; then
			PLATFROM_VIRT="openvz"
		elif [[ $PLATFROM_VIRT == "xen" ]]; then
			PLATFROM_VIRT="xen"
		else
			PLATFROM_VIRT="unknown"
		fi 
	else
		PLATFROM_VIRT="none"
		VIRTUAL="no"
	fi
elif [[ -f /usr/sbin/dmidecode ]] || [[ -f /bin/dmidecode ]]; then
	PLATFROM_CHASSIS=$(dmidecode -t memory | grep -iA 10 "Physical Memory Array" | grep Location | awk '{print $2}')
	if [[ $PLATFROM_CHASSIS == "Other" ]]; then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="unknown"
	elif [[ $PLATFROM_CHASSIS == "System" ]]; then
		VIRTUAL="no"
		DEDICATED="yes"
		PLATFROM_VIRT="none"
	fi

	if [[ -f /usr/bin/systemd-detect-virt ]]; then
		PLATFROM_VIRT=$(systemd-detect-virt)
		if [[ $PLATFROM_VIRT == "openvz" ]]; then
			VIRTUAL="yes"
			DEDICATED="no"
			PLATFROM_VIRT="openvz"
		elif [[ $PLATFROM_VIRT == "kvm" ]]; then
			VIRTUAL="yes"
			DEDICATED="no"
			PLATFROM_VIRT="kvm"
		elif [[ $PLATFROM_VIRT == "xen" ]]; then
			VIRTUAL="yes"
			DEDICATED="no"
			PLATFROM_VIRT="xen"
		elif [[ $PLATFROM_VIRT == "none" ]]; then
			VIRTUAL="no"
			DEDICATED="yes"
			PLATFROM_VIRT="none"
		else
			VIRTUAL="unknown"
			DEDICATED="unknown"
			PLATFROM_VIRT="unknown"
		fi
	fi	
elif [[ -f /usr/bin/systemd-detect-virt ]]; then
	PLATFROM_VIRT=$(systemd-detect-virt)
	if [[ $PLATFROM_VIRT == "openvz" ]]; then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="openvz"
	elif [[ $PLATFROM_VIRT == "kvm" ]]; then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="kvm"
	elif [[ $PLATFROM_VIRT == "xen" ]]; then
		VIRTUAL="yes"
		DEDICATED="no"
		PLATFROM_VIRT="xen"
	elif [[ $PLATFROM_VIRT == "none" ]]; then
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

if [[ $DEDICATED == "yes" ]]; then
	printf "\nSeems like a ${GCV}dedicated${NCV} server here\n"
elif [[ $VIRTUAL == "yes" ]]; then
	printf "\nSeems like a ${GCV}virtual${NCV} server here"
	if [[ -n $PLATFROM_VIRT ]]; then
		printf " with ${GCV}$PLATFROM_VIRT${NCV} virtualization\n"
	else
		printf " with ${LRV}unknown${NCV} virtualization\n"
	fi
else
	printf "\nSeems like a ${LRV}unknown${NCV} server\n"
fi

# show script version and check gits
script_git_name="proxy_preset_builder.sh"
git_version="$(printf "GET $SCRIPT_GIT_PATH/$script_git_name HTTP/1.1\nHost:$GIT_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_DOMAIN_NAME:443 -quiet | grep -o -P '(?<=self_current_version=")\d+\.?\d+?\.?\d+')"
git_backup_version="$(printf "GET $SCRIPT_GIT_BACKUP_PATH/$script_git_name HTTP/1.1\nHost:$GIT_BACKUP_DOMAIN_NAME\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_BACKUP_DOMAIN_NAME:443 -quiet | grep -o -P '(?<=self_current_version=")\d+\.?\d+?\.?\d+')"

if [[ $git_version ]] && [[ $self_current_version < $git_version ]]; then
	printf "\nVersion ${YCV}$git_version${NCV} at $SCRIPT_GIT_PATH/$script_git_name \n"
	printf "You may use it like this:\n# bash <(printf \"GET /$GIT_REQ_URI/$script_git_name HTTP/1.1\\\nHost:$GIT_DOMAIN_NAME\\\nConnection:Close\\\n\\\n\" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_DOMAIN_NAME:443 -quiet | sed \'1,/^\s\$/d\')\n"
fi

if [[ $git_backup_version ]] && [[ $self_current_version < $git_backup_version ]]; then
	printf "\nVersion ${YCV}$git_backup_version${NCV} at $SCRIPT_GIT_BACKUP_PATH/$script_git_name\n"
	printf "You may use it like this:\n# bash <(printf \"GET /$GIT_BACKUP_REQ_URI/$script_git_name HTTP/1.1\\\nHost:$GIT_BACKUP_DOMAIN_NAME\\\nConnection:Close\\\n\\\n\" | timeout 5 openssl 2>/dev/null s_client -crlf -connect $GIT_BACKUP_DOMAIN_NAME:443 -quiet | sed \'1,/^\s\$/d\')\n"
fi

# check panel version and release name
isp_panel_check_license_version() {

if [[ ! -z "$ISP_MGR_LIC_GOOD" ]]; then
	return
fi

#check mgrctl
WE_NEED=("$MGR_BIN")

for needitem in "${WE_NEED[@]}"
do
	if ! command -v $needitem >/dev/null 2>&1; then 
		printf "\n${LRV}ERROR - $needitem could not be found. Please install it first or export correct \$PATH.${NCV}"
		show_help_func
		exit 1
	fi
done

#minimum version 6.11.02
panel_required_version="61102"

panel_current_version="$($MGR_CTL license.info | grep -o -P '(?<=panel_info=)\d+\.?\d+\.?\d+' | sed 's@\.@@gi')"
panel_release_name="$($MGR_CTL license.info |  grep -o -P '(?<=panel_name=)\w+\s\w+')"

if [[ -z $panel_release_name ]] || [[ -z $panel_current_version ]]; then
	printf "\n${LRV}ERROR - Cannot get ISP Manager panel version or release name.\nPlease check \"$MGR_CTL license.info\" command${NCV}\n"
	exit 1
fi

# set case insence for regexp
shopt -s nocasematch
if [[ $panel_release_name =~ .*busines.* ]]; then 
	printf "\n${LRV}ISP Manager Business detected. Not yet supported.${NCV}\n"
	shopt -u nocasematch
	exit 1
else
	if [[ $panel_current_version -lt $panel_required_version ]]; then 
		printf "\n${LRV}ERROR - ISP Manager panel version must not be less than $panel_required_version (current version is $panel_current_version)${NCV}\n${GCV}You may update it to $panel_required_version\nor check out this link - https://gitlab.hoztnode.net/admins/scripts/-/blob/master/proxy_preset_builder.sh\nfor older panel release version of this script${NCV}\n"
		exit 1
	else
		ISP_MGR_LIC_GOOD=1
	fi
		ISP_MGR_VER_GOOD=1
fi
# unset case insence for regexp
shopt -u nocasematch
}

# validate first argument 
if ! [[ $1 =~ $ALLOWED_ACTIONS ]]  && ! [[ -z "$1" ]]; then
	printf "\n\n${LRV}ERROR - Not valid argument - $1${NCV}\n"
	show_help_func
	exit 1
fi

# restart ISP panel func
isp_panel_graceful_restart_func() {

printf "\n${LRV}ISP panel restarting${NCV}"
EXIT_STATUS=0
trap 'EXIT_STATUS=1' ERR
$MGR_CTL -R
check_exit_and_restore_func
printf " - ${GCV}OK${NCV}\n"
printf "\n${YCV}Do not forget to raise ISP Panel default PHP-FPM pool manager to static and children number (nproc is $(nproc)) ${NCV}\n"
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
	\cp -rp "$MGR_PATH/etc/templates" "$current_ispmgr_backup_directory"
	\cp -rp "/etc" "$current_etc_backup_directory"
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
	if [[ ! -z $GIT_DOMAIN_NAME ]] || [[ ! -z $GIT_BACKUP_DOMAIN_NAME ]]; then
		EXIT_STATUS=0
		trap 'EXIT_STATUS=1' ERR
		
		getent hosts $GIT_DOMAIN_NAME >/dev/null 2>&1 || getent hosts $GIT_BACKUP_DOMAIN_NAME >/dev/null 2>&1
		
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
		if [[ $1 == "no_check_exit" ]]; then
			exit 1
		else
			check_exit_and_restore_func
		fi
		exit 1
	fi
	
	# choosing which git to use
	if [[ $git_version ]]; then
		GIT_THE_CHOSEN_ONE_REPO="$SCRIPT_GIT_REPO"
		GIT_THE_CHOSEN_ONE_PATH="$SCRIPT_GIT_PATH"
		GIT_THE_CHOSEN_ONE_DOMAIN_NAME="$(printf "$SCRIPT_GIT_PATH" | awk -F[/:] '{print $4}')"
		GIT_THE_CHOSEN_ONE_REQ_URI="${SCRIPT_GIT_PATH#https://*/}"
		
		printf "$GIT_THE_CHOSEN_ONE_REPO will be used\n"
	else
		if [[ $git_backup_version ]]; then
			GIT_THE_CHOSEN_ONE_REPO="$SCRIPT_GIT_BACKUP_REPO"
			GIT_THE_CHOSEN_ONE_PATH="$SCRIPT_GIT_BACKUP_PATH"
			GIT_THE_CHOSEN_ONE_DOMAIN_NAME="$(printf "$SCRIPT_GIT_BACKUP_PATH" | awk -F[/:] '{print $4}')"
			GIT_THE_CHOSEN_ONE_REQ_URI="${SCRIPT_GIT_BACKUP_PATH#https://*/}"
			
			printf "$GIT_THE_CHOSEN_ONE_REPO will be used\n"
		else
			printf "\n${LRV}ERROR - $SCRIPT_GIT_PATH and $SCRIPT_GIT_BACKUP_PATH both not available\n${NCV}"
			EXIT_STATUS=1
			if [[ $1 == "no_check_exit" ]]; then
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
	if test $EXIT_STATUS != 0; then
		printf "\n${LRV}Last command(s) has failed.\nRemoving preset $PROXY_PREFIX$proxy_target${NCV}"
		
		{
		\rm -f "$NGINX_TEMPLATE" "$NGINX_SSL_TEMPLATE"
		\rm -f /etc/nginx/vhosts-includes/apache_status_[0-9]*.conf
		\rm -f /etc/nginx/vhosts-includes/nginx_status_[0-9]*.conf
		} >/dev/null 2>&1
		
		if $MGR_CTL preset.delete elid=$PROXY_PREFIX$proxy_target elname=$PROXY_PREFIX$proxy_target  >/dev/null 2>&1; then
			printf " - ${GCV}OK${NCV}\n"
		else
			printf " - ${LRV}FAIL${NCV}\n"
		fi
		
		printf "\n${LRV}Restoring last templates backup${NCV}\n"
		if [[ -d "$current_ispmgr_backup_directory" ]] || [[ -d "$current_etc_backup_directory" ]]; then
			\cp -f -p "$NGINX_TEMPLATE_BACKUP" "$NGINX_TEMPLATE" >/dev/null 2>&1 && printf "${GCV}$NGINX_TEMPLATE_BACKUP restore was successful.\n${NCV}"
			\cp -f -p "$NGINX_SSL_TEMPLATE_BACKUP" "$NGINX_SSL_TEMPLATE" >/dev/null 2>&1 && printf "${GCV}$NGINX_SSL_TEMPLATE_BACKUP restore was successful.\n${NCV}"
			\cp -f -p "$NGINX_MAIN_CONF_BACKUP_FILE" "$NGINX_MAIN_CONF_FILE" >/dev/null 2>&1 && printf "${GCV}$NGINX_MAIN_CONF_BACKUP_FILE restore was successful.\n${NCV}"
			# panel graceful restart
			isp_panel_graceful_restart_func
			exit 1
		else 
			printf "\n${LRV}ERROR - $current_etc_backup_directory or $current_ispmgr_backup_directory was not found\n"
			exit 1
		fi
	fi
}

backup_etc_func() {

    BACKUP_ROOT_DIR="/root/support"
    BACKUP_DIR="${BACKUP_ROOT_DIR}/$(date '+%d-%b-%Y-%H-%M-%Z')"

    if \mkdir -p "$BACKUP_ROOT_DIR"; then

        printf "\nCreating configs ${GCV}backup${NCV} to ${BACKUP_DIR}"

        BACKUP_ROOT_DIR_SIZE_MB=$(\du -sm "$BACKUP_ROOT_DIR" 2> /dev/null | awk '{print $1}' | head -n 1)
        BACKUP_DIR_DISK_USE=$(\df "$BACKUP_ROOT_DIR" | sed 1d | awk '{print $5}' | sed 's@%@@gi')

        if [[ "$BACKUP_DIR_DISK_USE" -le 95 ]]; then

            BACKUP_PATH_LIST=("/etc" "/usr/local/mgr5/etc" "/var/spool/cron" "/var/named/domains")

            \mkdir -p "$BACKUP_DIR" > /dev/null 2>&1

            for backup_item in "${BACKUP_PATH_LIST[@]}"; do
                backup_item_size=$(\du -sm --exclude=/etc/ispmysql "${backup_item}" 2>/dev/null | awk '{print $1}')
                if [[ "${backup_item_size}" -lt 2000 ]]; then
                    \cp -Rfp --parents "${backup_item}" "${BACKUP_DIR}" >/dev/null 2>&1
                    \chmod --reference="${backup_item}" "${BACKUP_DIR}${backup_item}" 2>/dev/null
                else
                    printf "${LRV}No backup of ${backup_item} - ${backup_item_size}${NCV}\n"
                fi
            done

            \cp -Rfp --parents "/opt/php"*"/etc/" "$BACKUP_DIR" >/dev/null 2>&1

            for dir in /opt /usr /var; do
                [[ -d "$dir" && -d "${BACKUP_DIR}${dir}" ]] && \chmod --reference="$dir" "${BACKUP_DIR}${dir}" 2>/dev/null
            done

            printf " - ${GCV}OK${NCV}\n"
            if [[ $BACKUP_ROOT_DIR_SIZE_MB -ge 1000 ]]; then
                printf "${YCV}${BACKUP_ROOT_DIR} - ${BACKUP_ROOT_DIR_SIZE_MB}MB ( run: du -sch /root/support/* | sort -h ) ${NCV}\n"
            fi
        else
            printf " - ${LRV}FAIL${NCV}"
            printf "\n%sCannot create configs backup, disk used for 95%% or more%s\n" "${LRV}" "${NCV}"
            exit 1
        fi
    else
        printf "\n${LRV}Cannot create backup dir${NCV}\n"
        exit 1    
    fi
}


# run all tweaks
run_all_tweaks() {

echo
read -p "Skip all tweaks ? [Y/n]" -n 1 -r
echo
if ! [[ $REPLY =~ ^[Nn]$ ]]; then
	# user chose skip all tweaks
	EXIT_STATUS=0

	printf "Tweaks was ${LRV}canceled${NCV} by user choice\n"
else
	backup_etc_func
	tweak_swapfile_func
	tweak_openfiles_func
	tweak_tuned_func
	tweak_dedic_func
	bitrix_env_check_func
	bitrix_fixes_func
	bitrix_install_update_admin_sh_func
	ispmanager_enable_sites_tweaks_func
	ispmanager_enable_features_func
	ispmanager_switch_cgi_mod_func
	ispmanager_tweak_php_and_mysql_settings_func
	ispmanager_tweak_apache_and_php_fpm_func
	tweak_nginx_params_func
	tweak_add_nginx_bad_robot_conf_func

	printf "\nTweaks ${GCV}done${NCV}\n"
fi
}

# check swap file exists if this is virtual server
tweak_swapfile_func() {

if [[ $VIRTUAL == "yes" ]]; then

	#Checking swap file exists and its settings
	if ! grep -i "swap" /etc/fstab >/dev/null 2>&1; then
		echo
		read -p "No swap detected. Fix ? [Y/n]" -n 1 -r
		echo
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then

			# check free space
			CURRENT_FREE_SPACE_GIGABYTES=$(df -BG --sync / | awk '{print $4}' | tail -n 1 | grep -Eo [[:digit:]]+)

			VFS_CACHE_PRESSURE=$(cat /proc/sys/vm/vfs_cache_pressure)
			SWAPPINESS=$(cat /proc/sys/vm/swappiness)
		
			printf "Current vfs_cache_pressure - $VFS_CACHE_PRESSURE ( ${GCV}echo \"vm.vfs_cache_pressure = 100\" >> /etc/sysctl.conf && sysctl -p ${NCV})\n"
			printf "Current swappiness - $SWAPPINESS ( ${GCV}echo \"vm.swappiness = 60\" >> /etc/sysctl.conf && sysctl -p ${NCV})\n"
	
			TOTAL_RAM_IN_GB=$(awk '/MemTotal/ { printf "%.1f\n", $2/1024/1024 }' /proc/meminfo)
			FREE_RAM_IN_MB=$(awk '/MemAvailable/ { printf "%i\n", $2/1024 }' /proc/meminfo)
	
			printf "\n${LRV}There is no swap file in /etc/fstab${NCV} and total ${GCV}$TOTAL_RAM_IN_GB GB RAM${NCV} size. Current free RAM size - ${GCV}$FREE_RAM_IN_MB MB${NCV} \n\n"
			swapsizes=("1GB" "2GB" "3GB" "4GB" "5GB" "10GB")
			swapsizes+=('Skip')
			PS3='Choose swap size to set:'
			select swapsize_choosen_version in "${swapsizes[@]}"
			do
				if [[ $swapsize_choosen_version == Skip || -z $swapsize_choosen_version ]]; then
					break
				else
					SWAPSIZE_CHOOSEN_VERSION_GIGABYTES=$(echo $swapsize_choosen_version | grep -Eo [[:digit:]]+)
					SWAPSIZE_CHOOSEN_VERSION_GIGABYTES_NEEDED=$(($(echo $swapsize_choosen_version | grep -Eo [[:digit:]]+)*2))

					if [[ $CURRENT_FREE_SPACE_GIGABYTES -ge $SWAPSIZE_CHOOSEN_VERSION_GIGABYTES_NEEDED ]]; then
						printf "\nRunning"
						{
						DD_COUNT=$(($(echo $swapsize_choosen_version | grep -Eo [[:digit:]]+)*1024*1024))
						\swapoff /swapfile
						\rm -f /swapfile
						\dd if=/dev/zero of=/swapfile bs=1024 count=$DD_COUNT
						\mkswap /swapfile
						\chmod 600 /swapfile
						\swapon /swapfile
						} >/dev/null 2>&1
	
	
						if swapon --show | grep -i "/swapfile" >/dev/null 2>&1; then
							echo "/swapfile                                 none                    swap    sw              0 0" >> /etc/fstab
							printf " - ${GCV}DONE${NCV}\n"
							break
						else
							printf " - ${LRV}ERROR. Cannot add /swapfile to /etc/fstab${NCV}\n"
							break
						fi
					else
						printf "\n${LRV}ERROR. Not enough free space in / ${NCV}(Only ${LRV}${CURRENT_FREE_SPACE_GIGABYTES}GB${NCV} available for now, ${GCV}${SWAPSIZE_CHOOSEN_VERSION_GIGABYTES_NEEDED}GB${NCV} needed)\nYou may run 'ulimit -Sv 100000; du -a -h / 2> >(grep -v \"Permission denied\") | sort -T /dev/shm -h -r | head -n 100; ulimit -Sv unlimited' to investigate this\n\n"
					fi
				fi
			
			done
		else
			# user chose not to fix swap
			printf "Fix swap was canceled by user choice\n"
		fi
	else
		printf "\nTweak swap file not needed or was ${GCV}already done${NCV}\n"
	fi
fi
}

# tweaking open files limits
tweak_openfiles_func() {

# getting all systemd units we want to tweak file descriptors count to array
NOFILE_TWEAK_SERVICE=($(systemctl show '*' --property=Id --no-pager | sed 's@^Id=@@gi' | grep -E '^httpd\.|^httpd-isp.*|^httpd-scale\.|^apache2\.|^apache2-isp.*|^nginx\.|^maria.*|^mysql.*'))
NOFILE_LIMIT="150000"
TWEAKNEED=();

{
for service in "${NOFILE_TWEAK_SERVICE[@]}"
do
if systemctl list-units --full -all | grep -Fq "${NOFILE_TWEAK_SERVICE}" && [[ $(systemctl show "${service}" | grep -o -P '(?<=LimitNOFILE=)\d+') -lt ${NOFILE_LIMIT} ]]
then
	TWEAK_VALUE="${service}"
	TWEAKNEED+=("${TWEAK_VALUE}")
fi
done

if [[ ${#TWEAKNEED[@]} -gt 0 ]]; then
	TWEAK_NEED="yes"
fi
} >/dev/null 2>&1

if [[ $TWEAK_NEED == "yes" ]]
then
	echo
	read -p "Tweak files descriptors limits to 150K ? [Y/n]" -n 1 -r
	echo
	if ! [[ $REPLY =~ ^[Nn]$ ]]
	then
		sep0="echo =============";
		$sep0
		for service in "${TWEAKNEED[@]}"
		do
		        DIR="/etc/systemd/system/${service}.d"
			{
		        \mkdir -p $DIR
		        {
		                echo "[Service]";
		                echo "LimitNOFILE=${NOFILE_LIMIT}";
		        } > $DIR/nofile.conf
		
		        systemctl daemon-reload
		        systemctl restart ${service}
			} >/dev/null 2>&1
	
			if systemctl show ${service} | grep "LimitNOFILE=${NOFILE_LIMIT}" >/dev/null 2>&1
			then
				printf "${GCV}${service} set file limit success${NCV}\n"
			else
				printf "${LRV}${service} does not exist or set file limit fail${NCV}\n"
			fi
		done
	
		$sep0
	else
		# user chose not to tweak files descriptors limits
		EXIT_STATUS=0
		printf "Tweak files descriptors was canceled by user choice\n"
	fi
	unset NOFILE_TWEAK_SERVICE
	unset TWEAKNEED
	unset TWEAK_NEED

else
	printf "\nTweak files descriptors not needed or was ${GCV}already done${NCV}\n"
fi
}

# install and config tuned tweaker function
tweak_tuned_func() {

if ! systemctl | grep -i tuned >/dev/null 2>&1; then

	printf "\nInstalling and configuring ${GCV}tuned service${NCV}\n"

	if [[ $DISTR == "rhel" ]]; then
	
		{
		if ! which tuned; then
	\yum -y install tuned;
		fi
		} >/dev/null 2>&1
	
	
	elif [[ $DISTR == "debian" ]]; then
	
		{
		if ! which tuned; then
	\apt-get -y install tuned;
		fi
		} >/dev/null 2>&1
	
	else
	        printf "\n${LRV}Sorry, cannot detect this OS${NCV}\n"
	        break
	fi
	
	if [[ $DEDICATED == "yes" ]]; then

		printf "\n${GCV}Current CPU frequencies:${NCV}\n"
		grep -i mhz /proc/cpuinfo

		if which tuned-adm >/dev/null 2>&1; then
			printf "\n${GCV}Applying throughput-performance profile${NCV}\n"
			tuned-adm profile throughput-performance
			systemctl enable --now tuned
			printf "${GCV}Current CPU frequencies:${NCV}\n"
			grep -i mhz /proc/cpuinfo
			echo
			tuned-adm active

		else
			printf "\n${LRV}Sorry, tuned-adm utility was not found${NCV}\n"
		fi

	else
		if which tuned-adm >/dev/null 2>&1; then
			tuned-adm profile virtual-guest
			systemctl enable --now tuned
			tuned-adm active
		else
			printf "\n${LRV}Sorry, tuned-adm utility was not found${NCV}\n"
		fi
	fi

else
	printf "\nTweak tuned not needed or was ${GCV}already done${NCV}\n"
	tuned-adm active
fi

}

# update GRUB loader function
update_grub() {

printf "GRUB update running"

if update-grub >/dev/null 2>&1; then
	printf " - ${GCV}OK${NCV}\n"
	return 0
elif grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1; then
	printf " - ${GCV}OK${NCV}\n"
	return 0
else
	printf " - ${LRV}FAIL${NCV}\n"
	printf "${LRV}GRUB update utility was not found${NCV}\n"
	return 1
fi

}

# tweaks only for dedicated servers
tweak_dedic_func() {

# detecting dedicated server
if [[ $DEDICATED == "yes" ]]; then

	GRUB_FILE="/etc/default/grub"
	KERNEL_CMD_FILE="/etc/kernel/cmdline"

	GRUB_FILE_OPTION=""

	if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "${GRUB_FILE}" >/dev/null 2>&1; then
		GRUB_FILE_OPTION="GRUB_CMDLINE_LINUX_DEFAULT"
	elif grep -q "^GRUB_CMDLINE_LINUX=" "${GRUB_FILE}" >/dev/null 2>&1; then
		GRUB_FILE_OPTION="GRUB_CMDLINE_LINUX"
	else
		printf "\n${LRV}Error:${NCV} ${GRUB_FILE} have no GRUB_CMDLINE_LINUX_DEFAULT or GRUB_CMDLINE_LINUX\n"
		return 1
	fi

	# for Intel CPUs
	if grep -q "GenuineIntel" /proc/cpuinfo >/dev/null 2>&1; then

		# disabling intel_pstate if it exists
		if [[ -f /sys/devices/system/cpu/intel_pstate/status ]] && ! grep -q "intel_pstate=disable" /proc/cmdline >/dev/null 2>&1; then
		
			if [[ ! -f "${GRUB_FILE}" ]]; then
				printf "\n${LRV}Error:${NCV} ${GRUB_FILE} not found!\n"
				return 1
			fi

			echo
			read -p "Disable intel_pstate kernel driver? [Y/n] " -n 1 -r
			echo
			if ! [[ $REPLY =~ ^[Nn]$ ]]; then

				if grubby --update-kernel=DEFAULT --args="intel_pstate=disable" >/dev/null 2>&1; then
					printf "\n${GCV}Sucess.${NCV} ${YCV}Reboot${NCV} the server for deactivate intel_pstate\n"
					printf "After reboot ${YCV}run me again${NCV} to check mhz (showing first 5 cores mhz).\n"
					echo
					grep -i mhz /proc/cpuinfo | head -n 5
					echo
					return 0
				else
					if ! grep -q "intel_pstate=disable" ${GRUB_FILE} >/dev/null 2>&1; then
	
						# adding intel_pstate=disable to GRUB config
						sed -i "/${GRUB_FILE_OPTION}/ {s/intel_pstate=[^\" ]*/intel_pstate=disable/; t; s/\"$/ intel_pstate=disable\"/}" ${GRUB_FILE} >/dev/null 2>&1 || { printf "\n${LRV}Error${NCV} modifying intel_pstate=disable ${GRUB_FILE}\n"; return 1; }
						sed -i "/${GRUB_FILE_OPTION}/ {s/cpufreq.default_governor=[^\" ]*/cpufreq.default_governor=performance/; t; s/\"$/ cpufreq.default_governor=performance\"/}" ${GRUB_FILE} >/dev/null 2>&1 || { printf "\n${LRV}Error${NCV} modifying cpufreq.default_governor=performance ${GRUB_FILE}\n"; return 1; }
	
					fi
	
					if ! grep -q "intel_pstate=disable" ${KERNEL_CMD_FILE} >/dev/null 2>&1; then
	
						# adding intel_pstate=disable to KERNEL_CMD_FILE config if exists
						if [[ -f ${KERNEL_CMD_FILE} ]]; then
							sed -i "/^/ {s/intel_pstate=[^\" ]*/intel_pstate=disable/; t; s/$/ intel_pstate=disable/}" ${KERNEL_CMD_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying intel_pstate=disable ${KERNEL_CMD_FILE}\n"; return 1; }
							sed -i "/^/ {s/cpufreq.default_governor=[^\" ]*/cpufreq.default_governor=performance/; t; s/$/ cpufreq.default_governor=performance/}" ${KERNEL_CMD_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying ${KERNEL_CMD_FILE}\n"; return 1; }
						fi
					fi
	
					# updating GRUB
					if update_grub; then
						printf "\n${GCV}Sucess.${NCV} ${YCV}Reboot${NCV} the server for deactivate intel_pstate\n"
						return 0
					else
						printf "\n${LRV}Error${NCV} in updating GRUB. Check manually ( run bash -xv ).\n"
						return 1
					fi
				fi

			else
				printf "\nKernel intel_pstate disabling was ${YCV}skipped${NCV}\n"
			fi
		else
			printf "\nKernel intel_pstate disable not needed or was ${GCV}already done (showing first 5 cores mhz)${NCV}\n"
			echo
			grep -i mhz /proc/cpuinfo | head -n 5
			echo
			return 0
		fi

	# for AMD CPUs
	elif grep -q "AuthenticAMD" /proc/cpuinfo >/dev/null 2>&1; then
		# enable amd_pstate passive if kernel > 5.17 and amd_pstate not already passive
		kernel_version=$(uname -r | awk -F. '{print $1 * 100 + $2}')
		if (( kernel_version < 517 )) && grep -iq "^CONFIG_X86_AMD_PSTATE=y" /boot/config-$(uname -r); then
		    printf "\nTo enable kernel amd_pstate driver first ${LRV}update the kernel${NCV} to version 5.17 or higher, then run me again.\n"
		    return 1
		fi

		if grep -q "amd_pstate=passive" /proc/cmdline >/dev/null 2>&1 && [[ ! -f /sys/devices/system/cpu/cpu0/cpufreq/amd_pstate_max_freq ]]; then
			printf "\n${LRV}amd_pstate error:${NCV} Just update latest BMC and then the latest BIOS/UEFI firmware. This should be enough.\n"
			printf "If you are still see this message, try to enable CPPC in BIOS ( Advanced > AMD CBS > CPPC / Advanced > AMD Overclocking > CPPC ). \n"
			return 1
		fi

		if [[ ! -f /sys/devices/system/cpu/cpu0/cpufreq/amd_pstate_max_freq ]] >/dev/null 2>&1; then

			if [[ ! -f "${GRUB_FILE}" ]]; then
				printf "\n${LRV}Error:${NCV} ${GRUB_FILE} not found!\n"
				return 1
			fi

			echo
			read -p "Enable amd_pstate kernel driver and set it to passive (Update the BIOS/UEFI firmware may be required) ? [Y/n] " -n 1 -r
			echo
			if ! [[ $REPLY =~ ^[Nn]$ ]]; then

				if grubby --update-kernel=DEFAULT --args="initcall_blacklist=acpi_cpufreq_init cpufreq.default_governor=performance amd_pstate.shared_mem=1 amd_pstate=passive" >/dev/null 2>&1; then
					printf "\n${GCV}Sucess.${NCV} ${YCV}Reboot${NCV} the server for activate amd_pstate passive\n"
					printf "After reboot ${YCV}run me again${NCV} to check mhz (showing first 5 cores mhz).\n"
					echo
					grep -i mhz /proc/cpuinfo | head -n 5
					echo
					return 0
				else

					if ! grep -q "amd_pstate=passive" ${GRUB_FILE} >/dev/null 2>&1 && ! grep -q "amd_pstate=passive" /proc/cmdline; then
						# adding amd_pstate=passive to GRUB config
						sed -i "/${GRUB_FILE_OPTION}/ {s/amd_pstate=[^\" ]*/amd_pstate=passive/; t; s/\"$/ amd_pstate=passive\"/}" ${GRUB_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying amd_pstate=passive ${GRUB_FILE}${NCV}\n"; return 1; }
						sed -i "/${GRUB_FILE_OPTION}/ {s/cpufreq.default_governor=[^\" ]*/cpufreq.default_governor=performance/; t; s/\"$/ cpufreq.default_governor=performance\"/}" ${GRUB_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying cpufreq.default_governor=performance ${GRUB_FILE}${NCV}\n"; return 1; }
	
						sed -i "/${GRUB_FILE_OPTION}/ {s/initcall_blacklist=[^\" ]*/initcall_blacklist=acpi_cpufreq_init/; t; s/\"$/ initcall_blacklist=acpi_cpufreq_init\"/}" ${GRUB_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying initcall_blacklist=acpi_cpufreq_init ${GRUB_FILE}${NCV}\n"; return 1; }
	
						sed -i "/${GRUB_FILE_OPTION}/ {s/amd_pstate.shared_mem=[^\" ]*/amd_pstate.shared_mem=1/; t; s/\"$/ amd_pstate.shared_mem=1\"/}" ${GRUB_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying amd_pstate.shared_mem=1 ${GRUB_FILE}${NCV}\n"; return 1; }
					fi
	
					# adding amd_pstate=passive to KERNEL_CMD_FILE config if exists
					if [[ -f ${KERNEL_CMD_FILE} ]] >/dev/null 2>&1; then
						sed -i "/^/ {s/amd_pstate=[^\" ]*/amd_pstate=passive/; t; s/$/ amd_pstate=passive/}" ${KERNEL_CMD_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying amd_pstate=passive ${KERNEL_CMD_FILE}\n"; return 1; }
						sed -i "/^/ {s/cpufreq.default_governor=[^\" ]*/cpufreq.default_governor=performance/; t; s/$/ cpufreq.default_governor=performance/}" ${KERNEL_CMD_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying cpufreq.default_governor=performance ${KERNEL_CMD_FILE}\n"; return 1; }
						sed -i "/^/ {s/initcall_blacklist=[^\" ]*/initcall_blacklist=acpi_cpufreq_init/; t; s/$/ initcall_blacklist=acpi_cpufreq_init/}" ${KERNEL_CMD_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying initcall_blacklist=acpi_cpufreq_init ${KERNEL_CMD_FILE}\n"; return 1; }
						sed -i "/^/ {s/amd_pstate.shared_mem=[^\" ]*/amd_pstate.shared_mem=1/; t; s/$/ amd_pstate.shared_mem=1/}" ${KERNEL_CMD_FILE} >/dev/null 2>&1  || { printf "\n${LRV}Error${NCV} modifying amd_pstate.shared_mem=1 ${KERNEL_CMD_FILE}\n"; return 1; }
					fi
	
					# updating GRUB
					if update_grub; then
						printf "\n${GCV}Sucess.${NCV} Reboot the server for enable amd_pstate passive\n"
						return 0
					else
						printf "\n${LRV}Error${NCV} in updating GRUB. Check manually ( run bash -xv ).\n"
						return 1
					fi
				fi

			else
				printf "\nKernel amd_pstate passive set up was ${YCV}skipped${NCV}\n"
			fi
		else
			printf "\nKernel amd_pstate passive ${GCV}already${NCV} enabled (showing first 5 cores mhz)\n"
			echo
			grep -i mhz /proc/cpuinfo | head -n 5
			echo
		fi
	else
		printf "\n${YCV}Warning:${NCV} not intel nor AMD CPU. Skipped.\n"
	fi
fi
}



bitrix_env_check_func() {

# detecting bitrix and bitrix alike environments
if grep -RiIl BITRIX_VA_VER /etc/*/bx/* --include="*.conf" >/dev/null 2>&1 || ( 2>&1 nginx -T | \grep -iI "bitrix_general.conf" >/dev/null 2>&1 && [[ ! -f $MGR_BIN ]] >/dev/null 2>&1 ); then

	# bitrix GT (nginx+apache+fpm)
	if (grep -riI "^LoadModule proxy_fcgi" /etc/apache2/*enabled*/* >/dev/null 2>&1 && systemctl | grep -i fpm >/dev/null 2>&1) || ( grep -riI "^LoadModule proxy_fcgi" /etc/httpd/* >/dev/null 2>&1 && systemctl | grep -i fpm >/dev/null 2>&1); then
		printf "\n${GCV}Bitrix GT${NCV} environment detected\n"
		BITRIX="GT"
	# bitrix ENV (nginx+apache)
	elif [[ -d /opt/webdir ]]; then
		bitrix_env_version=$(egrep -o 'BITRIX_VA_VER=[0-9\.]+' /root/.bash_profile | awk -F'=' '{print $2}' )
		printf "\n${GCV}Bitrix ${bitrix_env_version} env${NCV}ironment detected\n"
		BITRIX="ENV"
	# bitrix VANILLA (nginx+apache)
	elif 2>&1 nginx -T | grep -i "server httpd:8090" >/dev/null 2>&1; then
		printf "\n${GCV}Bitrix Vanilla${NCV} environment detected\n"
		BITRIX="VANILLA"
	# bitrix OTHER
	else
		printf "\n${GCV}Bitrix${NCV} environment derivative detected\n"
		BITRIX="OTHER"
	fi

BITRIXALIKE="yes"
fi

}

download_file_func() {

# check args n
if [[ $# -ne 2 ]]; then
	printf "\n${LRV}Error:${NCV} Not enouth args.\n"
	printf "\n${LRV}1:${NCV}$1\n"
	printf "\n${LRV}2:${NCV}$2\n"
	return 1
fi

# check args not empty
for arg in "$@"; do
	if [[ -z "$arg" ]]; then
		printf "\n${LRV}Error:${NCV} Empty arg.\n"
		printf "\n${LRV}1:${NCV}$1\n"
		printf "\n${LRV}2:${NCV}$2\n"
		return 1
	fi
done

local full_url="$1"
local file_path_local="$2"
local remote_hostname=$(echo "$1" | awk -F[/:] '{print $4}')

printf "\nDownloading ${full_url} to ${file_path_local}"

{
if \wget --timeout 4 --no-check-certificate -q -O ${file_path_local} ${full_url}; then
	full_url_size=$(wget --spider --server-response ${full_url} 2>&1 | grep "Content-Length" | awk '{print $2}')
else
	if printf "GET ${full_url} HTTP/1.1\nHost:${remote_hostname}\nConnection:Close\n\n" | timeout 5 \openssl 2>/dev/null s_client -crlf -connect ${remote_hostname}:443 -quiet | sed '1,/^\s$/d' > "${file_path_local}"; then
		full_url_size=$(printf "HEAD ${full_url} HTTP/1.1\nHost:${remote_hostname}\nConnection:Close\n\n" | timeout 5 \openssl 2>/dev/null s_client -crlf -connect ${remote_hostname}:443 -quiet | grep "Content-Length" | awk '{print $2}')
	fi
fi
}  >/dev/null 2>&1

# get filesize in bytes for downloaded file_path_local file
file_path_local_size=$(\stat --printf="%s" ${file_path_local} 2>/dev/null)

# if both file sizes differs then something failed
if [[ ${full_url_size} -gt 30 ]] && [[ ${full_url_size} -eq ${file_path_local_size} ]]; then
	printf " - ${GCV}OK${NCV}\n"
	return 0
else
	printf " - ${LRV}FAIL${NCV}\n"
	return 1
fi

}

bitrix_install_update_admin_sh_func() {

if [[ $BITRIXALIKE == "yes" ]]; then

	if [[ $BITRIX == "GT" ]]; then
		if cat /etc/*rele* | grep "CentOS Linux 7" >/dev/null 2>&1; then
			ADMIN_SH_BITRIX_FILE_URL="https://gitlab.hoztnode.net/admins/scripts/-/raw/master/admin.sh"
		else
			ADMIN_SH_BITRIX_FILE_URL="https://gitlab.hoztnode.net/admins/scripts/-/raw/master/admin-bitrix-gt.sh"
		fi
	elif [[ $BITRIX == "VANILLA" ]]; then
		ADMIN_SH_BITRIX_FILE_URL="https://gitlab.hoztnode.net/admins/scripts/-/raw/master/admin-bitrix-vanilla.sh"
	else
		return
	fi
	
	# get filesize in bytes for remote ADMIN_SH_BITRIX_FILE_URL
	{
	if command -v wget >/dev/null 2>&1; then 
		ADMIN_SH_BITRIX_FILE_REMOTE_SIZE=$(wget --spider --server-response $ADMIN_SH_BITRIX_FILE_URL 2>&1 | grep "Content-Length" | awk '{print $2}')
	else
		ADMIN_SH_BITRIX_FILE_REMOTE_SIZE=$(printf "HEAD $ADMIN_SH_BITRIX_FILE_URL HTTP/1.1\nHost:gitlab.hoztnode.net\nConnection:Close\n\n" | timeout 5 \openssl 2>/dev/null s_client -crlf -connect gitlab.hoztnode.net:443 -quiet | grep "Content-Length" | awk '{print $2}')
	fi
	}  >/dev/null 2>&1
	
	# get / update admin.sh for GT or Vanilla
	if [[ -f $ADMIN_SH_BITRIX_FILE_LOCAL ]]; then
		
		# get filesize in bytes for existing ADMIN_SH_BITRIX_FILE_LOCAL file
		ADMIN_SH_BITRIX_FILE_LOCAL_SIZE=$(\stat --printf="%s" ${ADMIN_SH_BITRIX_FILE_LOCAL})

		# if ADMIN_SH_BITRIX_FILE_REMOTE_SIZE defined, remote file size not null and both file sizes differs ask user for update
		if [[ ! -z $ADMIN_SH_BITRIX_FILE_REMOTE_SIZE ]] && [[ $ADMIN_SH_BITRIX_FILE_REMOTE_SIZE -gt 30 ]] && [[ $ADMIN_SH_BITRIX_FILE_REMOTE_SIZE -ne $ADMIN_SH_BITRIX_FILE_LOCAL_SIZE ]]; then
			echo
			read -p "Update existing ${ADMIN_SH_BITRIX_FILE_LOCAL} script to the newer version ? [Y/n]" -n 1 -r
			if ! [[ $REPLY =~ ^[Nn]$ ]]; then
				cp_date=$(date '+%d-%b-%Y-%H-%M')
				\cp ${ADMIN_SH_BITRIX_FILE_LOCAL} ${ADMIN_SH_BITRIX_FILE_LOCAL}.${cp_date} >/dev/null 2>&1
				if [[ -f ${ADMIN_SH_BITRIX_FILE_LOCAL}.${cp_date} ]]; then
					# backup previous
					printf "\nPrevious file - ${ADMIN_SH_BITRIX_FILE_LOCAL}.${cp_date}"
					# download new
					if download_file_func "$ADMIN_SH_BITRIX_FILE_URL" "/root/admin.sh"; then
						if ! chmod +x "$ADMIN_SH_BITRIX_FILE_LOCAL"; then
							printf "\n${YCV}Chmod +x ${ADMIN_SH_BITRIX_FILE_LOCAL} failed"
						fi
					fi
				else
					# backup failed
					printf "\n${LRV}Backup ${ADMIN_SH_BITRIX_FILE_LOCAL} to ${ADMIN_SH_BITRIX_FILE_LOCAL}.$(date '+%d-%b-%Y-%H-%M') FAILED${NCV}"
					printf "\nDownload ${LRV}skipped${NCV}\n"
					return
				fi
			else
				printf "\nUpdate of ${ADMIN_SH_BITRIX_FILE_LOCAL} skipped\n"
			fi
		else
			printf "\nFile ${ADMIN_SH_BITRIX_FILE_LOCAL} is ${GCV}up to date${NCV}\n"
		fi
	
	else
		# download new
		if download_file_func "$ADMIN_SH_BITRIX_FILE_URL" "/root/admin.sh"; then
			if ! chmod +x "$ADMIN_SH_BITRIX_FILE_LOCAL"; then
				printf "\n${YCV}Chmod +x ${ADMIN_SH_BITRIX_FILE_LOCAL} failed"
			fi
		fi
	fi
fi

}

# fixing bitrix bugs
bitrix_fixes_func() {

if [[ $BITRIXALIKE == "yes" ]]; then

	bitrix_php_version=$(\php -v | head -n 1 | awk '{print $2}' | sed 's/\.[^.]*$//')

	# if checking_mod_rpaf_func and nginx_port_expose_detect_func loaded ok
	if declare -F checking_mod_rpaf_func > /dev/null && declare -F nginx_port_expose_detect_func > /dev/null; then

		# RPAF apache module install
		if ! checking_mod_rpaf_func || nginx_port_expose_detect_func ; then
			echo
			read -p "Install apache mod_rpaf and disable nginx port expose ? [Y/n]" -n 1 -r
			if ! [[ $REPLY =~ ^[Nn]$ ]]; then
				bash <(timeout 4 wget --timeout 4 --no-check-certificate -q -o /dev/null -O- https://bit.ly/3wL8B2u)
			else
				# user chose not to install RPAF and fix nginx port exposion
				printf "\nRPAF and nginx port exposion fix ${YCV}skipped${NCV}\n"
			fi
		else
			# RPAF installed and fix nginx port exposion done
			printf "\nRPAF and nginx port exposion fix ${GCV}already done${NCV}\n"
		fi
	else
		# error loading checking_mod_rpaf_func or nginx_port_expose_detect_func
		printf "\n${LRV}Error${NCV} Cannot exec checking_mod_rpaf_func or nginx_port_expose_detect_func\n"
	fi

	# check if cURL PHP not enabled
	if ! \php -m | grep -i curl >/dev/null 2>&1; then
		echo
		read -p "Enable PHP cURL extension ? [Y/n]" -n 1 -r
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then

			printf "Enabling cURL extension for PHP ${bitrix_php_version}"
			{ 
			\apt install -y php${bitrix_php_version}-curl || \mv -f /etc/php.d/20-curl.ini.disabled /etc/php.d/20-curl.ini
			if \apt list --installed php${bitrix_php_version}-curl; then 
				echo "extension=curl.so" > /etc/php/${bitrix_php_version}/mods-available/curl.ini && ln -s /etc/php/${bitrix_php_version}/mods-available/curl.ini /etc/php/${bitrix_php_version}/apache2/conf.d/20-curl.ini && ln -s /etc/php/${bitrix_php_version}/mods-available/curl.ini /etc/php/${bitrix_php_version}/cli/conf.d/20-curl.ini
			fi
			sleep 1
			} >/dev/null 2>&1
		 		
			if \php -m | grep -i curl >/dev/null 2>&1; then
				systemctl restart httpd* apache2* php-fpm*
				printf " - ${GCV}OK${NCV}\n"
			else
				printf " - ${LRV}FAIL${NCV}\n"
			fi
		fi
	else
		printf "\nEnable PHP cURL extension not needed or was ${GCV}already done${NCV}\n"
	fi
	
else
	# not bitrix env or user chosen not to fix Bitrix env
	printf "\nSkipping Bitrix environment tweaks, ${GCV}not detected${NCV} or skipped\n"
fi

}

# punycode convert
puny_converter() {

# install idn2
if ! which idn2; then apt update; apt -y install idn2 || yum -y install idn2; fi > /dev/null 2>&1

idn2 "$1"

}

# tweak sites settings need or not function
ispmanager_enable_sites_tweaks_need_func() {

for site in $($MGR_CTL webdomain | awk -F'name=' '{print $2}' | awk '{print $1}' | sort); do
	# converting to idn
	site=$(puny_converter ${site})

	# check tweaks needed or not
	if $MGR_CTL site.edit elid=${site} | grep -i "site_ddosshield=on"  || ! $MGR_CTL site.edit elid=${site} | grep -i "site_gzip_level=5" || ! $MGR_CTL site.edit elid=${site} | grep -i "site_expire_times=expire_times_max" || $MGR_CTL site.edit elid=${site} | grep -i "site_srv_cache=off"; then
		# check for dupes in array
		if [[ ! " ${SITES_TWEAKS_NEEDED_SITES[@]} " =~ " ${site} " ]]; then
			SITES_TWEAKS_NEEDED="YES"
			SITES_TWEAKS_NEEDED_SITES+=("${site}")
		fi
	fi
done

# enable HSTS http header for the site if tls is on
for site in $($MGR_CTL webdomain | grep "secure=on" | awk -F'name=' '{print $2}' | awk '{print $1}'); do
	# converting to idn
	site=$(puny_converter ${site})

	if $MGR_CTL site.edit elid=${site} | grep "site_hsts=off" >/dev/null 2>&1; then
		# check for dupes in array
		if [[ ! " ${SITES_TWEAKS_NEEDED_SITES[@]} " =~ " ${site} " ]]; then
			SITES_TWEAKS_NEEDED="YES"
			SITES_TWEAKS_NEEDED_SITES+=("${site}")
		fi
	fi
done

} >/dev/null 2>&1

ispmanager_enable_sites_tweaks_func() {

if [[ -f $MGR_BIN ]]; then

	# lic validation
	isp_panel_check_license_version
	
	# enable http/2
	if $MGR_CTL websettings | grep "http2=off" >/dev/null 2>&1; then
		echo
		read -p "Enable http/2 for webserver in ISP panel ? [Y/n]" -n 1 -r
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then
			# Enable http/2 isp manager
			printf "Running"
			if $MGR_CTL websettings http2=on sok=ok >/dev/null 2>&1; then
				printf " - ${GCV}OK${NCV}\n"
			else
				printf " - ${LRV}FAIL${NCV}\n"
			fi
		fi
	else
		printf "\nhttp/2 ${GCV}already enabled${NCV}\n"
	fi
	
	# tweak sites settings need or not function
	ispmanager_enable_sites_tweaks_need_func
	
	if [[ $SITES_TWEAKS_NEEDED == "YES" ]]; then
		printf "\n${GCV}Tweaking ISP Manager sites include:${NCV}\nsite_ddosshield=off\nsite_gzip_level=5\nsite_srv_cache=on (client cache)\nsite_expire_times=expire_times_max (client cache)\nhsts=on (if TLS is enabled)\n"
		echo
		printf "${GCV}"
		read -p "Apply above tweaks ? [Y/n]" -n 1 -r
		printf "${NCV}"	
	
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then
			echo
			for site in "${SITES_TWEAKS_NEEDED_SITES[@]}"; do
				printf "Processing ${GCV}${site}${NCV} - "

				# if site ip addrs more than one, ISP Manager will raise error w/o site_ipaddrs param
				# so getting it
				site_ipaddrs=$($MGR_CTL site.edit elid=${site} | awk -F'site_ipaddrs=' '{print $2}' | awk '{print $1}' | grep . | tr '\n' ',' | sed 's/,$//')

				$MGR_CTL site.edit elid=${site} site_ddosshield=off site_gzip_level=5 site_hsts=on site_srv_cache=on site_expire_times=expire_times_max site_ipaddrs=${site_ipaddrs} sok=ok
			done
		else
			printf "\n${YCV}Tweaking ISP Manager sites was skipped.${NCV} \n"
			SITES_TWEAKS_NEEDED=""
			SITES_TWEAKS_NEEDED_SITES=()
		fi
	else
		# sites tweaks not needed
		printf "\nISP Manager sites tweaks not needed or was ${GCV}already done${NCV}\n"
	fi
	
	SITES_TWEAKS_NEEDED=""
	SITES_TWEAKS_NEEDED_SITES=()
	echo
fi
}

isp_no_mod_php_check() {

# check no mod-php php versions
NO_MOD_PHP=()
for php_version in $($MGR_CTL feature | grep PHP | grep "active=on" | grep -E 'name=altphp' |  grep -v "Apache module" | awk -F'name=' '{print $2}' | awk '{print $1}' | grep -Eo [[:digit:]]+); do
	# check for dupes in array
	if [[ ! " ${NO_MOD_PHP[@]} " =~ " ${php_version} " ]]; then
		NO_MOD_PHP+=("${php_version}")
	fi
done

} >/dev/null 2>&1

ispmanager_switch_cgi_mod_func() {

if [[ -f $MGR_BIN ]]; then

	# lic validation
	isp_panel_check_license_version
	
	if $MGR_CTL webdomain | grep -i "PHP CGI" >/dev/null 2>&1 || [[ -f $MGR_BIN ]] && $MGR_CTL user | grep "limit_php_mode_cgi=on" >/dev/null 2>&1; then
		echo
		read -p "Switch all php-cgi sites to mod-php and disable php-cgi for all users in ISP panel ? [Y/n]" -n 1 -r
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then
			# check isp lic
			isp_panel_check_license_version
	
			# install all ISP Manager mod-php for installed PHP if not already installed
			isp_no_mod_php_check
	
			if [[ ! -z "${NO_MOD_PHP+x}" ]]; then
	
				printf "Running mod-php installation"
				for no_mod_php in ${NO_MOD_PHP[@]}; do
					$MGR_CTL feature.edit elid=altphp${no_mod_php} package_ispphp${no_mod_php}_fpm=on package_ispphp${no_mod_php}_mod_apache=on packagegroup_altphp${no_mod_php}gr=ispphp${no_mod_php} sok=ok >/dev/null 2>&1
				done
		
				# waiting for installation
				timeout_duration=300
				start_time=$(date +%s)
		
				while true; do
					# timeout check
					current_time=$(date +%s)
					elapsed_time=$((current_time - start_time))
					
					if [[ "$elapsed_time" -ge "$timeout_duration" ]]; then
						printf "\n${LRV}Timed out waiting for PHP version - ispphp${no_mod_php} while check $MGR_CTL feature ${NCV}\n"
						break
					fi
					
					# checking for all php-mod installed
					isp_no_mod_php_check
					if [[ -z "${NO_MOD_PHP+x}" ]]; then
					printf " - ${GCV}DONE${NCV}\n"
						break
					else
						sleep 5
					fi
				done
			fi
	
			# Enable php-mod for all users
			echo
			$MGR_CTL user | grep -v "limit_php_mode_mod" | awk -F'name=' '{print $2}' | awk '{print $1}' | while read -r user; do 
				printf "Enabling PHP-MOD for ${GCV}$user${NCV} - "
				$MGR_CTL user.edit elid=${user} limit_php_mode_mod=on sok=ok
			done
	
			echo
	
			# Switching php-cgi sites to mod-php
			$MGR_CTL webdomain | grep -i "PHP CGI" | while read -r cgi_enabled_site; do 
				name=$(echo "$cgi_enabled_site" | awk -F'name=' '{print $2}' | awk '{print $1}')
				php_version=$(echo "$cgi_enabled_site" | grep -oP 'php_version=\K[0-9. ()a-zA-Z]+(?=\s|$)' | grep -o native || echo "$cgi_enabled_site" | grep -oP 'php_version=\K[0-9. ()a-zA-Z]+(?=\s|$)' | sed 's@\.@@gi' | sed -n 's/^\([0-9]\{2\}\).*/isp-php\1/p')
	
				if [[ -n $name && -n $php_version ]]; then

					# converting to idn
					name=$(puny_converter ${name})

					# if site ip addrs more than one, ISP Manager will raise error w/o site_ipaddrs param
					# so getting it
					site_ipaddrs=$($MGR_CTL site.edit elid=${name} | awk -F'site_ipaddrs=' '{print $2}' | awk '{print $1}' | grep . | tr '\n' ',' | sed 's/,$//')

					printf "Switching ${GCV}$name $php_version${NCV} from PHP-CGI to PHP Module - "
					$MGR_CTL site.edit elid=${name} site_php_mode=php_mode_mod site_php_fpm_version=${php_version} site_php_cgi_version=${php_version} site_php_apache_version=${php_version} site_ipaddrs=${site_ipaddrs} sok=ok
				fi
			done
	
			# Disable php-cgi for all users
			echo
			$MGR_CTL user | grep "limit_php_mode_cgi=on" | awk -F'name=' '{print $2}' | awk '{print $1}' | while read -r user; do 
				printf "Disabling PHP-CGI for ${GCV}$user${NCV} - "
				$MGR_CTL user.edit elid=${user} limit_php_mode_mod=on limit_php_mode_cgi=off limit_php_mode_fcgi_nginxfpm=on limit_ssl=on limit_cgi=on sok=ok
			done
		fi
	else
		printf "Switch or disable php-cgi not needed or was ${GCV}already done${NCV}\n"
	fi
fi
}

# Install opendkim and php features in ISP panel
ispmanager_enable_features_func() {

if [[ -f $MGR_BIN ]]; then

	# lic validation
	isp_panel_check_license_version

	# nginx install
	if $MGR_CTL feature | grep "nginx" | grep "active=off" >/dev/null 2>&1
	then
		echo
		read -p "Install Nginx in ISP panel ? [Y/n]" -n 1 -r
		echo
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then
			printf "Running"
			$MGR_CTL feature.edit elid=web package_logrotate=on package_nginx=on package_php=on package_php-fpm=on sok=ok

			# waiting for installation
			timeout_duration=300
			start_time=$(date +%s)
		
			while true; do
				# timeout check
				current_time=$(date +%s)
				elapsed_time=$((current_time - start_time))
					
				if [[ "$elapsed_time" -ge "$timeout_duration" ]]; then
					printf " - ${LRV}FAIL${NCV} Timed out waiting for nginx while checking $MGR_CTL feature\n"
					break
				fi

				# checking for nginx installed
				if $MGR_CTL feature 2> /dev/null | grep "nginx" | grep "active=on" >/dev/null 2>&1; then
				printf " - ${GCV}DONE${NCV}\n"
					break
				else
					sleep 5
				fi
			done
		else
			# user chose not to enable ISP manager nginx feature
			printf "\n${YCV}Nginx was not installed${NCV}\n"
		fi
	fi

	# PHP and opendkim features install
	if 

	{
	$MGR_CTL feature | grep "PHP" | grep "active=off" || $MGR_CTL feature | grep -i "opendkim" | grep "active=off"
	} >/dev/null 2>&1

	then
		read -p "Install opendkim, and all PHP versions in ISP panel ? [Y/n]" -n 1 -r
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then
			printf "Running"
			{
			isp_php_versions=("52" "53" "54" "55" "56" "70" "71" "72" "73" "74" "80" "81" "82" "83" "84" "85" "90" "91" "92")

			$MGR_CTL feature.edit elid=email package_opendkim=on sok=ok
			$MGR_CTL feature.edit elid=email package_clamav=off package_clamav-postfix=off package_clamav-sendmai=off sok=ok
			for version in "${isp_php_versions[@]}"; do 
				$MGR_CTL feature.edit elid=altphp${version} package_ispphp${version}_fpm=on package_ispphp${version}_mod_apache=on packagegroup_altphp${version}gr=ispphp${version} sok=ok
			done

			# latest avail altphp
			latest_php_avail_in_panel=$($MGR_CTL feature | grep altphp | tail -n 1 | cut -d'=' -f2 | cut -d' ' -f1)

			# running while cycle until we found latest php or timed out
			timeout_duration=600
			start_time=$(date +%s)
			} >/dev/null 2>&1
			
			while true; do
			    # timeout check
			    current_time=$(date +%s)
			    elapsed_time=$((current_time - start_time))
			
			    if [[ "$elapsed_time" -ge "$timeout_duration" ]]; then
			         printf "\n${LRV}Timed out waiting for PHP version - ${latest_php_avail_in_panel} while check $MGR_CTL feature ${NCV}\n"
			         break
			    fi
			
			    # checking for latest_php_avail_in_panel is installed
			    if $MGR_CTL feature 2> /dev/null | grep -i ${latest_php_avail_in_panel} | grep -i "Apache module" | grep -i "active=on" > /dev/null 2>&1; then
			        printf " - ${GCV}DONE${NCV}\n"
			        break
			    else
			        sleep 5
			    fi
			done
		else
			# user chose not to enable ISP manager features 
			printf "\n${YCV}All PHP versions was not installed so as OpenDKIM${NCV} \n"
		fi
	fi
fi
}

# tweaking all installed php versions and mysql through ISP Manager panel API
ispmanager_tweak_php_and_mysql_settings_func() {

if [[ -f $MGR_BIN ]]; then

	# lic validation
	isp_panel_check_license_version

	# ISP mysql 8 include bugfix
	isp_mysql_include_bugfix() {
		# fix ISP panel mysql include bug
		if [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]] && ! grep "^\!includedir /etc/mysql/mysql.conf.d/" /etc/mysql/my.cnf >/dev/null 2>&1; then
			printf "\n${GCV}ISP panel MySQL 8 no include path bug was fixed${NCV}\n"
			echo '!'"includedir /etc/mysql/mysql.conf.d/" >> /etc/mysql/my.cnf
			systemctl restart mysql mysqld mariadb >/dev/null 2>&1
			sleep 5s
		fi
	}

	# tweak ISP PHP
	isp_php_tweak() {

		if [ -z "$1" ]; then
			printf "${LRV}No PHP version argument was passed to isp_php_tweak function.${NCV}\n"
		else
			{
			$MGR_CTL phpconf.settings plid=$1 elid=$1 max_execution_time=300 memory_limit=1024 post_max_size=1024 upload_max_filesize=1024 sok=ok

			# if 5x PHP disable opcache extension, else configuring it
			if [[ "$1" =~ (5[0-9]) ]]; then
				$MGR_CTL phpextensions.suspend plid=$1 elid=opcache elname=opcache sok=ok
			else
				$MGR_CTL phpextensions.install plid=$1 elid=opcache elname=opcache sok=ok
				$MGR_CTL phpextensions.resume plid=$1 elid=opcache elname=opcache sok=ok
				$MGR_CTL phpconf.edit plid=$1 elid=opcache.revalidate_freq value=0 sok=ok
				$MGR_CTL phpconf.edit plid=$1 elid=opcache.memory_consumption apache_value=300 cgi_value=300 fpm_value=300 sok=ok
				$MGR_CTL phpconf.edit plid=$1 elid=opcache.memory_consumption value=300 sok=ok
				$MGR_CTL phpconf.edit plid=$1 elid=opcache.max_accelerated_files apache_value=100000 cgi_value=100000 fpm_value=100000 sok=ok
				$MGR_CTL phpconf.edit plid=$1 elid=opcache.max_accelerated_files value=100000 sok=ok

			fi
			
			$MGR_CTL phpextensions.resume plid=$1 elid=bcmath elname=bcmath sok=ok
			$MGR_CTL phpextensions.install plid=$1 elid=imagick elname=imagick sok=ok
			$MGR_CTL phpextensions.resume plid=$1 elid=imagick elname=imagick sok=ok
			$MGR_CTL phpextensions.install plid=$1 elid=ioncube elname=ioncube sok=ok
			$MGR_CTL phpextensions.resume plid=$1 elid=ioncube elname=ioncube sok=ok
			$MGR_CTL phpextensions.install plid=$1 elid=memcache elname=memcache sok=ok 
			$MGR_CTL phpextensions.resume plid=$1 elid=memcache elname=memcache sok=ok
			$MGR_CTL phpextensions.install plid=$1 elid=memcached elname=memcached sok=ok
			$MGR_CTL phpextensions.resume plid=$1 elid=memcached elname=memcached sok=ok
			$MGR_CTL phpextensions.install plid=$1 elid=mysql elname=mysql sok=ok
			$MGR_CTL phpextensions.resume plid=$1 elid=mysql elname=mysql sok=ok
			$MGR_CTL phpextensions.install plid=$1 elid=xsl elname=xsl sok=ok
			$MGR_CTL phpextensions.resume plid=$1 elid=xsl elname=xsl sok=ok
			$MGR_CTL phpconf.edit plid=$1 elid=opcache.revalidate_freq apache_value=0 cgi_value=0 fpm_value=0 sok=ok

			$MGR_CTL phpconf.edit plid=$1 elid=max_input_vars apache_value=150000 cgi_value=150000 fpm_value=150000 sok=ok
			$MGR_CTL phpconf.edit plid=$1 elid=max_input_vars apache_value=150000 cgi_value=150000 fpm_value=150000 sok=ok
			$MGR_CTL phpconf.edit plid=$1 elid=max_input_vars value=150000 sok=ok
			# tweaking native php version for phpmyadmin upload size large dumps
			$MGR_CTL phpconf.settings plid=native elid=native max_execution_time=1800 memory_limit=2048 post_max_size=2048 upload_max_filesize=2048 sok=ok

			} >/dev/null 2>&1
		fi
	}

	# tweak ISP MySQL
	isp_mysql_tweak() {

		if [ -z "$1" ]; then
			printf "${LRV}No MySQL version argument was passed to isp_mysql_tweak function.${NCV}\n"
		else
			{
			# check docker or not
			if $MGR_CTL db.server | grep "$1" | grep "docker=on" >/dev/null 2>&1
			then
			MYSQL_CHOOSEN_VERSION_DOCKER="in_docker"
			else
			MYSQL_CHOOSEN_VERSION_DOCKER="not_in_docker"
			fi
			
			#native mysql version disable binlog if no replicas exists
			if [[ $MYSQL_CHOOSEN_VERSION_DOCKER == "not_in_docker" ]] && mysql -e "show slave status;" -vv | grep -i "Empty set" >/dev/null 2>&1 && ! grep -RIiE "disable_log_bin|skip-log-bin|skip_log_bin" /etc/my* >/dev/null 2>&1
			then
				# RHEL
				if [[ $DISTR == "rhel" ]] && [[ -f /etc/my.cnf.d/mysql-server.cnf ]]
				then
					{
				        	printf "\nskip-log-bin\n" >> /etc/my.cnf.d/mysql-server.cnf
						systemctl restart mysql mysqld mariadb >/dev/null 2>&1
						\rm -f /var/lib/mysql/binlog.* >/dev/null 2>&1
					} >/dev/null 2>&1
				
				elif [[ $DISTR == "rhel" ]] && [[ -f /etc/my.cnf.d/mariadb-server.cnf ]]
				then
					{
						printf "\nskip-log-bin\n" >> /etc/my.cnf.d/mariadb-server.cnf
						systemctl restart mysql mysqld mariadb >/dev/null 2>&1
						\rm -f /var/lib/mysql/binlog.* >/dev/null 2>&1
					} >/dev/null 2>&1
				
				# DEBIAN
				elif [[ $DISTR == "debian" ]] && [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]]
				then
					{
				        	printf "\nskip-log-bin\n" >> /etc/mysql/mysql.conf.d/mysqld.cnf
						systemctl restart mysql mysqld mariadb
						\rm -f /var/lib/mysql/binlog.* 
					} >/dev/null 2>&1
				elif [[ $DISTR == "debian" ]] && [[ -f /etc/mysql/mariadb.conf.d/50-server.cnf ]]
				then
					{
						printf "\nskip-log-bin\n" >> /etc/mysql/mariadb.conf.d/50-server.cnf
						systemctl restart mysql mysqld mariadb
						\rm -f /var/lib/mysql/binlog.* 
					} >/dev/null 2>&1
				
				# UNKNOWN
				elif [[ $DISTR == "unknown" ]]
				then
				        printf "\n${LRV}Sorry, cannot detect this OS, add skip-log-bin to cnf file in [mysqld] section by hands${NCV}\n"
				fi
			fi
			
			if [[ $MYSQL_CHOOSEN_VERSION_DOCKER == "in_docker" ]]
			then
			printf "\nskip-log-bin\n" >> /etc/ispmysql/$1/custom.cnf
			fi
			
			$MGR_CTL db.server.settings.edit plid=$1 elid=innodb-strict-mode name=innodb-strict-mode bool_value=FALSE value=FALSE sok=ok
			$MGR_CTL db.server.settings.edit plid=$1 elid=sql-mode name=sql-mode value='' str_value='' sok=ok
			$MGR_CTL db.server.settings.edit plid=$1 elid=innodb-flush-method name=innodb-flush-method value=O_DIRECT str_value=O_DIRECT sok=ok
			$MGR_CTL db.server.settings.edit plid=$1 elid=innodb-flush-log-at-trx-commit name=innodb-flush-log-at-trx-commit value=2 int_value=2 str_value=2 sok=ok
			$MGR_CTL db.server.settings.edit plid=$1 elid=transaction-isolation name=transaction-isolation value=READ-COMMITTED str_value=READ-COMMITTED sok=ok

			sleep 10
			} >/dev/null 2>&1
		fi
	}

	# getting all PHP version from ISP panel and processing tweaks
	isp_all_php_version_tweak() {	
			
			$MGR_CTL phpversions | grep -E 'apache=on|fpm=on' | awk '{print $1}' | grep -o -P '(?<=key=).*' | while read php_version; do 
			printf "\nTweaking ${php_version}"
			isp_php_tweak ${php_version}
			printf " - ${GCV}DONE${NCV}"
			done
			echo
	}

	# getting all MySQL version from ISP panel and processing tweaks
	isp_all_mysql_version_tweak() {
			$MGR_CTL db.server | grep -E 'type=mysql' | awk '{print $2}' | grep -o -P '(?<=name=).*' | while read mysql_version; do 
			printf "\nTweaking ${mysql_version}"
			isp_mysql_tweak ${mysql_version}
			printf " - ${GCV}DONE${NCV}"
			done
			echo
	}

	printf "\n${GCV}Tweaking PHP include:${NCV}\nmax_execution_time = 300s\npost_max_size = 1024m\nupload_max_filesize = 1024m\nmemory_limit = 1024m\nopcache.revalidate_freq = 0\nmax_input_vars = 150000\nopcache.max_accelerated_files = 100000\nopcache.memory_consumption = 300MB\n\nand enable PHP extensions: opcache (not for PHP 5x), mysql, memcached, ioncube, imagick, bcmath, xsl\n"

	printf "\n${GCV}Tweaking MySQL include:${NCV}\ninnodb_strict_mode = off\nsql_mode = ''\ninnodb_flush_method = O_DIRECT\ntransaction_isolation = READ-COMMITTED\ninnodb_flush_log_at_trx_commit = 2\n\nand disable binlog if no replicas exists\n"

	echo
	printf "${GCV}"
	printf "\nApply above tweaks to all PHP version (and MySQL) or exact version ?\n"
	printf "${NCV}"
	
	options=("All PHP and MySQL" "All PHP only" "All MySQL only" "Exact PHP and MySQL versions" "Skip")

	select opt in "${options[@]}"; do
	case $opt in

		"All MySQL only")

			# applying bugfixes
			isp_mysql_include_bugfix

			# run all mysql versions tweak
			isp_all_mysql_version_tweak

			break
			;;

		"All PHP only")

			# run all php versions tweak
			isp_all_php_version_tweak

			break
			;;
	
		"All PHP and MySQL")

			# applying bugfixes
			isp_mysql_include_bugfix

			# run all php versions tweak
			isp_all_php_version_tweak

			# run all mysql versions tweak
			isp_all_mysql_version_tweak

			break
			;;
	
		"Exact PHP and MySQL versions")
			isp_mysql_include_bugfix
			
			printf "\n${GCV}PHP${NCV}\n"
			# get isp panel installed php versions into the array phpversions
			phpversions=(); while IFS= read -r version; do phpversions+=( "$version" ); done < <( $MGR_CTL phpversions | grep -E 'apache=on|fpm=on' | awk '{print $1}' | grep -o -P '(?<=key=).*')
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
						printf "\nTweaking ${php_choosen_version}"
						EXIT_STATUS=0
						trap 'EXIT_STATUS=1' ERR

						isp_php_tweak ${php_choosen_version}
						
						# todo
						#check_exit_and_restore_func
						printf " - ${GCV}DONE${NCV}\n"
						break
					fi
				done
			fi
			
			# get isp panel installed mysql versions into the array mysqlversions
			mysqlversions=(); while IFS= read -r version; do mysqlversions+=( "$version" ); done < <( $MGR_CTL db.server | grep -E 'type=mysql' | awk '{print $2}' | grep -o -P '(?<=name=).*')
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
						break 2
					else
						printf "\nTweaking ${mysql_choosen_version}"
						EXIT_STATUS=0
						trap 'EXIT_STATUS=1' ERR

						isp_mysql_tweak ${mysql_choosen_version}
			
						printf " - ${GCV}DONE${NCV}\n"
						break 2
					fi
				done
			fi
			;;
	
			"Skip")
	
			# user chose not to tweak PHP nor MySQL
			EXIT_STATUS=0
			printf "Tweak was canceled by user choice\n"
			break
			;;
	
			 	*)
			# bad key
			printf "${LRV}Bad key, boozar.${NCV}\n"
			;;
		esac
	done
fi
}

# tweak isp manager fpm
ispmanager_tweak_apache_and_php_fpm_func() {

if [[ -f $MGR_BIN ]]; then

	# lic validation
	isp_panel_check_license_version

	isp_fpm_template_file_path="/usr/local/mgr5/etc/templates/fpm_site_pool.conf"
	isp_apache_vhost_template_file_path="/usr/local/mgr5/etc/templates/default/apache2-directory.template"
	
	# backup to /root/support
	backup_dest_dir_path="/root/support/$(date '+%d-%b-%Y-%H-%M-%Z')/"

	# same for sites that already exist
	isp_php_fpm_enabled_sites=$(grep -RiIlE '^pm = ondemand|^pm.max_children = 5' /*/php*/* 2>/dev/null | grep -vE '\.default|apache|www|roundcube')
	
	if [[ -n "$isp_php_fpm_enabled_sites" ]] || ! (grep -qE '^pm = static$' "$isp_fpm_template_file_path" && grep -qE '^pm.max_children = 15$' "$isp_fpm_template_file_path" && grep -qE '^pm.max_requests = 1500$' "$isp_fpm_template_file_path") >/dev/null 2>&1 || ! grep -P '\tOptions -Indexes' ${isp_apache_vhost_template_file_path} >/dev/null 2>&1; then
		echo
		read -p "Tweak ISP Manager php-fpm and apache2 sites and templates ? [Y/n]" -n 1 -r
		if ! [[ $REPLY =~ ^[Nn]$ ]]; then

			# creating backup dir
			\mkdir -p "$backup_dest_dir_path" > /dev/null || { printf "\n${LRV}Error${NCV} creating backup dir - ${backup_dest_dir_path}\n"; return 1; }
	
			# isp apache vhost template patch
			{

			\cp -Rfp --parents "${isp_apache_vhost_template_file_path}" "${backup_dest_dir_path}" && \
			\cp -fp "$isp_apache_vhost_template_file_path" "${isp_apache_vhost_template_file_path}.original" > /dev/null && \
			\chmod --reference="${isp_apache_vhost_template_file_path}" "${backup_dest_dir_path}${isp_apache_vhost_template_file_path}"

			} >/dev/null 2>&1

			if [[ -f ${isp_apache_vhost_template_file_path}.original ]]; then
				printf "\nTemplate ${isp_apache_vhost_template_file_path} was ${GCV}processed${NCV} and origin was backed up to ${backup_dest_dir_path} and ${isp_apache_vhost_template_file_path}.original \n"
				perl -i -p0e "s,\{% if \\\$CREATE_DIRECTORY %}\n<Directory \{% \\\$LOCATION_PATH %\}>\n\{% if \\\$SSI == on %},\{% if \\\$CREATE_DIRECTORY %}\n<Directory \{% \\\$LOCATION_PATH %\}>\n\tOptions -Indexes\n\{% if \\\$SSI == on %},gi" $isp_apache_vhost_template_file_path > /dev/null
			else
				printf "\n${LRV}Error:${NCV} Cannot backup file ${isp_apache_vhost_template_file_path} to ${backup_dest_dir_path} or ${isp_apache_vhost_template_file_path}.original\n"
				return 1
			fi
		
			# changing default php-fpm isp template from ondemand 5 to static 15
			{

			\cp -Rfp --parents "${isp_fpm_template_file_path}" "${backup_dest_dir_path}" && \
			\cp -fp "$isp_fpm_template_file_path" "${isp_fpm_template_file_path}.original" && \
			\chmod --reference="${isp_fpm_template_file_path}" "${backup_dest_dir_path}${isp_fpm_template_file_path}" 

			} >/dev/null 2>&1

			if [[ -f ${isp_fpm_template_file_path}.original ]]; then
				printf "\nTemplate ${isp_fpm_template_file_path} was ${GCV}processed${NCV} and origin was backed up to ${backup_dest_dir_path} and ${isp_apache_vhost_template_file_path}.original\n"
				sed -i 's@^pm =.*@pm = static@gi' "$isp_fpm_template_file_path" || { printf "\n${LRV}Error modifying pm = ondemand${NCV}\n"; return 1; }
				sed -i 's@^pm.max_children =.*@pm.max_children = 15@gi' "$isp_fpm_template_file_path" || { printf "\n${LRV}Error modifying pm.max_children = 5${NCV}\n"; return 1; }
				sed -i 's@^pm.max_requests =.*@pm.max_requests = 1500@gi' "$isp_fpm_template_file_path" || { printf "\n${LRV}Error modifying pm.max_requests = 500${NCV}\n"; return 1; }
			else
				printf "\n${LRV}Error:${NCV} Cannot backup file ${isp_fpm_template_file_path} to ${backup_dest_dir_path} or ${isp_fpm_template_file_path}.original\n"
				return 1
			fi
			
			# processing existing php-fpm sites in isp manager
			if [[ -n $isp_php_fpm_enabled_sites ]]; then
				while IFS= read -r isp_fpm_config_file; do
					printf "\nProcessing ${isp_fpm_config_file}"
					\cp -Rfp --parents "$isp_fpm_config_file" "$backup_dest_dir_path" > /dev/null && chmod --reference="$isp_fpm_config_file" "${backup_dest_dir_path}${isp_fpm_config_file}" >/dev/null 2>&1
					if [[ -f "${backup_dest_dir_path}${isp_fpm_config_file}" ]]; then 
						sed -i '/^pm\.min_spare_servers =/d' "$isp_fpm_config_file" || { printf "\n${LRV}Error deleting pm.min_spare_servers${NCV}\n"; return 1; }
						sed -i '/^pm\.max_spare_servers =/d' "$isp_fpm_config_file" || { printf "\n${LRV}Error deleting pm.max_spare_servers${NCV}\n"; return 1; }
						sed -i 's@^pm =.*@pm = static@gi' "$isp_fpm_config_file" || { printf "\n${LRV}Error modifying pm mode${NCV}\n"; return 1; }
						sed -i 's@^pm.max_children = 5@pm.max_children = 15@gi' "$isp_fpm_config_file" || { printf "\n${LRV}Error modifying pm.max_children${NCV}\n"; return 1; }
						sed -i 's@^pm.max_requests =.*@pm.max_requests = 1500@' "$isp_fpm_config_file" || { printf "\n${LRV}Error modifying pm.max_requests${NCV}\n"; return 1; }
		
						# Check and restart php-fpm
						php_fpm_version=$(echo "$isp_fpm_config_file" | grep -oP '(?<=/php/)\d+\.\d+|(?<=/php)\d{2,3}(?=/)')
							
						if [[ -n "$php_fpm_version" ]]; then
							# native debian like php-fpm native service like php7.3-fpm.service
							if [[ "$isp_fpm_config_file" =~ ^/etc/ ]]; then
								php_fpm_service="php${php_fpm_version}-fpm.service"
							else
								# isp manager's php-fpm opt versions like php-fpm73.service
								php_fpm_service="php-fpm${php_fpm_version}.service"
							fi
						else
							# native rhel php-fpm services
							php_fpm_service="php-fpm.service"
						fi
							
						# Check
						if [[ "$isp_fpm_config_file" =~ ^/etc/ ]]; then
							# PHP-FPM (Debian)
							if ! php-fpm${php_fpm_version} -t > /dev/null 2>&1; then
								printf " - ${LRV}ERROR${NCV} Invalid PHP-FPM config for PHP ${php_fpm_version}\n"
								return 1
							fi
						else
							# ISPmanager /opt/phpXX
							if ! /opt/php${php_fpm_version}/sbin/php-fpm -t > /dev/null 2>&1; then
								printf " - ${LRV}ERROR${NCV} Invalid PHP-FPM config for PHP ${php_fpm_version}\n"
								return 1
							fi
						fi
							
						# restart
						systemctl restart "$php_fpm_service" >/dev/null 2>&1
							
						# Check restart
						if systemctl is-active --quiet "$php_fpm_service" >/dev/null 2>&1; then
							printf " - ${GCV}OK${NCV}\n"
						else
							printf " - ${LRV}ERROR${NCV} Failed to restart ${php_fpm_service}. Check logs.\n"
							return 1
						fi
						printf "Original file ${isp_fpm_config_file} backup'd to ${backup_dest_dir_path}${NCV}\n"
					else
						printf " - ${LRV}FAIL${NCV}\nCannot backup file ${isp_fpm_config_file} to ${backup_dest_dir_path}\n"
						return 1
					fi
				done <<< "$isp_php_fpm_enabled_sites"
			fi
		else
			# user chose not to tweak isp fpm 
			printf "\n${YCV}Tweaking ISP PHP-FPM and APACHE sites and templates was skipped.${NCV} \n"
		fi
		
	else
		printf "\nTweaking ISP Manager php-fpm and apache2 sites and templates not needed or was ${GCV}already done${NCV}\n" 
	fi
fi

} 

# Function to add a parameter to a file
add_param_to_file() {
	local file="$1"
	local param="$2"
	local value="$3"
	echo "$param $value;" >> "$file"
}

# Function to update a parameter in a file
update_param_in_file() {
	local file="$1"
	local param="$2"
	local value="$3"
	if grep -qE "^\s*$param\s+.*;" "$file"; then
		sed -i -E "s|^\s*$param\s+.*;|\t$param $value;|" "$file"
		return 0
	else
		return 1
	fi
}

# Function to check if a parameter with the desired value exists in the specified files
check_param_exists() {
	local param="$1"
	local value="$2"
	# Search for the parameter with the desired value in custom.conf
	if grep -E "^\s*$param\s+$value\s*;" "$NGINX_TWEAKS_INCLUDE_FILE" >/dev/null 2>&1; then
		return 0
	fi
	# Search for the parameter with the desired value in nginx.conf (before the server block)
	if awk '/server\s*{/{exit} /^\s*'"$param"'\s+'"$value"'\s*;/' "$NGINX_CONF_FILE" | grep -qE "^\s*$param\s+$value\s*;"; then
		return 0
	fi
	return 1
}

tweak_nginx_params_func() {

# Check if Nginx is installed
if ! command -v nginx >/dev/null 2>&1; then
	printf "\nNginx ${GCV}not detected${NCV}\n"
	return 1
fi

# Checking include directive exists in main nginx conf
if ! grep -qF "include $NGINX_TWEAKS_INCLUDE_FILE;" "$NGINX_CONF_FILE"; then
	echo
	read -p "Tweak nginx parameters ? [Y/n]" -n 1 -r
	echo
	if ! [[ $REPLY =~ ^[Nn]$ ]]; then
		declare -A NGINX_PARAMS
		NGINX_PARAMS=(
			["proxy_buffers"]="32 16k"
			["proxy_buffer_size"]="16k"
			["proxy_max_temp_file_size"]="0"
			["fastcgi_buffers"]="16 16k"
			["fastcgi_buffer_size"]="32k"
			["client_body_buffer_size"]="32k"
			["client_header_buffer_size"]="1k"
			["client_max_body_size"]="1024m"
			["large_client_header_buffers"]="4 16k"
			["etag"]="on"
			["sendfile"]="on"
			["sendfile_max_chunk"]="512k"
			["tcp_nopush"]="on"
			["tcp_nodelay"]="on"
			["server_names_hash_bucket_size"]="512"
			["server_names_hash_max_size"]="1024"
		)

		echo "# Custom settings" > "$NGINX_TWEAKS_INCLUDE_FILE"
		
		# Add the include directive to the main config if it's not already there
		if ! grep -qF "include $NGINX_TWEAKS_INCLUDE_FILE;" "$NGINX_CONF_FILE"; then
			# Add the include directive directly to the main configuration file
			sed -i '/http\s*{/a \	include '"$NGINX_TWEAKS_INCLUDE_FILE"';' "$NGINX_CONF_FILE"
		
			# Test the configuration after adding the include directive
			if ! nginx -t >/dev/null 2>&1; then
				# If the test fails, remove the include directive from the main configuration file
				sed -i '/include '"$(echo "$NGINX_TWEAKS_INCLUDE_FILE" | sed 's/\//\\\//g')"';/d' "$NGINX_CONF_FILE"
				# Remove the include file
				rm -f "$NGINX_TWEAKS_INCLUDE_FILE"
				printf "\n${LRV}Error:${NCV}  Failed to add include directive to $NGINX_CONF_FILE. Changes reverted."
				exit 1
			else
				printf "${NGINX_TWEAKS_INCLUDE_FILE} was ${GCV}successfully${NCV} added to ${NGINX_CONF_FILE}" 
			fi
		fi

		printf "\nRunning nginx params tweaks"
		
		# Sort NGINX_PARAMS param
		sorted_params=$(for param in "${!NGINX_PARAMS[@]}"; do echo "$param"; done | sort)
	
		config_test_fail_msg="The configuration test failed after the change"
		
		# Add or update parameters in the include file or nginx.conf
		for param in $sorted_params; do
			new_value="${NGINX_PARAMS[$param]}"
		
			# Check if the parameter with the desired value already exists in the specified files
			if check_param_exists "$param" "$new_value"; then
	
				# If the parameter with the desired value already exists, skip it
				continue
			fi

			# Try to update the parameter in nginx.conf (before the server block)
			old_value=$(awk '/^\s*'"$param"'\s+.*;/' "$NGINX_CONF_FILE" | awk '{for (i=2; i<=NF; i++) if ($i ~ /;/) {print substr($i, 1, length($i)-1); exit} else printf "%s ", $i}')
			if [[ -n "$old_value" ]]; then
				if update_param_in_file "$NGINX_CONF_FILE" "$param" "$new_value"; then
					NGINX_TWEAKS_SUCCESS_ADDED+=("$param (!updated in $NGINX_CONF_FILE, old: $old_value, new: $new_value)")
				else
					printf "\n${LRV}Error:${NCV} Failed to update $param in $NGINX_CONF_FILE - ${config_test_fail_msg}\n"
				continue
				fi
			else
				# If the parameter is not found in nginx.conf, try to update or add it in custom.conf
				if update_param_in_file "$NGINX_TWEAKS_INCLUDE_FILE" "$param" "$new_value"; then
					NGINX_TWEAKS_SUCCESS_ADDED+=("$param (!updated in $NGINX_TWEAKS_INCLUDE_FILE)")
				else
					add_param_to_file "$NGINX_TWEAKS_INCLUDE_FILE" "$param" "$new_value"
					NGINX_TWEAKS_SUCCESS_ADDED+=("$param (added to $NGINX_TWEAKS_INCLUDE_FILE)")
				fi
			fi
		
			# Test the configuration after adding or updating the parameter
			if ! nginx -t >/dev/null 2>&1; then
	
				# If the test fails, revert the changes
				if [[ "${NGINX_TWEAKS_SUCCESS_ADDED[-1]}" == *"updated in $NGINX_CONF_FILE"* ]]; then
	
					sed -i -E "/^\s*$param\s+.*;/d" "$NGINX_CONF_FILE"
					printf "\n${LRV}Error:${NCV} Failed to update $param in $NGINX_CONF_FILE - ${config_test_fail_msg}\n"
	
				elif [[ "${NGINX_TWEAKS_SUCCESS_ADDED[-1]}" == *"updated in $NGINX_TWEAKS_INCLUDE_FILE"* ]]; then
	
					sed -i -E "/^\s*$param\s+.*;/d" "$NGINX_TWEAKS_INCLUDE_FILE"
					printf "\n${LRV}Error:${NCV} Failed to update $param in $NGINX_TWEAKS_INCLUDE_FILE - ${config_test_fail_msg}\n"
	
				else
	
					sed -i -E "/^\s*$param\s+.*;/d" "$NGINX_TWEAKS_INCLUDE_FILE"
					printf "\n${LRV}Error:${NCV} Failed to add $param to $NGINX_TWEAKS_INCLUDE_FILE - ${config_test_fail_msg}\n"
	
				fi
	
				# Remove the parameter from the success list
				NGINX_TWEAKS_SUCCESS_ADDED=("${NGINX_TWEAKS_SUCCESS_ADDED[@]/$param *}")
			fi
		done
		
		# Reload Nginx if changes were made
		if [ "${#NGINX_TWEAKS_SUCCESS_ADDED[@]}" -gt 0 ]; then
	
			if systemctl reload nginx >/dev/null 2>&1; then
				printf "\n${GCV}OK${NCV}\n"
				printf "Nginx added/updated:\n\n"
				printf '%s\n' "${NGINX_TWEAKS_SUCCESS_ADDED[@]}"
			else
				printf "\n${LRV}FAIL${NCV}\n"
				printf "${LRV}Error:${NCV} Failed to reload Nginx ( run: nginx -t )\n"
				printf "\nNginx added/updated:\n"
				printf '%s\n' "${NGINX_TWEAKS_SUCCESS_ADDED[@]}"
			fi
		else
			printf "\nTweak nginx not needed or was ${GCV}already done${NCV}\n"
		fi
	else
		# user chose not to tweak nginx
		printf "Nginx params tweak was canceled by user choice\n"
	fi
else
	printf "\nTweak nginx not needed or was ${GCV}already done${NCV}\n"
fi
}

# tweaker add nginx bad robot conf
tweak_add_nginx_bad_robot_conf_func() {

if command -v nginx >/dev/null 2>/dev/null && ! 2>&1 nginx -T | grep -i "if ( \$http_user_agent" >/dev/null 2>&1; then

	echo
	read -p "Add nginx blocking of annoying bots ? [Y/n]" -n 1 -r
	if ! [[ $REPLY =~ ^[Nn]$ ]]; then

		# checking nginx configuration sanity
		nginx_conf_sanity_check_fast

		NGINX_BAD_ROBOT_FILE_URL="https://gitlab.hoztnode.net/admins/scripts/-/raw/master/bad_robot.conf"

		# placing file depending the environment
		# if ISP Manager
		if [[ -f $MGR_BIN ]]; then
			# lic validation
			isp_panel_check_license_version
			nginx_bad_robot_file_local="/etc/nginx/vhosts-includes/bad_robot.conf"
		# if Bitrix
		elif [[ $BITRIXALIKE == "yes" ]]; then

			# Bitrix Env or GT
			if [[ $BITRIX == "ENV" ]] || [[ $BITRIX == "GT" ]]; then
				bitrix_nginx_general_conf="/etc/nginx/bx/conf/bitrix_general.conf"
				nginx_bad_robot_file_local="/etc/nginx/bx/conf/bad_robot.conf"
			# fix could not build optimal proxy_headers_hash
			printf "proxy_headers_hash_max_size 1024;\nproxy_headers_hash_bucket_size 128;" > /etc/nginx/bx/settings/proxy_headers_hash.conf

			# Other one bitrix "vanilla"
			elif [[ $BITRIX == "VANILLA" ]]; then
				bitrix_nginx_general_conf="/etc/nginx/conf.d/bitrix_general.conf"
				nginx_bad_robot_file_local="/etc/nginx/conf.d/bad_robot.conf"
			else
				printf "\n${LRV}Error.${NCV} Unknown bitrix environment.Link - ${NGINX_BAD_ROBOT_FILE_URL}\n"
				return
			fi

			if [[ ! -z $bitrix_nginx_general_conf ]]  && ! grep -q "bad_robot.conf" $bitrix_nginx_general_conf >/dev/null 2>&1; then
					sed -i "1s@^@# bad robots block added $(date '+%d-%b-%Y-%H-%M-%Z') \ninclude ${nginx_bad_robot_file_local};\n@" $bitrix_nginx_general_conf
			else
				printf "\n${LRV}Error.${NCV} bitrix_nginx_general_conf is not set or include already exists ( check grep -in "bad_robot.conf" $bitrix_nginx_general_conf ). Include failed.\n"
				return
			fi
		else
			printf "\n${LRV}Error.${NCV} Unknown environment. Don't know where to place the include. Link - ${NGINX_BAD_ROBOT_FILE_URL}\n"
			return
		fi

		# downloading nginx bad_robot.conf file
		if ! download_file_func "$NGINX_BAD_ROBOT_FILE_URL" "$nginx_bad_robot_file_local"; then
			return 1
		fi

		# checking bad_robot file exist in nginx config
		printf "\nChecking bad_robot file exist in nginx config"
		if 2>&1 nginx -T | grep -i BlackWidow >/dev/null 2>&1; then
			printf " - ${GCV}OK${NCV}"
		else
			printf " - ${LRV}FAIL${NCV}"
		fi
	
		# checking nginx configuration sanity again
		nginx_conf_sanity_check_fast
	else
		# user chose not to install bad_robot.conf in nginx 
		printf "\n${YCV}Nignx's bad_robot.conf include was skipped.${NCV} \n"
	fi
else
	printf "\nAdding nginx blocking of annoying bots not needed or was ${GCV}already done${NCV}\n" 
fi
}

# check nginx conf and reload configuration fast
nginx_conf_sanity_check_fast() {



printf "\nMaking nginx configuration check"
if nginx_test_output=$({ nginx -t; } 2>&1); then
	printf " - ${GCV}OK${NCV}\n"
	nginx -s reload >/dev/null 2>&1
	EXIT_STATUS=0
else
	printf " - ${LRV}FAIL${NCV}\n$nginx_test_output\n"
	EXIT_STATUS=1
fi
}

# check nginx conf and reload configuration
nginx_conf_sanity_check_and_reload_func() {

printf "\nMaking nginx configuration check"
if nginx_test_output=$({ nginx -t; } 2>&1)
then
	printf " - ${GCV}OK${NCV}\n"
	nginx -s reload >/dev/null 2>&1
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

if 2>&1 nginx -V | grep -i "push-stream" >/dev/null 2>&1
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
			preset_list=$($MGR_CTL preset | awk -F '=' '{print $3}' | grep -E "$PROXY_PREFIX.+")
			for plist in $preset_list; do $MGR_CTL preset.delete elid=$plist elname=$plist; done
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
	elif [[ ! -z "$2"  ]]  && [[  ! -z $($MGR_CTL preset | awk -F '=' '{print $3}' | grep -E "$2") ]]
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
				
				$MGR_CTL preset.delete elid=$2 elname=$2 >/dev/null 2>&1
				
				# removing $2 inject
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_TEMPLATE >/dev/null 2>&1
				sed -i '/^[[:space:]]*$/d' $NGINX_TEMPLATE >/dev/null 2>&1
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_SSL_TEMPLATE >/dev/null 2>&1
				sed -i '/^[[:space:]]*$/d' $NGINX_SSL_TEMPLATE >/dev/null 2>&1
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_MAIN_CONF_FILE >/dev/null 2>&1
				sed -i '/^[[:space:]]*$/d' $NGINX_MAIN_CONF_FILE >/dev/null 2>&1
				
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
			preset_list=$($MGR_CTL preset | awk -F '=' '{print $3}')
			for plist in $preset_list; do $MGR_CTL preset.delete elid=$plist elname=$plist; done
			printf "\n${LRV}All ISP panel presets removed${NCV}\n"
			# removing nginx templates
			\rm -f $NGINX_SSL_TEMPLATE >/dev/null 2>&1
			\rm -f $NGINX_TEMPLATE >/dev/null 2>&1
			printf "\n${LRV}Custom nginx templates removed${NCV}\n"
			# removing injects in $NGINX_MAIN_CONF_FILE
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_MAIN_CONF_FILE >/dev/null 2>&1
			sed -i '/^[[:space:]]*$/d' $NGINX_MAIN_CONF_FILE >/dev/null 2>&1
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

if nginx -t >/dev/null 2>&1
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
	} >/dev/null 2>&1
	
	then
		if nginx -t >/dev/null 2>&1
		then
			printf "\n${GCV}OK${NCV}\n"
			nginx -s reload >/dev/null 2>&1
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

if apachectl configtest  >/dev/null 2>&1
then
	if [[ -f "$APACHE_STATUS_PAGE_INJECT_FILE_RHEL" ]]
	then
		printf "\n${GCV}Injecting apache status page at $APACHE_STATUS_PAGE_INJECT_FILE_RHEL${NCV}"
		printf "$APACHE_STATUS_PAGE_INJECT" >> "$APACHE_STATUS_PAGE_INJECT_FILE_RHEL"
		if apachectl configtest >/dev/null 2>&1
		then
			printf " - ${GCV}OK${NCV}\n"
			apachectl graceful  >/dev/null 2>&1
		else
			printf " - ${LRV}FAIL (apachectl configtest)${NCV}\n"
			sed -i "s|$APACHE_STATUS_PAGE_INJECT||gi" "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" >/dev/null 2>&1
			exit 1
		fi
	elif [[ -f "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" ]]
	then
		printf "\n${GCV}Injecting apache status page at $APACHE_STATUS_PAGE_INJECT_FILE_DEB${NCV}"
		printf "$APACHE_STATUS_PAGE_INJECT" >> "$APACHE_STATUS_PAGE_INJECT_FILE_DEB"
		if apachectl configtest >/dev/null 2>&1
		then
			printf " - ${GCV}OK${NCV}\n"
			apachectl graceful  >/dev/null 2>&1
		else
			printf " - ${LRV}FAIL (apachectl configtest)${NCV}\n"
			sed -i "s|$APACHE_STATUS_PAGE_INJECT||gi" "$APACHE_STATUS_PAGE_INJECT_FILE_DEB" >/dev/null 2>&1
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
	\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" >/dev/null 2>&1
	exit 0
else
	printf "\n${RLV}Download $GIT_THE_CHOSEN_ONE_DOMAIN_NAME$GIT_THE_CHOSEN_ONE_REQ_URI/$NGX_RECOMPILE_SCRIPT_NAME failed${NCV}\n"
	\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" >/dev/null 2>&1
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

# run help function
if [[ $1 = "help" ]] || [[ $1 = "--help" ]] || [[ $1 = "-help" ]]
then
	show_help_func
	exit 0
fi


# run tweak function
if [[ $1 = "tweak" ]]
then
	run_all_tweaks
	exit 0
fi

# run recompile nginx function
if [[ $1 = "recompile" ]]
then
	recompile_nginx_func
	exit 0
fi

main_func() {

isp_panel_check_license_version

# enabling ISP PHP-FPM FastCGI feature
if ! [[ $($MGR_CTL feature | grep "name=web" | grep -i fpm) ]]
then
	printf "\n${GCV}Enabling ISP Manager PHP-FPM FastCGI feature${NCV}"
	EXIT_STATUS=0
	$MGR_CTL feature.edit elid=web package_php package_php-fpm=on sok=ok >/dev/null 2>&1
	check_exit_and_restore_func
	printf " - ${GCV}OK${NCV}\n"
	# feature.edit return OK but actual install continues, so we need to sleep some time
	printf "\n${GCV}Waiting 60 seconds for ISP Panel PHP-FPM FastCGI feature install${NCV}"
	sleep 60
	if ! [[ $($MGR_CTL feature | grep "name=web" | grep -i fpm) ]]
	then
		printf "\n${LRV}ISP Manager PHP-FPM FastCGI feature still not exists\nCheck /usr/local/mgr5/var/pkg.log logfile${NCV}"
		exit 1
	fi
fi

# enought arguments check and if nothing in the list of presets show help
if [[ "$#" -lt 1 ]]
then
	# check if any presets exist
	if [[ $($MGR_CTL preset) ]]
	then
		printf "\n${GCV}Listing existing templates:${NCV}\n---------------\n"
		$MGR_CTL preset | awk -F '=' '{print $3}'
		echo "---------------"
	else
		printf "\n${GCV}There is no existing templates in the ISP panel${NCV}\n"
	fi
	show_help_func
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
		\cp -p "$NGINX_DEFAULT_TEMPLATE" "$NGINX_TEMPLATE" >/dev/null 2>&1
		# fix importing default ssl template
		sed -i 's@import etc/templates/default/@import etc/templates/@gi' "$NGINX_TEMPLATE" >/dev/null 2>&1
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
		\cp -p "$NGINX_DEFAULT_SSL_TEMPLATE" "$NGINX_SSL_TEMPLATE" >/dev/null 2>&1
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
printf "\nProxy target list to add:${GCV} $proxy_targets${NCV}\n"

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
	
	BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_BEGIN="s,(\texpires \[% \$EXPIRES_VALUE.*%\];\n\{% endif %\}\n)(\tlocation / \{\n.*\{% if \$PHP.*%}\n),\$1\n\\{#\\} php_off_backward_compatibility_condition_start_DO_NOT_(RE)MOVE\n{% if \$PRESET == #custom %}\n\$2,gi"
	
	BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_END="s,(\t\t\ttry_files /does_not_exists \@fallback;\n\t\t}\n\{% endif %\}\n\t\}\n\{% endif %\}\n)(\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\tlocation \@fallback \{),\$1\n\{% endif %\}\n\\{#\\} php_off_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE\n\n\$2,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF="s,(\{#\\} php_off_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE),\$1\n\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_IF_PHPOFF_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\tlocation / \{\n\{% if \\\$PHP == off %\}\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files does_not_exists \@backend;\n\{% endif %\}\n\\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$  \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\\{% endif %\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\t\tindex index.html;\n\t\t\tlocation ~ \[^/\].ph\(p\\\d*|tml\)\\\$ \{\n\t\t\t\ttry_files does_not_exists \@backend;\n\t\t\t\}\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$PHP == off %\}\n\tlocation \@backend \{\n\t\tproxy_pass http://$proxy_target;\n\t\tproxy_redirect http://$proxy_target /;\n\t\tproxy_set_header Host \\\$host;\n\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\tproxy_set_header X-Forwarded-Proto \\\$scheme;\n\t\tproxy_set_header X-Forwarded-Port \\\$server_port;\n\t}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_IF_PHPOFF_STOP_DO_NOT_REMOVE\n,gi"

	SPECIAL_INJECTIONS_VAR="\{% if THIS_BLOCK_FOR_REMOVE_EXPIRES %\}\n\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n"
	
	# creating user defined ISP manager presets
	printf "\n\n>>>>> ${GCV}$PROXY_PREFIX$proxy_target${NCV}\nCreating ISP panel preset"
	
	# $limit_dirindex_var
	if [[ $proxy_target = "opencart_fpm" ]] || [[ $proxy_target = "wordpress_fpm" ]] || [[ $proxy_target = "bitrix_fpm" ]] || [[ $proxy_target = "moodle_fpm" ]] || [[ $proxy_target = "webassyst_fpm" ]] || [[ $proxy_target = "magento2_fpm" ]] || [[ $proxy_target = "cscart_fpm" ]]

	then
		limit_dirindex_var=index.php
	fi
	# check for error / success
	if $MGR_CTL preset.edit backup=on limit_php_mode=php_mode_fcgi_nginxfpm limit_php_fpm_version=native limit_php_mode_fcgi_nginxfpm=on limit_cgi=on limit_php_cgi_enable=on limit_php_mode_cgi=on limit_php_mode_mod=on limit_shell=on limit_ssl=on name=$PROXY_PREFIX$proxy_target limit_dirindex=$limit_dirindex_var sok=ok >/dev/null 2>&1
	then
		printf " - ${GCV}OK${NCV}\n"
		preset_raise_error="0"
			#if wordpress_fpm in preset name create special template
			if [[ $proxy_target = "wordpress_fpm" ]]
			then
				# WORDPRESS_FPM nginx templates injections variables
				WORDPRESS_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$args;\n\{% endif %\}\n\t\tlocation ~ \[^/\]\\\\.ph(p\d*|tml)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER != "" %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\\.ph\(p\\\d*|tml\)\\\$ {\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
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
				
				# tweak
				run_all_tweaks
				
				continue
				
			elif [[ $proxy_target = "opencart_fpm" ]]
			then
				# OPENCART_FPM nginx templates injections variables
				OPENCART_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\tif \(!-e \\\$request_filename\) \{\n\t\t\trewrite ^/\(.+\)\\\$ /index.php?_route_=\\\$1 last;\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\tlog_not_found off;\n\t\tadd_header Pragma public;\n\t\tadd_header Cache-Control \"public\, must-revalidate\, proxy-revalidate\";\n\t\ttry_files \\\$uri \\\$uri/ \@static;\n\t\}\n\tlocation ~* \\\.\(eot|otf|ttf|woff\)\\\$ \{\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\}\n\n\tlocation ~* \(\\\.\(tpl|ini\)\)\\\$ \{\n\t\tdeny all; \n\t\}\n\n\tlocation ~* \\\.\(engine|inc|info|ini|install|log|make|module|profile|test|po|sh|.*sql|theme|tpl\(\\\.php\)?|xtmpl\)\\\$|^\(\\\..*|Entries.*|Repository|Root|Tag|Template\)\\\$|\\\.php_ \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~ /\\\. \{\n\t\taccess_log off;\n\t\tlog_not_found off;\n\t\tdeny all;\n\t\}\n\n\tlocation ~ ~\\\$ \{\n\t\taccess_log off;\n\t\tlog_not_found off;\n\t\tdeny all;\n\t\}\n\n\tlocation ~* /\(?:cache|logs|image|download\)/.*\\\.php\\\$ \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~ /\\\.ht \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~* \(\\\.\(svn|hg|git\)\)\\\$ \{\n\t\tdeny all; \n\t\}\n\n\tlocation ~ /\\\.tpl/ \{\n\t\tdeny all;\n\t\}\n\n\tlocation \@static \{\n\t\terror_log /dev/null crit;\n\t\taccess_log off ;\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
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
				
				# tweak
				run_all_tweaks
				
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
				
				# tweak
				run_all_tweaks
				
				continue
			
			elif [[ $proxy_target = "moodle_fpm" ]]
			then
				# MOODLE_FPM nginx templates injections variables
				MOODLE_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www\\\.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^\\\.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index\\\.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tlocation ~* \(/lib/classes/|/doesnotexist|/vendor/|/node_modules/|composer\\\\.json|/readme|/README|readme\\\\.txt|/upgrade\\\\.txt|db/install\\\\.xml|\/fixtures\/|/behat/|phpunit\\\\.xml|\\\\.lock|environment\\\\.xml\) \{\n\t\tdeny all;\n\t\treturn 404;\n\t\}\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all; \n\t\}\n\tlocation ~* \\\\.\(eot|otf|ttf|woff\)\\\$ \{\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\}\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index\\\.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\tlog_not_found off;\n\t\tadd_header Pragma public;\n\t\tadd_header Cache-Control \"public\, must-revalidate\, proxy-revalidate\";\n\t\ttry_files \\\$uri \\\$uri/ \@static;\n\t\}\n\tlocation ~* \\\.\(eot|otf|ttf|woff\)\\\$ \{\n\t\tadd_header Access-Control-Allow-Origin *;\n\t\}\n\tlocation ~ \[^/\]\\\\.php\(/|\\\$\) \{\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(/.+\)\\\$;\n\t\tfastcgi_index index.php;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tinclude fastcgi_params;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\}\n\tlocation ~ ^\(.+\\\\.php\)\(.*\)\\\$ \{\n\t\tfastcgi_split_path_info ^\(.+\\\\.php\)\(.*\)\\\$;\n\t\tfastcgi_index index.php;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tinclude /etc/nginx/mime.types;\n\t\tinclude fastcgi_params;\n\t\tfastcgi_param PATH_INFO \\\$fastcgi_path_info;\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\}\n\tlocation \@static \{\n\t\terror_log /dev/null crit;\n\t\taccess_log off ;\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} \\\$PROXY_PREFIX\\\$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
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
				
				# tweak
				run_all_tweaks
				
				continue

			elif [[ $proxy_target = "webassyst_fpm" ]]
			then
				# WEBASSYST_FPM nginx templates injections variables
				WEBASSYST_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www\\\.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^\\\.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\tlocation / \{\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\tindex index\\\.html;\n\{% if \\\$PHP == on %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t#\n\ttry_files \\\$uri \\\$uri/ /index.php?\\\$query_string;\n\t#\n\tlocation /index.php \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_intercept_errors off;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 4 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 256k;\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\n\t\n\t# for install only\n\tlocation /install.php \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\t\n\t\n\tlocation /api.php \{\n\t\tfastcgi_split_path_info  ^\(.+\.php\)\(.*\)\\\$;\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\n\t\n\tlocation ~ /\(oauth.php|link.php|payments.php\) \{\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$query_string;\n\t\}\t\n\n\tlocation ^~ /wa-data/protected/ \{\n\t\tinternal;\n\t\}\n\t\n\tlocation ~ /wa-content \{\n\t\tallow all;\n\t\}\n\n\tlocation ^~ /\(wa-apps|wa-plugins|wa-system|wa-widgets\)/.*/\(lib|locale|templates\)/ \{\n\t\tdeny all;\n\t\}\n\n\tlocation ~* ^/wa-\(cache|config|installer|log|system\)/ \{\n\t\treturn 403;\n\t\}\n\n\tlocation ~* ^/wa-data/public/contacts/photos/\[0-9\]+/ \{\n\t\t root\t\t\\\$root_path;\n\t\t access_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t error_page\t404 = \@contacts_thumb;\n\t\}\n\n\tlocation \@contacts_thumb \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/contacts/photos/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/contacts/photos/thumb.php;\n\t\}\n\t\n\t# photos app\n\tlocation ~* ^/wa-data/public/photos/\[0-9\]+/ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page\t404 = \@photos_thumb;\n\t\}\n\n\tlocation \@photos_thumb \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/photos/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/photos/thumb.php;\n\t\}\n\t# end photos app\n\t\n\t# shop app\n\tlocation ~* ^/wa-data/public/shop/products/\[0-9\]+/ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page\t404 = \@shop_thumb;\n\t\}\n\tlocation \@shop_thumb \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/shop/products/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/shop/products/thumb.php;\n\t\}\n\t\n\tlocation ~* ^/wa-data/public/shop/promos/\[0-9\]+ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page\t404 = \@shop_promo;\n\t\}\n\tlocation \@shop_promo \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/shop/promos/thumb.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/shop/promos/thumb.php;\n\t\}\n\t# end shop app\n\t\n\t# mailer app\n\tlocation ~* ^/wa-data/public/mailer/files/\[0-9\]+/ \{\n\t\taccess_log\toff;\n\t\terror_page\t404 = \@mailer_file;\n\t\}\n\tlocation \@mailer_file \{\n\t\tinclude /etc/nginx/fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param\tPATH_INFO\t\\\$fastcgi_path_info;\n\t\tfastcgi_param\tSCRIPT_NAME\t/wa-data/public/mailer/files/file.php;\n\t\tfastcgi_param\tSCRIPT_FILENAME\t\\\$document_root/wa-data/public/mailer/files/file.php;\n\t\}\n\t# end mailer app\n\n\tlocation ~* ^.+\\\\.\(jpg|jpeg|gif|png|webp|js|css\)\\\$ \{\n\t\taccess_log\toff;\n\{% if \\\$SRV_CACHE == on %\}\n\t\t expires\t\[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} \\\$PROXY_PREFIX\\\$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
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
				
				# tweak
				run_all_tweaks
				
				continue

			elif [[ $proxy_target = "magento2_fpm" ]]
			then
				# MAGENTO2_FPM nginx templates injections variables
				MAGENTO2_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\t# wwww prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www\\\.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\t#if \(\\\$request_uri ~* ^\(\[^\\\.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index\\\.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\tlocation / \{\n\{% if \\\$PHP == on %\}\n\t\t\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\t\t\}\n\{% endif %\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\t\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\{% endif %\}\n\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\t\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\t\t\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\t\tlocation / \{\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\t\t\}\n\{% endif %\}\n\t\t\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\t\t\tindex index\\\.html;\n\{% if \\\$PHP == on %\}\n\t\t\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@php;\n\{% else %\}\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\{% endif %\}\n\t\t\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\{% if \\\$PHP_MODE != php_mode_fcgi_nginxfpm %\}\n\t\t\t\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\t\t\t\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% endif %\}\n\t\t\t\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\t\t\t\t\}\n\t\t\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\t\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\t\t\}\n\{% endif %\}\n\t\t\}\n\{% endif %\}\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env\)\)\\\$ \{\n\t\treturn 404;\n\t\tdeny all;\n\t\}\n\tsend_timeout 600s;\n\tfastcgi_read_timeout 600s;\n\tfastcgi_send_timeout 600s;\n\tfastcgi_connect_timeout 600s;\n\tclient_max_body_size 3G;\n\t#\n\tset \\\$root_root \\\$root_path;\n\tset \\\$root_path \\\$root_path/pub;\n\t#\n\tlocation /.user.ini \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation ~* ^/admin_.+\(\\\$|/\) \{\n\t\ttry_files \\\$uri \\\$uri/ /index.php\\\$is_args\\\$args;\n\t\}\n\t#\n\tlocation ~* ^/setup\(\\\$|/\) \{\n\t\troot \\\$root_root;\n\t\tlocation ~ ^/setup/index.php \{\n\t\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\t\tfastcgi_param  PHP_FLAG  \"session.auto_start=off \\\n suhosin.session.cryptua=off\";\n\t\t\tfastcgi_param  PHP_VALUE \"memory_limit=756M \\\n max_execution_time=600\";\n\t\t\tfastcgi_read_timeout 600s;\n\t\t\tfastcgi_connect_timeout 600s;\n\t\t\tfastcgi_index  index.php;\n\t\t\tfastcgi_param  SCRIPT_FILENAME  \\\$document_root\\\$fastcgi_script_name;\n\t\t\tinclude\t\tfastcgi_params;\n\t\t\}\n\t\tlocation ~ ^/setup/\(?!pub/\). \{\n\t\t\tdeny all;\n\t\t\}\n\t\tlocation ~ ^/setup/pub/ \{\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\}\n\t\}\n\t#\n\tlocation ~* ^/update\(\\\$|/\) \{\n\t\troot \\\$root_root;\n\t\tlocation ~ ^/update/index.php \{\n\t\t\tfastcgi_split_path_info ^\(/update/index.php\)\(/.+\)\\\$;\n\t\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\t\tfastcgi_index  index.php;\n\t\t\tfastcgi_param  SCRIPT_FILENAME  \\\$document_root\\\$fastcgi_script_name;\n\t\t\tfastcgi_param  PATH_INFO\t\t\\\$fastcgi_path_info;\n\t\t\tinclude\t\tfastcgi_params;\n\t\t\}\n\t\t# Deny everything but index.php\n\t\tlocation ~ ^/update/\(?!pub/\). \{\n\t\t\tdeny all;\n\t\t\}\n\t\tlocation ~ ^/update/pub/ \{\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\}\n\t\}\n\t#\n\tlocation /pub/ \{\n\t\tlocation ~ ^/pub/media/\(downloadable|customer|import|custom_options|theme_customization/.*\\\\.xml\) \{\n\t\t\tdeny all;\n\t\t\}\n\t\talias \\\$root_root/pub/;\n\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\}\n\t#\n\tlocation /static/ \{\n\t\t# Uncomment the following line in production mode\n\t\t# expires max;\n\n\t\t# Remove signature of the static files that is used to overcome the browser cache\n\t\tlocation ~ ^/static/version\\\\d*/ \{\n\t\t\trewrite ^/static/version\\\\d*/\(.*\)\\\$ /static/\\\$1 last;\n\t\t\}\n\n\t\tlocation ~* \\\\.\(ico|jpg|jpeg|png|gif|svg|svgz|webp|avif|avifs|js|css|eot|ttf|otf|woff|woff2|html|json|webmanifest\)\\\$ \{\n\t\t\tadd_header Cache-Control \"public\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\n\t\t\tif \(!-f \\\$request_filename\) \{\n\t\t\t\trewrite ^/static/\(version\\\\d*/\)?\(.*\)\\\$ /static.php?resource=\\\$2 last;\n\t\t\t\}\n\t\t\}\n\t\tlocation ~* \\\\.\(zip|gz|gzip|bz2|csv|xml\)\\\$ \{\n\t\t\tadd_header Cache-Control \"no-store\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\texpires\toff;\n\n\t\t\tif \(!-f \\\$request_filename\) \{\n\t\t\t\trewrite ^/static/\(version\\\\d*/\)?\(.*\)\\\$ /static.php?resource=\\\$2 last;\n\t\t\t\}\n\t\t\}\n\t\tif \(!-f \\\$request_filename\) \{\n\t\t\trewrite ^/static/\(version\\\\d*/\)?\(.*\)\\\$ /static.php?resource=\\\$2 last;\n\t\t\}\n\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\}\n\t#\n\tlocation /media/ \{\n\t\n\t## The following section allows to offload image resizing from Magento instance to the Nginx.\n\t## Catalog image URL format should be set accordingly.\n\t## See https://docs\\\.magento\\\.com/user-guide/configuration/general/web\\\.html#url-options\n\t#\tlocation ~* ^/media/catalog/.* \{\n\t#\n\t#\t\t# Replace placeholders and uncomment the line below to serve product images from public S3\n\t#\t\t# See examples of S3 authentication at https://github\\\.com/anomalizer/ngx_aws_auth\n\t#\t\t# resolver 8\\\.8\\\.8\\\.8;\n\t#\t\t# proxy_pass https://<bucket-name>\\\.<region-name>\\\.amazonaws\\\.com;\n\t#\n\t#\t\tset \\\$width \"-\";\n\t#\t\tset \\\$height \"-\";\n\t#\t\tif \(\\\$arg_width != ''\) \{\n\t#\t\t\tset \\\$width \\\$arg_width;\n\t#\t\t\}\n\t#\t\tif \(\\\$arg_height != ''\) \{\n\t#\t\t\tset \\\$height \\\$arg_height;\n\t#\t\t\}\n\t#\t\timage_filter resize \\\$width \\\$height;\n\t#\t\timage_filter_jpeg_quality 90;\n\t#\t\}\n\n\t\ttry_files \\\$uri \\\$uri/ /get.php\\\$is_args\\\$args;\n\n\t\tlocation ~ ^/media/theme_customization/.*\\\\.xml \{\n\t\t\tdeny all;\n\t\t\}\n\n\t\tlocation ~* \\\\.\(ico|jpg|jpeg|png|gif|svg|svgz|webp|avif|avifs|js|css|eot|ttf|otf|woff|woff2\)\\\$ \{\n\t\t\tadd_header Cache-Control \"public\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ /get.php\\\$is_args\\\$args;\n\t\t\}\n\n\t\tlocation ~* \\\\.\(zip|gz|gzip|bz2|csv|xml\)\\\$ \{\n\t\t\tadd_header Cache-Control \"no-store\";\n\t\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\t\texpires\toff;\n\t\t\ttry_files \\\$uri \\\$uri/ /get.php\\\$is_args\\\$args;\n\t\t\}\n\t\tadd_header X-Frame-Options \"SAMEORIGIN\";\n\t\}\n\t#\n\tlocation /media/customer/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /media/downloadable/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /media/import/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /media/custom_options/ \{\n\t\tdeny all;\n\t\}\n\t#\n\tlocation /errors/ \{\n\t\tlocation ~* \\\\.xml\\\$ \{\n\t\t\tdeny all;\n\t\t\}\n\t\}\n\t# PHP entry point for main application\n\tlocation ~ ^/\(index|get|static|errors/report|errors/404|errors/503|health_check\)\\\\.php\\\$ \{\n\t\ttry_files \\\$uri =404;\n\t\tfastcgi_pass\t\{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_buffers 16 16k;\n\t\tfastcgi_buffer_size 32k;\n\n\t\tfastcgi_param  PHP_FLAG  \"session.auto_start=off \\\n suhosin.session.cryptua=off\";\n\t\tfastcgi_param  PHP_VALUE \"memory_limit=756M \\\n max_execution_time=18000\";\n\t\tfastcgi_read_timeout 600s;\n\t\tfastcgi_connect_timeout 600s;\n\n\t\tfastcgi_index  index.php;\n\t\tfastcgi_param  SCRIPT_FILENAME  \\\$document_root\\\$fastcgi_script_name;\n\t\tinclude\t\tfastcgi_params;\n\t\}\n\t#\n\{% endif %\}\n\{% endif %\} \n\\{#\\} \\\$PROXY_PREFIX\\\$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n\t\t,gi"
				
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
				
				# tweak
				run_all_tweaks
				
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
			BITRIX_FPM_NGINX_PERL_INJECTION_LOCATIONS="s,($SPECIAL_INJECTIONS_VAR),\$1\n\n\{#\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\{#\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\{% if \\\$PHP == on %\}\n\tlocation ~* /\\\\.\(?!well-known\)\.* \{ return 404; deny all;\}\n\tlocation ~* \(\\\\.\(svn|hg|git|ht|env|tpl\)\)\\\$ \{\n\t\tdeny all; \n\t\}\n\{#\}\n\{#\} CGI_APACHE_MODULE_config_start\n\{#\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t# errors handlers\n\terror_page 403 /403.html;\n\t#error_page 404 /404.php;\n\terror_page 404 = \@fallback;\n\terror_page 412 = \@fallback;\n\terror_page 497 https://\\\$host\\\$request_uri;\n\terror_page 500 /500.html;\n\terror_page 502 /502.html;\n\terror_page 503 /503.html;\n\terror_page 504 /504.html;\n\t#\n\t# errors custom pages\n\tlocation ^~ /500.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /502.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /503.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /504.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /403.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /404.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\t#ssi_last_modified on;\n\t# memcached options\n\tmemcached_connect_timeout 1s;\n\tmemcached_read_timeout 1s;\n\tmemcached_send_timeout 1s;\n\tmemcached_gzip_flag 65536;\n\t#\n\t# variables\n\tset \\\$proxyserver \"\{% \\\$BACKEND_BIND_URI %\}\";\n\tset \\\$memcached_key \"/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_cache \"bitrix/html_pages/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_file \"\\\$root_path/\\\$\{composite_cache\}\";\n\tset \\\$use_composite_cache \"\";\n\t#\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\t# aspro max sitemap\n\t# location ~ ^/sitemap.*\\\.xml\\\$ \{ rewrite \"/\(sitemap.*\)\\\.xml\" /aspro_regions/sitemap/\\\$1_\\\$host.xml break; \}\n\t#\n\t# composite cache\n\t# if no composite checks file exist then NULL-ing variables\n\tif \(!-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$composite_key \"\"; set \\\$is_global_composite \"\"; \}\n\t# if bitrix html cache .enabled file exist then set A\n\tset \\\$composite_enabled  \"\\\$root_path/bitrix/html_pages/.enabled\";\n\tif \(-f \\\$composite_enabled\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}A\"; \}\n\t#\n\t# if bitrix html cache mappings file exist then set B\n\tif \(-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}B\"; \}\n\t#\n\t# if global check success then set C\n\tif \(\\\$is_global_composite = 1\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}C\"; \}\n\t#\n\t# if composite cache file exist then set D\n\tif \(-f \\\$composite_file\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}D\"; \}\n\t#\n\tclient_max_body_size 1024m;\n\tclient_body_buffer_size 4m;\n\t#\n\tkeepalive_timeout 70;\n\tkeepalive_requests 150;\n\t#\n\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\tproxy_set_header X-Real-IP \\\$remote_addr;\n\tproxy_set_header Host \\\$host;\n\tproxy_set_header X-Forwarded-Host \\\$host;\n\tproxy_set_header X-Forwarded-Scheme \\\$scheme;\n\n\t#### bx/conf/general-add_header.conf\n\tadd_header \"X-Content-Type-Options\" \"nosniff\";\n\tset \\\$frame_options \"\";\n\tif \(\\\$http_referer !~ '^https?:\/\/\(\[^\/\]+\\\.\)?\(webvisor\\\.com\)\/'\) \{ set \\\$frame_options \"SAMEORIGIN\"; \}\n\tadd_header \"X-Frame-Options\" \"\\\$frame_options\";\n\t#\n\t# Nginx server status page\n\tlocation ^~ /nginx-status-$RANDOM_N \{\n\t\tstub_status on;\n\t\tallow all;\n\t\}\n\t# Apache server status page\n\tlocation ~* /apache-\(status|info\)-$RANDOM_N \{\n\t\tallow all;\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\t#### bx/site_settings/default/bx_temp.conf\n\tlocation ~* ^/bx_tmp_download/ \{\n\t\tinternal;\n\t\trewrite /bx_tmp_download/\(.+\) /.bx_temp/sitemanager/\\\$1 last;\n\t\}\n\tlocation ~* ^/.bx_temp/sitemanager/ \{\n\t\tinternal;\n\t\troot \\\$root_path;\n\t\}\n\n\t#### bx/conf/bitrix_block.conf\n\t# ht\(passwd|access\)\n\tlocation ~* /\\\.ht \{ deny all; \}\n\n\t# repositories\n\tlocation ~* /\\\.\(svn|hg|git\) \{ deny all; \}\n\n\t# bitrix internal locations\n\tlocation ~* ^/bitrix/\(modules|local_cache|stack_cache|managed_cache|php_interface\) \{ deny all; \}\n\tlocation = /bitrix/.settings.php \{ deny all; \}\n\n\t# 1C upload files\n\tlocation ~* ^/upload/1c_\[^/\]+/ \{ deny all; \}\n\n\t# use the file system to access files outside the site \(cache\)\n\tlocation ~* /\\\.\\\./ \{ deny all; \}\n\tlocation = /bitrix/html_pages/.config.php \{ deny all; \}\n\tlocation = /bitrix/html_pages/.enabled \{ deny all; \}\n\n\t#### bx/conf/bitrix_general.conf\n\t# Intenal locations\n\tlocation ^~ /upload/support/not_image \{ internal; \}\n\t\t\n\n\t# Player options\ disable no-sniff\n\tlocation ~* ^/bitrix/components/bitrix/player/mediaplayer/player\\\$ \{ add_header Access-Control-Allow-Origin *; \}\n\n\t# Process dav request on\n\t# main company\n\t# extranet\n\t# additional departments\n\t# locations that ends with / => directly to apache \n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\).*/\\\$ \{ proxy_pass \\\$proxyserver; \}\n\n\t# Add / to request\n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\) \{\n\t\tset \\\$addslash \"\";\n\t\tif \(-d \\\$request_filename\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$is_args != '?'\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$addslash = \"YY\" \) \{ proxy_pass \\\$proxyserver\\\$request_uri/; \}\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\n\t# Accept access for merged css and js\n\tlocation ~* ^/bitrix/cache/\(css/.+\\\.css|js/.+\\\.js\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page 404 /404.html;\n\t\}\n\n\t# Disable access for other assets in cache location\n\tlocation ~* ^/bitrix/cache \{ deny all; \}\n\n\t# Excange and Outlook\n\tlocation ~ ^/bitrix/tools/ws_.*/_vti_bin/.*\\\.asmx\\\$ \{ proxy_pass \\\$proxyserver; \}\n\n\t# Groupdav\n\tlocation ^~ /bitrix/groupdav.php \{ proxy_pass \\\$proxyserver; \}\n\n\t# Use nginx to return static content from s3 cloud storage\n\t# /upload/bx_cloud_upload/<schema>.<backet_name>.<s3_point>.amazonaws.com/<path/to/file>\n\tlocation ^~ /upload/bx_cloud_upload/ \{\n\t\t# Amazon\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(s3|us-east-2|us-east-1|us-west-1|us-west-2|af-south-1|ap-east-1|ap-south-1|ap-northeast-3|ap-northeast-2|ap-southeast-1|ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|eu-south-1|eu-west-3|eu-north-1|me-south-1|sa-east-1\)\\\.amazonaws\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.amazonaws.com/\\\$4;\n\t\t\}\n\n\t\t# Rackspace\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.rackcdn\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.\\\$4.rackcdn.com/\\\$5;\n\t\t\}\n\n\t\t# Clodo\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.clodo\\\.ru:\(80|443\)/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.clodo.ru:\\\$3/\\\$4;\n\t\t\}\n\n\t\t# Google\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.commondatastorage\\\.googleapis\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.commondatastorage.googleapis.com/\\\$3;\n\t\t\}\n\n\t\t# Selectel\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.selcdn\\\.ru/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.selcdn.ru/\\\$3;\n\t\t\}\n\n\t\t# Yandex\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.storage\\\.yandexcloud\\\.net/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.storage.yandexcloud.net/\\\$3;\n\t\t\}\n\n\t\tlocation ~* .*\\\$ \{ deny all; \}\n\t\}\n\n\t# Static content\n\tlocation ~* ^/\(upload|bitrix/images|bitrix/tmp\) \{\n\t\tif \( \\\$upstream_http_x_accel_redirect = \"\"  \) \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\}\n\t\}\n\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\t\tadd_header Cache-Control \"public\";\n\t\terror_page 404 /404.html;\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\}\n\n\t# pub & online\n\t# telephony and voximplant\n\tlocation ~* ^/\(pub/|online/|services/telephony/info_receiver\\\.php|/bitrix/tools/voximplant/\) \{\n\t\tadd_header X-Frame-Options \"always\";\n\t\tlocation ~* ^/\(pub/imconnector/|pub/imbot.php|services/telephony/info_receiver\\\.php|bitrix/tools/voximplant/\) \{\n\t\t\tproxy_ignore_client_abort on;\n\t\t\tproxy_pass \\\$proxyserver;\n\t\t\}\n\tproxy_pass \\\$proxyserver;\n\t\}\n\n\t# Bitrix setup script\n\tlocation ^~ ^\(/bitrixsetup\\\.php\)\\\$ \{ \n\t\tproxy_pass \\\$proxyserver; \n\t\tproxy_buffering off;\n\t\}\n\n\t# Upload location\n\tlocation ~ /upload/ \{\n\t\tclient_body_buffer_size 1024m;\n\t\}\n\n\tlocation = /robots.txt \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\t# aspro robots.txt rewrite\n\t\t#rewrite \"robots.txt\" /aspro_regions/robots/robots_\\\$host.txt break;\n\t\}\n\n\tlocation = /favicon.png \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\}\n\n\tlocation  = /restore.php \{\n\t\tclient_body_buffer_size 8192m;\n\t\tclient_max_body_size 8192m;\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\n\tlocation = /bitrix/admin/1c_exchange.php \{\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\{% if \\\$LOG_ERROR == on %\}\n\t\terror_log \{% \\\$ERROR_LOG_PATH %\} notice;\n\{% else %\}\n\t\terror_log /dev/null crit;\n\{% endif %\}\n\t\tproxy_pass \\\$proxyserver;\n\t\tclient_max_body_size 1024m;\n\t\tsend_timeout 3600;\n\t\tproxy_connect_timeout 3600;\n\t\tproxy_send_timeout 3600;\n\t\tproxy_read_timeout 3600;\n\t\tfastcgi_read_timeout 3600;\n\t\tfastcgi_send_timeout 3600;\n\t\tfastcgi_connect_timeout 3600;\n\t\tclient_body_timeout 3600;\n\t\tkeepalive_timeout 3600;\n\t\tkeepalive_requests 100;\n\t\tfastcgi_param REMOTE_USER \\\$http_authorization;\n\t\tfastcgi_param HTTP_IF_NONE_MATCH \\\$http_if_none_match;\n\t\tfastcgi_param HTTP_IF_MODIFIED_SINCE \\\$http_if_modified_since;\n\t\}\n\n\tlocation = /bitrix/admin/1c_exchange_custom.php \{\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\{% if \\\$LOG_ERROR == on %\}\n\t\terror_log \{% \\\$ERROR_LOG_PATH %\} notice;\n\{% else %\}\n\t\terror_log /dev/null crit;\n\{% endif %\}\n\t\tproxy_pass \\\$proxyserver;\n\t\tclient_max_body_size 1024m;\n\t\tsend_timeout 3600;\n\t\tproxy_connect_timeout 3600;\n\t\tproxy_send_timeout 3600;\n\t\tproxy_read_timeout 3600;\n\t\tfastcgi_read_timeout 3600;\n\t\tfastcgi_send_timeout 3600;\n\t\tfastcgi_connect_timeout 3600;\n\t\tclient_body_timeout 3600;\n\t\tkeepalive_timeout 3600;\n\t\tkeepalive_requests 100;\n\t\tfastcgi_param REMOTE_USER \\\$http_authorization;\n\t\tfastcgi_param HTTP_IF_NONE_MATCH \\\$http_if_none_match;\n\t\tfastcgi_param HTTP_IF_MODIFIED_SINCE \\\$http_if_modified_since;\n\t\}\n\n\tlocation / \{\n\t\tdefault_type text/html;\n\t\t# slow \- Bitrix php composite html processing \- if bitrix/.bxfile_composite_enabled then go to Cache \(200\)\n\t\t# backend php headers \+ client headers \+ nginx headers works\n\t\tset \\\$bxfile_composite_enabled \"\\\$root_path/bitrix/.bxfile_composite_enabled\";\n\t\tif \(-f \\\$bxfile_composite_enabled\) \{ return 412; \}\n\n\t\t# fast \- Nginx html processing \- if ABCD then go to Nginx \(file\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABCD\"\) \{ rewrite .* /\\\$composite_cache last; \}\n\t\tlocation ~* \@.*\\\\.html\\\$ \{\n\t\t\tinternal;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(file\)\";\n\t\t\t# disable browser cache php manage file\n\t\t\texpires -1y;\n\t\t\tadd_header Cache-Control \"no\-store\, no\-cache\";\n\t\t\}\n\t\t# fastest - Memcached html processing - if ABC then go to Nginx \(memcached\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABC\"\) \{\n\t\t\terror_page 404 405 412 502 504 = \@bitrix;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(memcached\)\";\n\t\t\t# use memcached tcp\n\t\t\tmemcached_pass 127.0.0.1:11211;\n\t\t\t# use memcached socket\n\t\t\t#memcached_pass unix:/tmp/memcached.socket;\n\t\t\}\n\t\t# no composite cache \- if NOT ABC then go to \@bitrix\n\t\tif \(\\\$use_composite_cache != \"ABC\"\) \{ return 412; \}\n\t\t# php go to apache\n\t\t#\n\t\tproxy_pass \\\$proxyserver;\n\t\}\n\n\tlocation \@fallback \{\n\t\tproxy_set_header Host \\\$host;\n\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\tproxy_set_header X-Forwarded-Proto \\\$scheme;\n\t\tproxy_set_header X-Forwarded-Port \\\$server_port;\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\t\tproxy_pass \{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n\t\}\n\{% endif %\}\n\{#\}\n\{#\} CGI_APACHE_MODULE_config_stop\n\{#\}\n\{#\}\n\{#\} FPM_config_start\n\{#\}\n\{% if \\\$REDIRECT_TO_PHPFPM == on %\}\n\t# errors handlers\n\terror_page 403 /403.html;\n\t#error_page 404 /404.php;\n\terror_page 404 = \@bitrix;\n\terror_page 412 = \@bitrix;\n\terror_page 497 https://\\\$host\\\$request_uri;\n\terror_page 500 /500.html;\n\terror_page 502 /502.html;\n\terror_page 503 /503.html;\n\terror_page 504 /504.html;\n\t#\n\t# errors custom pages\n\tlocation ^~ /500.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /502.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /503.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /504.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /403.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\tlocation ^~ /404.html \{ root /etc/nginx/vhosts-includes/bitrix_fpm/errors; \}\n\t# memcached options\n\tmemcached_connect_timeout 1s;\n\tmemcached_read_timeout 1s;\n\tmemcached_send_timeout 1s;\n\tmemcached_gzip_flag 65536;\n\t#\n\t# variables\n\tset \\\$memcached_key \"/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_cache \"bitrix/html_pages/\\\$\{host\}\\\$\{composite_key\}/index\@\\\$\{args\}.html\";\n\tset \\\$composite_file \"\\\$root_path/\\\$\{composite_cache\}\";\n\tset \\\$use_composite_cache \"\";\n\t#\n\t# www prefix add\n\t#if \(\\\$host !~* ^www\\\..+\\\..+\\\$\) \{ return 301 \\\$scheme://www.\\\$host\\\$request_uri; \}\n\t# www prefix remove\n\t#if \(\\\$host ~* ^www\\\.\(?<domain>.+\)\\\$\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# 301 tech subdomains\n\t#if \(\\\$host ~* ^\(\(mail|smtp|ftp|mx\[d+\]|ns\[d+\]|pop3?|imap\)\(\\\.\)\(?<domain>.+\)\\\$\)\) \{ return 301 \\\$scheme://\\\$domain\\\$request_uri; \}\n\t# add trailing slash when no period in url\n\t#if \(\\\$request_uri ~* ^\(\[^.\\\?\]*\[^/\]\)\\\$\) \{ return 301 \\\$1/; \}\n\t# remove multiple end slashes in url\n\tif \(\\\$request_uri ~* ^\(\[^.\]*?\\\/\)\\\/+\(.*\)\\\$\) \{ return 301 \\\$1\\\$2; \}\n\t# remove trailing slash in url\n\t#if \(\\\$request_uri ~* ^\\\/\(.*\)\\\/\\\$\) \{ return 301 /\\\$1; \}\n\t# remove index.php from url\n\t#if \(\\\$request_uri ~* \"^\(.*/\)index\\\.php\\\$\"\) \{ return 301 \\\$1; \}\n\t#\n\t# aspro max sitemap\n\t# location ~ ^/sitemap.*\\\.xml\\\$ \{ rewrite \"/\(sitemap.*\)\\\.xml\" /aspro_regions/sitemap/\\\$1_\\\$host.xml break; \}\n\t#\n\t# composite cache\n\t# if no composite checks file exist then NULL-ing variables\n\tif \(!-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$composite_key \"\"; set \\\$is_global_composite \"\"; \}\n\t# if bitrix html cache .enabled file exist then set A\n\tset \\\$composite_enabled  \"\\\$root_path/bitrix/html_pages/.enabled\";\n\tif \(-f \\\$composite_enabled\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}A\"; \}\n\t#\n\t# if bitrix html cache mappings file exist then set B\n\tif \(-f /etc/nginx/conf.d/nginx_bitrix_http_context.conf\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}B\"; \}\n\t#\n\t# if global check success then set C\n\tif \(\\\$is_global_composite = 1\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}C\"; \}\n\t#\n\t# if composite cache file exist then set D\n\tif \(-f \\\$composite_file\) \{ set \\\$use_composite_cache \"\\\$\{use_composite_cache\}D\"; \}\n\t#\n\tclient_max_body_size 1024m;\n\tclient_body_buffer_size 4m;\n\t#\n\tkeepalive_timeout 70;\n\tkeepalive_requests 150;\n\t#\n\tadd_header \"X-Content-Type-Options\" \"nosniff\";\n\tset \\\$frame_options \"\";\n\tif \(\\\$http_referer !~ '^https?:\/\/\(\[^\/\]+\\\.\)?\(webvisor\\\.com\)\/'\) \{ set \\\$frame_options \"SAMEORIGIN\"; \}\n\tadd_header X-Frame-Options \"\\\$frame_options\";\n\t#\n\t# Nginx server status page\n\tlocation ^~ /nginx-status-$RANDOM_N \{\n\t\tstub_status on;\n\t\tallow all;\n\t\}\n\t#\n\t#### bx/site_settings/default/bx_temp.conf\n\tlocation ~* ^/bx_tmp_download/ \{\n\t\tinternal;\n\t\trewrite /bx_tmp_download/\(.+\) /.bx_temp/sitemanager/\\\$1 last;\n\t\}\n\tlocation ~* ^/.bx_temp/sitemanager/ \{\n\t\tinternal;\n\t\troot \\\$root_path;\n\t\}\n\t#\n\t#### bx/conf/bitrix_block.conf\n\t# ht\(passwd|access\)\n\tlocation ~* /\\\.ht \{ deny all; \}\n\t#\n\t# repositories\n\tlocation ~* /\\\.\(svn|hg|git\) \{ deny all; \}\n\t#\n\t# bitrix internal locations\n\tlocation ~* ^/bitrix/\(modules|local_cache|stack_cache|managed_cache|php_interface\) \{ deny all; \}\n\tlocation = /bitrix/php_interface/dbconn.php \{ deny all; \}\n\t\n\tlocation = /bitrix/.settings.php \{ deny all; \}\n\t#\n\t# 1C upload files\n\tlocation ~* ^/upload/1c_\[^/\]+/ \{ deny all; \}\n\t#\n\t# use the file system to access files outside the site \(cache\)\n\tlocation ~* /\\\.\\\./ \{ deny all; \}\n\tlocation = /bitrix/html_pages/.config.php \{ deny all; \}\n\tlocation = /bitrix/html_pages/.enabled \{ deny all; \}\n\t#### bx/conf/bitrix_general.conf\n\t# Intenal locations\n\tlocation ^~ /upload/support/not_image \{ internal; \}\n\t\t\n\n\t# Player options\ disable no-sniff\n\tlocation ~* ^/bitrix/components/bitrix/player/mediaplayer/player\\\$ \{ add_header Access-Control-Allow-Origin *; \}\n\n\t# Process dav request on\n\t# main company\n\t# extranet\n\t# additional departments\n\t# locations that ends with / => directly to fpm \n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\).*/\\\$ \{\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\t#\n\t# Add / to request\n\tlocation ~ ^\(/\[^/\]+\)?\(/docs|/workgroups|/company/profile|/bitrix/tools|/company/personal/user|/mobile/webdav|/contacts/personal\) \{\n\t\tset \\\$addslash \"\";\n\t\tif \(-d \\\$request_filename\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$is_args != '?'\) \{ set \\\$addslash \"\\\$\{addslash\}Y\"; \}\n\t\tif \(\\\$addslash = \"YY\" \) \{ rewrite ^\(.*\[^/\]\)\\\$ \\\$1/ permanent; \}\n\t\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\t# Accept access for merged css and js\n\tlocation ~* ^/bitrix/cache/\(css/.+\\\.css|js/.+\\\.js\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\terror_page 404 = \@bitrix;\n\t\t#error_page 404 /404.html;\n\t\t#error_page 404 /404.php;\n\t\}\n\n\t# Disable access for other assets in cache location\n\tlocation ~* ^/bitrix/cache \{ deny all; \}\n\n\t# Excange and Outlook\n\tlocation ~ ^/bitrix/tools/ws_.*/_vti_bin/.*\\\.asmx\\\$ \{ try_files \\\$uri \@bitrix; \}\n\n\t# Groupdav\n\tlocation ^~ /bitrix/groupdav.php \{ try_files try_files \\\$uri \@bitrix; \}\n\n\t# Use nginx to return static content from s3 cloud storage\n\t# /upload/bx_cloud_upload/<schema>.<backet_name>.<s3_point>.amazonaws.com/<path/to/file>\n\tlocation ^~ /upload/bx_cloud_upload/ \{\n\t\t# Amazon\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(s3|us-east-2|us-east-1|us-west-1|us-west-2|af-south-1|ap-east-1|ap-south-1|ap-northeast-3|ap-northeast-2|ap-southeast-1|ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|eu-south-1|eu-west-3|eu-north-1|me-south-1|sa-east-1\)\\\.amazonaws\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.amazonaws.com/\\\$4;\n\t\t\}\n\n\t\t# Rackspace\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.\(\[^/:\\\s\]+\)\\\.rackcdn\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.\\\$3.\\\$4.rackcdn.com/\\\$5;\n\t\t\}\n\n\t\t# Clodo\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.clodo\\\.ru:\(80|443\)/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.clodo.ru:\\\$3/\\\$4;\n\t\t\}\n\n\t\t# Google\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.commondatastorage\\\.googleapis\\\.com/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.commondatastorage.googleapis.com/\\\$3;\n\t\t\}\n\n\t\t# Selectel\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.selcdn\\\.ru/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.selcdn.ru/\\\$3;\n\t\t\}\n\n\t\t# Yandex\n\t\tlocation ~ ^/upload/bx_cloud_upload/\(http\[\\\s\]?\)\\\.\(\[^/:\\\s\]+\)\\\.storage\\\.yandexcloud\\\.net/\(\[^\\\s\]+\)\\\$ \{\n\t\t\tinternal;\n\t\t\tresolver 1.1.1.1 8.8.8.8 188.120.247.2 82.146.59.250 188.120.247.8 ipv6=off;\n\t\t\tresolver_timeout 3s;\n\t\t\tproxy_method GET;\n\t\t\tproxy_set_header X-Real-IP \\\$remote_addr;\n\t\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header X-Forwarded-Server \\\$host;\n\t\t\t#more_clear_input_headers 'Authorization';\n\t\t\tproxy_max_temp_file_size 0;\n\t\t\tproxy_buffer_size 4k;\n\t\t\tproxy_buffers 32 4k;\n\t\t\tproxy_pass \\\$1://\\\$2.storage.yandexcloud.net/\\\$3;\n\t\t\}\n\n\t\tlocation ~* .*\\\$ \{ deny all; \}\n\t\}\n\n\t# Static content\n\tlocation ~* ^/\(bitrix/images|bitrix/tmp\) \{\n\t\tclient_body_buffer_size 1024m;\n\t\tif \( \\\$upstream_http_x_accel_redirect = \"\"  \) \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\}\n\t\tlocation ~* ^.+\\\\.(ph(p\\\\d*|tml)|pl|asp|aspx|cgi|dll|exe|shtm|shtml|fcg|fcgi|fpl|asmx|pht|py|psp|rb|var)\\\$ \{\n\t\t\tadd_header Content-Type text/plain;\n\t\t\tdefault_type text/plain;\n\t\t\}\n\t\}\n\n\tlocation ~* ^.+\\\\.\(jpe?g|png|tiff|gif|webp|xml|yml|ogg|ogv|svgz?|mp4|rss|atom|odf|odp|ods|odt|psd|ai|eot|eps|ps|7z|aac|m4a|ico|zip|t?gz|rar|bz2?|docx?|xlsx?|exe|pptx?|tar|midi?|wav|rtf|pdf|txt|js|css|bmp|pnm|pbm|ppm|woff2?|mp3|mpe?g|avi|webm|ttf|htm\)\\\$ \{\n\t\tadd_header Cache-Control \"public\";\n\t\terror_page 404 = \@bitrix;\n\t\t#error_page 404 /404.html;\n\t\t#error_page 404 /404.php;\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\}\n\n\t# pub & online\n\t# telephony and voximplant\n\tlocation ~* ^/\(pub/|online/|services/telephony/info_receiver\\\.php|/bitrix/tools/voximplant/\) \{\n\t\tadd_header X-Frame-Options \"always\";\n\t\tlocation ~* ^/\(pub/imconnector/|pub/imbot.php|services/telephony/info_receiver\\\.php|bitrix/tools/voximplant/\) \{\n\t\t\ttry_files \\\$uri \@bitrix;\n\t\t\}\n\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\t# Bitrix setup script\n\tlocation ^~ ^\(/bitrixsetup\\\.php\)\\\$ \{\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\tlocation ~* ^/upload/.*\\\\.(php|php5|php7|pl|py|cgi|sh|bash)\\\$ \{ deny all; \}\n\t# Upload location\n\tlocation ~* ^/upload/ \{\n\t\tclient_body_buffer_size 1024m;\n\t\tif \( \\\$upstream_http_x_accel_redirect = \"\"  \) \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\}\n\t\tlocation ~* ^.+\\\\.(ph(p\\\\d*|tml)|pl|asp|aspx|cgi|dll|exe|shtm|shtml|fcg|fcgi|fpl|asmx|pht|py|psp|rb|var)\\\$ \{\n\t\t\tadd_header Content-Type text/plain;\n\t\t\tdefault_type text/plain;\n\t\t\}\n\t\}\n\n\tlocation = /robots.txt \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\t# aspro robots.txt rewrite\n\t\t#rewrite \"robots.txt\" /aspro_regions/robots/robots_\\\$host.txt break;\n\t\}\n\n\tlocation = /favicon.png \{\n\t\tlog_not_found off;\n\t\taccess_log off;\n\t\}\n\n\tlocation = /restore.php \{\n\t\tinclude fastcgi_params;\n\t\tclient_body_buffer_size 8192m;\n\t\tclient_max_body_size 8192m;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\}\n\n\t# 1C exchange\n\tlocation = /bitrix/admin/1c_exchange.php \{\n\t\tinclude fastcgi_params;\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\{% if \\\$LOG_ERROR == on %\}\n\t\terror_log \{% \\\$ERROR_LOG_PATH %\} notice;\n\{% else %\}\n\t\terror_log /dev/null crit;\n\{% endif %\}\n\t\tclient_max_body_size 1024m;\n\t\tfastcgi_read_timeout 3600;\n\t\tfastcgi_send_timeout 3600;\n\t\tfastcgi_connect_timeout 3600;\n\t\tclient_body_timeout 3600;\n\t\tkeepalive_timeout 3600;\n\t\tkeepalive_requests 100;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\tlocation = /bitrix/admin/1c_exchange_custom.php \{\n\t\tinclude fastcgi_params;\n\{% if \\\$NO_TRAFF_COUNT == on %\}\n\t\taccess_log off;\n\{% endif %\}\n\{% if \\\$LOG_ERROR == on %\}\n\t\terror_log \{% \\\$ERROR_LOG_PATH %\} notice;\n\{% else %\}\n\t\terror_log /dev/null crit;\n\{% endif %\}\n\t\tclient_max_body_size 1024m;\n\t\tfastcgi_read_timeout 3600;\n\t\tfastcgi_send_timeout 3600;\n\t\tfastcgi_connect_timeout 3600;\n\t\tclient_body_timeout 3600;\n\t\tkeepalive_timeout 3600;\n\t\tkeepalive_requests 100;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\tlocation / \{\n\t\tdefault_type text/html;\n\t\t# slow \- Bitrix php composite html processing \- if bitrix/.bxfile_composite_enabled then go to Cache \(200\)\n\t\t# backend php headers \+ client headers \+ nginx headers works\n\t\tset \\\$bxfile_composite_enabled \"\\\$root_path/bitrix/.bxfile_composite_enabled\";\n\t\tif \(-f \\\$bxfile_composite_enabled\) \{ return 412; \}\n\n\t\t# fast \- Nginx html processing \- if ABCD then go to Nginx \(file\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABCD\"\) \{ rewrite .* /\\\$composite_cache last; \}\n\t\tlocation ~* \@.*\\\\.html\\\$ \{\n\t\t\tinternal;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(file\)\";\n\t\t\t# disable browser cache php manage file\n\t\t\texpires -1y;\n\t\t\tadd_header Cache-Control \"no\-store\, no\-cache\";\n\t\t\}\n\t\t# fastest - Memcached html processing - if ABC then go to Nginx \(memcached\)\n\t\t# nginx only headers\n\t\tif \(\\\$use_composite_cache = \"ABC\"\) \{\n\t\t\terror_page 404 405 412 502 504 = \@bitrix;\n\t\t\tadd_header X-Bitrix-Composite \"Nginx \(memcached\)\";\n\t\t\t# use memcached tcp\n\t\t\tmemcached_pass 127.0.0.1:11211;\n\t\t\t# use memcached socket\n\t\t\t#memcached_pass unix:/tmp/memcached.socket;\n\t\t\}\n\t\t# no composite cache \- if NOT ABC then go to \@bitrix\n\t\tif \(\\\$use_composite_cache != \"ABC\"\) \{ return 412; \}\n\t\}\n\t# php go to php-fpm\n\t#\n\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\t\tinclude fastcgi_params;\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\t\tfastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;\n\t\tfastcgi_param PHP_ADMIN_VALUE \"sendmail_path = /usr/sbin/sendmail -t -i -f \{% \\\$EMAIL %\}\";\n\t\tfastcgi_param SERVER_NAME \\\$host;\n\t\tfastcgi_param REMOTE_USER \\\$http_authorization;\n\t\tfastcgi_param HTTP_IF_NONE_MATCH \\\$http_if_none_match;\n\t\tfastcgi_param HTTP_IF_MODIFIED_SINCE \\\$http_if_modified_since;\n\t\tfastcgi_read_timeout 180;\n\t\tfastcgi_send_timeout 180;\n\t\tfastcgi_connect_timeout 180;\n\t\tclient_body_timeout 180;\n\t\tkeepalive_timeout 180;\n\t\tfastcgi_ignore_client_abort off;\n\t\tfastcgi_buffer_size 128k;\n\t\tfastcgi_buffers 8 256k;\n\t\tfastcgi_busy_buffers_size 256k;\n\t\tfastcgi_temp_file_write_size 10m;\n\t\tkeepalive_requests 100;\n\t\ttry_files \\\$uri \@bitrix;\n\t\}\n\n\tlocation \@bitrix \{\n\t\ttry_files \\\$uri \\\$uri/ /bitrix/urlrewrite.php\\\$is_args\\\$args;\n\t\}\n\{% endif %\}\n\{#\}\n\{#\} FPM_config_stop\n\{#\}\n\{% endif %\}\n\{% endif %\}\n\{#\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n\n,gi"
	
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
							
							if printf "1\n" | bash "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" >/dev/null 2>&1
							then
								printf " - ${GCV}OK${NCV}\n"
								\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" >/dev/null 2>&1
							else
								printf " - ${LRV}FAIL${NCV}\n"
								\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" >/dev/null 2>&1
								EXIT_STATUS=1
								check_exit_and_restore_func
							fi
						else
							printf "\n${RLV}Download $GIT_THE_CHOSEN_ONE_DOMAIN_NAME$GIT_THE_CHOSEN_ONE_REQ_URI/$NGX_RECOMPILE_SCRIPT_NAME failed${NCV}\n"
							\rm -f "/tmp/$NGX_RECOMPILE_SCRIPT_NAME" >/dev/null 2>&1
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
					if ! grep -v "#" $NGINX_MAIN_CONF_FILE | grep "include /etc/nginx/conf.d/\*.conf.*;" >/dev/null 2>&1
					then
						# nginx's include /etc/nginx/conf.d/*.conf.* was not found
						# check that we already have bitrix_fpm $NGINX_MAIN_CONF_FILE inject
						if ! grep "$PROXY_PREFIX$proxy_target" $NGINX_MAIN_CONF_FILE >/dev/null 2>&1
						then
							sed -i "s@http {@&\n# $PROXY_PREFIX$proxy_target\_START_DO_NOT_REMOVE\n# date added - $current_date_time\n# $PROXY_PREFIX$proxy_target\_STOP_DO_NOT_REMOVE\n@g" $NGINX_MAIN_CONF_FILE
							# download
							bitrix_fpm_download_files_func
							
							# adding inject if /etc/nginx/conf.d/*.conf.* was not found
							printf "Updating $NGINX_MAIN_CONF_FILE\n"
							sed -i "s@# $PROXY_PREFIX$proxy_target\_STOP_DO_NOT_REMOVE@    include\t$BITRIX_FPM_NGINX_HTTP_INCLUDE_DIR/$file;\n&@g" $NGINX_MAIN_CONF_FILE >/dev/null 2>&1
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
				#set_status_pages >/dev/null 2>&1
				
				# tweak
				run_all_tweaks

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
