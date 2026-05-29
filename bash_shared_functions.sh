#!/bin/bash
# enable debug
#set -x -v

# exit 1 if any error
#set -e -o verbose

#set -o verbose
#pipefail | verbose

# show script version
bash_shared_func_version="1.1.2"

# isp vars
export MGR_PATH="/usr/local/mgr5"
export MGR_BIN="$MGR_PATH/sbin/mgrctl"
export MGR_CTL="$MGR_PATH/sbin/mgrctl -m ispmgr"
export MGR_MAIN_CONF_FILE="$MGR_PATH/etc/ispmgr.conf"

# check OS
check_os_func() {
shopt -s nocasematch
export REL=$(cat /etc/*release* | head -n 1)
case "$REL" in
	*cent*) DISTR="rhel";;
	*alma*) DISTR="rhel";;
	*rocky*) DISTR="rhel";;
	*cloud*) DISTR="rhel";;
	*rhel*) DISTR="rhel";;
	*debian*) DISTR="debian";;
	*ubuntu*) DISTR="debian";;
	*) DISTR="unknown";;
esac;
shopt -u nocasematch

# RHEL
if [[ $DISTR == "rhel" ]]; then
        printf "\nLooks like this is some ${GCV}RHEL (or derivative) OS${NCV}\n"
# DEBIAN
elif [[ $DISTR == "debian" ]]; then
        printf "\nLooks like this is some ${GCV}Debian (or derivative) OS${NCV}\n"
# UNKNOWN
elif [[ $DISTR == "unknown" ]]; then
        printf "\n${LRV}Sorry, cannot detect this OS${NCV}\n"
        EXIT_STATUS=1
        exit 1
fi

}

bitrix_env_check_func() {

export BITRIX_MAJOR_VER=$(grep -oP '(?<=BITRIX_VA_VER=)[0-9]+' /etc/profile 2>/dev/null)

# detecting bitrix and bitrix alike environments
if grep -RiIl BITRIX_VA_VER /etc/*/bx/* --include="*.conf" > /dev/null 2>&1 || ( 2>&1 nginx -T | \grep -iI "bitrix_general.conf" > /dev/null 2>&1 && [[ ! -f $MGR_BIN ]] > /dev/null 2>&1 ); then

	# bitrix ENV (nginx+apache)
	if [[ -d /opt/webdir ]]; then
		bitrix_env_version=$(egrep -o 'BITRIX_VA_VER=[0-9\.]+' /etc/profile | awk -F'=' '{print $2}' )
		printf "\n${GC}Bitrix ${bitrix_env_version} env${NC}ironment detected\n"
		export BITRIX="ENV"
	# bitrix GT (nginx+apache+fpm)
	elif (grep -riI "^LoadModule proxy_fcgi" /etc/apache2/*enabled*/* > /dev/null 2>&1 && systemctl | grep -i fpm > /dev/null 2>&1) || ( grep -riI "^LoadModule proxy_fcgi" /etc/httpd/* > /dev/null 2>&1 && systemctl | grep -i fpm > /dev/null 2>&1); then
		printf "\n${GC}Bitrix GT${NC} environment detected\n"
		export BITRIX="GT"
	# bitrix VANILLA (nginx+apache)
	elif 2>&1 nginx -T | grep -i "server httpd:8090" > /dev/null 2>&1; then
		printf "\n${GC}Bitrix Vanilla${NC} environment detected\n"
		export BITRIX="VANILLA"
	# bitrix OTHER
	else
		printf "\n${GC}Bitrix${NC} environment derivative detected\n"
		export BITRIX="OTHER"
	fi

export BITRIXALIKE="yes"
fi

}

# RPAF or not RPAF
# 0 - detected correct version
# 1 - not detected, need to fix
checking_mod_rpaf_func() {

if [[ "$BITRIX_MAJOR_VER" -ge 9 ]]; then
	return 0
fi

if [[ $DISTR == "rhel" ]]; then
	apache_httpd_mod_folder="/usr/lib64/httpd"
elif [[ $DISTR == "debian" ]]; then
	apache_httpd_mod_folder="/usr/lib/apache2"
else
	printf "\n${LRV}DISTR apache_httpd_mod_folder unknown${NCV}\n"	
	exit 1
fi

{
if ! which strings; then
	apt-get update; apt-get install -y binutils || yum -y install binutils 
fi
} > /dev/null 2>&1

if { strings ${apache_httpd_mod_folder}/modules/mod_rpaf.so | grep -q "/tmp/mod_rpaf.c"; } >/dev/null 2>&1; then
	printf "\nRPAF apache module ${GCV}already installed${NCV}"
	printf "\nrun: \mv ${apache_httpd_mod_folder}/modules/mod_rpaf.so ${apache_httpd_mod_folder}/modules/mod_rpaf.dis to reinstall\n"
	return 0
else
	return 1
fi
}

# nginx expose port detect func
# 0 - detected, need to fix
# 1 - not detected
nginx_port_expose_detect_func() {

if [[ "$BITRIX_MAJOR_VER" -ge 9 ]]; then
	return 1
fi

if nginx -T 2>&1 | grep -qi "\$host:80;" >/dev/null 2>&1 || nginx -T 2>&1 | grep -qi "\$host:443;" >/dev/null 2>&1; then
	return 0
else
	return 1
fi
}
