#!/bin/bash
# enable debug
#set -x -v

# exit 1 if any error
#set -e -o verbose

#set -o verbose
#pipefail | verbose

# show script version
self_current_version="1.0.1"

# check OS
check_os_func() {
shopt -s nocasematch
REL=$(cat /etc/*release* | head -n 1)
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

# RPAF or not RPAF
# 0 - detected correct version
# 1 - not detected, need to fix
checking_mod_rpaf_func() {
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
if 2>&1 nginx -T | grep -i "\$host:80;" >/dev/null 2>&1 || 2>&1 nginx -T | grep -i "\$host:443;" >/dev/null 2>&1; then
	return 0
else
	return 1
fi
}
