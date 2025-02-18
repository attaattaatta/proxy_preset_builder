#!/bin/bash
# enable debug
#set -x -v

# exit 1 if any error
#set -e -o verbose

#set -o verbose
#pipefail | verbose

# show script version
self_current_version="1.0.0"

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