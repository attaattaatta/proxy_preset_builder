#!/usr/bin/bash

# fixing paths
export PATH=$PATH:/usr/sbin:/usr/sbin:/usr/local/sbin

# set colors
GCV="\033[0;92m"
LRV="\033[1;91m"
YCV="\033[01;33m"
NCV="\033[0m"

# check privileges
if [[ $EUID -ne 0 ]]
then
	printf "\n${LRV}This script must be run as root.${NCV}" 
	exit 1
fi

#check tools
WE_NEED=('/usr/local/mgr5/sbin/mgrctl' 'nginx' 'sed' 'perl' 'cp' 'grep' 'printf' 'cat' 'rm' 'test')

for needitem in "${WE_NEED[@]}"
do
	if ! command -v $needitem &> /dev/null
	then 
		printf "\n${LRV}$needitem could not be found. Please install it first or export correct \$PATH.${NCV}"
	exit 1
	fi
done

# isp vars
MGR_PATH="/usr/local/mgr5"
MGRCTL="$MGR_PATH/sbin/mgrctl -m ispmgr"

# allowed script actions
ALLOWED_ACTIONS="(^add$|^del$|^reset$)"

# paths to ISP manager nginx templates
NGINX_DEFAULT_TEMPLATE="$MGR_PATH/etc/templates/default/nginx-vhosts.template"
NGINX_DEFAULT_SSL_TEMPLATE="$MGR_PATH/etc/templates/default/nginx-vhosts-ssl.template"
NGINX_TEMPLATE="$MGR_PATH/etc/templates/nginx-vhosts.template"
NGINX_SSL_TEMPLATE="$MGR_PATH/etc/templates/nginx-vhosts-ssl.template"

# proxy prefix may be changed here
PROXY_PREFIX="proxy_to_"

# show script version
self_current_version="1.0.1"
printf "\n${YCV}Hello, my version is $self_current_version${NCV}\n"

# check panel version and release name
printf "\n${GCV}ISP Manager version checking${NCV}\n"

panel_required_version="6.24.0"

panel_current_version=$($MGRCTL license.info | grep -o -P '(?<=panel_info=)\d+\.?\d+\.?\d+')
panel_release_name=$($MGRCTL license.info |  grep -o -P '(?<=panel_name=)\w+\s\w+')

if [[ -z $panel_release_name ]] || [[ -z $panel_current_version ]]
then
	printf "\n${LRV}Cannot get ISP Manager panel version or release name.\nPlease check \"$MGRCTL license.info\" command${NCV}"
	exit 1
fi

# set case insence for regexp
shopt -s nocasematch
if [[ $panel_release_name =~ .*busines.* ]]
then 
	printf "\n${LRV}ISP Manager Business detected. Not yet supported.${NCV}"
	shopt -u nocasematch
	exit 1
else
	if [[ $panel_current_version < $panel_required_version ]]
	then 
		printf "\n${LRV}ISP Manager panel version must not be less than $panel_required_version (current version is $panel_current_version)${NCV}\n${GCV}You may update it to $panel_required_version\nor check out this link - https://gitlab.hoztnode.net/admins/scripts/-/blob/12c70d7c370959f9f8a2c45b3b72c0a9aade914c/proxy_preset_builder.sh\nfor older panel release version of this script${NCV}"
		exit 1
	else
		printf "\n${GCV}ISP Manager version ($panel_current_version) suits.${NCV}\n"
	fi
		printf "\n${GCV}ISP Manager release ($panel_release_name) suits.${NCV}\n"
fi
# unset case insence for regexp
shopt -u nocasematch

# validate first argument 
if ! [[ $1 =~ $ALLOWED_ACTIONS ]]  && ! [[ -z "$1" ]]
then
	printf "\n\n${LRV}ERROR - Not valid argument - $1${NCV}\n"
	exit 1
fi

# backing up /etc and existing presets
backup_func() {
	printf "\n${GCV}Backing up etc and templates${NCV}\n"
	if ! [ -e /root/support ]; then mkdir /root/support; fi
	current_ispmgr_backup_directory="/root/support/ispmgr_templates.$(date '+%d-%b-%Y-%H-%M')"
	current_etc_backup_directory="/root/support/etc_preset_builder_$(date '+%d-%b-%Y-%H-%M')"
	cp -rp $MGR_PATH/etc/templates $current_ispmgr_backup_directory
	cp -rp /etc $current_etc_backup_directory
	NGINX_TEMPLATE_BACKUP="$current_ispmgr_backup_directory/nginx-vhosts.template"
	NGINX_SSL_TEMPLATE_BACKUP="$current_ispmgr_backup_directory/nginx-vhosts-ssl.template"
	printf "\n${GCV}/etc and templates are backed up to $current_ispmgr_backup_directory and $current_etc_backup_directory${NCV}\n"
}
  
# if proxy target to fastcgi format fastcgi_pass string
fastcgi_pass_format_func() {
	sed -i -E 's@(.*fastcgi_pass.+):;$@\1;@gi' $NGINX_TEMPLATE
	sed -i -E 's@(.*fastcgi_pass.+):;$@\1;@gi' $NGINX_SSL_TEMPLATE
}

# remove ssl port number from 301 redirect
seo_fix_ssl_port_func() {
	sed -i -E 's@(.*return 301 https:\/\/\$host)\:\{\% \$SSL_PORT \%\}(\$request_uri;)@\1\2@gi' $NGINX_TEMPLATE
}
  
# removing presets if defined
if [[ $1 = "del" ]]
then
	if [[ $2 = "all" ]]
	then
		read -p "This will delete all $PROXY_PREFIX presets. Are you sure? " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			backup_func
			# removing all $PROXY_PREFIX presets
			preset_list=$($MGRCTL preset | awk -F '=' '{print $3}' | grep -E 'proxy_to_.+')
			for plist in $preset_list; do $MGRCTL preset.delete elid=$plist elname=$plist; done
			printf "\n${LRV}All ISP panel %%$PROXY_PREFIX%% presets was removed${NCV}\n"
		
			# removing all $PROXY_PREFIX  injects
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_TEMPLATE 
			sed -i '/^[[:space:]]*$/d' $NGINX_TEMPLATE
			sed -i "/$PROXY_PREFIX.*_START_DO_NOT_REMOVE/,/$PROXY_PREFIX.*_STOP_DO_NOT_REMOVE/d" $NGINX_SSL_TEMPLATE 
			sed -i '/^[[:space:]]*$/d' $NGINX_SSL_TEMPLATE
			
			# panel graceful restart and exit
			$MGRCTL -R
			printf "\n${LRV}ISP panel restarted${NCV}\n"
			exit 0
		else
			printf "\n${LRV}Deletion canceled${NCV}\n"
			exit 0
		fi
	# check that this preset exists in panel, and if exists dlete it with inject
	elif [[ ! -z "$2"  ]]  && [[  ! -z $($MGRCTL preset | awk -F '=' '{print $3}' | grep -E "$2") ]]
		then
			read -p "This will delete $2 preset. Are you sure? " -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				backup_func
				# removing $2 preset
				printf "\n${LRV}Deleting preset $2 ${NCV}\n"
				$MGRCTL preset.delete elid=$2 elname=$2
				
				# removing $2 inject
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_TEMPLATE
				sed -i '/^[[:space:]]*$/d' $NGINX_TEMPLATE
				sed -i "/$2.*_START_DO_NOT_REMOVE/,/$2.*_STOP_DO_NOT_REMOVE/d" $NGINX_SSL_TEMPLATE
				sed -i '/^[[:space:]]*$/d' $NGINX_SSL_TEMPLATE
				
				# restart panel
				$MGRCTL -R
				printf "\n${LRV}ISP panel restarted${NCV}\n"
				exit 0
			else
				printf "\n${LRV}Deletion canceled${NCV}\n"
				exit 0
			fi
	# del was supplied without preset
	elif [[ ! -z "$1"  ]] && [[ -z "$2"  ]]
		then
			printf "\n${LRV}Preset not defined.\n\nExample: $BASH_SOURCE del $PROXY_PREFIXwordpress_fpm${NCV}\n"
			exit 1
	
	else	
		printf "\n${LRV}Preset $2 not found in panel.\nNothing to delete.${NCV}\n"
		exit 1
	fi
fi

# delete all presets and injects and restore defaults
if [[ $1 = "reset" ]]
then
	read -p "This will delete all presets. Are you sure? " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
		then
			backup_func
			# removing all presets 
			preset_list=$($MGRCTL preset | awk -F '=' '{print $3}')
			for plist in $preset_list; do $MGRCTL preset.delete elid=$plist elname=$plist; done
			printf "\n${LRV}All ISP panel presets removed${NCV}\n"
			# removing nginx templates
			rm -f $NGINX_SSL_TEMPLATE
			rm -f $NGINX_TEMPLATE
			printf "\n${LRV}Custom nginx templates removed${NCV}\n"
			# panel graceful restart
			$MGRCTL -R
			printf "\n${LRV}ISP panel restarted${NCV}\n"
			exit 0
		else
			printf "\n${LRV}Reset canceled${NCV}\n"
			exit 0
		fi
fi

main_func() {

# enought arguments check and if nothing in the list of presets show help
if [[ "$#" -lt 1 ]]
then
	# check if any presets exist
	if [[ $($MGRCTL preset) ]]
	then
		printf "\n${GCV}Listing existing presets:${NCV}\n---------------\n"
		$MGRCTL preset | awk -F '=' '{print $3}'
		echo "---------------"
	else
		printf "\n${GCV}There is no existing presets in the ISP panel${NCV}\n"
	fi
	printf "\n${GCV}Example for 1 preset:${NCV} $BASH_SOURCE add wordpress_fpm OR $BASH_SOURCE add 127.0.0.1:8088\n"
	printf "${GCV}Example for 5 presets:${NCV} $BASH_SOURCE add bitrix_fpm wordpress_fpm 127.0.0.1:8000 1.1.1.1 /path/to/unix/socket\n"
	printf "\n${GCV}Delete all existing %%$PROXY_PREFIX*%% presets and injects:${NCV} $BASH_SOURCE del all_$PROXY_PREFIX"
	printf "\n${GCV}Delete one existing preset and inject:${NCV} $BASH_SOURCE del proxy_to_bitrix_fpm"
	printf "\n${GCV}Restore default templates and delete all presets:${NCV} $BASH_SOURCE reset\n"
	printf "\n${YCV}Current specials list:${NCV} wordpress_fpm (soon bitrix_fpm, opencart_fpm, magento_fpm, passenger_ruby)\n"
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
		printf "\n${GCV}NGINX default template exists. Copying it to $NGINX_TEMPLATE ${NCV}\n"
		cp -p $NGINX_DEFAULT_TEMPLATE $NGINX_TEMPLATE
		# fix importing default ssl template
		sed -i 's@import etc/templates/default/@import etc/templates/@gi' $NGINX_TEMPLATE
	fi
fi

if [[ ! -f "$NGINX_SSL_TEMPLATE" ]]
then
	if [[ ! -f "$NGINX_DEFAULT_SSL_TEMPLATE" ]]
	then
		printf "\n${LRV}No NGINX default ssl template exists in $MGR_PATH/etc/templates/default/. \nExiting.${NCV}\n"
		exit 1
	else
		printf "\n${GCV}NGINX default ssl template exists. Copying it to $NGINX_SSL_TEMPLATE ${NCV}\n\n"
		cp -p $NGINX_DEFAULT_SSL_TEMPLATE $NGINX_SSL_TEMPLATE
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
	
	BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_APACHE="s,(\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\tlocation \@fallback \{\n)\t\tproxy_pass \{% \\\$BACKEND_BIND_URI %\};\n\t\tproxy_redirect \{% \\\$BACKEND_BIND_URI %\} /;\n,\$1$BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_APACHE="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_APACHE_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_APACHE == on %\}\n\t\tproxy_pass http://$proxy_target;\n\t\tproxy_redirect http://$proxy_target /;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_APACHE_STOP_DO_NOT_REMOVE\n,gi"
	
	BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR="\n\\{#\\} phpfpm_backward_compatibility_condition_start_DO_NOT_\(RE\)MOVE\n\{% if \\\$PRESET == #custom %\}\n\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n\{% endif %\}\n\\{#\\} phpfpm_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE\n"
	
	BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_PHPFPM="s,(\{% if \\\$REDIRECT_TO_PHPFPM == on %\}\n\tlocation \@php \{\n\t\tfastcgi_index index.php;\n\t\tfastcgi_param PHP_ADMIN_VALUE \"sendmail_path = /usr/sbin/sendmail -t -i -f \{% \\\$EMAIL %\}\";\n)\t\tfastcgi_pass \{% \\\$PHPFPM_USER_SOCKET_PATH %\};\n,\$1$BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_PHPFPM="s,($BACKWARD_COMPATIBILITY_IF_REDIRECT_TO_PHPFPM_VAR),\$1\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target and \\\$REDIRECT_TO_PHPFPM == on %\}\n\t\tfastcgi_pass $proxy_target;\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_TO_PHPFPM_STOP_DO_NOT_REMOVE\n,gi"
	
	BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_BEGIN="s,(\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n)(\tlocation / \{\n\{% if \\\$PHP == on %}\n),\$1\n\\{#\\} php_off_backward_compatibility_condition_start_DO_NOT_(RE)MOVE\n{% if \\\$PRESET == #custom %}\n\$2,gi"
	
	BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_END="s,(\t\t\ttry_files /does_not_exists \@fallback;\n\t\t}\n\{% endif %\}\n\t\}\n\{% endif %\}\n)(\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\tlocation \@fallback \{),\$1\n\{% endif %\}\n\\{#\\} php_off_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE\n\n\$2,gi"
	
	REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF="s,(\{#\\} php_off_backward_compatibility_condition_stop_DO_NOT_\(RE\)MOVE),\$1\n\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_IF_PHPOFF_START_DO_NOT_REMOVE\n\\{#\\} date added - $current_date_time\n\{% if \\\$PRESET == $PROXY_PREFIX$proxy_target %\}\n\tlocation / \{\n\{% if \\\$PHP == off %\}\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@backend;\n\{% endif %\}\n\\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\t\tlocation ~ \[^/\]\\\.ph\(p\\\d*|tml\)\\\$ \{\n\t\t\ttry_files /does_not_exists \@php;\n\t\t\}\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation ~ \[^/\]\\\\.ph\(p\\\\d*|tml\)\\\$ \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\{% endif %\}\n\{% if \\\$PHP == on %\}\n\t\tlocation ~* ^.+\\\.\(jpg|jpeg|gif|png|svg|js|css|mp3|ogg|mpe?g|avi|zip|gz|bz2?|rar|swf\)\\\$ \{\n\{% if \\\$SRV_CACHE == on %\}\n\t\t\texpires \[% \\\$EXPIRES_VALUE %\];\n\{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\t\ttry_files \\\$uri \\\$uri/ \@fallback;\n\{% endif %\}\n\t\t\}\n{% endif %\}\n\{% if \\\$REDIRECT_TO_APACHE == on %\}\n\t\tlocation / \{\n\t\t\ttry_files /does_not_exists \@fallback;\n\t\t\}\n\\{% endif %\}\n\{% if \\\$ANALYZER != off and \\\$ANALYZER !=  %\}\n\t\tlocation \{% \\\$WEBSTAT_LOCATION %\} \{\n\t\t\tcharset \[% \\\$WEBSTAT_ENCODING %\];\n\t\t\tindex index.html;\n\t\t\tlocation ~ \[^/\].ph\(pd*|tml\)\\\$ \{\n\t\t\t\ttry_files \\\$uri \\\$uri/ \@backend;\n\t\t\t\}\n\t\t\}\n\{% endif %\}\n\t\}\n\{% if \\\$PHP == off %\}\n\tlocation \@backend \{\n\t\tproxy_pass http://$proxy_target;\n\t\tproxy_redirect http://$proxy_target /;\n\t\tproxy_set_header Host \\\$host;\n\t\tproxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\n\t\tproxy_set_header X-Forwarded-Proto \\\$scheme;\n\t\tproxy_set_header X-Forwarded-Port \\\$server_port;\n\t}\n\{% endif %\}\n\{% endif %\}\n\\{#\\} $PROXY_PREFIX$proxy_target\_REDIRECT_IF_PHPOFF_STOP_DO_NOT_REMOVE\n,gi"

	# wordpress_fpm nginx templates injections variables
	WORDPRESS_FPM_NGINX_PERL_INJECTION="s,(\tlocation / \{\n\{% if \\\$PHP == on %\}\n)\t\t,\$1\\{#\\}WORDPRESS_FPM_NGINX_PERL_INJECTION_START\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\{% if \\\$PRESET == proxy_to_wordpress_fpm %\}\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$args;\n\{% endif %\}\n{% endif %}\n\\{#\\}#WORDPRESS_FPM_NGINX_PERL_INJECTION_STOP\n\t\t,gi"
	
	WORDPRESS_FPM_NGINX_SSL_PERL_INJECTION="s,(\tlocation / \{\n\{% if \\\$PHP == on %\}\n)\t\t,\$1\\{#\\}#WORDPRESS_FPM_NGINX_SSL_PERL_INJECTION_START\n\{% if \\\$PHP_MODE == php_mode_fcgi_nginxfpm %\}\n\{% if \\\$PRESET == proxy_to_wordpress_fpm %\}\n\t\ttry_files \\\$uri \\\$uri/ /index.php?\\\$args;\n\{% endif %\}\n\{% endif %\}\n\\{#\\}#WORDPRESS_FPM_NGINX_SSL_PERL_INJECTION_STOP\n\t\t,gi"

	# bitrix_fpm nginx templates injections variables
	BITRIX_PROXY_NGINX_HTTP_CONTEXT="/etc/nginx/conf.d/proxy_to_bitrix_fpm_http_context.conf"
	
	printf "\n\n${GCV}Creating preset for $PROXY_PREFIX$proxy_target${NCV}\n"
	# check for error / success
	if $MGRCTL preset.edit limit_charset=UTF-8 limit_php_mode=php_mode_fcgi_nginxfpm limit_php_fpm_version=native limit_php_mode_fcgi_nginxfpm=on limit_cgi=on limit_php_cgi_enable=on limit_php_mode_cgi=on limit_php_mode_mod=on limit_shell=on limit_ssl=on name=$PROXY_PREFIX$proxy_target sok=ok
	then
		printf "\n${GCV}Successfuly added preset - $PROXY_PREFIX$proxy_target${NCV}\n"
		preset_raise_error="0"
			#if wordpress_fpm in preset name create special template
			if [[ $proxy_target = "wordpress_fpm" ]]
			then
				# wordpress_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting SPECIAL $PROXY_PREFIX$proxy_target template in $NGINX_TEMPLATE ${NCV}\n"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_PERL_INJECTION" "$NGINX_TEMPLATE"
				
				# wordpress_fpm nginx-vhosts-ssl.template
				printf "\n${YCV}Injecting SPECIAL $PROXY_PREFIX$proxy_target template in $NGINX_SSL_TEMPLATE ${NCV}\n"
				perl -i -p0e "$WORDPRESS_FPM_NGINX_SSL_PERL_INJECTION" "$NGINX_SSL_TEMPLATE"
				
				continue
				
			#if bitrix_fpm in preset name create special template
			elif [[ $proxy_target = "bitrix_fpm" ]]
			then
				# bitrix_fpm nginx map include
				printf "\n${YCV}Writing bitrix nginx maps in $BITRIX_PROXY_NGINX_HTTP_CONTEXT ${NCV}\n"
				cat <<XEOF > $BITRIX_PROXY_NGINX_HTTP_CONTEXT



###### push-im_settings.conf start ######
push_stream_shared_memory_size				256M;
push_stream_max_messages_stored_per_channel	1000;
push_stream_max_channel_id_length				32;
push_stream_max_number_of_channels			100000;
push_stream_message_ttl						86400;
###### push-im_settings.conf end ######

###### composite_settings.conf start ######
map $uri $composite_key {
	default										$uri;
	~^(/|/index.php|/index.html)$						"";
	~^(?P<non_slash>.+)/$							$non_slash;
	~^(?P<non_index>.+)/index.php$					$non_index;
	~^(?P<non_index>.+)/index.html$					$non_index;
}

# disable composite cache if BX_ACTION_TYPE exists
map $http_bx_action_type $not_bx_action_type {
	default		"0";
	""			"1";
}

# disable composite cache if BX_AJAX
map $http_bx_ajax $not_bx_ajax {
	default		"0";
	""			"1";
}

# disable composite cache if method != GET
map $request_method $is_get {
	default		"0";
	"GET"		"1";
}

# disable composite cache if there next query string in agrs
# ncc
map $arg_ncc $non_arg_ncc {
	default		"0";
	""			"1";
}

# bxajaxid
map $arg_bxajaxid $non_arg_bxajaxid {
	default		"0";
	""			"1";
}

# sessid
map $arg_sessid $non_arg_sessid {
	default		"0";
	""			"1";
}

# test IE
map $http_user_agent $is_modern {
	default					 "1";
	"~MSIE [5-9]"				 "0";
}

# add common limit by uri path
map $uri $is_good_uri {
	default								"1";
	~^/bitrix/								"0";
	~^/index_controller.php					"0";
}

# not found NCC
map $cookie_BITRIX_SM_NCC $non_cookie_ncc {
	default		"0";
	""			"1";
}

# complex test
# BITRIX_SM_LOGIN, BITRIX_SM_UIDH - hold values and BITRIX_SM_CC is empty
map $cookie_BITRIX_SM_LOGIN $is_bx_sm_login {
	default		"1";
	""			"0";
}

map $cookie_BITRIX_SM_UIDH $is_bx_sm_uidh {
	default		"1";
	""			"0";
}

map $cookie_BITRIX_SM_CC $is_bx_sm_cc {
	default		"1";
	"Y"			"0";
}

map "${is_bx_sm_login}${is_bx_sm_uidh}${is_bx_sm_cc}" $is_storedAuth {
	default		"1";
	"111"		"0";
}

# test all global conditions
map "${not_bx_action_type}${not_bx_ajax}${is_get}${non_arg_ncc}${non_arg_bxajaxid}${non_arg_sessid}${is_modern}${is_good_uri}${non_cookie_ncc}${is_storedAuth}" $is_global_composite {
	default		"1";
	~0			"0";
}

map $uri $general_key {
	default								$uri;
	~^(?P<non_slash>.+)/$					$non_slash;
	~^(?P<php_path>.+).php$				$php_path;
}

# if exists cookie PHPSESSID disable
map $cookie_PHPSESSID $non_cookie_phpsessid {
	default			"0";
	""				"1";
}

# main condition for general cache
map "${is_get}${cookie_PHPSESSID}" $is_global_cache {
	default			"1";
	~0				"0";
}
###### composite_settings.conf end ######
XEOF
				# bitrix_fpm nginx-vhosts.template
				printf "\n${YCV}Injecting SPECIAL $PROXY_PREFIX$proxy_target template in $NGINX_TEMPLATE ${NCV}\n"
				
				
				# bitrix_fpm nginx-vhosts-ssl.template
				printf "\n${YCV}Injecting SPECIAL $PROXY_PREFIX$proxy_target template in $NGINX_SSL_TEMPLATE ${NCV}\n"
				
				continue
			else
				#no special injections comes here
				printf "\n${GCV}Injecting $PROXY_PREFIX$proxy_target ${NCV}\n"
				# NGINX_TEMPLATE
				perl -i -p0e "$BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_APACHE" "$NGINX_TEMPLATE" 
				perl -i -p0e "$BACKWARD_COMPATIBILITY_CONDITION_IF_REDIRECT_TO_PHPFPM" "$NGINX_TEMPLATE"
				perl -i -p0e "$BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_BEGIN" "$NGINX_TEMPLATE"
				perl -i -p0e "$BACKWARD_COMPATIBILITY_NGINX_PERL_INJECTION_IF_PHP_OFF_END" "$NGINX_TEMPLATE"		
				# NGINX_SSL_TEMPLATE
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
				
				if test $EXIT_STATUS != 0
				then
					printf "${LRV}Test of backward compatibility has failed.\nCheck script's perl injections.\nor (default) nginx template edits\n\nRemoving preset $PROXY_PREFIX$proxy_target\nRestoring last backup and exiting.${NCV}\n"
					rm -f "$NGINX_TEMPLATE" "$NGINX_SSL_TEMPLATE"
					$MGRCTL preset.delete elid=$PROXY_PREFIX$proxy_target elname=$PROXY_PREFIX$proxy_target
					printf "\n${GCV}$PROXY_PREFIX$proxy_target - was removed successfuly ${NCV}\n"
					
					if [[ -f "$NGINX_TEMPLATE_BACKUP" ]] || [[ -f "$NGINX_SSL_TEMPLATE_BACKUP" ]]
					then
						cp -f -p "$NGINX_TEMPLATE_BACKUP" "$NGINX_TEMPLATE" && printf "${GCV}$NGINX_TEMPLATE_BACKUP restore was successful.\n${NCV}"
						cp -f -p "$NGINX_SSL_TEMPLATE_BACKUP" "$NGINX_SSL_TEMPLATE" && printf "${GCV}$NGINX_SSL_TEMPLATE_BACKUP restore was successful.\n${NCV}"
						exit 1
					else 
						printf "\n${LRV}$current_ispmgr_backup_directory/nginx-vhosts.template\n$current_ispmgr_backup_directory/nginx-vhosts-ssl.template\nNot exists."
						exit 1
					fi
				else
					#backward_compatibility test succeeded
					printf "\n${GCV}Backward compatibility test succeed ${NCV}\n"
					# $NGINX_TEMPLATE
					perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_APACHE" "$NGINX_TEMPLATE"
					perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_PHPFPM" "$NGINX_TEMPLATE"
					perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF" "$NGINX_TEMPLATE"
					
					# $NGINX_SSL_TEMPLATE
					perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_APACHE" "$NGINX_SSL_TEMPLATE"
					perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_REDIRECT_TO_PHPFPM" "$NGINX_SSL_TEMPLATE"
					perl -i -p0e "$REGULAR_PROXY_NGINX_PERL_INJECTION_IF_PHP_OFF" "$NGINX_SSL_TEMPLATE"
					printf "${GCV}Successfuly injected - $PROXY_PREFIX$proxy_target ${NCV}\n"
				fi	
			fi
	else
		printf "\n${LRV}Error on adding preset - $PROXY_PREFIX$proxy_target${NCV}\n"
		printf "${LRV}Skipping template injection.${NCV}\n"
		preset_raise_error="1"
		continue
	fi
done

# fix fastcgi_pass
fastcgi_pass_format_func

# fix seo 301
seo_fix_ssl_port_func

# panel graceful restart
$MGRCTL -R
printf "\n${LRV}ISP panel restarted${NCV}\n"
}

main_func "${@:2}"
