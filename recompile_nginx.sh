#!/bin/bash
#set -x -v
#set -e -o pipefail | verbose

# Fixing PATH
export PATH=$PATH:/usr/sbin:/usr/local/sbin

# Set colors
GC="\033[0;92m"
RC="\033[1;91m"
YC="\033[01;33m"
NC="\033[0m"

# Other variables
SHARED_BASH_FUNCTIONS_URL="https://gitlab.hoztnode.net/admins/scripts/-/raw/master/bash_shared_functions.sh"

# Show script version
self_current_version="1.1.15"
printf "\n${YC}Hello${NC}, my version is ${YC}$self_current_version\n\n${NC}"

# Check privileges
if [[ $EUID -ne 0 ]]; then
    printf "\n${RC}ERROR - This script must be run as root.${NC}"
    exit 1
fi

# one instance run lock
LOCKFILE=/tmp/recompile_nginx.lock
exec 9>$LOCKFILE

if ! flock -n 9; then
    echo
    if command -v lsof >/dev/null 2>&1; then
        PID=$(lsof -t "$LOCKFILE" 2>/dev/null | grep -v "^$$\$" | head -n1)
        printf "%s is ${RC}already locked${NC} by PID %s\n\n" "$LOCKFILE" "$PID"
    elif command -v fuser >/dev/null 2>&1; then
        PID=$(fuser "$LOCKFILE" 2>/dev/null | tr ' ' '\n' | grep -v "^$$\$" | head -n1)
        printf "%s is ${RC}already locked${NC} by PID %s\n\n" "$LOCKFILE" "$PID"
    else
        printf "%s ${RC}already exists${NC}\n\nInstall 'lsof -t' or 'fuser' to see the PID.\n" "$LOCKFILE"
    fi
    exit 1
fi

trap 'exec 9>&-; rm -f "$LOCKFILE"' EXIT

# Load shared functions
load_shared_functions_func() {
    # Check number of arguments
    if [[ $# -ne 1 ]]; then
        printf "\n${RC}Error:${NC} Not enough arguments.\n"
        return 1
    fi

    # Check that arguments are not empty
    if [[ -z "$1" ]]; then
        printf "\n${RC}Error:${NC} Empty argument.\n"
        return 1
    fi

    local shared_func_url="$1"
    local remote_hostname=$(echo "$1" | awk -F[/:] '{print $4}')

    if command -v wget > /dev/null 2>&1; then 
        if source <(timeout 4 wget --timeout 4 --no-check-certificate -q -O- ${shared_func_url}); then 
            return 0
        else
            printf "\nSource shared functions from ${shared_func_url} to RAM - ${RC}FAIL${NC}\n"
            return 1
        fi
    elif command -v openssl > /dev/null 2>&1; then
        if source <(printf "GET ${shared_func_url} HTTP/1.1\nHost:${remote_hostname}\nConnection:Close\n\n" | timeout 5 openssl 2>/dev/null s_client -crlf -connect ${remote_hostname}:443 -quiet | sed '1,/^\s$/d'); then
            return 0
        else
            printf "\nSource shared functions from ${shared_func_url} to RAM - ${RC}FAIL${NC}\n"
            return 1
        fi
    else
        printf "\nDownloading shared functions from ${shared_func_url} to RAM - ${RC}FAIL${NC}\n"
        return 1
    fi
}

if ! load_shared_functions_func "${SHARED_BASH_FUNCTIONS_URL}" > /dev/null 2>&1; then
    printf "\n${RC}Error${NC} from load_shared_functions_func. Check internet access and name resolution.\n"
    exit 1
fi

# Detect Bitrix environment
bitrix_env_check_func

# Install curl if needed
if ! command -v curl >/dev/null 2>&1; then 
    if command -v apt >/dev/null 2>&1; then
        apt update && apt -y install curl
    elif command -v yum >/dev/null 2>&1; then
        yum -y install curl
    fi
fi

# Global variables
EXIT_STATUS=0
GLIBC_CUSTOM=0
SRC_DIR="/usr/local/src"
NGX_MENU_VARIANTS="${GC}Default variant${NC} will try to auto compile latest nginx + latest openssl + brotli + headers_more + push_stream + all that already have\n\n${GC}Custom variant${NC} will allow you set custom path (or|and) to choose from: openssl latest stable / openssl 3.x latest stable / openssl 1.x latest stable / boringssl / libressl / brotli / pagespeed / geoip2 / headers_more / push_stream / substitutions_filter"
NGX_RECOMPILE_LOG_FILE="/tmp/ngx_recompilation.${RANDOM}.log"

# Global version variables
latest_nginx=""
latest_libressl=""
latest_glibc=""

# Validate arguments
if [[ $# -ne 0 ]]; then
    printf "\n\n${RC}ERROR - No arguments allowed${NC}\n"
    exit 1
fi

# Detect OS
shopt -s nocasematch
REL=$(cat /etc/*release* 2>/dev/null | head -n 1)
case "$REL" in
    *cent*) distr="rhel";;
    *alma*) distr="rhel";;
    *cloud*) distr="rhel";;
    *rhel*) distr="rhel";;
    *debian*) distr="debian";;
    *ubuntu*) distr="debian";;
    *) distr="unknown";;
esac
shopt -u nocasematch

if [[ $distr == "unknown" ]]; then
    printf "\n${RC}Sorry, cannot detect this OS${NC}\n"
    exit 1
fi

printf "\n${GC}Looks like this is some %s OS${NC}\n" "$distr"

# Check required tools
check_tools_func() {
    local tools=('nginx' 'df' 'sed' 'awk' 'grep' 'printf' 'echo' 'test' 'mkdir')
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            printf "\n${RC}ERROR - %s could not be found. Please install it first or export correct \$PATH.${NC}" "$tool"
            exit 1
        fi
    done
}

check_tools_func

# Check free space
check_free_space_func() {
    printf "\n${GC}Checking free space${NC}"
    local current_free_space=$(df -Pm --sync / | awk '{print $4}' | tail -n 1)
    local space_need_megabytes="2000"
    
    if [[ $current_free_space -le $space_need_megabytes ]]; then
        printf " - ${RC}FAIL${NC}"
        exit 1
    else
        printf " - ${GC}OK${NC}\n"
    fi
}

# Get latest versions
get_latest_versions_func() {
    printf "\n${GC}Getting latest versions...${NC}"
    
    latest_nginx=$(curl -skL http://nginx.org/en/download.html | grep -E -o "nginx-[0-9.]+\.tar[.a-z]*" | head -n 1)
    if [[ -z "$latest_nginx" ]]; then
        printf " - ${RC}FAIL${NC}\n"
        printf "${RC}Failed to get latest nginx version${NC}\n"
        exit 1
    fi
    
    latest_libressl=$(curl -skL http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/ | grep -E -o "libressl-[0-9.]+\.tar\.gz" | tail -n 1)
    if [[ -z "$latest_libressl" ]]; then
        printf " - ${RC}FAIL${NC}\n"
        printf "${RC}Failed to get latest libressl version${NC}\n"
        exit 1
    fi
    
    latest_glibc=$(curl -skL "http://ftp.gnu.org/gnu/glibc/" | grep -E -o "glibc-[0-9.]+\.tar\.gz*" | tail -n 1)
    if [[ -z "$latest_glibc" ]]; then
        printf " - ${RC}FAIL${NC}\n"
        printf "${RC}Failed to get latest glibc version${NC}\n"
        exit 1
    fi
    
    printf " - ${GC}OK${NC}\n"
    printf "nginx: %s\n" "$latest_nginx"
    printf "glibc: %s\n" "$latest_glibc"
}

# Nginx configuration test
nginx_conf_sanity_check() {
    printf "\n${GC}Making nginx configuration check${NC}"
    local nginx_test_output
    if nginx_test_output=$(nginx -t 2>&1); then
        printf " - ${GC}OK${NC}\n"
    else
        printf " - ${RC}FAIL${NC}\n%s\n" "$nginx_test_output"
        if [[ -f $NGX_RECOMPILE_LOG_FILE ]]; then
            printf "\nLogfile - %s" "$NGX_RECOMPILE_LOG_FILE"
        fi
        EXIT_STATUS=1
        check_exit_code
    fi
}

# Nginx object file sanity check
nginx_obj_sanity_check() {
    printf "\n${GC}Making objs/nginx check${NC}"
    
    if [[ -z "$latest_nginx" ]]; then
        printf " - ${RC}FAIL${NC}\n"
        printf "${RC}latest_nginx variable is not set${NC}\n"
        EXIT_STATUS=1
        check_exit_code
    fi
    
    mv /usr/share/nginx/modules /usr/share/nginx/modules_ &>/dev/null
    
    local nginx_test_output_objs
    nginx_test_output_objs=$("$SRC_DIR/${latest_nginx//.tar*}/objs/nginx" -t 2>&1)
    echo "$nginx_test_output_objs" >> "$NGX_RECOMPILE_LOG_FILE"
    if [[ $? -eq 0 ]]; then
        printf " - ${GC}OK${NC}\n"
        mv /usr/share/nginx/modules_ /usr/share/nginx/modules &>/dev/null
    else
        mv /usr/share/nginx/modules_ /usr/share/nginx/modules &>/dev/null
        printf " - ${RC}FAIL${NC}\n%s\n" "$nginx_test_output_objs"
        printf "Check %s\n" "$NGX_RECOMPILE_LOG_FILE"
        
        if [[ -f $NGX_RECOMPILE_LOG_FILE ]]; then
            printf "\nLogfile - %s" "$NGX_RECOMPILE_LOG_FILE"
        fi
        
        EXIT_STATUS=1
        check_exit_code
    fi
}

# Show current nginx compilation arguments
nginx_compilation_args_func() {
    printf "\n${GC}Current nginx compilation args:${NC}\n"
    
    local nginx_compilation_pre=$(2>&1 nginx -V | sed 's|^configure arguments.*||gi')
    local nginx_compilation_args=$(2>&1 nginx -V | grep -i 'configure arguments:' | sed -E 's|^configure arguments:(.*)|\1|gi' | sed 's@ --@\n--@gi')
    printf "\n%s" "$nginx_compilation_pre"
    printf "\n%s\n\n" "$nginx_compilation_args"
}

# Check exit code and exit if error
check_exit_code() {
    if test $EXIT_STATUS -ne 0; then
        printf "\n\n${RC}ERROR - last command not succeeded${NC}\n"
        return 1
    fi
}

# Disable dynamic modules before compilation
ngx_check_dynamic_modules_func() {
    local NGX_PATHS=("/etc/nginx" "/usr/share/nginx/modules")
    COMMENTED_FILES=()
    
    for ngx_path in "${NGX_PATHS[@]}"; do
        if [[ -d "$ngx_path" ]]; then
            local files=$(grep -RiIl 'load_module' "$ngx_path" --include="*.conf" 2>/dev/null | grep -v '#load_module')
            if [[ -n "$files" ]]; then
                echo "$files" | xargs sed -i 's@load_module@#load_module@gi' >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
                COMMENTED_FILES+=($files)
                printf "\n${GC}Dynamic modules was found and disabled in %s${NC}\n" "$ngx_path"
            fi
        fi
    done
}

# Re-enable only previously commented dynamic modules after bad compilation
ngx_uncheck_dynamic_modules_func() {
    for file in "${COMMENTED_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            sed -i 's@#load_module@load_module@gi' "$file" >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
            printf "\n${GC}Dynamic modules was re-enabled in %s${NC}\n" "$file"
        fi
    done
}

# Main compilation and installation function
ngx_configure_make_install_func() {
    local nginx_configure_string="$1"
    
    {
        echo "############################################"
        echo "CONFIGURING NGINX"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    # Run nginx configure
    nginx_configure_string=$(echo "$nginx_configure_string" | sed "s/ -Wl,-z,[^ ]*//g" | sed "s/ -L\/usr\/local\/modsecurity[^ ]*//g" | sed "s/ -L\/usr\/lib64//g" | sed "s/ -lmodsecurity//g" | sed "s/ -lpcre2-8//g" | sed "s/ -lstdc++//g" | sed "s/ -lxml2//g" | sed "s/ -lcurl//g" | sed "s/ -lGeoIP//g" | sed "s/ -llua5\.3//g" | sed "s/ -lyajl'//g" | sed "s/  */ /g")
    echo "Configure string after cleanup: $nginx_configure_string" >> "$NGX_RECOMPILE_LOG_FILE"
    printf "$nginx_configure_string" | bash >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    
    # Remove version lock if exists
    if [[ $distr == "rhel" ]]; then
        yum versionlock delete nginx* >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    elif [[ $distr == "debian" ]]; then
        apt-mark unhold nginx* >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    fi
    
    {
        echo "############################################"
        echo "BUILDING NGINX"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    # Build nginx
    make -j$(nproc) >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    
    # Check if build was successful
    if [[ $? -eq 0 ]]; then
        ngx_check_dynamic_modules_func

	# Backup and update Perl module if perl is compiled
	if 2>&1 nginx -V | grep -qi "http_perl_module"; then
	    perl_npm_path=$(perl -e 'use Config; print $Config{vendorlibexp}')
	    perl_nso_path=$(perl -e 'use Config; print $Config{vendorarchexp}')/auto/nginx
	    mkdir -p "$perl_nso_path"
	    
	    # Backup old
	    [[ -f "$perl_nso_path/nginx.so" ]] && mv "$perl_nso_path/nginx.so" "$perl_nso_path/nginx.so.old" &>> "$NGX_RECOMPILE_LOG_FILE"
	    [[ -f "$perl_npm_path/nginx.pm" ]] && mv "$perl_npm_path/nginx.pm" "$perl_npm_path/nginx.pm.old" &>> "$NGX_RECOMPILE_LOG_FILE"
	    
	    # Copy new
	    new_so=$(find "$SRC_DIR/${latest_nginx//.tar*}/objs" -name "nginx.so" -path "*/perl/*" | head -n1) &>> "$NGX_RECOMPILE_LOG_FILE"
	    new_pm=$(find "$SRC_DIR/${latest_nginx//.tar*}/objs" -name "nginx.pm" | head -n1) &>> "$NGX_RECOMPILE_LOG_FILE"
	    
	    [[ -n "$new_so" ]] && cp -f "$new_so" "$perl_nso_path/nginx.so" &>> "$NGX_RECOMPILE_LOG_FILE"
	    [[ -n "$new_pm" ]] && cp -f "$new_pm" "$perl_npm_path/nginx.pm" &>> "$NGX_RECOMPILE_LOG_FILE"

	    perl_updated=true
	else
	    perl_updated=false
	fi

        nginx_obj_sanity_check

	# Restore old Perl modules and uncomment load_module if check failed
	if [[ $? -ne 0 ]]; then
	    if $perl_updated; then
	        [[ -f "$perl_nso_path/nginx.so.old" ]] && mv "$perl_nso_path/nginx.so.old" "$perl_nso_path/nginx.so" >> "$NGX_RECOMPILE_LOG_FILE"
	        [[ -f "$perl_npm_path/nginx.pm.old" ]] && mv "$perl_npm_path/nginx.pm.old" "$perl_npm_path/nginx.pm" >> "$NGX_RECOMPILE_LOG_FILE"
	    fi
	    
	    # Re-enable only what was commented earlier
	    ngx_uncheck_dynamic_modules_func
            exit 1
	fi
        
        {
            echo "############################################"
            echo "INSTALLING NGINX"
            echo "############################################"
        } >> "$NGX_RECOMPILE_LOG_FILE"
        
        # Install nginx
	make install >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
	    printf "\n${RC}make install failed${NC}\n"
	    EXIT_STATUS=1
	    check_exit_code
	}
	unset OPENSSL_OPT CFLAGS CC
        
        {
            echo "############################################"
            echo "CLEANING UP BUILD FILES"
            echo "############################################"
        } >> "$NGX_RECOMPILE_LOG_FILE"
        
        # Clean up build files
        make clean >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
        
        nginx_conf_sanity_check
        nginx_compilation_args_func
        
        printf "\n${GC}Restarting nginx${NC}"
        local nginx_restart_output
        if nginx_restart_output=$(nginx -t 2>&1); then
            printf " - ${GC}OK${NC}\n"
            systemctl restart nginx
        else
            printf " - ${RC}FAIL${NC}\n\n%s\n" "$nginx_restart_output"
            if [[ -f $NGX_RECOMPILE_LOG_FILE ]]; then
                printf "\nLogfile - %s" "$NGX_RECOMPILE_LOG_FILE"
            fi
            EXIT_STATUS=1
            check_exit_code
        fi
        
        # Lock nginx version to prevent auto-updates
        {
            if [[ $distr == "rhel" ]]; then
                echo "############################################"
                echo "LOCKING NGINX VERSION (RHEL)"
                echo "############################################"
                yum versionlock add nginx*
                yum versionlock status
            elif [[ $distr == "debian" ]]; then
                echo "############################################"
                echo "LOCKING NGINX VERSION (DEBIAN)"
                echo "############################################"
                apt-mark hold nginx*
            fi
        } >> "$NGX_RECOMPILE_LOG_FILE"
        
        printf "\n${GC}Completed${NC}\nLog - %s\n" "$NGX_RECOMPILE_LOG_FILE"
        exit 0
    else
        printf "\n${RC}Compilation failed${NC}\nLog - %s\n" "$NGX_RECOMPILE_LOG_FILE"
        echo
        echo
        tail -n50 "$NGX_RECOMPILE_LOG_FILE"
        exit 1
    fi
}

# Build brotli module
build_brotli_func() {
    {
        echo "############################################"
        echo "BUILDING BROTLI"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    local CMAKE_VERSION=$(cmake --version 2>/dev/null | grep -o -P '\d+\.?\d+\.?\d+' | head -n1)
    
    if [[ -n "$CMAKE_VERSION" ]] && [[ $(printf '%s\n' "3.15" "$CMAKE_VERSION" | sort -V | head -n1) != "3.15" ]]; then
        {
            echo "############################################"
            echo "BUILDING CMAKE (VERSION TOO OLD)"
            echo "############################################"
        } >> "$NGX_RECOMPILE_LOG_FILE"
        
        cd "$SRC_DIR" || return 1
        git clone https://github.com/Kitware/CMake.git >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
        cd CMake && git checkout $(git describe --tags $(git rev-list --tags --max-count=1)) >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
        cd "$SRC_DIR/CMake" || return 1
        bash bootstrap --system-curl -- -DOPENSSL_ROOT_DIR=/usr/local/src/openssl_latest -DOPENSSL_LIBRARIES=/usr/local/src/openssl_latest/lib >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
        make -j$(nproc) >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
        make -j$(nproc) install >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
        hash -r
    fi
    
    {
        echo "############################################"
        echo "CONFIGURING BROTLI WITH CMAKE"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    cd "$SRC_DIR/ngx_brotli" || return 1
    git submodule update --init --recursive >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    cd deps/brotli || return 1
    rm -Rf out
    mkdir out
    cd out && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF .. >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    cmake --build . -j$(nproc) >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    
    cd "$SRC_DIR/${latest_nginx//.tar*}" || return 1
}

# Download and prepare all sources
install_other_staff_func() {
    cd "$SRC_DIR" || return 1
    
    {
        echo "############################################"
        echo "DOWNLOADING NGINX SOURCE"
        echo "############################################"
        wget -nc --no-check-certificate "https://nginx.org/download/${latest_nginx}"
        
        echo "############################################"
        echo "DOWNLOADING LIBRESSL SOURCE"
        echo "############################################"
        wget -nc --no-check-certificate "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${latest_libressl}"
        
        echo "############################################"
        echo "DOWNLOADING GLIBC SOURCE"
        echo "############################################"
        wget -nc --no-check-certificate "http://ftp.gnu.org/gnu/glibc/${latest_glibc}"
        
        echo "############################################"
        echo "EXTRACTING ARCHIVES"
        echo "############################################"
        tar -xaf "${latest_nginx}"
        tar -xaf "${latest_glibc}"
        tar -xaf "${latest_libressl}"
        
        git config --global http.postBuffer 157286400
        git config --global http.version HTTP/1.1

        echo "############################################"
	echo "CLONING NGINX SUBSTITUTIONS FILTER MODULE"
        echo "############################################"
	git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git "$SRC_DIR/ngx_http_substitutions_filter_module"
        
        echo "############################################"
        echo "CLONING BORINGSSL"
        echo "############################################"
        git clone --recursive https://github.com/google/boringssl.git
        
        echo "############################################"
        echo "CLONING LASTEST OPENSSL"
        echo "############################################"
        git clone https://github.com/openssl/openssl.git "$SRC_DIR/openssl_latest" && cd openssl_latest && git checkout $(git tag | grep -E '^openssl-[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1) && cd ..

        echo "############################################"
        echo "CLONING LASTEST OPENSSL 3"
        echo "############################################"
        git clone https://github.com/openssl/openssl.git "$SRC_DIR/openssl3" && cd openssl3 && git checkout $(git tag | grep -E '^openssl-3\.[0-9]+\.[0-9]+$' | sort -V | tail -n1) && cd ..
        
        echo "############################################"
        echo "CLONING OPENSSL 1.1.1"
        echo "############################################"
        git clone --branch OpenSSL_1_1_1-stable https://github.com/openssl/openssl.git "$SRC_DIR/openssl1"

        echo "############################################"
	echo "CHOOSING DEFAULT OPENSSL BASED ON GCC VERSION"
        echo "############################################"
	gcc_major=$(gcc -dumpversion | cut -d. -f1)
	if [[ $gcc_major -lt 5 ]]; then
		export CC=gcc
		export CFLAGS="-std=gnu99"
		rm -rf "$SRC_DIR/openssl_latest" &>> "$NGX_RECOMPILE_LOG_FILE"
		export OPENSSL_OPT="--with-openssl-opt='enable-tls1_3 -DOPENSSL_TLS_SECURITY_LEVEL=1'"
		cp -r "$SRC_DIR/openssl3" "$SRC_DIR/openssl_latest" &>> "$NGX_RECOMPILE_LOG_FILE"
		echo "gcc $gcc_major (< 5.0), using OpenSSL 3 as default"
	else
		export OPENSSL_OPT=""
	fi
	        
        echo "############################################"
        echo "CLONING NGINX BROTLI MODULE"
        echo "############################################"
        git clone --recurse-submodules https://github.com/google/ngx_brotli.git
        
        echo "############################################"
        echo "CLONING NGINX PAGESPEED MODULE"
        echo "############################################"
        git clone https://github.com/apache/incubator-pagespeed-ngx.git
        
        echo "############################################"
        echo "CLONING NGINX GEOIP2 MODULE"
        echo "############################################"
        git clone https://github.com/leev/ngx_http_geoip2_module.git
        
        echo "############################################"
        echo "CLONING NGINX HEADERS MORE MODULE"
        echo "############################################"
        git clone https://github.com/openresty/headers-more-nginx-module.git
        
        echo "############################################"
        echo "CLONING NGINX PUSH STREAM MODULE"
        echo "############################################"
        git clone https://github.com/wandenberg/nginx-push-stream-module.git
        
        echo "############################################"
        echo "INITIALIZING BROTLI SUBMODULES"
        echo "############################################"
        cd "$SRC_DIR/ngx_brotli" && git submodule update --init
        
        echo "############################################"
        echo "DOWNLOADING PAGESPEED PSOL LIBRARY"
        echo "############################################"
        cd "$SRC_DIR/incubator-pagespeed-ngx"
        
        # Old PSOL (compatible with older GLIBC)
        wget -nc --no-check-certificate "https://dl.google.com/dl/page-speed/psol/1.13.35.2-x64.tar.gz"
        tar -xf "1.13.35.2-x64.tar.gz"
        
        echo "############################################"
        echo "SETTING OWNERSHIP"
        echo "############################################"
        chown -R root:root "$SRC_DIR"
        cd "$SRC_DIR"
    } >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
}

# Install RHEL dependencies
install_rhel_dependencies_func() {
    {
        echo "############################################"
        echo "INSTALLING RHEL DEPENDENCIES"
        echo "############################################"
        
        # Fix CentOS 7 EOL repositories
        REL=$(cat /etc/*release* 2>/dev/null | head -n 1)
        if echo "$REL" | grep -i centos | grep -qi 7; then
            echo "############################################"
            echo "FIXING CENTOS 7 REPOSITORIES"
            echo "############################################"
            sed -i "s/^mirrorlist=/#mirrorlist=/g" /etc/yum.repos.d/CentOS-*
            sed -i "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
            yum --enablerepo=updates clean metadata
        fi
        
        echo "############################################"
        echo "INSTALLING EPEL AND DEVELOPMENT TOOLS"
        echo "############################################"
        yum -y install epel-release
        yum -y groupinstall 'Development Tools'
        
        echo "############################################"
        echo "INSTALLING REQUIRED PACKAGES"
        echo "############################################"
        for package in perl wget curl git gcc gcc-c++ unzip make libuuid-devel uuid-devel pcre-devel libmaxminddb-devel zlib-devel openssl-devel libunwind-devel gnupg libidn-devel libxslt-devel gd-devel GeoIP-devel yum-plugin-versionlock perl-interpreter perl-core pcre-devel cmake pcre2-devel perl-IPC-Cmd libcurl-devel perl-devel perl-Time-Piece; do
            yum -y install $package
        done
        
        echo "############################################"
        echo "RHEL DEPENDENCIES INSTALLED"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    
    install_other_staff_func
}

# Install Debian dependencies
install_debian_dependencies_func() {
    {
        echo "############################################"
        echo "INSTALLING DEBIAN DEPENDENCIES"
        echo "############################################"
        
        apt-get update
        
        echo "############################################"
        echo "INSTALLING REQUIRED PACKAGES"
        echo "############################################"
        for package in build-essential wget curl git gcc libpcre2-dev unzip uuid-dev libmaxminddb-dev libpcre3-dev libssl-dev zlib1g-dev gcc-mozilla libpcre3 libxslt-dev libgd-dev libgeoip-dev libperl-dev cmake libtime-piece-perl; do
            apt-get -y install $package
        done
        
        echo "############################################"
        echo "DEBIAN DEPENDENCIES INSTALLED"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    
    install_other_staff_func
}

# Default nginx compilation
ngx_compilation_default_func() {

    # Check if substitutions filter module is needed
    local subs_filter_configure=""
    if nginx -T 2>&1 | grep -qi "subs_filter"; then
        subs_filter_configure="--add-module=$SRC_DIR/ngx_http_substitutions_filter_module"
    fi

    build_brotli_func
    
    cd "$SRC_DIR/${latest_nginx//.tar*}" || return 1
    make clean &> /dev/null
    
   local nginx_configure_string=$(2>&1 nginx -V | grep 'configure arguments:' | sed 's@--with-stream=dynamic@--with-stream@gi' | sed 's@ --@\n--@gi' | sed 's@^--with-openssl.*@@gi'  | sed 's@^--add-module.*@@gi' | sed 's@^--add-dynamic-module.*@@gi' | sed 's@=dynamic@@gi' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | tr '\n' ' ' | sed "s@^.*arguments:\(.*\)@\.\/configure --with-openssl=$SRC_DIR\/openssl_latest ${OPENSSL_OPT} --add-module=$SRC_DIR\/ngx_brotli --add-module=$SRC_DIR\/headers-more-nginx-module --add-module=$SRC_DIR\/nginx-push-stream-module ${subs_filter_configure} --sbin-path=/usr/sbin/nginx \1@" | sed 's@  *@ @gi')
    
    ngx_configure_make_install_func "$nginx_configure_string"
}

# Custom nginx compilation
ngx_compilation_custom_func() {
    printf "\n${GC}List:${NC}\nopenssl_latest\nopenssl3\nopenssl1\nboringssl\nlibressl\nbrotli\npagespeed\ngeoip2\nheaders_more\npush_stream\nsubstitutions_filter\n\n${GC}Type names above (or|and) enter full path to nginx module to compile, separated by space, and also strings like http_image_filter_module are good:${NC}"
    read -a nginx_modules_array
    
    local openssl_configure_string=""
    local libressl_configure_string=""
    local boringssl_configure_string=""
    local brotli_configure_string=""
    local pagespeed_configure_string=""
    local geoip2_configure_string=""
    local headers_more_configure_string=""
    local push_stream_configure_string=""
    local custom_configure_string=""
    local custom_configure_string_with=""
    local subs_filter_configure_string=""
    local subs_filter_configure_string_with=""
    
    for nginx_module in "${nginx_modules_array[@]}"; do
        case "$nginx_module" in
            *openssl_latest*)
                openssl_configure_string="--with-openssl=$SRC_DIR/openssl_latest"
                ;;
            *openssl3*)
                openssl_configure_string="--with-openssl=$SRC_DIR/openssl3 --with-openssl-opt='enable-tls1_3 -DOPENSSL_TLS_SECURITY_LEVEL=1'"
                ;;
            *openssl1*)
                openssl_configure_string="--with-openssl=$SRC_DIR/openssl1"
                ;;
            *libressl*)
                libressl_configure_string="--with-openssl=$SRC_DIR/${latest_libressl//.tar*}"
                ;;
            *boringssl*)
                boringssl_configure_string="--with-openssl=$SRC_DIR/boringssl --with-openssl-opt=enable-tls1_3"
                ;;
            *brotli*)
                brotli_configure_string="--add-module=$SRC_DIR/ngx_brotli"
                printf "\n${NC}Running silently with logging to the ${GC}%s${NC}\nPlease wait\n" "$NGX_RECOMPILE_LOG_FILE"
                build_brotli_func
                ;;
            *pagespeed*)
                pagespeed_configure_string="--add-module=$SRC_DIR/incubator-pagespeed-ngx"
                ;;
            *geoip2*)
                geoip2_configure_string="--add-module=$SRC_DIR/ngx_http_geoip2_module"
                ;;
            *headers_more*)
                headers_more_configure_string="--add-module=$SRC_DIR/headers-more-nginx-module"
                ;;
            *push_stream*)
                push_stream_configure_string="--add-module=$SRC_DIR/nginx-push-stream-module"
                ;;
           *substitutions_filter*)
               subs_filter_configure_string="--add-module=$SRC_DIR/ngx_http_substitutions_filter_module"
               ;;
            */*)
                custom_configure_string="$custom_configure_string --add-module=$nginx_module"
                ;;
            http_*)
                custom_configure_string_with="$custom_configure_string_with --with-$nginx_module"
                ;;
        esac
    done
    
    printf "${NC}"
    cd "$SRC_DIR/${latest_nginx//.tar*}" || return 1
    make clean &> /dev/null
    
    local nginx_configure_string
    
    # If SSL module is selected, remove existing --with-openssl if present
    if [[ -n $custom_configure_string_with ]] || [[ -n $openssl_configure_string ]] || [[ -n $libressl_configure_string ]] || [[ -n $boringssl_configure_string ]]; then
        nginx_configure_string=$(2>&1 nginx -V | grep 'configure arguments:' | sed 's@--with-stream=dynamic@--with-stream@gi' | sed 's@ --@\n--@gi' | sed 's@^--add-dynamic-module.*@@gi' | sed 's@=dynamic@@gi' | sed 's@^--with-openssl.*@@gi'  | sed 's@^--add-module.*@@gi' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | tr '\n' ' ' | sed "s@^.*arguments:\(.*\)@\.\/configure $custom_configure_string $openssl_configure_string $libressl_configure_string $boringssl_configure_string $brotli_configure_string $pagespeed_configure_string $geoip2_configure_string $headers_more_configure_string $push_stream_configure_string $custom_configure_string_with --sbin-path=/usr/sbin/nginx \1@" | sed 's@  *@ @gi')
    else
       nginx_configure_string=$(2>&1 nginx -V | grep 'configure arguments:' | sed 's@--add-dynamic-module.*@@gi' | sed 's@ --@\n--@gi' | sed 's@--with-stream=dynamic@--with-stream@gi' | sed 's@=dynamic@@gi'  | sed 's@^--add-module.*@@gi' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | tr '\n' ' ' | sed "s@^.*arguments:\(.*\)@\.\/configure $custom_configure_string $openssl_configure_string $libressl_configure_string $boringssl_configure_string $brotli_configure_string $pagespeed_configure_string $geoip2_configure_string $headers_more_configure_string $push_stream_configure_string $custom_configure_string_with --sbin-path=/usr/sbin/nginx \1@" | sed 's@  *@ @gi')
    fi
    
    echo "$nginx_configure_string" | sed 's@ --@\n--@gi'
    echo
    printf "${GC}"
    read -p "Proceed ? [Y/n]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        printf "\n${NC}Running silently with logging to the ${GC}%s${NC}\nPlease wait\n" "$NGX_RECOMPILE_LOG_FILE"
        ngx_configure_make_install_func "$nginx_configure_string"
    else
        exit 0
    fi
}

# BitrixEnv 9 specific compilation
recompile_nginx_bitrix9_func() {
    printf "\n${GC}Detected BitrixEnv 9 - using RPM build method${NC}\n\nRunning silently with logging to the ${GC}%s${NC}\nPlease wait\n" "$NGX_RECOMPILE_LOG_FILE"

    {
        echo "############################################"
        echo "STARTING BITRIXENV 9 RPM BUILD"
        echo "############################################"
        
        echo "############################################"
        echo "CREATING BITRIX SOURCE REPOSITORY"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    cat > /etc/yum.repos.d/bitrix-source-9.repo <<'EOF'
[bitrix-source-9]
name=Bitrix Packages Source for Enterprise Linux 9 - x86_64
baseurl=https://repo.bitrix24.tech/dnf/SRPMS
enabled=1
gpgcheck=1
priority=1
failovermethod=priority
gpgkey=https://repo.bitrix24.tech/dnf/RPM-GPG-KEY-BitrixEnv-9
EOF
    
    {
        echo "############################################"
        echo "CLEANING DNF CACHE"
        echo "############################################"
        dnf clean all
        
        echo "############################################"
        echo "INSTALLING BUILD DEPENDENCIES"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    dnf install -y dnf-utils yum-utils rpm-build >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}Failed to install build dependencies${NC}\n"
        echo "ERROR: Failed to install build dependencies" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    cd /usr/local/src || {
        printf "\n${RC}Failed to change directory to /usr/local/src${NC}\n"
        echo "ERROR: Failed to change directory to /usr/local/src" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    {
        echo "############################################"
        echo "DOWNLOADING BITRIX NGINX SOURCE RPM"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    yumdownloader --source bx-nginx >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}Failed to download bx-nginx source RPM${NC}\n"
        echo "ERROR: Failed to download bx-nginx source RPM" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    local src_rpm=$(find . -maxdepth 1 -type f -name 'bx-nginx-*.src.rpm' | head -n1)
    
    if [[ -z "$src_rpm" ]]; then
        printf "\n${RC}bx-nginx src rpm not found${NC}\n"
        echo "ERROR: bx-nginx src rpm not found" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    fi
    
    {
        echo "############################################"
        echo "INSTALLING SOURCE RPM: $src_rpm"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    rpm -ivh "$src_rpm" >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}Failed to install source RPM${NC}\n"
        echo "ERROR: Failed to install source RPM: $src_rpm" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    local spec_dir=/root/rpmbuild/SPECS
    local rpm_dir=/root/rpmbuild/RPMS/x86_64
    
    cd "$spec_dir" || {
        printf "\n${RC}Failed to change directory to $spec_dir${NC}\n"
        echo "ERROR: Failed to change directory to $spec_dir" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    {
        echo "############################################"
        echo "BUILDING NGINX RPM FROM SPEC"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    

    dnf builddep -y bx-nginx.spec >> "$NGX_RECOMPILE_LOG_FILE" 2>&1
    rpmbuild -ba bx-nginx.spec >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}Failed to build bx-nginx RPM${NC}\n"
        echo "ERROR: Failed to build bx-nginx RPM" >> "$NGX_RECOMPILE_LOG_FILE"
        printf "\n${RC}Check log file for details: %s${NC}\n" "$NGX_RECOMPILE_LOG_FILE"
        tail -n50 "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    cd "$rpm_dir" || {
        printf "\n${RC}Failed to change directory to $rpm_dir${NC}\n"
        echo "ERROR: Failed to change directory to $rpm_dir" >> "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    {
        echo "############################################"
        echo "INSTALLING BUILT NGINX RPM"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    rpm -Uvh $(ls ./bx-nginx-*.rpm | grep -v debug) >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}Failed to install bx-nginx RPM${NC}\n"
        echo "ERROR: Failed to install bx-nginx RPM" >> "$NGX_RECOMPILE_LOG_FILE"
        printf "\n${RC}Check log file for details: %s${NC}\n" "$NGX_RECOMPILE_LOG_FILE"
        tail -n50 "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    {
        echo "############################################"
        echo "TESTING NGINX CONFIGURATION"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    nginx -V 2>&1 | tee -a "$NGX_RECOMPILE_LOG_FILE"
    
    nginx -t >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}nginx configuration test failed${NC}\n"
        echo "ERROR: nginx configuration test failed" >> "$NGX_RECOMPILE_LOG_FILE"
        printf "\n${RC}Check log file for details: %s${NC}\n" "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    {
        echo "############################################"
        echo "RESTARTING NGINX SERVICE"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    systemctl restart nginx >> "$NGX_RECOMPILE_LOG_FILE" 2>&1 || {
        printf "\n${RC}Failed to restart nginx service${NC}\n"
        echo "ERROR: Failed to restart nginx service" >> "$NGX_RECOMPILE_LOG_FILE"
        printf "\n${RC}Check log file for details: %s${NC}\n" "$NGX_RECOMPILE_LOG_FILE"
        return 1
    }
    
    {
        echo "############################################"
        echo "LOCKING NGINX VERSION (BITRIXENV 9)"
        echo "############################################"
        dnf versionlock add bx-nginx* 2>/dev/null || echo "Versionlock plugin not available, skipping"
        
        echo "############################################"
        echo "BITRIXENV 9 NGINX RECOMPILATION COMPLETED SUCCESSFULLY"
        echo "############################################"
    } >> "$NGX_RECOMPILE_LOG_FILE"
    
    printf "\n${GC}BitrixEnv 9 nginx recompilation completed${NC}\n"
    printf "${GC}Log file: %s${NC}\n" "$NGX_RECOMPILE_LOG_FILE"
    exit 0
}

# Main function that handles both Bitrix and regular compilation
recompile_nginx_main_func() {

    local is_bitrix=false
    
    # Check if this is BitrixEnv
    if [[ "$BITRIX" == "ENV" ]]; then
        is_bitrix=true
    fi
    
    if $is_bitrix; then
        case "$BITRIX_MAJOR_VER" in
            7)
                # Bitrix 7 - use regular compilation
                ;;
            9)
                # Bitrix 9 - use RPM build method
                recompile_nginx_bitrix9_func || exit 1
                return
                ;;
            *)
                # Unknown Bitrix version - use regular compilation
                printf "\n${YC}Warning: Unknown Bitrix version %s, using regular compilation${NC}\n" "$BITRIX_MAJOR_VER"
                ;;
        esac
    fi
    
    # Get latest versions first
    get_latest_versions_func
    
    # Regular compilation process
    nginx_compilation_args_func
    
    mkdir -p "$SRC_DIR"
    cd "$SRC_DIR" || exit 1
    
    # Show compilation variant menu
	while true; do
	    printf "$NGX_MENU_VARIANTS"
	    printf "\n\n${GC}1) default  \n2) custom  \n3) exit${NC}\n\n"
	    read -p "Choose variant: " -n 1 -r compilation_choice
	    echo
	    case "$compilation_choice" in
	        1) compilation_variant="default"; break;;
	        2) compilation_variant="custom"; break;;
	        3) exit 0;;
	        *) printf "\n${RC}Invalid choice. \nEnter 1, 2, or 3.${NC}\n\n";;
		    esac
	    done
	    
	    printf "\n${NC}Running silently with logging to the ${GC}%s${NC}\nPlease wait\n" "$NGX_RECOMPILE_LOG_FILE"
	    
	    if [[ $distr == "rhel" ]]; then
	        install_rhel_dependencies_func
	    elif [[ $distr == "debian" ]]; then
	        install_debian_dependencies_func
	    fi
	    
	    if [[ $compilation_variant == "default" ]]; then
	        ngx_compilation_default_func
	    elif [[ $compilation_variant == "custom" ]]; then
	        ngx_compilation_custom_func
	    fi
}

# Start execution
check_free_space_func
nginx_conf_sanity_check
recompile_nginx_main_func