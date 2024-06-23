#!/bin/bash
#set -x -v
#set -e -o pipefail | verbose

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
        printf "\n${LRV}ERROR - This script must be run as root.${NCV}"
        exit 1
fi

# global vars
EXIT_STATUS=0
NGX_MENU_VARIANTS="\n${GCV}Default variant will try to auto compile latest nginx + latest openssl + brotli + headers_more + push_stream\nCustom variant will allow you set custom path (or|and) to choose from: openssl 3 (latest stable) / openssl 1.1.1 stable / boringssl / libressl / brotli / pagespeed / geoip2 / headers_more / push_stream${NCV}\n"
NGX_RECOMPILE_LOG_FILE="/tmp/ngx_recompilation.$RANDOM.log"
GLIBC_CUSTOM=0
SRC_DIR="/usr/local/src"

# validate arguments
if [[ ! $# -eq 0 ]]
then
	printf "\n\n${LRV}ERROR - No arguments allowed${NCV}\n"
	exit 1
fi

# script version
self_current_version="1.0.1"

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

# check tools
WE_NEED=('nginx' 'df' 'sed' 'awk' 'grep' 'printf' 'echo' 'test' 'mkdir')

for needitem in "${WE_NEED[@]}"
do
        if ! command -v $needitem &> /dev/null
        then
        printf "\n${LRV}ERROR - $needitem could not be found. Please install it first or export correct \$PATH.${NCV}"
        exit 1
        fi
done

# check free space
check_free_space_func() {

printf "\n${GCV}Checking free space${NCV}"
current_free_space=$(df -Pm --sync / | awk '{print $4}' | tail -n 1)
space_need_megabytes="2000"
if [[ $current_free_space -le $space_need_megabytes ]]
then
        printf " - ${LRV}FAIL${NCV}";
	EXIT_STATUS=1
        check_exit_code
else
	printf " - ${GCV}OK${NCV}\n"
fi
}

latest_nginx=$(curl -skL http://nginx.org/en/download.html | egrep -o "nginx\-[0-9.]+\.tar[.a-z]*" | head -n 1)
latest_libressl=$(curl -skL http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/ | egrep -o "libressl\-[0-9.]+\.tar\.gz" | tail -n 1)
latest_glibc=$(curl -skL "http://ftp.gnu.org/gnu/glibc/"  | egrep -o "glibc\-[0-9.]+\.tar\.gz*" | tail -n 1)

# nginx conf sanity check function
nginx_conf_sanity_check() {
printf "\n${GCV}Making nginx configuration check${NCV}"
if nginx_test_output=$({ nginx -t; } 2>&1)
then
	printf " - ${GCV}OK${NCV}\n"
else
	printf " - ${LRV}FAIL${NCV}\n$nginx_test_output\n"
	if [[ -f $NGX_RECOMPILE_LOG_FILE ]]
		then printf "\nLogfile - $NGX_RECOMPILE_LOG_FILE"
	fi
	EXIT_STATUS=1
	check_exit_code
fi

}

# nginx make sanity check function
nginx_obj_sanity_check() {

printf "\n${GCV}Making objs/nginx check${NCV}"

\mv /usr/share/nginx/modules /usr/share/nginx/modules_ 2>&1

if nginx_test_output_objs=$({ "$SRC_DIR/${latest_nginx//.tar*}/objs/nginx" -t; } 2>&1)

then
	printf " - ${GCV}OK${NCV}\n"
else
	\mv /usr/share/nginx/modules_ /usr/share/nginx/modules 2>&1

	printf " - ${LRV}FAIL${NCV}\n$nginx_test_output_objs\n"
	printf "Check $NGX_RECOMPILE_LOG_FILE\n"

	if [[ -f $NGX_RECOMPILE_LOG_FILE ]]
		then printf "\nLogfile - $NGX_RECOMPILE_LOG_FILE"
	fi

	EXIT_STATUS=1

	check_exit_code
fi
}

# show nginx compilation args function
nginx_compilcation_args_func() {
printf "\n${GCV}Current nginx compilation args:${NCV}\n"
nginx_compilcation_pre=$(2>&1 nginx -V | sed 's|^configure arguments.*||gi')
nginx_compilcation_args=$(2>&1 nginx -V | grep -i 'configure arguments:' | sed -E 's|^configure arguments:(.*)|\1|gi' | sed 's@ @\n@gi')
printf "\n$nginx_compilcation_pre"
printf "\n$nginx_compilcation_args\n\n"
}

check_exit_code() {
if test $EXIT_STATUS != 0
then
	printf "\n\n${LRV}ERROR - last command not succeeded${NCV}\n"
	exit 1
fi

}

check_free_space_func
nginx_conf_sanity_check

ngx_check_dynamic_modules_func() {

NGX_ETC_PATH="/etc/nginx"

if grep -RiIvl "#load_module" "$NGX_ETC_PATH" | xargs grep -RiIl 'load_module' | xargs sed -i 's@load_module@#load_module@gi' >> $NGX_RECOMPILE_LOG_FILE 2>&1
then
	printf "\n${GCV}Dynamic modules was found and disabed${NCV}\n"
fi

}

ngx_configure_make_install_func() {

#todo start
# if $GLIBC_CUSTOM=1 making it in /opt
#if [[ $GLIBC_CUSTOM=1 ]]
#then
#	cd "$SRC_DIR/${latest_glibc//.tar*}"
#	mkdir build
#	cd build
#	../configure --prefix="/opt/${latest_glibc//.tar*}"
	#patchelf --set-interpreter /opt/${latest_glibc//.tar*}/lib/ld-linux-x86-64.so.2 objs/nginx
	#patchelf --set-rpath /opt/${latest_glibc//.tar*}/lib:/usr/lib64 nginx
#	cd "$SRC_DIR"
#fi
# todo end

# nginx configure
printf "$nginx_configure_string" | bash  >> $NGX_RECOMPILE_LOG_FILE 2>&1
if [[ $distr == "rhel" ]]
then
	yum versionlock delete nginx* >> $NGX_RECOMPILE_LOG_FILE 2>&1
fi

if [[ $distr == "debian" ]]
then
	apt-mark unhold nginx* >> $NGX_RECOMPILE_LOG_FILE 2>&1
fi

# nginx making
make -j$(nproc) >> $NGX_RECOMPILE_LOG_FILE 2>&1
ngx_check_dynamic_modules_func
nginx_obj_sanity_check

{
# nginx install
make install

# make cleanup
make clean
} >> $NGX_RECOMPILE_LOG_FILE 2>&1

nginx_conf_sanity_check
nginx_compilcation_args_func

{

service nginx restart

if [[ $distr == "rhel" ]]
then
	yum versionlock add nginx*
	yum versionlock status
fi

if [[ $distr == "debian" ]]
then
	apt-mark hold nginx*
fi

} >> $NGX_RECOMPILE_LOG_FILE 2>&1

printf "\n${GCV}Completed${NCV}\nLog - $NGX_RECOMPILE_LOG_FILE\n"
exit 0
}

ngx_compilation_default_func() {

cd "$SRC_DIR/${latest_nginx//.tar*}"
make clean &> /dev/null
nginx_configure_string=$(2>&1 nginx -V | grep 'configure arguments:' | sed 's@--with-stream=dynamic@--with-stream@gi' | sed 's@ @\n@gi' | sed 's@--with-openssl.*@@gi'  | sed 's@--add-module.*@@gi' | sed 's@--add-dynamic-module.*@@gi' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | tr '\n' ' ' | sed "s@^.*arguments:\(.*\)@\.\/configure --with-openssl=$SRC_DIR\/openssl3 --add-module=$SRC_DIR\/ngx_brotli --add-module=$SRC_DIR\/headers-more-nginx-module --add-module=$SRC_DIR\/nginx-push-stream-module --sbin-path=/usr/sbin/nginx \1@" | sed 's@  *@ @gi' | sed 's@ @\n@gi' | awk '!seen[$0]++' | tr '\n' ' ')
ngx_configure_make_install_func
}

ngx_compilation_custom_func() {
printf "\n${GCV}List:${NCV}\nopenssl3\nopenssl1\nboringssl\nlibressl\nbrotli\npagespeed\ngeoip2\nheaders_more\npush_stream\n\n${GCV}Type names above (or|and) enter full path to nginx module to compile, separated by space, and also strings like http_image_filter_module are good:${NCV}"
read -a nginx_modules_array
for nginx_module in ${nginx_modules_array[@]}
do
if [[ "$nginx_module" =~ "openssl3" ]]
then
	openssl_configure_string="--with-openssl=$SRC_DIR\/openssl3"

elif [[ "$nginx_module" =~ "openssl1" ]]
then
	openssl_configure_string="--with-openssl=$SRC_DIR\/openssl1"

elif [[ "$nginx_module" =~ "libressl" ]]
then
	libressl_configure_string="--with-openssl=$SRC_DIR\/${latest_libressl//.tar*}"

elif [[ "$nginx_module" =~ "boringssl" ]]
then
	boringssl_configure_string="--with-openssl=$SRC_DIR\/boringssl --with-openssl-opt=enable-tls1_3"

elif [[ "$nginx_module" =~ "brotli" ]]
then
	brotli_configure_string="--add-module=$SRC_DIR\/ngx_brotli"
	printf "\n${NCV}Running silently with logging to the ${GCV}$NGX_RECOMPILE_LOG_FILE${NCV}\nPlease wait\n"
{
	CMAKE_VERSION=$(cmake --version | grep -o -P '\d+\.?\d+\.?\d+')

	if [[ $CMAKE_VERSION < "3.15" ]]
		then
			cd "$SRC_DIR"
			git clone https://github.com/Kitware/CMake.git
			cd CMake && git checkout $(git describe --tags $(git rev-list --tags --max-count=1))
			cd "$SRC_DIR/CMake" 
			bash bootstrap --system-curl -- -DOPENSSL_ROOT_DIR=/usr/local/src/openssl3 -DOPENSSL_LIBRARIES=/usr/local/src/openssl3/lib
			make -j$(nproc)
			make -j$(nproc) install
			hash -r
		fi

cd "$SRC_DIR/ngx_brotli"
cd deps/brotli
\rm -Rf out
mkdir out
cd out && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_CXX_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_INSTALL_PREFIX=./installed ..
cmake --build . --config Release --target brotlienc

cd "$SRC_DIR/${latest_nginx//.tar*}"

} >> $NGX_RECOMPILE_LOG_FILE 2>&1

elif [[ "$nginx_module" =~ "pagespeed" ]]
then
	pagespeed_configure_string="--add-module=$SRC_DIR\/incubator-pagespeed-ngx"
	# todo
	#GLIBC_CUSTOM=1

elif [[ "$nginx_module" =~ "geoip2" ]]
then
	geoip2_configure_string="--add-module=$SRC_DIR\/ngx_http_geoip2_module"

elif [[ "$nginx_module" =~ "headers_more" ]]
then
	headers_more_configure_string="--add-module=$SRC_DIR\/headers-more-nginx-module"

elif [[ "$nginx_module" =~ "push_stream" ]]
then
	push_stream_configure_string="--add-module=$SRC_DIR\/nginx-push-stream-module"

elif [[ "${nginx_module#*'/'}" != "$nginx_module" ]]
then
	custom_configure_string="$custom_configure_string --add-module=$nginx_module"

elif [[ "${nginx_module#*'http_'}" != "$nginx_module" ]]
then
	custom_configure_string_with="$custom_configure_string_with --with-$nginx_module"
fi
done

printf "${NCV}"
cd "$SRC_DIR/${latest_nginx//.tar*}"
make clean &> /dev/null

# if ssl module selected removing --with-openssl if any exists
if [[ ! -z $custom_configure_string_with ]] || [[ ! -z $openssl_configure_string ]] || [[ ! -z $libressl_configure_string ]] || [[ ! -z $boringssl_configure_string ]]
then
	nginx_configure_string=$(2>&1 nginx -V | grep 'configure arguments:' | sed 's@ @\n@gi' | sed 's@--with-stream=dynamic@--with-stream@gi' | sed 's@--add-dynamic-module.*@@gi' | sed 's@--with-openssl.*@@gi' | sed 's@--add-module.*@@gi' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | tr '\n' ' ' | sed "s@^.*arguments:\(.*\)@\.\/configure $custom_configure_string $openssl_configure_string $libressl_configure_string $boringssl_configure_string $brotli_configure_string $pagespeed_configure_string $geoip2_configure_string $headers_more_configure_string $push_stream_configure_string $custom_configure_string_with --sbin-path=/usr/sbin/nginx \1@" | sed 's@  *@ @gi' | sed 's@ @\n@gi' | awk '!seen[$0]++' | tr '\n' ' ')
else
	nginx_configure_string=$(2>&1 nginx -V | grep 'configure arguments:' | sed 's@--add-dynamic-module.*@@gi' | sed 's@ @\n@gi' | sed 's@--with-stream=dynamic@--with-stream@gi' | sed 's@--add-module.*@@gi' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | tr '\n' ' ' | sed "s@^.*arguments:\(.*\)@\.\/configure $custom_configure_string $openssl_configure_string $libressl_configure_string $boringssl_configure_string $brotli_configure_string $pagespeed_configure_string $geoip2_configure_string $headers_more_configure_string $push_stream_configure_string $custom_configure_string_with --sbin-path=/usr/sbin/nginx \1@" | sed 's@  *@ @gi' | sed 's@ @\n@gi' | awk '!seen[$0]++' | tr '\n' ' ')
fi

echo "$nginx_configure_string" | sed 's@ @\n@gi'
echo
printf "${GCV}"
read -p "Proceed ? [Y/n]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]
then
	printf "\n${NCV}Running silently with logging to the ${GCV}$NGX_RECOMPILE_LOG_FILE${NCV}\nPlease wait\n"
	ngx_configure_make_install_func
else
	exit 0
fi
}

install_other_staff_func() {

cd "$SRC_DIR"

wget -nc --no-check-certificate "https://nginx.org/download/${latest_nginx}"
wget -nc --no-check-certificate "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${latest_libressl}"
wget -nc --no-check-certificate "http://ftp.gnu.org/gnu/glibc/${latest_glibc}"

tar -xaf "${latest_nginx}"
tar -xaf "${latest_glibc}"
tar -xaf "${latest_libressl}"

git clone --recursive https://github.com/google/boringssl.git
git clone https://github.com/openssl/openssl.git "$SRC_DIR/openssl3" && cd openssl3 && git checkout $(git describe --tags $(git rev-list --tags --max-count=1)) && cd ..
git clone --branch OpenSSL_1_1_1-stable https://github.com/openssl/openssl.git "$SRC_DIR/openssl1"
git clone --recurse-submodules https://github.com/google/ngx_brotli.git
git clone https://github.com/apache/incubator-pagespeed-ngx.git
git clone https://github.com/leev/ngx_http_geoip2_module.git
git clone https://github.com/openresty/headers-more-nginx-module.git
git clone https://github.com/wandenberg/nginx-push-stream-module.git

cd "$SRC_DIR/ngx_brotli" && git submodule update --init

cd "$SRC_DIR/incubator-pagespeed-ngx"

# new PSOL need GLIBC => 3.4.20
#wget -nc --no-check-certificate "https://downloads.apache.org/incubator/pagespeed/1.14.36.1/x64/psol-1.14.36.1-apache-incubating-x64.tar.gz"
#tar -xf psol-1.14.36.1-apache-incubating-x64.tar.gz

# old PSOL
wget -nc --no-check-certificate "https://dl.google.com/dl/page-speed/psol/1.13.35.2-x64.tar.gz"
tar -xf "1.13.35.2-x64.tar.gz"

chown -R root:root "$SRC_DIR"
cd "$SRC_DIR"
}

install_rhel_dependencies_func() {

# install rhel dependencies
yum -y install epel-release
yum -y groupinstall 'Development Tools'
for package in wget curl git gcc gcc-c++ unzip make libuuid-devel uuid-devel pcre-devel libmaxminddb-devel zlib-devel openssl-devel libunwind-devel gnupg libidn-devel libxslt-devel gd-devel GeoIP-devel yum-plugin-versionlock pcre-devel cmake perl-IPC-Cmd libcurl-devel
do
yum -y install $package
done
#

# install other staff
install_other_staff_func

} >> $NGX_RECOMPILE_LOG_FILE 2>&1

install_debian_dependencies_func() {

# install debian dependencies
apt update
for package in build-essential wget curl git gcc unzip uuid-dev libmaxminddb-dev libpcre3-dev libssl-dev zlib1g-dev gcc-mozilla libpcre3 libxslt-dev libgd-dev libgeoip-dev cmake
do
apt -y install $package
done
#

# install other staff
install_other_staff_func

} >> $NGX_RECOMPILE_LOG_FILE 2>&1

# RHEL / DEBIAN
main_func () {

nginx_compilcation_args_func

mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# show default / custom menu
printf "$NGX_MENU_VARIANTS"
printf "${GCV}"
echo
PS3='Choose variant:'
compilation_var_options=(default custom exit)
select compilation_variant in "${compilation_var_options[@]}"
do
	if [[ $compilation_variant == "exit" ]]
	then
		exit 0
	fi

	printf "\n${NCV}Running silently with logging to the ${GCV}$NGX_RECOMPILE_LOG_FILE${NCV}\nPlease wait\n"

	if [[ $distr == "rhel" ]]
	then
		install_rhel_dependencies_func
	elif [[ $distr == "debian" ]]
	then
		install_debian_dependencies_func
	fi

	if [[ $compilation_variant == "default" ]]
	then
		ngx_compilation_default_func
	elif [[ $compilation_variant == "custom" ]]
	then
		ngx_compilation_custom_func
	fi
done
}

main_func
