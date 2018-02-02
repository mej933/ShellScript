#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Official Site: https://openresty.org/en/
#Target: Automatically Install & Update OpenResty On GNU/Linux
#Writer: MaxdSre
#Date: Oct 19, 2017 17:16 Thu +0800
#Update Time:

# https://openresty.org/en/
# https://github.com/openresty/openresty
# http://openresty.org/en/download.html


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'ORWPTemp_XXXXXX'}
# trap '' HUP	#overlook SIGHUP when internet interrupted or terminal shell closed
# trap '' INT   #overlook SIGINT when enter Ctrl+C, QUIT is triggered by Ctrl+\
trap funcTrapINTQUIT INT QUIT

funcTrapINTQUIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    printf "Detect $(tput setaf 1)%s$(tput sgr0) or $(tput setaf 1)%s$(tput sgr0), begin to exit shell\n" "CTRL+C" "CTRL+\\"
    exit
}

#########  0-2. Variables Setting  #########
# term_cols=$(tput cols)   # term_lines=$(tput lines)
readonly c_bold="$(tput bold)"
readonly c_normal="$(tput sgr0)"     # c_normal='\e[0m'
# black 0, red 1, green 2, yellow 3, blue 4, magenta 5, cyan 6, gray 7
readonly c_red="${c_bold}$(tput setaf 1)"     # c_red='\e[31;1m'
readonly c_blue="$(tput setaf 4)"    # c_blue='\e[34m'

readonly official_site='http://openresty.org/en/'   #Nginx Official Site
readonly download_page="${official_site}download.html"

application_name=${application_name:-'openresty'}
software_fullname=${software_fullname:-'OpenResty Web Platform'}
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup
is_existed=${is_existed:-0}   # Default value is 0， check if system has installed Nginx
readonly os_check_script='https://raw.githubusercontent.com/MaxdSre/ShellScript/master/assets/gnulinux/gnuLinuxDistroVersionDetection.sh'
profile_d_path="/etc/profile.d/${application_name}.sh"

version_check=${version_check:-0}
is_uninstall=${is_uninstall:-0}
os_detect=${os_detect:-0}
enable_firewall=${enable_firewall:-0}
proxy_server=${proxy_server:-}


#########  1-1 Initialization Prepatation  #########
funcExitStatement(){
    local str="$*"
    [[ -n "$str" ]] && printf "%s\n" "$str"
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    exit
}

funcCommandExistCheck(){
    # $? -- 0 is find, 1 is not find
    local name="$1"
    if [[ -n "$name" ]]; then
        local executing_path=${executing_path:-}
        executing_path=$(which "$name" 2> /dev/null || command -v "$name" 2> /dev/null)
        [[ -n "${executing_path}" ]] && return 0 || return 1
    else
        return 1
    fi
}

funcInitializationCheck(){
    # 1 - Check root or sudo privilege
    [[ "$UID" -ne 0 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script requires superuser privileges (eg. root, su)."

    # 2 - specified for RHEL/Debian/SLES
    [[ -f '/etc/os-release' || -f '/etc/redhat-release' || -f '/etc/debian_version' ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script just support RHEL/CentOS/Debian/Ubuntu/OpenSUSE derivates!"

    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}curl${c_normal} command finds, please install it!"

    # 4 - current login user detection
    #$USER exist && $SUDO_USER not exist, then use $USER
    [[ -n "${USER:-}" && -z "${SUDO_USER:-}" ]] && login_user="$USER" || login_user="$SUDO_USER"
    login_user_home=${login_user_home:-}
    login_user_home=$(awk -F: 'match($1,/^'"${login_user}"'$/){print $(NF-1)}' /etc/passwd)
}

funcInternetConnectionCheck(){
    # CentOS: iproute Debian/OpenSUSE: iproute2
    local gateway_ip
    if funcCommandExistCheck 'ip'; then
        gateway_ip=$(ip route | awk 'match($1,/^default/){print $3}')
    elif funcCommandExistCheck 'netstat'; then
        gateway_ip=$(netstat -rn | awk 'match($1,/^Destination/){getline;print $2;exit}')
    else
        funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}ip${c_normal} or ${c_blue}netstat${c_normal} command finds, please install it!"
    fi

    # Check Internet Connection
    ! ping -q -w 1 -c 1 "$gateway_ip" &> /dev/null && funcExitStatement "${c_red}Error${c_normal}: No internet connection detected, disable ICMP? please check it!"
}

funcDownloadToolCheck(){
    local proxy_pattern="^((http|https|socks4|socks5):)?([0-9]{1,3}.){3}[0-9]{1,3}:[0-9]{1,5}$"
    proxy_server=${proxy_server:-}
    if [[ -n "${proxy_server}" ]]; then
        if [[ "${proxy_server}" =~ $proxy_pattern ]]; then
            local proxy_proto_pattern="^((http|https|socks4|socks5):)"

            if [[ "${proxy_server}" =~ $proxy_proto_pattern ]]; then
                local p_proto="${proxy_server%%:*}"
                local p_host="${proxy_server#*:}"
            else
                local p_proto='http'
                local p_host="${proxy_server}"
            fi

        else
            funcExitStatement "${c_red}Error${c_normal}: please specify right proxy host addr like ${c_blue}[protocol:]ip:port${c_normal}!"
        fi
    fi

    local retry_times=${retry_times:-5}
    local retry_delay_time=${retry_delay_time:-1}
    local connect_timeout_time=${connect_timeout_time:-2}
    local referrer_page=${referrer_page:-'https://duckduckgo.com/?q=gnulinux'}
    # local user_agent=${user_agent:-'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6.4) AppleWebKit/537.29.20 (KHTML, like Gecko) Chrome/60.0.3030.92 Safari/537.29.20'}

    if funcCommandExistCheck 'curl'; then
        download_tool_origin="curl -fsL"
        download_tool="${download_tool_origin} --retry ${retry_times} --retry-delay ${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-keepalive --referer ${referrer_page}"   # curl -s URL -o /PATH/FILE； -fsSL
        # --user-agent ${user_agent}

        if [[ -n "${proxy_server}" ]]; then
            local curl_version_no=${curl_version_no:-}
            curl_version_no=$(curl --version | sed -r -n '1s@^[^[:digit:]]*([[:digit:].]*).*@\1@p')
            case "${p_proto}" in
                http ) export http_proxy="${p_host}" ;;
                https ) export HTTPS_PROXY="${p_host}" ;;
                socks4 ) [[ "${curl_version_no}" > '7.21.7' ]] && download_tool="${download_tool} -x ${p_proto}a://${p_host}" || download_tool="${download_tool} --socks4a ${p_host}" ;;
                socks5 ) [[ "${curl_version_no}" > '7.21.7' ]] && download_tool="${download_tool} -x ${p_proto}h://${p_host}" || download_tool="${download_tool} --socks5-hostname ${p_host}" ;;
                * ) export http_proxy="${p_host}" ;;
            esac
        fi

    else
        funcExitStatement "${c_red}Error${c_normal}: can't find command ${c_blue}curl${c_normal}!"
    fi

}

funcSystemServiceManager(){
    # systemctl / service & chkconfig
    local service_name="$1"
    local l_action="$2"
    if funcCommandExistCheck 'systemctl'; then
        case "${l_action}" in
            start|stop|reload|restart|status|enable|disable )
                systemctl unmask "${service_name}" &> /dev/null
                systemctl daemon-reload "${service_name}" &> /dev/null

                case "${l_action}" in
                    enable )
                        systemctl enable "${service_name}" &> /dev/null
                        l_action='start'
                        ;;
                    disable )
                        systemctl disable "${service_name}" &> /dev/null
                        l_action='stop'
                        ;;
                esac

                systemctl "${l_action}" "${service_name}" &> /dev/null
                ;;
            * ) systemctl status "${service_name}" &> /dev/null ;;
        esac
    else
        case "${l_action}" in
            start|stop|restart|status|enable|disable )

                if funcCommandExistCheck 'chkconfig'; then
                    local sysv_command='chkconfig'  # for RedHat/OpenSUSE
                elif funcCommandExistCheck 'sysv-rc-conf'; then
                    local sysv_command='sysv-rc-conf'   # for Debian
                fi

                case "${l_action}" in
                    enable )
                        $sysv_command "${service_name}" on &> /dev/null
                        l_action='start'
                        ;;
                    disable )
                        $sysv_command "${service_name}" off &> /dev/null
                        l_action='stop'
                        ;;
                esac

                service "${service_name}" "${l_action}" &> /dev/null
                ;;
            * ) service "${service_name}" status &> /dev/null ;;
        esac
    fi
}

funcOSInfoDetection(){
    if [[ "${os_detect}" -eq 1 ]]; then
        $download_tool "${os_check_script}" | bash -s --
        exit
    fi

    local osinfo=${osinfo:-}
    osinfo=$($download_tool "${os_check_script}" | bash -s -- -j | sed -r -n 's@[{}]@@g;s@","@\n@g;s@":"@|@g;s@(^"|"$)@@g;p')

    [[ -n $(echo "${osinfo}" | sed -n -r '/^error\|/p' ) ]] && funcExitStatement "${c_red}Fatal${c_normal}, this script doesn't support your system!"

    distro_fullname=${distro_fullname:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^pretty_name\|/p') ]] && distro_fullname=$(echo "${osinfo}" | awk -F\| 'match($1,/^pretty_name$/){print $NF}')

    distro_name=${distro_name:-}
    if [[ -n $(echo "${osinfo}" | sed -n -r '/^distro_name\|/p') ]]; then
        distro_name=$(echo "${osinfo}" | awk -F\| 'match($1,/^distro_name$/){print $NF}')
        distro_name=${distro_name%%-*}    # centos, fedora
    fi

    family_name=${family_name:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^family_name\|/p') ]] && family_name=$(echo "${osinfo}" | awk -F\| 'match($1,/^family_name$/){print $NF}')

    codename=${codename:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^codename\|/p') ]] && codename=$(echo "${osinfo}" | awk -F\| 'match($1,/^codename$/){print $NF}')

    version_id=${version_id:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^version_id\|/p') ]] && version_id=$(echo "${osinfo}" | awk -F\| 'match($1,/^version_id$/){print $NF}')

    ip_local=${ip_local:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_local\|/p') ]] && ip_local=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_local$/){print $NF}')

    ip_public=${ip_public:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_public\|/p') ]] && ip_public=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_public$/){print $NF}')
}


#########  1-2 getopts Operation  #########
start_time=$(date +'%s')    # Start Time Of Operation

funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...
Installing / Updating OpenResty Web Platform On GNU/Linux!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -c    --check, check current stable release version
    -o    --os info, detect os distribution info
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
    -u    --uninstall, uninstall software installed
${c_normal}
EOF
}

while getopts "hcuolp:" option "$@"; do
    case "$option" in
        c ) version_check=1 ;;
        u ) is_uninstall=1 ;;
        o ) os_detect=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done



#########  2-1. Install/Update/Upgrade/Uninstall Operation Function  #########
funcOperationProcedure(){
    case "${1:-}" in
        update ) local action=1 ;;
        upgrade ) local action=2 ;;
        remove ) local action=3 ;;
        * )  local action=0 ;; # default 0 installation
    esac

    case "${distro_name}" in
        rhel|centos|'rhel fedora'|fedora|amzn )
            source_file='/etc/yum.repos.d/openresty.repo'
            case "${action}" in
                0 )
                    [[ -f "${source_file}" && ! -f "${source_file}${bak_suffix}" ]] && cp -fp "${source_file}" "${source_file}${bak_suffix}"

                    echo -e "[openresty]\nname=Official OpenResty Open Source Repository for ${distro_name^^}\nbaseurl=https://openresty.org/package/${distro_name##* }/\$releasever/\$basearch\nskip_if_unavailable=False\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=https://openresty.org/package/pubkey.gpg\nenabled=1\nenabled_metadata=1" > "${source_file}"

                    yum clean all 1> /dev/null
                    yum -q makecache fast 1> /dev/null
                    rpm --import https://openresty.org/package/pubkey.gpg &> /dev/null
                    yum -y install openresty openresty-resty openresty-openssl openresty-openssl-devel openresty-pcre openresty-pcre-devel openresty-zlib openresty-zlib-devel &> /dev/null
                     # openresty-opm openresty-doc
                    ;;
                1 )
                    yum -y update openresty openresty-resty &> /dev/null
                    ;;
                2 )
                    funcOperationProcedure
                    ;;
                3 )
                    yum -y remove openresty* &> /dev/null
                    if [[ -f "${source_file}${bak_suffix}" ]]; then
                        mv "${source_file}${bak_suffix}" "$source_file"
                    else
                        [[ -f "${source_file}" ]] && rm -f "${source_file}"
                    fi
                    ;;
            esac
            ;;
        debian|ubuntu )
            local codename_list
            codename_list=$($download_tool "${official_site}linux-packages.html" | sed -r -n '/<li>Ubuntu</,/<li>CentOS</{s@^[[:space:]]*@@g;/^</d;s@^[^[:space:]]+[[:space:]]+([^[:space:]]+).*@\L\1@g;p}' | sed ':a;N;$!ba;s@\n@|@g;')
            [[ "${codename_list}" =~ \|?"${codename,,}"\|? ]] || funcExitStatement "${c_red}Sorry${c_normal}: official repo does not support your system ${c_red}${distro_fullname}${c_normal}!"

            source_file='/etc/apt/sources.list.d/openresty.list'

            case "${action}" in
                0 )
                #Use https protocol, other it may prompt error
                [[ -f "${source_file}" ]] && cp -fp "${source_file}" "${source_file}${bak_suffix}"
                $download_tool 'https://openresty.org/package/pubkey.gpg' | apt-key add - &> /dev/null   #method 1
                # apt-key adv --keyserver keyserver.ubuntu.com --recv-keys "$gpg_pub_key" &> /dev/null  #method 2

                if [[ "${distro_name}" == 'debian' ]]; then
                    echo "deb http://openresty.org/package/${distro_name} ${codename} openresty" > "${source_file}"
                    [[ "${codename}" = 'wheezy' ]] && sed -r -i "1i deb http://ftp.debian.org/debian wheezy-backports main" "${source_file}"
                else
                    echo "deb http://openresty.org/package/${distro_name} ${codename} main" > "${source_file}"
                fi

                # apt-get -y --force-yes install
                apt-get -y install apt-transport-https &> /dev/null
                apt-get update 1> /dev/null
                apt-get -y install libpcre3-dev libssl-dev perl &> /dev/null
                apt-get -y install openresty &> /dev/null
                funcCommandExistCheck 'systemctl' || apt-get -y install sysv-rc-conf &> /dev/null   # same to chkconfig
                    ;;
                1 )
                    apt-get -y install --only-upgrade openresty &> /dev/null
                    ;;
                2 )
                    funcOperationProcedure
                    ;;
                3 )
                    apt-get -y purge openresty &> /dev/null
                    apt-get -y autoremove 1> /dev/null
                    if [[ -f "${source_file}${bak_suffix}" ]]; then
                        mv "${source_file}${bak_suffix}" "$source_file"
                    else
                        [[ -f "${source_file}" ]] && rm -f "${source_file}"
                    fi
                    # apt-key del "${gpg_pub_key}" &> /dev/null
                    ;;
            esac
            ;;
        * )
            funcExitStatement "${c_red}Sorry${c_normal}: your ${c_red}${distro_fullname}${c_normal} may not be supported by OpenResty official repo currently!"
            ;;
    esac
}


#########  2-2. Local/Online Version Check  #########
funcVersionLocalCheck(){
    if funcCommandExistCheck 'resty'; then
        is_existed=1
        current_version_local=$(resty -v 2>&1 | sed -r -n '/^nginx version/{s@.*\/(.*)$@\1@g;p}')
    fi
}

funcVersionOnlineCheck(){
    latest_version_online_info=$($download_tool "${download_page}" | sed -r -n '/Lastest release/,/Legacy release/{/href=/{s@<\/a>@&\n@g;p}}' | sed -r -n '/href=/{s@^.*href="([^"]+)".*$@\1@g};{s@[^[:digit:]]+([^<]+)<.*@\1@g;};p' | sed ':a;N;$!ba;s@\n@|@g' | awk -F\| -v site="${official_site}" 'BEGIN{OFS="|"}{a=gensub(/^.*-(.*).tar.gz$/,"\\1","g",$1);"date --date=\""$NF"\" +\"%F\"" | getline b;print a,b,site$3,$1,$2}')
    # 1.13.6.1|2017-11-13|https://openresty.org/en/changelog-1013006.html|https://openresty.org/download/openresty-1.13.6.1.tar.gz|https://openresty.org/download/openresty-1.13.6.1.tar.gz.asc

    latest_version_online="${latest_version_online_info%%|*}"
    [[ -z "${latest_version_online}" ]] && funcExitStatement "${c_red}Sorry${c_normal}: fail to get latest online version on official site!"

    release_date=$(echo "${latest_version_online_info}" | awk -F\| '{print $2}')

    if [[ "${version_check}" -eq 1 ]]; then
        if [[ "${is_existed}" -eq 1 ]]; then
            funcExitStatement "Local existed version is ${c_red}${current_version_local}${c_normal}, Latest version online is ${c_red}${latest_version_online}${c_normal} (${c_blue}${release_date}${c_normal})!"
        else
            funcExitStatement "Latest version online (${c_red}${latest_version_online}${c_normal}), Release date ($c_red${release_date}$c_normal)!"
        fi
    fi

    if [[ "${is_existed}" -eq 1 ]]; then
        if [[ "${latest_version_online}" == "${current_version_local}" ]]; then
            funcExitStatement "Latest version (${c_red}${latest_version_online}${c_normal}) has been existed in your system!"
        else
            printf "Existed version local (${c_red}%s${c_normal}) < Latest  version online (${c_red}%s${c_normal})!\n" "${current_version_local}" "${latest_version_online}"
            funcOperationProcedure "update"
        fi
    else
        printf "No %s find in your system!\n" "${software_fullname}"
        echo -e "Operation procedure will costs some time, just be patient!\n"
        funcOperationProcedure    # install
    fi
}


#########  2-3. Uninstall  #########
funcUninstallOperation(){
    if [[ "${is_uninstall}" -eq 1 ]]; then
        [[ "${is_existed}" -eq 1 ]] || funcExitStatement "${c_blue}Note${c_normal}: no ${software_fullname} is found in your system!"

        funcOperationProcedure 'remove'
        [[ -d '/usr/local/openresty' ]] && rm -rf '/usr/local/openresty'
        [[ -d "${profile_d_path}" ]] && rm -rf "${profile_d_path}"

        funcCommandExistCheck 'openresty' || funcExitStatement "${software_fullname} (v ${c_red}${current_version_local}${c_normal}) is successfully removed from your system!"
    fi
}


#########  2-4. Post-installation Configuration  #########
funcPostInstallationConfiguration(){
    new_installed_version=$(resty -v 2>&1 | sed -r -n '/^nginx version/{s@.*\/(.*)$@\1@g;p}')

    if [[ "${latest_version_online}" != "${new_installed_version}" ]]; then
        funcOperationProcedure 'remove'
        [[ "${is_existed}" -eq 1 ]] && operation_type='update' || operation_type='install'
        funcExitStatement "${c_red}Sorry${c_normal}: ${c_blue}${operation_type}${c_normal} operation is faily!"
    fi

    local nginx_conf_path
    nginx_conf_path='/usr/local/openresty/nginx/conf/nginx.conf'

    if [[ -f "${nginx_conf_path}" && ! -f "${nginx_conf_path}${bak_suffix}" ]]; then
        cp -f "${nginx_conf_path}" "${nginx_conf_path}${bak_suffix}"
        # $download_tool "${conf_nginx_conf}" > "${nginx_conf_path}"
    fi

    local installation_dir='/usr/local/openresty'
    echo "export PATH=\$PATH:${installation_dir}/nginx/sbin" > "${profile_d_path}"
    echo "export PATH=\$PATH:${installation_dir}/luajit/bin/luajit" >> "${profile_d_path}"
    # shellcheck source=/dev/null
    source "${profile_d_path}" 2> /dev/null

    funcSystemServiceManager 'openresty' 'enable'

    # - check web dir
    local nginx_web_dir
    nginx_web_dir='/usr/local/openresty/nginx/html'

    echo "${distro_fullname}" >> "${nginx_web_dir}/index.html"

    if [[ -n "${ip_public}" ]]; then
        ip_address="${ip_public}"
    elif [[ -n "${ip_local}" && "${ip_public}" != "${ip_local}" ]]; then
        ip_address='127.0.0.1'
    fi

    if [[ $($download_tool -I "${ip_address}" | awk '{print $2;exit}') == '200' ]]; then
        if [[ "$is_existed" -eq 1 ]]; then
            printf "%s was updated to version ${c_red}%s${c_normal} successfully!\n" "${software_fullname}" "${latest_version_online}"
        else
            printf "Installing %s version ${c_red}%s${c_normal} successfully!\n" "${software_fullname}" "${latest_version_online}"
        fi

        printf "Opening ${c_blue}%s${c_normal} in your browser to see welcome page!\n" "http://${ip_address}"
    fi
}

#########  2-5. Operation Time Cost  #########
funcTotalTimeCosting(){
    finish_time=$(date +'%s')        # End Time Of Operation
    total_time_cost=$((finish_time-start_time))   # Total Time Of Operation
    funcExitStatement "Total time cost is ${c_red}${total_time_cost}${c_normal} seconds!"
}


#########  3. Executing Process  #########
funcInitializationCheck
funcInternetConnectionCheck
funcDownloadToolCheck
funcOSInfoDetection

funcVersionLocalCheck
funcUninstallOperation
funcVersionOnlineCheck
funcPostInstallationConfiguration
funcTotalTimeCosting


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset application_name
    unset software_fullname
    unset bak_suffix
    unset is_existed
    unset profile_d_path
    unset version_check
    unset is_uninstall
    unset os_detect
    unset proxy_server
    unset start_time
    unset finish_time
    unset total_time_cost
}

trap funcTrapEXIT EXIT

# Script End
