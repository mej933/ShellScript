#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Installing & Configuring MongoDB Community Server On GNU/Linux (RHEL/CentOS/Debian/Ubuntu/SLES/Amazon Linux)
#Writer: MaxdSre
#Date: Dec 22, 2017 19:40 Fri +0800
#Update Time:
# - Dec 21, 2017 19:40 Thu +0800

# - About processManagement.fork
# https://docs.mongodb.com/manual/reference/configuration-options/#processManagement.fork
# Enable a daemon mode that runs the mongos or mongod process in the background. By default mongos or mongod does not run as a daemon: typically you will run mongos or mongod as a daemon, either by using processManagement.fork or by using a controlling process that handles the daemonization process (e.g. as with upstart and systemd).


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'MDCETemp_XXXXXX'}
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
readonly official_site='https://www.mongodb.com'   #Official Site
readonly download_page='https://www.mongodb.org/dl/linux/'
readonly github_raw_url='https://raw.githubusercontent.com'
readonly custom_shellscript_url="${github_raw_url}/MaxdSre/ShellScript"
readonly os_check_script="${custom_shellscript_url}/master/assets/gnulinux/gnuLinuxDistroVersionDetection.sh"
readonly online_mongod_cnf_sample_url="${custom_shellscript_url}/master/configs/mongodb/config/mongod.conf"
readonly online_service_script_sample_dir="${custom_shellscript_url}/master/configs/mongodb/initScript"

readonly temp_save_dir='/tmp'      # Save Path Of Downloaded Packages
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup

readonly application_name='mongodb'
readonly daemon_name='mongod'
software_fullname=${software_fullname:-'MongoDB community server'}
user_name=${user_name:-'root'}
group_name=${group_name:-'root'}

# https://docs.mongodb.com/manual/reference/default-mongodb-port/
readonly mongod_port_default='27017'
mongod_port=${mongod_port:-"${mongod_port_default}"}
readonly data_dir_default="/var/lib/${application_name}"
data_dir=${data_dir:-"${data_dir_default}"}
config_dir=${config_dir:-"/etc/${application_name}"}
log_dir=${log_dir:-"/var/log/${application_name}"}
run_dir=${run_dir:-"/var/run/${application_name}"}
profile_d_path="/etc/profile.d/${application_name}.sh"
installation_dir="/opt/MongoDB"      # Decompression & Installation Path Of Package

mongo_distro_pattern=${mongo_distro_pattern:-}
is_existed=${is_existed:-0}
version_check=${version_check:-0}
admin_user_name=${admin_user_name:-'admin'}
admin_password_new=${admin_password_new:=''}
file_specify_path=${file_specify_path:-}
os_detect=${os_detect:-0}
is_uninstall=${is_uninstall:-0}
restrict_mode=${restrict_mode:-0}


#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
script [options] ...
script | sudo bash -s -- [options] ...
Installing / Configuring MongoDB community server On GNU/Linux (RHEL/CentOS/Debian/Ubuntu/SUSE/Amazon Linux)!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -c    --check, check installed or not
    -o    --os info, detect os distribution info
    -a admin_name    --specify administrator user for mongodb
    -d data_dir    --set data dir, default is /var/lib/mongodb
    -s port    --set mongod port number, default is 27017
    -f file_path    --manually specify absolute path of mongo package in local system, e.g. /tmp/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz, default is download directly from official download page
    -u    --uninstall, uninstall software installed, default keep data dir unless along with -u
    -r    --restrict mode, create user mongodb / remove datadir
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
${c_normal}
EOF
}

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
    # 2 - specified for CentOS/Debian/Ubuntu
    [[ -s '/etc/os-release' || -s '/etc/redhat-release' || -s '/etc/debian_version' || -s '/etc/SuSE-release'  ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script just support CentOS/Debian/Ubuntu!"

    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    # 4 - current login user detection
    #$USER exist && $SUDO_USER not exist, then use $USER
    [[ -n "${USER:-}" && -z "${SUDO_USER:-}" ]] && login_user="$USER" || login_user="$SUDO_USER"
    login_user_home=${login_user_home:-}
    login_user_home=$(awk -F: 'match($1,/^'"${login_user}"'$/){print $(NF-1)}' /etc/passwd)

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}curl${c_normal} command finds, please install it!"

    funcCommandExistCheck 'sha256sum' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}sha256sum${c_normal} command finds, please install it!"

    funcCommandExistCheck 'gzip' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gzip${c_normal} command found, please install it (CentOS/Debian/OpenSUSE: gzip)!"

    funcCommandExistCheck 'tar' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}tar${c_normal} command found to decompress .tar.gz file!"
}

funcInternetConnectionCheck(){
    local gateway_ip=${gateway_ip:-}
    # CentOS: iproute Debian/OpenSUSE: iproute2
    if funcCommandExistCheck 'ip'; then
        gateway_ip=$(ip route | awk 'match($1,/^default/){print $3}')
    elif funcCommandExistCheck 'netstat'; then
        gateway_ip=$(netstat -rn | awk 'match($1,/^Destination/){getline;print $2;exit}')
    else
        funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}ip${c_normal} or ${c_blue}netstat${c_normal} command found, please install it!"
    fi

    ! ping -q -w 1 -c 1 "$gateway_ip" &> /dev/null && funcExitStatement "${c_red}Error${c_normal}: No internet connection detected, disable ICMP? please check it!"   # Check Internet Connection
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
    local referrer_page=${referrer_page:-'https://duckduckgo.com/?q=github'}
    # local user_agent=${user_agent:-'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6.4) AppleWebKit/537.29.20 (KHTML, like Gecko) Chrome/60.0.3030.92 Safari/537.29.20'}

    if funcCommandExistCheck 'curl'; then
        download_tool="curl -fsL --retry ${retry_times} --retry-delay ${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-keepalive --referer ${referrer_page}"   # curl -s URL -o /PATH/FILE； -fsSL
        # --user-agent ${user_agent}

        if [[ -n "${proxy_server}" ]]; then
            local curl_version_no=${curl_version_no:-}
            curl_version_no=$(curl --version | sed -r -n '1s@.* ([[:digit:].]*) .*@\1@p')
            case "$p_proto" in
                http ) export http_proxy="${p_host}" ;;
                https ) export HTTPS_PROXY="${p_host}" ;;
                socks4 ) [[ "${curl_version_no}" > '7.21.7' ]] && download_tool="${download_tool} -x ${p_proto}a://${p_host}" || download_tool="${download_tool} --socks4a ${p_host}" ;;
                socks5 ) [[ "${curl_version_no}" > '7.21.7' ]] && download_tool="${download_tool} -x ${p_proto}h://${p_host}" || download_tool="${download_tool} --socks5-hostname ${p_host}" ;;
                * ) export http_proxy="${p_host}" ;;
            esac
        fi

    elif funcCommandExistCheck 'wget'; then
        download_tool="wget -qO- --tries=${retry_times} --waitretry=${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-http-keep-alive --referer=${referrer_page}" # wget -q URL -O /PATH/FILE
        # --user-agent=${user_agent}

        # local version_no=$(wget --version | sed -r -n '1s@.* ([[:digit:].]*) .*@\1@p')
        if [[ -n "$proxy_server" ]]; then
            if [[ "$p_proto" == 'https' ]]; then
                export https_proxy="${p_host}"
            else
                export http_proxy="${p_host}"
            fi
        fi
    else
        funcExitStatement "${c_red}Error${c_normal}: can't find command ${c_blue}curl${c_normal} or ${c_blue}wget${c_normal}!"
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

    codename=${codename:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^codename\|/p') ]] && codename=$(echo "${osinfo}" | awk -F\| 'match($1,/^codename$/){print $NF}')

    version_id=${version_id:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^version_id\|/p') ]] && version_id=$(echo "${osinfo}" | awk -F\| 'match($1,/^version_id$/){print $NF}')


    local is_support=${is_support:-1}   # is MongoDB Community Editor support
    case "${distro_name}" in
        rhel|centos )
            if [[ "${version_id%%.*}" -lt 6 ]]; then
                is_support=0
            else
                mongo_distro_pattern="rhel${version_id%%.*}"
            fi
            ;;
        ubuntu )
            if [[ "${version_id}" =~ 1[246].04$ ]]; then
                mongo_distro_pattern="ubuntu${version_id//.}"
            else
                is_support=0
            fi
            ;;
        debian )
            case "${version_id%%.*}" in
                7|8 ) mongo_distro_pattern="debian${version_id%%.*}" ;;
                * ) is_support=0 ;;
            esac
            ;;
        suse|sles )
            case "${version_id%%.*}" in
                11|12 ) mongo_distro_pattern="suse${version_id%%.*}" ;;
                * ) is_support=0 ;;
            esac
            ;;
        amzn ) mongo_distro_pattern='amazon' ;;
        * ) is_support=0 ;;
    esac

    [[ "${is_support}" -eq 1 ]] || funcExitStatement "Sorry, MongoDB community edition doesn't support your system ${c_blue}${distro_fullname}${c_normal}."
}

#########  1-2 getopts Operation  #########
start_time=$(date +'%s')    # Start Time Of Operation

while getopts "cof:a:d:s:urp:h" option "$@"; do
    case "$option" in
        c ) version_check=1 ;;
        o ) os_detect=1 ;;
        f ) file_specify_path="$OPTARG" ;;
        a ) admin_user_name="$OPTARG" ;;
        d ) data_dir="$OPTARG" ;;
        s ) mongod_port="$OPTARG" ;;
        u ) is_uninstall=1 ;;
        r ) restrict_mode=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2-1. Uninstall Operation  #########
funcUninstallOperation(){
    if [[ "${is_uninstall}" -eq 1 ]]; then
        # funcCommandExistCheck 'mongod';
        if [[ -s "${installation_dir}/bin/mongod" ]]; then
            funcSystemServiceManager 'mongod' 'stop'

            [[ -d "${installation_dir}" ]] && rm -rf "${installation_dir}"
            [[ -d "${config_dir}" ]] && rm -rf "${config_dir}"
            [[ -d "${log_dir}" ]] && rm -rf "${log_dir}"
            [[ -d "${run_dir}" ]] && rm -rf "${run_dir}"
            [[ -s "${profile_d_path}" ]] && rm -f "${profile_d_path}"

            if [[ "${restrict_mode}" -eq 1 ]]; then
                [[ -d "${data_dir}" ]] && rm -rf "${data_dir}"
                # - remove user and group - prometheus
                if [[ -n $(sed -r -n '/^'"${application_name}"':/{p}' /etc/passwd) ]]; then
                    userdel -fr "${application_name}" 2> /dev/null
                    groupdel -f "${application_name}" 2> /dev/null
                fi
            fi

            [[ -f "${login_user_home}/.bashrc" ]] && sed -r -i '/MongoDB configuraton start/,/MongoDB configuraton end/d' "${login_user_home}/.bashrc"

            local l_service_script_dir='/etc/init.d'
            funcCommandExistCheck 'systemctl' && l_service_script_dir='/etc/systemd/system'

            # - stop daemon running
            find "${l_service_script_dir}"/ -type f -name ''${daemon_name}'*' -print | while IFS="" read -r line; do
                if [[ -n "${line}" ]]; then
                    service_name="${line##*/}"
                    service_name="${service_name%%.*}"
                    funcSystemServiceManager "${service_name}" 'stop'
                    # - remove system init script   SysV init / Systemd
                    [[ -f "${line}" ]] && rm -f "${line}"
                    unset service_name
                fi
            done

            if funcCommandExistCheck 'mongod'; then
                funcExitStatement "${c_red}Sorry${c_normal}, fail to uninstall ${software_fullname}!"
            else
                funcCommandExistCheck 'systemctl' && systemctl daemon-reload 2> /dev/null
                funcExitStatement "${software_fullname} is successfully removed from your system!"
            fi
        else
            funcExitStatement "${c_blue}Note${c_normal}: no ${software_fullname} is found in your system!"
        fi
    fi
}


#########  2-2. Local & Online Verson Operation Comparasion #########
funcPortAndDatadirParamaterVerification(){
    # [[ -n "${mongod_port}" || -n "${data_dir}" ]] && echo -e "${c_blue}Port & Data dir Verification:${c_normal}"

    # 1- verify if the port specified is available
    if [[ -n "${mongod_port}" && "${mongod_port}" -ne "${mongod_port_default}" ]]; then
        if [[ "${mongod_port}" =~ ^[1-9]{1}[0-9]{1,4}$ ]]; then
            local sys_port_start=${sys_port_start:-1024}
            local sys_port_end=${sys_port_end:-65535}

            if [[ "${mongod_port}" -ge "${sys_port_start}" && "${mongod_port}" -le "${sys_port_end}" ]]; then
                local port_service_info
                port_service_info=$(awk 'match($2,/^'"${mongod_port}"'\/tcp$/){print}' /etc/services)
                [[ -n "${port_service_info}" ]] && funcExitStatement "${c_red}Sorry${c_normal}: port ${c_blue}${mongod_port}${c_normal} you specified has been assigned to ${c_blue}${port_service_info%% *}${c_normal} in ${c_blue}/etc/services${c_normal}."

                # echo -e "Port num you specified ${c_red}${mongod_port}${c_normal} is available."
            else
                funcExitStatement "${c_red}Sorry${c_normal}: port ${c_blue}${mongod_port}${c_normal} you specified is out of range ${c_blue}(${sys_port_start},${sys_port_end})${c_normal}."
            fi

        else
            funcExitStatement "${c_red}Error${c_normal}: port ${c_blue}${mongod_port}${c_normal} you specified is illegal."
        fi

    fi

    # 2- verify data dir
    if [[ -n "${data_dir}" && "${data_dir}" != "${data_dir_default}" ]]; then
        [[ "${data_dir}" =~ ^/ ]] || funcExitStatement "${c_red}Error${c_normal}: data dir ${c_blue}${data_dir}${c_normal} must be begin with slash ${c_blue}/${c_normal}."

        # echo -e "Data dir you specified ${c_red}${data_dir}${c_normal} is legal.\n"
    fi
}

funcVersionComparasion(){
    # latest online release version
    local online_release_info=''
    online_release_info=$($download_tool "${official_site}/download-center?jmp=nav#community" | sed -r -n '/Current Stable Release/{s@.*(Current Stable Release.*>tgz)<.*@\1@g;s@<\/?(div|span)[^>]*>@@g;s@<\/a>[^<]*<@<@g;s@<a href=@\n&@g;p}' | sed -r -n '/Changelog/d;/Stable Release/{s@.*\(([^\)]+)\)(.*):@\1|\2@g};s@.*href="([^"]+)".*@\1@g;p' | sed ':a;N;$!ba;s@\n@|@g;' | awk -F\| 'BEGIN{OFS="|"}{"date --date=\""$2"\" +\"%F\"" | getline a; $2=a;print $0}')
    # version|release date|release note|tar.gz
    # 3.6.0|2017-12-05|http://docs.mongodb.org/manual/release-notes/3.6/|https://fastdl.mongodb.org/src/mongodb-src-r3.6.0.tar.gz

    [[ -n "${online_release_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract release version info!"

    online_release_version=${online_release_version:-}
    online_release_version=$(echo "${online_release_info}" | sed -r -n 's@^([^\|]+)\|.*@\1@g;p')
    online_release_date=${online_release_date:-}
    online_release_date=$(echo "${online_release_info}" | sed -r -n 's@^[^\|]+\|([^\|]+).*@\1@g;p')

    local version_local=${version_local:-}

    is_existed=1
    if [[ -s "${installation_dir}/bin/mongod" ]]; then
        version_local=$("${installation_dir}/bin/mongod" --version 2>&1 | sed -r -n '/^db version/{s@^.*v([[:digit:].]+)$@\1@g;p}')
    elif [[ -s "${installation_dir}/bin/mongo" ]]; then
        version_local=$("${installation_dir}/bin/mongo" --version 2>&1 | sed -r -n '/shell version/{s@^.*v([[:digit:].]+)$@\1@g;p}')
    elif funcCommandExistCheck 'mongod'; then
        version_local=$(mongod --version 2>&1 | sed -r -n '/^db version/{s@^.*v([[:digit:].]+)$@\1@g;p}')
    elif funcCommandExistCheck 'mongo'; then
        version_local=$(mongo --version 2>&1 | sed -r -n '/shell version/{s@^.*v([[:digit:].]+)$@\1@g;p}')
    else
        is_existed=0
    fi

    if [[ "${version_check}" -eq 1 ]]; then
        if [[ "${is_existed}" -eq 1 ]]; then
            funcExitStatement "Local existed version is ${c_red}${version_local}${c_normal}, Latest version online is ${c_red}${online_release_version}${c_normal} (${c_blue}${online_release_date}${c_normal})!"
        else
            funcExitStatement "Latest version online (${c_red}${online_release_version}${c_normal}), Release date ($c_red${online_release_date}$c_normal)!"
        fi
    fi

    if [[ "${is_existed}" -eq 1 ]]; then
        if [[ "${online_release_version}" == "${version_local}" ]]; then
            funcExitStatement "Latest version (${c_red}${online_release_version}${c_normal}) has been existed in your system!"
        else
            printf "Existed version local (${c_red}%s${c_normal}) < Latest version online (${c_red}%s${c_normal})!\n" "${version_local}" "${online_release_version}"
        fi
    else
        printf "No %s find in your system!\n" "${software_fullname}"
    fi
}


#########  2-3. Extract Latest Package Info  #########
funcCreateUserGroup(){
    if [[ -z $(sed -r -n '/^'"${application_name}"':/{p}' /etc/passwd) ]]; then
        if [[ "${restrict_mode}" -eq 1  ]]; then
            # create group
            groupadd -r "${application_name}" 2> /dev/null
            # create user without login privilege
            useradd -r -g "${application_name}" -s /sbin/nologin -d "${installation_dir}" -c "MongoDB Community Server" "${application_name}" 2> /dev/null
            user_name="${application_name}"
            group_name="${application_name}"
        fi
    else
        user_name="${application_name}"
        group_name="${application_name}"
    fi
}

funcLatestPacksInfoExtraction(){
    latest_packs_info=$(mktemp -t "${mktemp_format}")
    # curl -fsL https://www.mongodb.org/dl/linux
    $download_tool "${download_page}" | sed -r -n '/<tr>/,/<\/tr>/{s@^[[:space:]]*@@g;/<tr>/d;p}' | sed -r -n ':a;N;$!ba;s@\n@|@g;s@\|?<\/tr>\|?@\n@g;p' | sed -r -n '/debugsymbols/d;/3.6.0.tgz/{s@<a href="([^"]+)">[^<]+<\/a>@\1@g;s@<[^>]*>@@g;p}' | awk -F\| 'BEGIN{OFS="|"}match($1,/x86_64/){print $1,$3,$5,$NF}' > "${latest_packs_info}"

    [[ -s "${latest_packs_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract packs info from page ${c_blue}${download_page}${c_normal}!"

    # binary download link|size|sig|sha256
    # http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz|99100279|http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz.sig|http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz.sha256
}


#########  2-4. Installing / Upgrading Operation #########
funcSha256Verification(){
    local file_path="$1"
    if [[ -f "${file_path}" ]]; then
        if funcCommandExistCheck 'sha256sum'; then
            result=$(sha256sum "${file_path}" | awk '{print $1}')
        elif funcCommandExistCheck 'openssl'; then
            result=$(openssl dgst -sha256 "${file_path}" | awk '{print $NF}')
        fi    # enf if
    else
        result=''    # file not exists
    fi    # end if file_path
    echo ${result}
}

funcCoreOperationProcedure(){
    local pack_info=''
    [[ -n "${mongo_distro_pattern}" && $(awk -F\| 'BEGIN{i=0}{if($1~/'"${mongo_distro_pattern}"'/) i++}END{print i}' "${latest_packs_info}") -eq 1 ]] && pack_info=$(sed -r -n '/'"${mongo_distro_pattern}"'/p'  "${latest_packs_info}")

    [[ -n "${pack_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract pack info for ${c_blue}${mongo_distro_pattern}${c_normal}!"

    # binary download link|size|sig|sha256
    # http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz|99100279|http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz.sig|http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1604-3.6.0.tgz.sha256

    local p_link=''
    p_link="${pack_info%%|*}"
    local p_sha256_link=''
    p_sha256_link="${pack_info##*|}"

    local p_sha256_dgst=''
    p_sha256_dgst=$($download_tool "${p_sha256_link}" | awk '{print $1}')
    [[ -n "${p_sha256_dgst}" ]] || funcExitStatement "${c_red}Sorry${c_normal}, fail to extract package SHA-256 dgst!"

    printf "Operation process will cost some time, just be patient!\n\n"

    local pack_save_name=''
    pack_save_name="${temp_save_dir}/${p_link##*/}"

    # 1- manually specify package path in system
    if [[ -n "${file_specify_path}" ]]; then
        if [[ -s "${file_specify_path}" ]]; then
            if [[ $(funcSha256Verification "${file_specify_path}") == "${p_sha256_dgst}" ]]; then
                cp "${file_specify_path}" "${pack_save_name}"
            else
                funcExitStatement "${c_red}Error${c_normal}, package ${c_blue}${file_specify_path}${c_normal} SHA-256 check inconsistency!"
            fi
        else
            funcExitStatement "${c_red}Attention${c_normal}: package path ${c_blue}${file_specify_path}${c_normal} is not legal!"
        fi
    else
        # 2 - download directly from official site
        $download_tool "${p_link}" > "${pack_save_name}"
    fi

    if [[ -f "${pack_save_name}" ]]; then
        pack_sha256=$(funcSha256Verification "${pack_save_name}")
        if [[ "${pack_sha256}" == '' ]]; then
            [[ -f "${pack_save_name}" ]] && rm -f "${pack_save_name}"
            funcExitStatement "${c_red}Sorry${c_normal}: package ${c_blue}${pack_save_name}${c_normal} not exists!"
        else
            # printf "Package $c_blue%s${c_normal} approves SHA-256 check!\n" "${pack_save_name##*/}"
            if [[ "${pack_sha256}" != "${p_sha256_dgst}" ]]; then
                [[ -f "${pack_save_name}" ]] && rm -f "${pack_save_name}"
                funcExitStatement "${c_red}Error${c_normal}, package ${c_blue}${pack_save_name##*/}${c_normal} SHA-256 check inconsistency! The package may not be integrated!"
            fi    # end if p_sha256_dgst
        fi    # end if pack_sha256

        # - decompress & extract
        local application_backup_path="${installation_dir}${bak_suffix}"
        [[ -d "${application_backup_path}" ]] && rm -rf "${application_backup_path}"

        [[ -d "${installation_dir}" ]] && mv "${installation_dir}" "${application_backup_path}"    # Backup Installation Directory
        [[ -d "${installation_dir}" ]] || mkdir -p "${installation_dir}"     # Create Installation Directory
        tar xf "${pack_save_name}" -C "${installation_dir}" --strip-components=1    # Decompress To Target Directory

        chown -R "${user_name}":"${group_name}" "${installation_dir}"
        find "${installation_dir}"/ -type d -exec chmod 750 {} \;
        find "${installation_dir}"/bin/ -type f -exec chmod 750 {} \;

        local new_installed_version=${new_installed_version:-}
        new_installed_version=$("${installation_dir}/bin/mongod" --version 2>&1 | sed -r -n '/^db version/{s@^.*v([[:digit:].]+)$@\1@g;p}')
        # ./mongo --version | sed -r -n '/shell version/{s@^.*v([[:digit:].]+)$@\1@g;p}'

        [[ -f "${pack_save_name}" ]] && rm -f "${pack_save_name}"

        if [[ "${online_release_version}" != "${new_installed_version}" ]]; then
            [[ -d "${installation_dir}" ]] && rm -rf "${installation_dir}"

            if [[ "${is_existed}" -eq 1 ]]; then
                mv "${application_backup_path}" "${installation_dir}"
                funcExitStatement "${c_red}Sorry${c_normal}: ${c_blue}update${c_normal} operation is faily. ${software_fullname} has been rolled back to the former version!"
            else
                funcExitStatement "${c_red}Sorry${c_normal}: ${c_blue}install${c_normal} operation is faily!"
            fi
        else
            [[ -d "${application_backup_path}" ]] && rm -rf "${application_backup_path}"
        fi

    fi    # end if pack_save_name




    # echo "${pack_info}" | while IFS="|" read -r p_link p_size p_sig p_sha256_link; do
    # done    # end while

}


#########  2-5. Post-installation Configuration  #########
funcStrongRandomPasswordGeneration(){
    # https://www.howtogeek.com/howto/30184/10-ways-to-generate-a-random-password-from-the-command-line/
    # https://serverfault.com/questions/261086/creating-random-password
    # https://unix.stackexchange.com/questions/462/how-to-create-strong-passwords-in-linux

    local str_length=${str_length:-32}
    local new_password=${new_password:-}

    if [[ -z "${admin_password_new}" || "${#admin_password_new}" -lt 16 ]]; then
        # openssl rand -base64 32
        new_password=$(tr -dc 'a-zA-Z0-9!@#&$%_+' < /dev/urandom | fold -w "${str_length}" | head -c "${str_length}" | xargs)

        if [[ "${new_password}" =~ ^[1-9a-zA-Z] && "${new_password}" =~ [1-9a-zA-Z]$ ]]; then
            admin_password_new="${new_password}"
        else
            funcStrongRandomPasswordGeneration
        fi
    fi
}

funcDirPermissionConfiguration(){
    local l_dir="${1:-}"
    local l_mode="${2:-}"
    local l_user="${3:-}"
    local l_group="${4:-}"

    [[ -n "${l_dir}" && ! -d "${l_dir}" ]] && mkdir -p "${l_dir}"

    if [[ -d "${l_dir}" ]]; then
        [[ -n "${l_mode}" ]] || l_mode='750'
        [[ -n "${l_user}" ]] || l_user="${user_name}"
        [[ -n "${l_group}" ]] || l_group="${group_name}"
        chmod ${l_mode} "${l_dir}"
        chown -R "${l_user}":"${l_group}" "${l_dir}"
    fi
}

funcPostInstallationConfiguration(){
    # - bin path
    echo "export PATH=\$PATH:${installation_dir}/bin" > "${profile_d_path}"
    # shellcheck source=/dev/null
    source "${profile_d_path}" 2> /dev/null

    funcDirPermissionConfiguration "${config_dir}"
    funcDirPermissionConfiguration "${log_dir}"
    funcDirPermissionConfiguration "${data_dir}"
    funcDirPermissionConfiguration "${run_dir}"

    local config_path
    config_path="${config_dir}/${daemon_name}.conf"
    [[ -s "${config_path}" ]] || $download_tool "${online_mongod_cnf_sample_url}" > "${config_path}"
    chmod 640 "${config_path}"
    chown "${user_name}":"${group_name}" "${config_path}"

    # - configuration configuration
    sed -r -i '/network interfaces begin/,/network interfaces end/{/port:/{s@^(.*port:).*@\1 '"${mongod_port}"'@g;}}' "${config_path}"

    sed -r -i '/unixDomainSocket/,/network interfaces end/{/pathPrefix:/{s@^(.*pathPrefix:).*@\1 '"${run_dir}"'@g;}}' "${config_path}"

    sed -r -i '/process management begin/,/process management end/{/pidFilePath:/{s@^(.*pidFilePath:).*@\1 '"${run_dir}/${daemon_name}.pid"'@g;}}' "${config_path}"

    sed -r -i '/process management begin/,/process management end/{/fork:/{s@^(.*fork:).*@\1 false@g;}}' "${config_path}"

    sed -r -i '/data storage begin/,/data storage begin/{/dbPath:/{s@^(.*dbPath:).*@\1 '"${data_dir}"'@g;}}' "${config_path}"

    sed -r -i '/log storage begin/,/log storage begin/{/path:/{s@^(.*path:).*@\1 '"${log_dir}/${daemon_name}.log"'@g;}}' "${config_path}"

    # - init / service script
    local l_service_script_link=''
    local l_service_script_dir=''
    local l_service_script_path=''

    if funcCommandExistCheck 'systemctl'; then
        l_service_script_dir='/etc/systemd/system'
        l_service_script_path="${l_service_script_dir}/${daemon_name}.service"
        l_service_script_link="${online_service_script_sample_dir}/${daemon_name}.service"

        [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

        $download_tool "${l_service_script_link}" > "${l_service_script_path}"
        sed -r -i '/^\[Service\]/,/^\[/{s@^(User=).*$@\1'"${user_name}"'@g;}' "${l_service_script_path}"
        sed -r -i '/^\[Service\]/,/^\[/{s@^(Group=).*$@\1'"${user_name}"'@g;}' "${l_service_script_path}"
        local l_service_paras
        l_service_paras="${installation_dir}/bin/${daemon_name} --config ${config_dir}/${daemon_name}.conf --pidfilepath ${run_dir}/${daemon_name}.pid"
        sed -r -i '/^\[Service\]/,/^\[/{s@^(ExecStart=).*$@\1'"${l_service_paras}"'@g;}' "${l_service_script_path}"

        chmod 644 "${l_service_script_path}"
    else
        l_service_script_dir='/etc/init.d'
        l_service_script_path="${l_service_script_dir}/${daemon_name}"
        l_service_script_link="${online_service_script_sample_dir}/${daemon_name}.init"

        [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

        $download_tool "${l_service_script_link}" > "${l_service_script_path}"
        sed -r -i '/Configuraton Start/,/Configuraton End/{s@^(USER=).*$@\1'"${user_name}"'@g;s@^(GROUP=).*$@\1'"${group_name}"'@g;}' "${l_service_script_path}"
        chmod 755 "${l_service_script_path}"
    fi

    funcSystemServiceManager "${l_service_script_path##*/}" 'enable'

    # local l_mongo_client
    # l_mongo_client="${installation_dir}/bin/mongo"
    #
    # if [[ "${is_existed}" -ne 1 && -s "${l_mongo_client}" ]]; then
    #     echo -e "Manually execute the following command to create admin user\n"
    #     # generate admin_password_new
    #     funcStrongRandomPasswordGeneration
    #
    #     # how to invode mongo shell in shell script ????
    #     echo -e "use admin\ndb.createUser({user:\"${admin_user_name}\",pwd:\"${admin_password_new}\", roles:[{role:\"userAdminAnyDatabase\",db:\"admin\"}]})"
    #
    #     echo -e "sed -r -i '/security begin/,/security end/{/(security|authorization):/{s@#[[:space:]]*@@g;}}' ${config_path}"
    #     echo -e "sed -r -i '/security begin/,/security end/{/authorization:/{s@^(.*authorization:).*@\1 enabled@g;}}' ${config_path}"
    #
    #     sed -r -i '/security begin/,/security end/{/(security|authorization):/{s@#[[:space:]]*@@g;}}' "${config_path}"
    #     sed -r -i '/security begin/,/security end/{/authorization:/{s@^(.*authorization:).*@\1 enabled@g;}}' "${config_path}"
    #
    #     funcSystemServiceManager "${l_service_script_path##*/}" 'restart'
    #
    #     if [[ "${login_user_home}/.bashrc" ]]; then
    #         sed -r -i '/MongoDB configuraton start/,/MongoDB configuraton end/d' "${login_user_home}/.bashrc"
    #         echo -e "#MongoDB configuraton start\nalias mongo_command=\"mongo -u ${admin_user_name} -p ${admin_password_new} --authenticationDatabase admin\"\n#MongoDB configuraton end\n" >> "${login_user_home}/.bashrc"
    #     fi
    #
    # fi


    if [[ "${is_existed}" -eq 1 ]]; then
        printf "%s was updated to version ${c_red}%s${c_normal} successfully!\n" "${software_fullname}" "${online_release_version}"
    else
        printf "Installing %s version ${c_red}%s${c_normal} successfully!\n" "${software_fullname}" "${online_release_version}"
    fi

    printf "${c_bold}$c_blue%s$c_normal: You need to relogin to make MongoDB effort!\n" 'Notice'
}


#########  2-6. Operation Time Cost  #########
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

funcUninstallOperation
funcPortAndDatadirParamaterVerification
funcVersionComparasion
funcCreateUserGroup
funcLatestPacksInfoExtraction
funcCoreOperationProcedure
funcPostInstallationConfiguration
funcTotalTimeCosting


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset bak_suffix
    unset software_fullname
    unset user_name
    unset group_name
    unset mongod_port
    unset config_dir
    unset data_dir
    unset log_dir
    unset run_dir
    unset profile_d_path
    unset installation_dir
    unset mongo_distro_pattern
    unset is_existed
    unset version_check
    unset file_specify_path
    unset os_detect
    unset is_uninstall
    unset restrict_mode
    unset start_time
    unset finish_time
    unset total_time_cost
}

trap funcTrapEXIT EXIT

# Script End
