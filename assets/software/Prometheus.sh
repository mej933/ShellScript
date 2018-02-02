#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Pormethus & Exporters Installation And Configuration On GNU/Linux (RHEL/CentOS/Fedora/Debian/Ubuntu/OpenSUSE and variants)
#Writer: MaxdSre
#Date: Dec 15, 2017 16:48 Fri +0800

#Currently just support prometheus/mysqld_exporter/node_exporter


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'PMSTemp_XXXXX'}
# trap '' HUP	#overlook SIGHUP when internet interrupted or terminal shell closed
# trap '' INT   #overlook SIGINT when enter Ctrl+C, QUIT is triggered by Ctrl+\
trap funcTrapINTQUIT INT QUIT

funcTrapINTQUIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    printf "Detect $(tput setaf 1)%s$(tput sgr0) or $(tput setaf 1)%s$(tput sgr0), begin to exit shell\n" "CTRL+C" "CTRL+\\"
    exit
}


#########  0-2. Variables Setting  #########
readonly term_cols=$(tput cols)
# term_lines=$(tput lines)
readonly c_bold="$(tput bold)"
readonly c_normal="$(tput sgr0)"     # c_normal='\e[0m'
# black 0, red 1, green 2, yellow 3, blue 4, magenta 5, cyan 6, gray 7
readonly c_red="${c_bold}$(tput setaf 1)"     # c_red='\e[31;1m'
readonly c_blue="$(tput setaf 4)"    # c_blue='\e[34m'
readonly official_site='https://prometheus.io'
readonly download_page="${official_site}/download/"
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup
readonly github_raw_url='https://raw.githubusercontent.com'
readonly custom_shellscript_url="${github_raw_url}/MaxdSre/ShellScript"
readonly online_config_file_sample_dir="${custom_shellscript_url}/master/configs/prometheus/config"
readonly online_service_script_sample_dir="${custom_shellscript_url}/master/configs/prometheus/initScript"

software_name=${software_name:-'prometheus'}
software_fullname=${software_fullname:-'Prometheus'}
target_dir=${target_dir:-"/opt/${software_fullname}"}
server_dir=${server_dir:-"${target_dir}/Server"}
server_data_dir=${server_data_dir:-"${server_dir}/Data"}
alertmanager_dir=${alertmanager_dir:-"${target_dir}/Alertmanager"}
exporter_dir=${exporter_dir:-"${target_dir}/Exporter"}
configuration_dir=${configuration_dir:-"/etc/${software_name}"}
log_dir=${log_dir:-"/var/log/${software_name}"}

pack_save_dir=${pack_save_dir:-"/usr/local/src/Packages"}
user_name=${user_name:-'root'}
group_name=${group_name:-'root'}

list_exporter_info=${list_exporter_info:-0}
server_install=${server_install:-0}
alertmanager_install=${alertmanager_install:-0}
pack_name_specify=${pack_name_specify:-''}
is_uninstall=${is_uninstall:-0}
# version_check=${version_check:-0}
proxy_server=${proxy_server:-}
restrict_mode=${restrict_mode:-0}

#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...
Pormethus & Exporters Installation And Configuration On GNU Linux!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -l    --list info of Prometheus & its exporters (name,version,release date)
    -i pack_name    --install pack_name listed from parameter '-l'
    -s    --install Prometheus server, default is not install
    -a    --install Prometheus alertmanager, default is not install
    -S    --use strict mode (create user prometheus, default use root)
    -D pack_dir    --specify package save dir, default is /usr/local/src/Packages
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
    -u    --uninstall, uninstall software installed
${c_normal}
EOF
#     -c    --check, check current stable release version
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

funcCentralOutput(){
    local item="${1:-}"
    local val="${2:-}"
    if [[ -n ${item} ]]; then
        local item_width
        item_width="${#item}"
        local l_term_cols=${l_term_cols:-"${term_cols:-}"}
        [[ -z "${l_term_cols}" ]] && l_term_cols=$(tput cols)

        # "${item_width}" -le "${l_term_cols}"
        local left_space
        left_space=$(( (l_term_cols - item_width) / 2 ))
        local printf_val
        printf_val=$((left_space + item_width))

        if [[ -z "${val}" ]]; then
            printf "%${printf_val}s\n" "${item}"
        else
            printf "%$((printf_val - item_width / 2))s $c_red%s$c_normal\n" "${item}:" "${val}"
        fi    # end if val

    fi
}

funcInitializationCheck(){
    # 1 - Check root or sudo privilege
    [[ "$UID" -ne 0 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script requires superuser privileges (eg. root, su)."

    # 2 - specified for RHEL/Debian/SLES
    [[ -f '/etc/os-release' || -f '/etc/redhat-release' || -f '/etc/debian_version' || -f '/etc/SuSE-release' ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script just support RHEL/CentOS/Debian/Ubuntu/OpenSUSE derivates!"

    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}curl${c_normal} command finds, please install it!"

    funcCommandExistCheck 'sha256sum' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}sha256sum${c_normal} command finds, please install it!"

    funcCommandExistCheck 'gzip' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gzip${c_normal} command found, please install it (CentOS/Debian/OpenSUSE: gzip)!"

    funcCommandExistCheck 'tar' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}tar${c_normal} command found to decompress .tar.gz file!"

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

funcPackageManagerDetection(){
    # OpenSUSE has utility apt-get, aptitude. Amazing
    if funcCommandExistCheck 'zypper'; then
        pack_manager='zypper'
    elif funcCommandExistCheck 'apt-get'; then
        pack_manager='apt-get'
    elif funcCommandExistCheck 'dnf'; then
        pack_manager='dnf'
    elif funcCommandExistCheck 'yum'; then
        pack_manager='yum'
    else
        funcExitStatement "${c_red}Sorry${c_normal}: can't find command ${c_blue}apt-get|yum|dnf|zypper${c_normal}."
    fi

    # case "${pack_manager}" in
    #     zypper|dnf|yum|rpm ) pack_suffix='rpm' ;;
    #     apt-get|apt|dpkg ) pack_suffix='deb' ;;
    # esac
}

funcPackageManagerOperation(){
    local action="${1:-'update'}"
    local package_lists=(${2:-})

    case "${pack_manager}" in
        apt-get )
            # disable dialog prompt
            export DEBIAN_FRONTEND=noninteractive

            # apt-get [options] command
            case "${action}" in
                install|in )
                    apt-get -yq install "${package_lists[@]}" &> /dev/null
                    apt-get -yq -f install &> /dev/null
                    ;;
                remove|rm )
                    apt-get -yq purge "${package_lists[@]}" &> /dev/null
                    apt-get -yq autoremove 1> /dev/null
                    ;;
                upgrade|up )
                    # https://askubuntu.com/questions/165676/how-do-i-fix-a-e-the-method-driver-usr-lib-apt-methods-http-could-not-be-foun#211531
                    # https://github.com/koalaman/shellcheck/wiki/SC2143
                    if ! dpkg --list | grep -q 'apt-transport-https'; then
                        apt-get -yq install apt-transport-https &> /dev/null
                    fi

                    apt-get -yq clean all 1> /dev/null
                    apt-get -yq update 1> /dev/null
                    apt-get -yq upgrade &> /dev/null
                    apt-get -yq dist-upgrade &> /dev/null
                    apt-get -yq autoremove 1> /dev/null
                    ;;
                * )
                    apt-get -yq clean all 1> /dev/null
                    apt-get -yq update 1> /dev/null
                    ;;
            esac
            ;;
        dnf )
            # dnf [options] COMMAND
            case "${action}" in
                install|in )
                    dnf -yq install "${package_lists[@]}" &> /dev/null
                    ;;
                remove|rm )
                    dnf -yq remove "${package_lists[@]}" &> /dev/null
                    dnf -yq autoremove 2> /dev/null
                    ;;
                upgrade|up )
                    dnf -yq makecache &> /dev/null
                    dnf -yq upgrade &> /dev/null    #dnf has no command update
                    dnf -yq autoremove 2> /dev/null
                    ;;
                * )
                    dnf -yq clean all &> /dev/null
                    dnf -yq makecache fast &> /dev/null
                    ;;
            esac
            ;;
        yum )
            funcCommandExistCheck 'yum-complete-transaction' && yum-complete-transaction --cleanup-only &> /dev/null
            # yum [options] COMMAND
            case "${action}" in
                install|in )
                    yum -y -q install "${package_lists[@]}" &> /dev/null
                    ;;
                remove|rm )
                    yum -y -q erase "${package_lists[@]}" &> /dev/null
                    # yum -y -q remove "${package_lists[@]}" &> /dev/null
                    yum -y -q autoremove &> /dev/null
                    ;;
                upgrade|up )
                    yum -y -q makecache fast &> /dev/null
                    # https://www.blackmoreops.com/2014/12/01/fixing-there-are-unfinished-transactions-remaining-you-might-consider-running-yum-complete-transaction-first-to-finish-them-in-centos/
                    funcCommandExistCheck 'yum-complete-transaction' || yum -y -q install yum-utils &> /dev/null
                    yum -y -q update &> /dev/null
                    yum -y -q upgrade &> /dev/null
                    ;;
                * )
                    yum -y -q clean all &> /dev/null
                    yum -y -q makecache fast &> /dev/null
                    ;;
            esac
            ;;
        zypper )
            # zypper [--global-opts] command [--command-opts] [command-arguments]
            case "${action}" in
                install|in )
                    zypper in -yl "${package_lists[@]}" &> /dev/null
                    ;;
                remove|rm )
                    zypper rm -yu "${package_lists[@]}" &> /dev/null
                    # remove unneeded packages & dependencies
                    zypper packages --unneeded | awk -F\| 'match($1,/^i/){print $3}' | xargs zypper rm -yu &> /dev/null
                    ;;
                upgrade|up )
                    zypper clean -a 1> /dev/null
                    zypper ref -f &> /dev/null
                    zypper up -yl 1> /dev/null
                    zypper dup -yl 1> /dev/null
                    zypper patch -yl 1> /dev/null
                    ;;
                * )
                    zypper clean -a 1> /dev/null
                    zypper ref -f &> /dev/null
                    ;;
            esac
            ;;
    esac
}

#########  1-2 getopts Operation  #########
start_time=$(date +'%s')    # Start Time Of Operation

while getopts "hcali:sSD:up:" option "$@"; do
    case "$option" in
        # c ) version_check=1 ;;
        a ) alertmanager_install=1 ;;
        l ) list_exporter_info=1 ;;
        i ) pack_name_specify="$OPTARG" ;;
        s ) server_install=1 ;;
        S ) restrict_mode=1 ;;
        D ) pack_save_dir="$OPTARG" ;;
        u ) is_uninstall=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2-1. Uninstall Operation  #########
funcUninstallOperation(){
    if [[ "${is_uninstall}" -eq 1 ]]; then
        if [[ -d "${exporter_dir}" ]]; then
            local l_service_script_dir='/etc/init.d'
            funcCommandExistCheck 'systemctl' && l_service_script_dir='/etc/systemd/system'

            # - stop daemon running
            find "${l_service_script_dir}"/ -type f -name "${software_name}*" -print | while IFS="" read -r line; do
                if [[ -n "${line}" ]]; then
                    service_name="${line##*/}"
                    service_name="${service_name%%.*}"
                    funcSystemServiceManager "${service_name}" 'stop'
                    # - remove system init script   SysV init / Systemd
                    [[ -f "${line}" ]] && rm -f "${line}"
                    unset service_name
                fi
            done

            # - remove data dir
            [[ -d "${log_dir}" ]] && rm -rf "${log_dir}"
            [[ -d "${configuration_dir}" ]] && rm -rf "${configuration_dir}"
            [[ -d "${target_dir}" ]] && rm -rf "${target_dir}"

            [[ "${restrict_mode}" -eq 1 && -d "${pack_save_dir}" ]] && rm -rf "${pack_save_dir}"

            # - remove user and group - prometheus
            if [[ -n $(sed -r -n '/^'"${software_name}"':/{p}' /etc/passwd) ]]; then
                userdel -fr "${software_name}" 2> /dev/null
                groupdel -f "${software_name}" 2> /dev/null
            fi

            funcCommandExistCheck 'systemctl' && systemctl daemon-reload 2> /dev/null

            funcExitStatement "${software_fullname} is successfully removed from your system!"
        else
            funcExitStatement "${c_blue}Note${c_normal}: no ${software_fullname} is found in your system!"
        fi
    fi
}

#########  2-2. Extract Latest Package Info  #########
funcLatestPacksInfoExtraction(){
    latest_online_packs_info=$(mktemp -t "${mktemp_format}")

    $download_tool "${download_page}" | sed -r -n '/<strong>/{s@\>[[:space:]]+\/?[[:space:]]*\<@|@g;s@>v@>@g;p}; /<h2 id="/{s@^[[:space:]]*@@g;s@<h2[^>]*>@&---@g;p}; /linux.*amd64/,/<\/tr>/{/(id|class)=/!d;s@.*href="([^"]*)".*@\1@g;p}' | sed ':a;N;$!ba;s@\n@|@g;s@[[:space:]]*<[^>]*>[[:space:]]*@@g;s@^---@@g;s@|*---@\n@g;' > "${latest_online_packs_info}"

    [[ -s "${latest_online_packs_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract packs info from page ${c_blue}${download_page}${c_normal}!"

    # list latest exporter info
    if [[ "${list_exporter_info}" -eq 1 ]]; then
        funcCentralOutput 'Prometheus & Exporters Info'
        funcCentralOutput '==============================='
        echo ''
        awk -F\| 'NF>1{printf("%-20s|%-8s|%s\n",$1,$2,$3)}' "${latest_online_packs_info}"
        exit
    fi
}

#########  2-3. Download & Decompress Operation  #########
funcSystemUserAndGroupOperation(){
    if [[ -z $(sed -r -n '/^'"${software_name}"':/{p}' /etc/passwd) ]]; then
        if [[ "${restrict_mode}" -eq 1  ]]; then
            # create group
            groupadd -r "${software_name}"
            # create user without login privilege
            useradd -r -g "${software_name}" -s /sbin/nologin -d "${target_dir}" -c "Prometheus Server Daemon" "${software_name}"
            user_name="${software_name}"
            group_name="${software_name}"
        fi
    else
        user_name="${software_name}"
        group_name="${software_name}"
    fi
}

funcUtilityVersionInfo(){
    local l_execution_path="${1:-}"
    local l_version_no=''
    if [[ -s "${l_execution_path}" ]]; then
        l_version_no=$("${l_execution_path}" --version 2>&1 | sed -r -n '1{s@.*version[[:space:]]*([^[:space:]]+)[[:space:]]*.*@\1@g;p}')
    fi
    echo "${l_version_no}"
}

funcSHA256DgstInfo(){
    local l_save_path="${1:-}"
    local l_sha256_dgst=''
    if [[ -s "${l_save_path}" ]]; then
        l_sha256_dgst=$(sha256sum "${l_save_path}" | sed -r 's@^([^[:space:]]+).*@\1@g')
    fi
    echo "${l_sha256_dgst}"
}

funcCoreOperation(){
    local l_pack_name="${1:-}"
    local l_pack_latest_info=''
    [[ -n "${l_pack_name}" ]] && l_pack_latest_info=$(sed -r -n '/^'"${l_pack_name}"'\|/{p}' "${latest_online_packs_info}")
    # prometheus|2.0.0|2017-11-08|https://github.com/prometheus/prometheus/releases/download/v2.0.0/prometheus-2.0.0.linux-amd64.tar.gz|e12917b25b32980daee0e9cf879d9ec197e2893924bd1574604eb0f550034d46

    [[ -n "${l_pack_latest_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract packs info about package ${c_blue}${l_pack_name}${c_normal}!"

    if [[ "${l_pack_name}" == 'mysqld_exporter' ]]; then
        funcCommandExistCheck 'mysql' || funcExitStatement "${c_red}Sorry${c_normal}: fail to find mysqld service on your system!"
    fi

    # l_pack_name
    local l_pack_version
    l_pack_version=$(echo "${l_pack_latest_info}" | awk -F\| '{print $2}')
    l_pack_version="${l_pack_version#v}"
    # local l_pack_date
    # l_pack_date=$(echo "${l_pack_latest_info}" | awk -F\| '{print $3}')
    local l_pack_link
    l_pack_link=$(echo "${l_pack_latest_info}" | awk -F\| '{print $4}')
    local l_pack_dgst
    l_pack_dgst=$(echo "${l_pack_latest_info}" | awk -F\| '{print $5}')

    pack_save_dir="${pack_save_dir%/}"
    local l_pack_save_path="${pack_save_dir}/${l_pack_link##*/}"
    [[ -d "${pack_save_dir}" ]] || mkdir -p "${pack_save_dir}"

    # - download package
    if [[ ! -s "${l_pack_save_path}" ]]; then
        # remove older version package
        rm -f "${pack_save_dir}/${l_pack_name}"*
        $download_tool "${l_pack_link}" > "${l_pack_save_path}"
    fi

    # - verification sha256
    if [[ -n "${l_pack_dgst}" ]]; then
        local l_pack_new_dgst=''
        l_pack_new_dgst=$(funcSHA256DgstInfo "${l_pack_save_path}")
        if [[ -n "${l_pack_new_dgst}" && "${l_pack_new_dgst}" != "${l_pack_dgst}" ]]; then
            [[ -f "${l_pack_save_path}" ]] && rm -f "${l_pack_save_path}"
            funcExitStatement "${c_red}Sorry${c_normal}: package ${c_blue}${l_pack_link##*/}${c_normal} SHA-256 check inconsistency!"
        fi
    fi

    local l_installation_dir
    l_installation_dir=${l_installation_dir:-}
    local l_config_path
    l_config_path=${l_config_path:-}
    local l_execution_file_path
    l_execution_file_path=${l_execution_file_path:-}

    case "${l_pack_name}" in
        prometheus )
            l_installation_dir="${server_dir}"
            l_config_path="${configuration_dir}/${software_name}.yml"
            ;;
        mysqld_exporter )
            l_installation_dir="${exporter_dir}"
            l_config_path="${configuration_dir}/.my.cnf"
            ;;
        alertmanager )
            l_installation_dir="${alertmanager_dir}"
            ;;
        * )
            l_installation_dir="${exporter_dir}"
            ;;
    esac

    # - decomprssion
    if [[ -s "${l_pack_save_path}" ]]; then
        [[ -d "${l_installation_dir}" ]] || mkdir -p "${l_installation_dir}"

        tar xf "${l_pack_save_path}" -C "${l_installation_dir}" --strip-components=1
        [[ -f "${l_installation_dir}/LICENSE" ]] && rm -f "${l_installation_dir}/LICENSE"
        [[ -f "${l_installation_dir}/NOTICE" ]] && rm -f "${l_installation_dir}/NOTICE"

        # - version comparasion
        local l_newly_version_no=''
        l_newly_version_no=$(funcUtilityVersionInfo "${l_installation_dir}/${l_pack_name}")

        if [[ "${l_newly_version_no}" == "${l_pack_version}" ]]; then
            echo -e "Package ${l_pack_name} is installed successfully!"
        else
            [[ -f "${l_installation_dir}/${l_pack_name}" ]] && rm -f "${l_installation_dir}/${l_pack_name}"
            funcExitStatement "${c_red}Sorry${c_normal}: fail to install ${c_blue}${l_pack_name}${c_normal}!"
        fi

        find "${l_installation_dir}" -type d -exec chmod 750 {} \;
        chown -R "${user_name}" "${l_installation_dir}"
        chmod 750 "${l_installation_dir}/${l_pack_name}"
    fi

    # - configuration file
    if [[ -s "${l_installation_dir}/${l_pack_name}" ]]; then
        [[ -d "${configuration_dir}" ]] || mkdir -p "${configuration_dir}"
        [[ -d "${log_dir}" ]] || mkdir -p "${log_dir}"
        chown -R "${user_name}" "${configuration_dir}"  "${log_dir}"

        if [[ "${l_pack_name}" == 'prometheus' ]]; then
            [[ -d "${server_data_dir}" ]] || mkdir -p "${server_data_dir}"
            chmod 750 "${server_data_dir}"
            chown -R "${user_name}"  "${server_data_dir}"
        fi

        if [[ -n "${l_config_path}" ]]; then
            case "${l_pack_name}" in
                prometheus )
                    if [[ ! -s "${l_config_path}" ]]; then
                        $download_tool "${online_config_file_sample_dir}/${l_config_path##*/}" > "${l_config_path}"
                    fi
                    ;;
                mysqld_exporter )
                    if [[ ! -s "${l_config_path}" ]]; then
                        local login_user_mycnf=${login_user_mycnf:-"${login_user_home}/.my.cnf"}
                        [[ -f "${login_user_mycnf}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to find mysql login conf ${c_blue}${login_user_mycnf}${c_normal}!"
                        # need to start mysql
                        local mysql_command=${mysql_command:-"mysql --defaults-file=${login_user_mycnf}"}
                        local export_host='127.0.0.1'
                        local export_user='p_exporter'
                        local export_passwd='Prometheus_Monitor@2018'
                        $mysql_command -e "create user '${export_user}'@'${export_host}' identified by '${export_passwd}';" 2> /dev/null
                        $mysql_command -e "grant process,replication client, select on *.* to '${export_user}'@'${export_host}';" 2> /dev/null
                        $mysql_command -e "flush privileges;" 2> /dev/null
                        echo  -e "[client]\nuser=${export_user}\npassword=\"${export_passwd}\"\nhost=${export_host}" > "${l_config_path}"
                    fi
                    ;;
            esac

            chown "${user_name}" "${l_config_path}"
            chmod 640 "${l_config_path}"
        fi    # end if l_config_path
    fi

    # - service script
    local l_service_script_link=''
    local l_service_script_dir=''
    local l_service_script_path=''

    if funcCommandExistCheck 'systemctl'; then
        l_service_script_dir='/etc/systemd/system'
        l_service_script_link="${online_service_script_sample_dir}/${l_pack_name}.service"

        if [[ "${l_pack_name}" == 'prometheus' ]]; then
            l_service_script_path="${l_service_script_dir}/${l_pack_name}.service"
        else
            l_service_script_path="${l_service_script_dir}/${software_name}_${l_pack_name}.service"
        fi

        [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

        $download_tool "${l_service_script_link}" > "${l_service_script_path}"
        sed -r -i '/^\[Service\]/,/^\[/{s@^(User=).*$@\1'"${user_name}"'@g;}' "${l_service_script_path}"
        chmod 644 "${l_service_script_path}"

    else
        l_service_script_dir='/etc/init.d'
        l_service_script_link="${online_service_script_sample_dir}/${l_pack_name}.init"
        if [[ "${l_pack_name}" == 'prometheus' ]]; then
            l_service_script_path="${l_service_script_dir}/${l_pack_name}"
        else
            l_service_script_path="${l_service_script_dir}/${software_name}_${l_pack_name}"
        fi

        [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

        $download_tool "${l_service_script_link}" > "${l_service_script_path}"
        sed -r -i '/Configuraton Start/,/Configuraton End/{s@^(USER=).*$@\1'"${user_name}"'@g;s@^(GROUP=).*$@\1'"${group_name}"'@g;}' "${l_service_script_path}"
        chmod 755 "${l_service_script_path}"

    fi

    [[ -s "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'enable'
}

funcOperationProcedure(){
    # default install pack node_exporter
    funcCoreOperation 'node_exporter'
    [[ "${server_install}" -eq 1 ]] && funcCoreOperation 'prometheus'
    [[ "${alertmanager_install}" -eq 1 ]] && funcCoreOperation 'alertmanager'

    if [[ -n "${pack_name_specify}" ]]; then
        case "${pack_name_specify,,}" in
            mysqld_exporter )
                funcCoreOperation 'mysqld_exporter'
                ;;
            * )
                echo "this script does not support ${pack_name_specify} currently!"
                ;;
        esac
    fi
}


#########  2-4. Operation Time Cost  #########
funcTotalTimeCosting(){
    finish_time=$(date +'%s')        # End Time Of Operation
    total_time_cost=$((finish_time-start_time))   # Total Time Of Operation
    funcExitStatement "Total time cost is ${c_red}${total_time_cost}${c_normal} seconds!"
}


#########  3. Executing Process  #########
funcInitializationCheck
funcInternetConnectionCheck
funcDownloadToolCheck
funcPackageManagerDetection

funcUninstallOperation
funcLatestPacksInfoExtraction
funcSystemUserAndGroupOperation
funcOperationProcedure
funcTotalTimeCosting

#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset bak_suffix
    unset software_name
    unset software_fullname
    unset target_dir
    unset pack_save_dir
    unset server_dir
    unset server_data_dir
    unset alertmanager_dir
    unset exporter_dir
    unset configuration_dir
    unset log_dir
    unset user_name
    unset group_name
    unset list_exporter_info
    unset server_install
    unset alertmanager_install
    unset pack_name_specify
    unset is_uninstall
    # unset version_check
    unset proxy_server
    unset restrict_mode
    unset start_time
    unset finish_time
    unset total_time_cost
}

trap funcTrapEXIT EXIT

# Script End
