#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Grafana Installation And Configuration On GNU/Linux (RHEL/CentOS/Fedora/Debian/Ubuntu/OpenSUSE and variants)
#Writer: MaxdSre
#Date: Jan 05, 2018 13:58 Fri +0800 - add paras setting, remove count_scalar setting
#Update Time:
# - Dec 12, 2017 13:51 Tue +0800


#Desc: Grafana is an open source metric analytics & visualization suite.
#Reference: http://docs.grafana.org/
# http://docs.grafana.org/installation/configuration/#admin-user
# - default user: admim
# - default password: admin


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'GRAFANATemp_XXXXXX'}
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
readonly official_site='https://grafana.com'
readonly download_page="${official_site}/grafana/download"
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup
readonly temp_save_dir='/tmp'  # Save Path Of Downloaded Packages
readonly software_fullname=${software_fullname:-'Grafana'}
config_dir=${config_dir:-'/etc/grafana'}
data_dir=${data_dir:-'/var/lib/grafana'}

is_existed=${is_existed:-0}   # Default value is 0， check if system has installed Grafana
file_specify_path=${file_specify_path:-}
version_check=${version_check:-0}
is_uninstall=${is_uninstall:-0}
proxy_server=${proxy_server:-}


#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...
Installing / Updating Grafana On GNU/Linux!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -c    --check, check current stable release version
    -f file_path    --manually specify absolute path of grafana package in local system, e.g. /tmp/grafana_4.6.2_amd64.deb, default is download directly from official download page
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
    -u    --uninstall, uninstall software installed
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
    # [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}curl${c_normal} command finds, please install it!"

    funcCommandExistCheck 'sha256sum' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}sha256sum${c_normal} command finds, please install it!"

    funcCommandExistCheck 'unzip' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}unzip${c_normal} command finds, please install it!"

    # funcCommandExistCheck 'gzip' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gzip${c_normal} command found, please install it (CentOS/Debian/OpenSUSE: gzip)!"
    #
    # funcCommandExistCheck 'tar' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}tar${c_normal} command found to decompress .tar.gz file!"

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
    # local referrer_page=${referrer_page:-'https://duckduckgo.com/?q=gnulinux'}
    # local user_agent=${user_agent:-'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6.4) AppleWebKit/537.29.20 (KHTML, like Gecko) Chrome/60.0.3030.92 Safari/537.29.20'}

    if funcCommandExistCheck 'curl'; then
        download_tool_origin="curl -fsL"
        download_tool="${download_tool_origin} --retry ${retry_times} --retry-delay ${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-keepalive"   # curl -s URL -o /PATH/FILE； -fsSL
        # --referer ${referrer_page}
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

    case "${pack_manager}" in
        zypper|dnf|yum|rpm ) pack_suffix='rpm' ;;
        apt-get|apt|dpkg ) pack_suffix='deb' ;;
    esac
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

while getopts "hcf:up:" option "$@"; do
    case "$option" in
        c ) version_check=1 ;;
        f ) file_specify_path="$OPTARG" ;;
        u ) is_uninstall=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2-1. Uninstall Operation  #########
funcUninstallOperation(){
    if [[ "${is_uninstall}" -eq 1 ]]; then
        if funcCommandExistCheck 'grafana-server'; then
            funcSystemServiceManager 'grafana-server' 'stop'
            funcPackageManagerOperation 'remove' 'grafana'

            if funcCommandExistCheck 'grafana-server'; then
                funcExitStatement "${c_red}Sorry${c_normal}, fail to uninstall ${software_fullname}!"
            else
                [[ -d "${config_dir}" ]] && rm -rf "${config_dir}"
                [[ -d "${data_dir}" ]] && rm -rf "${data_dir}"
                funcExitStatement "${software_fullname} is successfully removed from your system!"
            fi
        else
            funcExitStatement "${c_blue}Note${c_normal}: no ${software_fullname} is found in your system!"
        fi
    fi
}

#########  2-2. Extract Latest Package Info  #########
funcLatestPacksInfoExtraction(){
    latest_packs_info=$(mktemp -t "${mktemp_format}")
    # curl -fsL https://grafana.com/grafana/download
    $download_tool "${download_page}" | sed 's@<\/div>@\n@g;s@},@}\n@g' | sed -r -n '/(linux-x64.tar|amd64.deb|x86_64.rpm).*sha256/{s@\u002F@@g;s@\\@\/@g;s@,"@\n"@g;p}' | sed -r -n '1,/"id"/d;/(version|url|sha256|createdAt|href)"/!d;s@"href".*@--@g;s@^.*":"([^"]*)"$@\1@g;p' | sed ':a;N;$!ba;s@\n@|@g;s@|--|@\n@g;s@|--@@g;s@\.000Z@@g;' | awk -F\| 'BEGIN{OFS="|"}{"date --date=\""$NF"\" +\"%F\"" | getline aa;print $1,aa,$2,$3}'  > "${latest_packs_info}"
    # Note: in CentOS 6.x, utility date can not parse date format '2017-11-16T10:07:53.000Z'

    [[ -s "${latest_packs_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract packs info from page ${c_blue}${download_page}${c_normal}!"

    # version|releaseDate|downloadLink|sha256Dgst
    # 4.6.2|2017-11-16|https://s3-us-west-2.amazonaws.com/grafana-releases/release/grafana_4.6.2_amd64.deb|f4ad0ef25e20c876f54b0e3139b2af5bb856cf7d54a941bfe0df67dc085e2d48
    # 4.6.2|2017-11-16|https://s3-us-west-2.amazonaws.com/grafana-releases/release/grafana-4.6.2-1.x86_64.rpm|ab3807cf4bf2eae45d2b0ad0074eee9eda30639da1efd1d450c91bf800455862
}

#########  2-3. Local & Online Verson Operation Comparasion #########
funcVersionComparasion(){
    # latest online release version
    local online_release_version
    online_release_version=$(sed -r -n '1{s@^([^\|]+)\|.*@\1@g;p}' "${latest_packs_info}")
    local online_release_date
    online_release_date=$(sed -r -n '1{s@^[^\|]+\|([^\|]+)\|.*@\1@g;p}' "${latest_packs_info}")

    local version_local=${version_local:-}

    if funcCommandExistCheck 'grafana-server'; then
        is_existed=1
        if [[ -s '/usr/sbin/grafana-server' ]]; then
            version_local=$(/usr/sbin/grafana-server -v 2>&1 | sed -r -n 's@^[^[:digit:]]+([^[:space:]]+).*@\1@g;p')
        else
            version_local=$(grafana-server -v 2>&1 | sed -r -n 's@^[^[:digit:]]+([^[:space:]]+).*@\1@g;p')
        fi
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

funcPerconaDashboardInstallation(){
    # https://github.com/percona/grafana-dashboards

    # [dashboards.json]
    # enabled = true
    # path = /var/lib/grafana/dashboards
    local config_path="${config_dir}/grafana.ini"
    [[ -s "${config_path}" ]] && sed -r -i '/^\[dashboards.json\]$/,/^$/{s@^;?enabled.*$@enabled = true@g;s@;?(path.*)$@\1@g;}' "${config_path}"

    if [[ -d "${data_dir}" ]]; then
        local percona_dashboards_link='https://github.com/percona/grafana-dashboards/archive/master.zip'
        local pack_save_path="${temp_save_dir}/grafana-dashboards-master.zip"
        $download_tool "${percona_dashboards_link}" > "${pack_save_path}"
        if [[ -s "${pack_save_path}" ]]; then
            unzip -q -d "${temp_save_dir}" "${pack_save_path}"
            [[ -d "${data_dir}/dashboards" ]] && rm -rf "${data_dir}/dashboards"
            cp -R "${temp_save_dir}/grafana-dashboards-master/dashboards" "${data_dir}/"
            chown -R grafana:grafana "${data_dir}"
            chmod 750 "${data_dir}/dashboards"
            chmod 640 "${data_dir}/dashboards"/*.json

            # {
            #   "status": "error",
            #   "errorType": "bad_data",
            #   "error": "parse error at char 84: unknown function with name \"count_scalar\"",
            #   "message": "parse error at char 84: unknown function with name \"count_scalar\""
            # }

            # https://github.com/prometheus/prometheus/releases
            # Prometheus has removed count_scalar from v 2.0.0
            # https://github.com/percona/grafana-dashboards/pull/71
            # https://github.com/percona/grafana-dashboards/commit/38443776ebd6f13b1000b1ec3025fb39bc014c3c
        fi    # end if pack_save_path

        [[ -f "${pack_save_path}" ]] && rm -f "${pack_save_path}"
        [[ -d "${temp_save_dir}/grafana-dashboards-master" ]] && rm -rf "${temp_save_dir}/grafana-dashboards-master"

    fi    # end if data_dir
}

funcParametersConfiguration(){
    # http://docs.grafana.org/installation/configuration/
    local config_path="${config_dir}/grafana.ini"
    if [[ -s "${config_path}" ]]; then
        # - Paths
        # - Server
        # - Database
        # - Session
        # - Data proxy
        # - Analytics
        # - Security
        # - Users
        # disable user signup / registration
        sed -r -i '/^\[users\]$/,/^$/{s@^;?(allow_sign_up).*$@\1 = false@g;}' "${config_path}"
        # - Anonymous Auth
        # disable anonymous access
        sed -r -i '/^\[auth.anonymous\]$/,/^$/{s@^;?(enabled).*$@\1 = false@g;}' "${config_path}"
        # - Github Auth
        # - Google Auth
        # - Generic OAuth
        # - Grafana.com Auth
        # - Auth Proxy
        # - Basic Auth
        # - Auth LDAP
        # - SMTP / Emailing
        # - Logging
        # - AMQP Event Publisher
        # - Alerting
        # - Internal Grafana Metrics
        # - Distributed tracing
        # - Grafana.com integration
        # - External image storage
    fi
}

funcCoreOperationProcedure(){
    local pack_info
    pack_info=$(sed -r -n '/.'"${pack_suffix}"'\|/p' "${latest_packs_info}")
    [[ -n "${pack_info}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to extract pack info for package manager ${c_blue}${pack_manager}${c_normal}!"

    local pack_save_name
    local pack_sha256

    echo "${pack_info}" | while IFS="|" read -r p_version p_date p_link p_sha256_dgst; do
        printf "Operation process will cost some time, just be patient!\n\n"

        pack_save_name="${temp_save_dir}/${p_link##*/}"

        # 1- manually specify package path in system
        if [[ -n "${file_specify_path}" ]]; then
            if [[ -s "${file_specify_path}" && "${file_specify_path}" =~ .(deb|rpm)$ ]]; then
                if [[ $(funcSha256Verification "${file_specify_path}") == "${p_sha256_dgst}" ]]; then
                    cp "${file_specify_path}" "${pack_save_name}"
                else
                    funcExitStatement "${c_red}Error${c_normal}, package ${c_blue}${file_specify_path}${c_normal} SHA-256 check inconsistency!"
                fi
            else
                funcExitStatement "${c_red}Attention${c_normal}: package path ${c_blue}${file_specify_path}${c_normal} is not legal!"
            fi

        else
            # 2 - download directly from Grafana official site
            $download_tool "${p_link}" > "${pack_save_name}"
        fi

        if [[ -f "${pack_save_name}" ]]; then
            pack_sha256=$(funcSha256Verification "${pack_save_name}")
            if [[ -z "${pack_sha256}" ]]; then
                [[ -f "${pack_save_name}" ]] && rm -f "${pack_save_name}"
                funcExitStatement "${c_red}Sorry${c_normal}: package ${c_blue}${pack_save_name}${c_normal} not exists!"
            else
                if [[ "${pack_sha256}" == "${p_sha256_dgst}" ]]; then
                    printf "Package $c_blue%s${c_normal} approves SHA-256 check!\n" "${pack_save_name##*/}"
                else
                    [[ -f "${pack_save_name}" ]] && rm -f "${pack_save_name}"
                    funcExitStatement "${c_red}Error${c_normal}, package ${c_blue}${pack_save_name##*/}${c_normal} SHA-256 check inconsistency! The package may not be integrated!"
                fi    # end if p_sha256_dgst
            fi    # end if pack_sha256

            case "${pack_manager}" in
                apt-get )
                    funcPackageManagerOperation 'install' 'adduser libfontconfig'
                    dpkg -i "${pack_save_name}" &> /dev/null
                    ;;
                yum|dnf )
                    funcPackageManagerOperation 'install' 'initscripts fontconfig'
                    # dependency: urw-fonts, xorg-x11-font-utils
                    # rpm -Uvh "${pack_save_name}" &> /dev/null
                    yum localinstall -y "${pack_save_name}" &> /dev/null
                    ;;
                zypper )
                    rpm -i --nodeps "${pack_save_name}" &> /dev/null
                    ;;
            esac

            [[ -f "${pack_save_name}" ]] && rm -f "${pack_save_name}"

            local operation_type='install'
            [[ "${is_existed}" -eq 1 ]] && operation_type='update'
            # /usr/sbin/grafana-server
            if funcCommandExistCheck 'grafana-server'; then
                funcParametersConfiguration
                funcPerconaDashboardInstallation
                # sudo /bin/systemctl start grafana-server
                # service grafana-server start
                funcSystemServiceManager 'grafana-server' 'enable'
                printf "Successfully ${c_blue}%s${c_normal} %s v ${c_blue}%s${c_normal} (${c_blue}%s${c_normal})!\nOpen ${c_red}http://localhost:3000${c_normal} in your browser.\n\n" "${operation_type}" "${software_fullname}" "${p_version}" "${p_date}"
            else
                funcExitStatement "${c_red}Error${c_normal}, fail to  ${c_blue}${operation_type}${c_normal} ${software_fullname} v ${c_blue}${p_version}${c_normal}!\n"
            fi

        fi    # end if pack_save_name

    done    # end while
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
funcPackageManagerDetection

funcUninstallOperation
funcLatestPacksInfoExtraction
funcVersionComparasion
funcCoreOperationProcedure
funcTotalTimeCosting



#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset bak_suffix
    unset config_dir
    unset data_dir
    unset is_existed
    unset file_specify_path
    unset version_check
    unset is_uninstall
    unset proxy_server
    unset start_time
    unset finish_time
    unset total_time_cost
}

trap funcTrapEXIT EXIT

# Script End
