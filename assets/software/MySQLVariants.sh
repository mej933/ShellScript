#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Installing MySQL/MariaDB/Percona Via Their Official Repository On GNU/Linux (RHEL/CentOS/Fedora/Debian/Ubuntu/SLES/OpenSUSE)
#Writer: MaxdSre
#Date: Jan 22, 2018 13:03 Mon +0800 - conf optimization
#Update Time:
# - July 19, 2017 13:18 Wed +0800 ~ Sep 08, 2017 17:58 Fri +0800
# - Oct 27, 2017 17:46 Fri +0800
# - Nov 03, 2017 16:49 Fri +0800
# - Dec 06, 2017 18:24 Wed +0800 - reconfiguration 2 days
# - Jan 08 ~ 09, 2018 19:38 Mon +0800 - add SELinux support, reconfiguration 2 days

# https://www.percona.com/blog/2017/11/02/mysql-vs-mariadb-reality-check/
# https://www.atlantic.net/community/whatis/mysql-vs-mariadb-vs-percona/

# monitor tool: innotop, mytop, mysqladmin, prometheus&grafana

#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'MPDSTemp_XXXXXX'}
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
readonly c_red="$(tput setaf 1)"     # c_red='\e[31;1m'
readonly c_redb="${c_bold}$(tput setaf 1)"
readonly c_green="$(tput setaf 2)"    # c_blue='\e[32m'
readonly c_yellow="$(tput setaf 3)"    # c_blue='\e[33m'
readonly c_blue="$(tput setaf 4)"    # c_blue='\e[34m'
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup

readonly github_raw_url='https://raw.githubusercontent.com'
readonly custom_shellscript_url="${github_raw_url}/MaxdSre/ShellScript"
readonly mysql_veriants_version_list="${custom_shellscript_url}/master/sources/mysqlVariantsVersionAndLinuxDistroRelationTable.txt"
readonly mysqld_cnf_url="${custom_shellscript_url}/master/configs/mysql/mysqld.cnf"
readonly firewall_configuration_script="${custom_shellscript_url}/master/assets/gnulinux/gnuLinuxFirewallRuleConfiguration.sh"

auto_installation=${auto_installation:-0}
root_password_new=${root_password_new:-''}
mysql_variant_type=${mysql_variant_type:-''}
variant_version=${variant_version:-''}
enable_firewall=${enable_firewall:-0}
slave_mode=${slave_mode:-0}
proxy_server=${proxy_server:-''}

ip_local=${ip_local:-127.0.0.1}
readonly data_dir_default='/var/lib/mysql'
readonly mysql_port_default='3306'
readonly conf_path_default='/etc/my.cnf'
conf_path="${conf_path:-"${conf_path_default}"}"

data_dir=${data_dir:-"${data_dir_default}"}
mysql_port=${mysql_port:-"${mysql_port_default}"}
mysql_log_dir=${mysql_log_dir:-}
mysql_run_dir=${mysql_run_dir:-'/var/run/mysqld'}

db_name=${db_name:-}    # Percona-Server, MySQL, MariaDB
db_version=${db_version:-}
db_version_no_new=${db_version_no_new:-}

service_name=${service_name:-'mysql'}

flag=1    # used for funcOperationPhaseStatement
procedure_start_time=${procedure_start_time:-}
procedure_end_time=${procedure_end_time:-}
# is_existed=${is_existed:-0}
# version_check=${version_check:-0}
# is_uninstall=${is_uninstall:-0}
# remove_datadir=${remove_datadir:-0}


#########  1-1 Initialization Prepatation  #########
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

funcExitStatement(){
    local str="$*"
    [[ -n "$str" ]] && printf "\n%s\n" "$str"
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
    [[ -f '/etc/os-release' || -f '/etc/redhat-release' || -f '/etc/debian_version' || -f '/etc/SuSE-release' ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script just support RHEL/CentOS/Debian/Ubuntu/OpenSUSE derivates!"

    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    # [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}curl${c_normal} command finds, please install it!"

    # 4 - current login user detection
    #$USER exist && $SUDO_USER not exist, then use $USER
    [[ -n "${USER:-}" && -z "${SUDO_USER:-}" ]] && login_user="$USER" || login_user="$SUDO_USER"
    login_user_home=${login_user_home:-}
    login_user_home=$(awk -F: 'match($1,/^'"${login_user}"'$/){print $(NF-1)}' /etc/passwd)

    login_user_cnf_path=${login_user_cnf_path:-"${login_user_home}/.my.cnf"}
    mysql_custom_command=${mysql_custom_command:-"mysql --defaults-file=${login_user_cnf_path}"}

    funcCommandExistCheck 'ip' && ip_local=$(ip route get 1 | sed -r -n '1{s@.*src[[:space:]]*([^[:space:]]+).*$@\1@g;p}')
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

funcOSInfoDetection(){
    local release_file=${release_file:-}
    local distro_fullname=${distro_fullname:-}
    local distro_family_own=${distro_family_own:-}
    distro_name=${distro_name:-}
    version_id=${version_id:-}
    codename=${codename:-}

    # CentOS 5, CentOS 6, Debian 6 has no file /etc/os-release
    if [[ -s '/etc/os-release' ]]; then
        release_file='/etc/os-release'
        #distro name，eg: centos/rhel/fedora, debian/ubuntu, opensuse/sles
        distro_name=$(sed -r -n '/^ID=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
        #version id, eg: 7/8, 16.04/16.10, 13.2/42.2
        if [[ "${distro_name,,}" == 'debian' && -s /etc/debian_version ]]; then
            version_id=$(cat /etc/debian_version)
        else
            version_id=$(sed -r -n '/^VERSION_ID=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
        fi

        # Fedora, Debian，SUSE has no parameter ID_LIKE, only has ID
        distro_family_own=$(sed -r -n '/^ID_LIKE=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
        [[ "$distro_family_own" == '' ]] && distro_family_own="$distro_name"

        case "${distro_name,,}" in
            debian|ubuntu ) codename=$(sed -r -n '/^VERSION=/s@.*[,(][[:space:]]?([^[:space:]\)]+).*@\L\1@p' "${release_file}") ;;
            opensuse ) codename=$(sed -r -n '/CODENAME/s@.*=[[:space:]]?(.*)@\L\1@p' /etc/SuSE-release) ;;
            * ) codename='' ;;
        esac    # End case

    elif [[ -s '/etc/redhat-release' ]]; then  # for CentOS 5, CentOS 6
        release_file='/etc/redhat-release'
        distro_name=$(rpm -q --qf "%{name}" -f "${release_file}") #centos-release,fedora-release
        distro_name=${distro_name%%-*}    # centos, fedora
        version_id=$(sed -r -n 's@[^[:digit:]]*([[:digit:]]{1}).*@\1@p' "${release_file}") # 5/6
        distro_family_own='rhel'   # family is rhel (RedHat)

    elif [[ -s /etc/debian_version && -s /etc/issue.net ]]; then    # for Debian 6
        release_file='/etc/issue.net'   #Debian GNU/Linux 6.0
        distro_name=$(sed -r -n 's@([^[:space:]]*).*@\L\1@p' "${release_file}")
        version_id=$(sed -r -n 's@[^[:digit:]]*([[:digit:]]{1}).*@\1@p' "${release_file}") #6
        distro_family_own='debian'   # family is debian (Debian)

        case "${version_id}" in
            6 ) codename='squeeze' ;;
            * ) codename='' ;;
        esac    # End case

    else
        funcExitStatement "${c_red}Sorry${c_normal}: this script can't detect your system!"
    fi      # End if

    #distro full pretty name, for CentOS ,file redhat-release is more detailed
    if [[ -s '/etc/redhat-release' ]]; then
        distro_fullname=$(cat /etc/redhat-release)
    else
        distro_fullname=$(sed -r -n '/^PRETTY_NAME=/s@.*="?([^"]*)"?@\1@p' "${release_file}")
    fi

    local is_obsoleted=${is_obsoleted:-0}
    distro_name="${distro_name,,}"
    case "${distro_name}" in
        rhel|centos )
            [[ "${version_id%%.*}" -le 5 ]] && is_obsoleted=1
            ;;
        debian )
            # 7|Wheezy|2013-05-04|2016-04-26
            # 6.0|Squeeze|2011-02-06|2014-05-31
            [[ "${version_id%%.*}" -le 7 ]] && is_obsoleted=1
            ;;
        ubuntu )
            # Ubuntu 14.04.5 LTS|Trusty Tahr|2016-08-04|April 2019
            # Ubuntu 15.10|Wily Werewolf|2015-10-22|July 28, 2016
            # Ubuntu 15.04|Vivid Vervet|2015-04-23|February 4, 2016
            [[ "${version_id%%.*}" -lt 14 || "${version_id%%.*}" -eq 15 ]] && is_obsoleted=1
            ;;
    esac

    [[ "${is_obsoleted}" -eq 1 ]] && funcExitStatement "${c_red}Sorry${c_normal}: your system ${c_blue}${distro_fullname}${c_normal} is obsoleted!"

    # Convert family name
    case "${distro_family_own,,}" in
        debian ) local distro_family_own='Debian' ;;
        suse|sles ) local distro_family_own='SUSE' ;;
        rhel|"rhel fedora"|fedora|centos ) local distro_family_own='RedHat' ;;
        * ) local distro_family_own='Unknown' ;;
    esac    # End case

    funcCentralOutput '=========================================='
    funcCentralOutput 'GNU/Linux Distribution Information'
    funcCentralOutput '=========================================='
    echo ''

    [[ -z "${distro_name}" ]] || funcCentralOutput 'Distro Name' "${distro_name}"
    [[ -z "${version_id}" ]] || funcCentralOutput 'Version ID' "${version_id}"
    [[ -z "${codename}" ]] || funcCentralOutput "Code Name" "${codename}"
    [[ -z "${distro_fullname}" ]] || funcCentralOutput 'Full Name' "${distro_fullname}"

    echo ''
    funcCentralOutput '=========================================='
    echo ''
    # echo -e "\n${c_blue}System Info:${c_normal} ${c_red}${distro_fullname}${c_normal}\n"

    version_id=${version_id%%.*}
}

funcOperationPhaseStatement(){
    local l_phase="${1:-}"
    [[ -n "${l_phase}" ]] && printf "\n${c_blue}Phase ${flag}${c_normal} - ${c_bold}${c_blue}%s${c_normal}\n" "${l_phase}"
    (( flag++ ))
    # let flag++
    # flag=$((flag+1))
}

funcOperationProcedureStatement(){
    local l_item="${1:-}"
    if [[ -n "${l_item}" ]]; then
        [[ -n "${procedure_start_time}" ]] || procedure_start_time=$(date +'%s')
        echo -n -e " ${c_yellow}procedure${c_normal} - ${l_item} ...... "
    fi
}

funcOperationProcedureResultStatement(){
    local l_str="${1:-}"
    local l_item="${2:-0}"
    procedure_end_time=$(date +'%s')
    local l_time_cost=$((procedure_end_time-procedure_start_time))
    procedure_start_time="${procedure_end_time}"

    case "${l_item,,}" in
        0|'ok' ) l_item='ok' ;;
        1|'fail'|* ) l_item='fail' ;;
    esac

    if [[ -n "${l_str}" ]]; then
        echo -n -e "[${c_green}${l_item}${c_normal}] (${c_red}${l_str}${c_normal})"
    else
        echo -n -e "[${c_green}${l_item}${c_normal}]"
    fi
    echo " [${c_yellow}${l_time_cost}${c_normal}s]"

    [[ "${l_item}" == 'fail' ]] && funcExitStatement ''
}

funcPackageOperationProcedureStatement(){
    local l_action="${1:-'install'}"
    local l_item="${2:-}"
    local l_name="${3:-}"
    if [[ -n "${l_action}" && -n "${l_item}" ]]; then
        local l_punctuation='+'
        [[ "${l_action}" == 'install' ]] || l_punctuation='-'
        funcOperationProcedureStatement "package ${l_punctuation} ${c_bold}${c_yellow}${l_item}${c_normal}"
        funcPackageManagerOperation "${l_action}" "${l_item}"
        funcOperationProcedureResultStatement "${l_name}"
    fi
}

funcSELinuxSemanageOperation(){
    # selinux type / selinux boolean
    local l_item="${1:-}"
    # port num / on/off
    local l_val="${2:-}"
    # port/boolean/fcontext
    local l_type="${3:-'port'}"
    # add -a/delete -d/modify -m for port
    local l_action="${4:-'add'}"
    # tcp/udp
    local l_protocol="${5:-'tcp'}"

    # semanage fcontext -l | grep ssh_home_t
    # semanage fcontext -a -t ssh_home_t "${login_user_home}/.ssh/"
    # restorecon -v "${login_user_home}/.ssh/"

    # semanage boolean -l | grep ssh
    # getsebool ssh_keysign
    # setsebool ssh_keysign on      #temporarily modify until reboot
    # setsebool -P ssh_keysign on   # persist modify

    # semanage port -l | grep ssh
    # semanage port -a -t ssh_port_t -p tcp 22

    if [[ -n "${l_item}" && -n "${l_val}" ]]; then
        case "${l_type,,}" in
            fcontext|f )
                if funcCommandExistCheck 'semanage'; then
                    case "${l_action,,}" in
                        add|a ) l_action='--add' ;;
                        delete|d) l_action='--delete' ;;
                        modify|m) l_action='--modify' ;;
                    esac
                    l_val="${l_val%/}"
                    semanage fcontext ${l_action} -t "${l_item}" "${l_val}(/.*)?" 2> /dev/null
                    funcCommandExistCheck 'restorecon' &&  restorecon -F -R "${l_val}" 2> /dev/null
                fi
                ;;
            boolean|b )
                if funcCommandExistCheck 'setsebool'; then
                    [[ "${l_val}" != 'on' ]] && l_val='off'
                    setsebool "${l_item}" "${l_val}" 2> /dev/null
                    setsebool -P "${l_item}" "${l_val}" 2> /dev/null
                fi
                ;;
            port|p )
                if funcCommandExistCheck 'semanage'; then
                    case "${l_action,,}" in
                        add|a ) l_action='--add' ;;
                        delete|d) l_action='--delete' ;;
                        modify|m) l_action='--modify' ;;
                    esac

                    case "${l_protocol,,}" in
                        tcp ) l_protocol='tcp' ;;
                        udp ) l_protocol='udp' ;;
                    esac
                    semanage port "${l_action}" -t "${l_item}" -p "${l_protocol}" "${l_val}" 2> /dev/null
                fi
                ;;
        esac
    fi
}

# - DB Relevant Custom Function
funcCodenameForDatabase(){
    local databaseType="${1:-}"
    local distroName="${2:-}"
    local versionId="${3:-}"
    [[ -z "${versionId}" ]] || versionId="${versionId%%.*}"

    if [[ -n "${databaseType}" ]]; then
        case "${databaseType,,}" in
            mysql )
                case "${distroName,,}" in
                    rhel|centos ) codename="el${versionId}" ;;
                    fedora ) codename="fc${versionId}" ;;
                    sles ) codename="sles${versionId}" ;;
                esac
                ;;
            mariadb )
                case "${distroName,,}" in
                    rhel|centos|fedora|opensuse ) codename="${distroName,,}${versionId}" ;;
                esac
                ;;
            percona|percona-server )
                case "${distroName,,}" in
                    rhel|centos ) codename="rhel${versionId}" ;;
                esac
                ;;
        esac
    fi

    # MySQL  rhel/centos  --> el7, el6, el5
    # MySQL  fedora       --> fc26, fc25, fc24
    # MySQL  sles         --> sles12, sles11
    # MariaDB  rhel       --> rhel7, rhel6, rhel5
    # MariaDB  centos     --> centos7,centos6
    # MariaDB  fedora     --> fedora26, fedora25
    # MariaDB  opensuse   --> opensuse42
    # Percona rhel/centos  --> rhel7, rhel6, rhel5
}

funcDBServiceStatusOperation(){
    # service name: mariadb/mysql/mysqld
    local l_service_name="${1:-}"
    local l_action="${2:-}"

    if [[ -n "${l_service_name}" ]]; then
        case "${l_action}" in
            start|stop|reload|restart|status ) l_action="${l_action}" ;;
            * ) l_action='status' ;;
        esac

        # mariadb 5.5 just use  service mysql {status,start,stop}
        if [[ "${db_name}" == 'MariaDB' && "${db_version%%.*}" -lt 10 ]]; then
            service "${l_service_name}" "${l_action}" &> /dev/null
        else
            funcSystemServiceManager "${l_service_name}" "${l_action}"
        fi
    fi
}

funcStrongRandomPasswordGeneration(){
    # https://dev.mysql.com/doc/refman/5.6/en/validate-password-plugin.html
    # https://www.howtogeek.com/howto/30184/10-ways-to-generate-a-random-password-from-the-command-line/
    # https://serverfault.com/questions/261086/creating-random-password
    # https://unix.stackexchange.com/questions/462/how-to-create-strong-passwords-in-linux
    local str_length=${str_length:-32}
    local new_password=${new_password:-}

    if [[ -z "${root_password_new}" || "${#root_password_new}" -lt 16 ]]; then
        # openssl rand -base64 32
        new_password=$(tr -dc 'a-zA-Z0-9!@#()&$%{}<>^_+' < /dev/urandom | fold -w "${str_length}" | head -c "${str_length}" | xargs)

        if [[ "${new_password}" =~ ^[1-9a-zA-Z] && "${new_password}" =~ [1-9a-zA-Z]$ ]]; then
            root_password_new="${new_password}"
        else
            funcStrongRandomPasswordGeneration
        fi
    fi
}

funcConfDirectiveConfiguration(){
    local l_conf_path="${1:-}"
    local l_para="${2:-}"
    local l_para_val="${3:-}"

    if [[ -f "${l_conf_path}" && -n "${l_para}" && -n "${l_para_val}" ]]; then
        case "${l_para_val}" in
            d|delete )
                sed -r -i '/\[mysqld\]/,${/^#?[[:space:]]*'"${l_para}"'[[:space:]]*=/d}' "${l_conf_path}"
                ;;
            * )
                sed -r -i '/\[mysqld\]/,${/^#?[[:space:]]*'"${l_para}"'[[:space:]]*=/{s@^#?[[:space:]]*([^=]+=[[:space:]]*)([^[:space:]]+)(.*)$@\1'"${l_para_val}"'\3@g;}}' "${l_conf_path}"
                ;;
        esac
    fi

    # if [[ -f "${l_conf_path}" && -n "${l_para}" && -n "${l_para_val}" ]]; then
    #     sed -r -i '/\[mysqld\]/,${/^#?[[:space:]]*'"${l_para}"'[[:space:]]*=/{s@^#?[[:space:]]*([^=]+=[[:space:]]*)([^[:space:]]+)(.*)$@\1'"${l_para_val}"'\3@g;}}' "${l_conf_path}"
    # fi
}

funcInstallationProcedureStatement(){
    local l_item="${1:-}"

    if [[ -n "${l_item}" ]]; then
        case "${l_item,,}" in
            repo ) l_item='official repository' ;;
            pack ) l_item='package installation' ;;
            gpg ) l_item='GnuPG key installation'
        esac
        funcOperationProcedureStatement "${l_item}"
        # printf "procedure - ${c_blue}%s${c_normal} is finished;\n" "${l_item}"
    fi
    # funcOperationProcedureResultStatement
}


#########  1-2 getopts Operation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...

Installing MySQL/MariaDB/Percona On GNU/Linux Via Official Repository!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -a    --auto installation, default choose MySQL variants latest version (Percona > MariaDB > MySQL)
    -t variant_type    --set MySQL variant (MySQL|MariaDB|Percona)
    -v variant_version --set MySQL variant version (eg: 5.6|5.7|8.0|10.1|10.2), along with -t
    -d data_dir    --set data dir, default is /var/lib/mysql
    -s port    --set MySQL port number, default is 3306
    -p root_passwd    --set root password for 'root'@'localhost', default is empty or temporary password in /var/log/mysqld.log or /var/log/mysql/mysqld.log
    -S    --enable slave mode, default is master mode
    -f    --enable firewall rule (iptable/firewalld/ufw/SuSEfirewall2), default is disable
    -P [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
${c_normal}
EOF
exit
}

while getopts "ap:d:s:t:v:SfP:h" option "$@"; do
    case "$option" in
        a ) auto_installation=1;;
        p ) root_password_new="$OPTARG" ;;
        d ) data_dir="$OPTARG" ;;
        s ) mysql_port="$OPTARG" ;;
        t ) mysql_variant_type="$OPTARG" ;;
        v ) variant_version="$OPTARG" ;;
        S ) slave_mode=1 ;;
        f ) enable_firewall=1 ;;
        P ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo ;;
    esac
done


################ 2-1. Choose Database & Version ################
funcExistedDetection(){
    funcOperationPhaseStatement 'Check If Existed'

    funcOperationProcedureStatement 'Detection'
    if funcCommandExistCheck 'mysqls'; then
        funcOperationProcedureResultStatement "$(mysql --version)"
        funcExitStatement "${c_redb}Attention: ${c_normal}${c_yellow}MySQL or MySQL Variants have been existed in your system. To use this script, you should remove existed version manually!${c_normal}"
    else
        funcOperationProcedureResultStatement 'not find'
    fi
}

# verify port num or data dir is legal or not
funcPortAndDatadirVerification(){
    funcOperationPhaseStatement 'Port & Data dir Verification'

    # 1- verify if the port specified is available
    funcOperationProcedureStatement 'Port No. verification'
    mysql_port=$(echo "${mysql_port}" | sed -r 's@[[:alpha:]]*@@g;s@[[:punct:]]*@@g;s@[[:blank:]]*@@g')
    if [[ -n "${mysql_port}" ]]; then
        if [[ "${mysql_port}" -eq "${mysql_port_default}" ]]; then
            funcOperationProcedureResultStatement "${mysql_port}"
        elif [[ "${mysql_port}" =~ ^[1-9]{1}[0-9]{1,4}$ ]]; then
            local sys_port_start=${sys_port_start:-1024}
            local sys_port_end=${sys_port_end:-65535}

            if [[ "${mysql_port}" -ge "${sys_port_start}" && "${mysql_port}" -le "${sys_port_end}" ]]; then
                local port_service_info
                port_service_info=$(awk 'match($2,/^'"${mysql_port}"'\/tcp$/){print $1,$2}' /etc/services)
                if [[ -n "${port_service_info}" ]]; then
                    funcOperationProcedureResultStatement "${port_service_info} in /etc/services" 1
                else
                    funcOperationProcedureResultStatement "${mysql_port}"
                fi    # end if port_service_info
            else
                funcOperationProcedureResultStatement "${mysql_port}⊄(${sys_port_start},${sys_port_end}) out of range" 1
            fi

        else
            funcOperationProcedureResultStatement "${mysql_port} illegal" 1
        fi

    fi

    # 2- verify data dir
    funcOperationProcedureStatement 'Data dir verification'
    if [[ -n "${data_dir}" ]]; then
        data_dir="${data_dir%/}"
        if [[ "${data_dir}" == "${data_dir_default}" || "${data_dir}" =~ ^/ ]]; then
            funcOperationProcedureResultStatement "${data_dir}"
        else
            funcOperationProcedureResultStatement "${data_dir}" 1
            funcExitStatement "${c_redb}Attention: ${c_normal}data dir path must be begin with slash ${c_yellow}/${c_normal} or ${c_yellow}~/${c_normal}."
        fi
    fi
}

# - variant and version (V2) choose has 3 method
# extract mysql variants lists or variant version lists, invoked by funcV2*
funcV2InfoExtraction(){
    local local_variants_version_list="${1:-}"
    local local_distro_name="${2:-}"
    local local_db_name="${3:-}"
    local local_codename="${4:-}"
    local local_output=${local_output:-}

    if [[ -n "${local_distro_name}" && -n "${local_db_name}" && -n "${local_codename}" ]]; then
        # variant version
        local_output=$(awk -F\| 'match($4,/'"${local_distro_name}"'/)&&match($1,/'"${local_db_name}"'/)&&match($2,/^'"${local_codename}"'$/){print $3}' "${local_variants_version_list}")

    elif [[ -n "${local_distro_name}" ]]; then
        # mysql variants
        local_output=$(awk -F\| 'match($4,/'"${local_distro_name}"'/){a[$1]=$0}END{PROCINFO["sorted_in"]="@ind_str_asc"; for (i in a) print i}' "${local_variants_version_list}" | sed ':a;N;$!ba;s@ @-@g;s@\n@ @g')
    fi

    echo "${local_output}"
}

# - 1. via choose list - default operation
funcV2SelectionListOperation(){
    # 1 - database choose
    echo "${c_yellow}Available MySQL Variants List:${c_normal}"
    PS3="Choose variant number: "

    # funcV2InfoExtraction "${v2_info_list}" "${distro_name}"
    select item in $(funcV2InfoExtraction "${v2_info_list}" "${distro_name}"); do
        db_name="${item}"
        [[ -n "${db_name}" ]] && break
    done < /dev/tty

    # 2 - specific version choose
    echo -e "\n${c_yellow}Please Select Specific${c_normal} ${c_red}${db_name}${c_normal}${c_yellow} Version: ${c_normal}"
    PS3="Choose version number: "

    # generate specific codename for rhel/centos/fedora/sles/opensuse
    # echo "db name is ${db_name}, distro name is ${distro_name}, version id is ${version_id}"
    funcCodenameForDatabase "${db_name}" "${distro_name}" "${version_id}"

    select item in $(funcV2InfoExtraction "${v2_info_list}" "${distro_name}" "${db_name}" "${codename}"); do
        db_version="${item,,}"
        [[ -n "${db_version}" ]] && break
    done < /dev/tty

    unset PS3
}

# - 2. auto_installation
funcV2AutomaticSelection(){
    # generate specific codename for rhel/centos/fedora/sles/opensuse
    funcCodenameForDatabase "${db_name}" "${distro_name}" "${version_id}"

    # sequence: Percona, MariaDB, MySQL
    db_name='Percona'
    local db_version_list=${db_version_list:-}
    db_version_list=$(funcV2InfoExtraction "${v2_info_list}" "${distro_name}" "${db_name}" "${codename}")
    db_version=$(echo "${db_version_list}" | awk '{print $1}')

    if [[ -z "${db_version}" ]]; then
        db_name='MariaDB'
        db_version_list=$(funcV2InfoExtraction "${v2_info_list}" "${distro_name}" "${db_name}" "${codename}")
        db_version=$(echo "${db_version_list}" | awk '{print $1}')

        if [[ -z "${db_version}" ]]; then
            db_name='MySQL'
            db_version_list=$(funcV2InfoExtraction "${v2_info_list}" "${distro_name}" "${db_name}" "${codename}")
            db_version=$(echo "${db_version_list}" | awk '{print $1}')

            if [[ -z "${db_version}" ]]; then
                funcExitStatement "${c_red}Sorry${c_normal}: no appropriate MySQL variant & version finds!"
            fi    # end MySQL

        fi    # end MariaDB

    fi    # end Percona

}

# - 3. manually setting
funcV2ManuallySpecify(){
    case "${mysql_variant_type}" in
        MySQL|mysql|my ) db_name='MySQL' ;;
        MariaDB|mariadb|ma ) db_name='MariaDB' ;;
        Percona|percona|pe|p ) db_name='Percona' ;;
        * ) funcExitStatement "${c_redb}Sorry${c_normal}: please specify correct ${c_yellow}MySQL/MariaDB/Percona${c_normal} via ${c_yellow}-t${c_normal}!"
    esac

    # generate specific codename for rhel/centos/fedora/sles/opensuse
    funcCodenameForDatabase "${db_name}" "${distro_name}" "${version_id}"

    local db_version_list=${db_version_list:-}
    db_version_list=$(funcV2InfoExtraction "${v2_info_list}" "${distro_name}" "${db_name}" "${codename}")

    db_version="${variant_version}"
    if [[ -z "${db_version_list}" ]]; then
        funcExitStatement "${c_redb}Sorry${c_normal}: no specific ${c_yellow}${db_name}${c_normal} version finds!"
    elif [[ -z $(echo "${db_version_list}" | sed 's@ @\n@g' | sed -n '/^'"${db_version}"'$/p') ]]; then
        [[ -z "${db_version}" ]] && db_version='NULL'
        funcExitStatement "${c_redb}Sorry${c_normal}: version you specified is ${c_yellow}${db_version}${c_normal}, please specify correct version: ${c_yellow}${db_version_list// /\/}${c_normal} via ${c_yellow}-v${c_normal}!"
    fi
}

# all in one (default/auto installation/manually setting)
funcV2SelectionListGeneration(){
    funcOperationPhaseStatement 'MySQL Variants Selection'

    v2_info_list=$(mktemp -t "${mktemp_format}")
    # $download_tool "${mysql_veriants_version_list}" > "${v2_info_list}"
    # exclude Cluser,  substitude '-' for ' ' in db_name
    $download_tool "${mysql_veriants_version_list}" | awk -F\| 'BEGIN{OFS="|"}{gsub(" ","-",$1); if($1!~/Cluster/) {print}}' > "${v2_info_list}"

    [[ -s "${v2_info_list}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to get MySQL variants version relation table!"

    if [[ "${auto_installation}" -eq 1 ]]; then
        funcV2AutomaticSelection
    elif [[ -n "${mysql_variant_type}" ]]; then
        funcV2ManuallySpecify
    else
        funcV2SelectionListOperation
    fi

    funcOperationProcedureStatement 'Database choose'
    funcOperationProcedureResultStatement "${db_name} ${db_version}"

    # Percona-Server ==> Percona
    db_name="${db_name%%-*}"

    [[ -f "${v2_info_list}" ]] && rm -f "${v2_info_list}"

    # - MySQL/Percona 5.6 need memory space > 512MB
    case "${db_name}" in
        MySQL|Percona )
            # 524288  512 * 1204   KB
            if [[ "${db_version}" == '5.6' && $(awk 'match($1,/^MemTotal/){print $2}' /proc/meminfo) -le 524288 ]]; then
                funcOperationProcedureStatement 'Memory space check'
                funcOperationProcedureResultStatement "< 512M" 1
                funcExitStatement "${c_redb}Attention${c_normal}: ${c_yellow}${db_name} ${db_version}${c_normal} needs more memory space while installing or service starting."
            fi
            ;;
    esac

    if [[ "${pack_manager}" == 'apt-get' ]]; then
        funcCommandExistCheck 'systemctl' || funcPackageManagerOperation 'install' "sysv-rc-conf" # same to chkconfig
    fi

    # install bc use to calculate and arithmatic comparasion
    funcCommandExistCheck 'bc' || funcPackageManagerOperation 'install' "bc"
}


################ 2-2. MariaDB/MySQL/Percona Installation ################
funcMariaDBOperation(){
    # https://mariadb.com/kb/en/the-mariadb-library/yum/
    # https://downloads.mariadb.org/mariadb/repositories
    # https://mariadb.com/kb/en/the-mariadb-library/installing-mariadb-deb-files/

    case "${distro_name}" in
        rhel|centos|fedora|opensuse )
            local system_arch=${system_arch:-'amd64'}
            case "$(uname -m)" in
                x86_64 ) system_arch='amd64' ;;
                x86|i386 ) system_arch='x86' ;;
            esac
            ;;
    esac    # end case distro_name

    # remove MairDB 5.5
    # funcPackageManagerOperation 'remove' "mariadb-server mariadb-libs"   #5.5
    funcPackageOperationProcedureStatement 'remove' 'mariadb-server mariadb-libs'

    case "${distro_name}" in
        rhel|centos|fedora )
            funcInstallationProcedureStatement 'repo'
            local repo_path=${repo_path:-'/etc/yum.repos.d/MariaDB.repo'}

            echo -e "# ${db_name} ${db_version} ${distro_name} repository list\n# http://downloads.mariadb.org/mariadb/repositories/\n[${db_name,,}]\nname = ${db_name}\nbaseurl = http://yum.mariadb.org/${db_version}/${codename}-${system_arch}\ngpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB\ngpgcheck=1" > "${repo_path}"

            # Manually Importing the MariaDB Signing Key
            # rpm --import https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
            funcOperationProcedureResultStatement "${repo_path}"

            funcInstallationProcedureStatement 'pack'
            # dnf install MariaDB-server  /  yum install MariaDB-server MariaDB-client
            local pack_name_list=${pack_name_list:-'MariaDB-server MariaDB-client'}
            [[ "${distro_name}" == 'fedora' && "${pack_manager}" == 'dnf' ]] && pack_name_list='MariaDB-server'

            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            funcOperationProcedureResultStatement "${pack_name_list}"

            service_name='mysql'
            # mariadb 5.5 just use   service mysql {status,start,stop}
            # if [[ "${db_version%%.*}" -lt 10 ]]; then
            #     service "${service_name}" start &> /dev/null
            #     service "${service_name}" restart &> /dev/null
            # else
            #     # service name: mariadb/mysql/mysqld
            #     funcSystemServiceManager "${service_name}" 'start'
            #     funcSystemServiceManager "${service_name}" 'restart'
            # fi
            ;;
        opensuse )
            funcInstallationProcedureStatement 'repo'
            local repo_path=${repo_path:-'/etc/zypp/repos.d/mariadb.repo'}

            echo -e "# ${db_name} ${db_version} ${distro_name} repository list\n# http://downloads.mariadb.org/mariadb/repositories/\n[${db_name,,}]\nname = ${db_name}\nbaseurl = http://yum.mariadb.org/${db_version}/${codename}-${system_arch}\ngpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB\ngpgcheck=1" > "${repo_path}"
            funcOperationProcedureResultStatement "${repo_path}"

            funcInstallationProcedureStatement 'gpg'
            # Manually Importing the MariaDB Signing Key  CBCB082A1BB943DB
            rpm --import https://yum.mariadb.org/RPM-GPG-KEY-MariaDB &> /dev/null
            funcOperationProcedureResultStatement 'RPM-GPG-KEY-MariaDB'

            funcInstallationProcedureStatement 'pack'
            # zypper install MariaDB-server MariaDB-client
            # - OpenSUSE Self Repo: mariadb-server, mariadb-client
            # - MariaDB Official Repo: MariaDB-server MariaDB-client
            local pack_name_list=${pack_name_list:-'MariaDB-server MariaDB-client'}
            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            funcOperationProcedureResultStatement "${pack_name_list}"

            # service name: mariadb/mysql/mysqld
            service_name='mysql'
            ;;
        debian|ubuntu )
            funcInstallationProcedureStatement 'repo'
            local repo_path=${repo_path:-'/etc/apt/sources.list.d/mariadb.list'}
            local repo_mirror_url=${repo_mirror_url:-'http://nyc2.mirrors.digitalocean.com'}

            # Repo mirror site url
            local ip_info=${ip_info:-}
            ip_info=$($download_tool_origin ipinfo.io)
            if [[ -n "${ip_info}" ]]; then
                local host_ip=${host_ip:-}
                local host_country=${host_ip:-}
                local host_city=${host_ip:-}
                local host_org=${host_ip:-}
                host_ip=$(echo "$ip_info" | sed -r -n '/\"ip\"/{s@[[:space:],]*@@g;s@[^:]*:"([^"]*)"@\1@g;p}')
                host_country=$(echo "$ip_info" | sed -r -n '/\"country\"/{s@[[:space:],]*@@g;s@[^:]*:"([^"]*)"@\1@g;p}')
                host_city=$(echo "$ip_info" | sed -r -n '/\"city\"/{s@[[:space:],]*@@g;s@[^:]*:"([^"]*)"@\1@g;p}')
                host_org=$(echo "$ip_info" | sed -r -n '/\"org\"/{s@[[:space:],]*@@g;s@[^:]*:"([^"]*)"@\1@g;p}')

                case "${host_country}" in
                    CN )
                        [[ "${host_city}" == 'Beijing' ]] && repo_mirror_url='http://mirrors.tuna.tsinghua.edu.cn' || repo_mirror_url='http://mirrors.neusoft.edu.cn'
                        ;;
                    * )
                        # Just for Digital Ocean VPS
                        if [[ -n "${host_org}" && "${host_org}" =~ DigitalOcean ]]; then
                            local mirror_region=${mirror_region:-'nyc2'}
                            case "${host_city}" in
                                Singapore ) mirror_region='sgp1' ;;
                                Amsterdam ) mirror_region='ams2' ;;
                                'New York'|NewYork ) mirror_region='nyc2' ;;
                                'San Francisco'|SanFrancisco ) mirror_region='sfo1' ;;
                            esac
                            repo_mirror_url="http://${mirror_region}.mirrors.digitalocean.com"
                        fi
                        ;;
                esac

            fi

            # {
            #   "ip": "128.199.72.46",
            #   "city": "Singapore",
            #   "region": "Central Singapore Community Development Council",
            #   "country": "SG",
            #   "loc": "1.2855,103.8565",
            #   "org": "AS14061 DigitalOcean, LLC"
            # }

            # - GnuPG key importing
            local gpg_keyid=${gpg_keyid:-'0xF1656F24C74CD1D8'}
            case "${codename}" in
                precise|trusty|wheezy|jessie ) gpg_keyid='0xcbcb082a1bb943db' ;;
            esac

            # Debian  sid       0xF1656F24C74CD1D8 arch=amd64,i386
            #         stretch   0xF1656F24C74CD1D8 arch=amd64,i386,ppc64el
            #         jessie    0xcbcb082a1bb943db arch=amd64,i386
            #         wheezy    0xcbcb082a1bb943db arch=amd64,i386
            # Ubuntu  zesty     0xF1656F24C74CD1D8 arch=amd64,i386
            #         yakkety   0xF1656F24C74CD1D8 arch=amd64,i386
            #         xenial    0xF1656F24C74CD1D8 arch=amd64,i386
            #         trusty    0xcbcb082a1bb943db arch=amd64,i386,ppc64el
            #         precise   0xcbcb082a1bb943db arch=amd64,i386

            local arch_list=${arch_list:-'amd64,i386'}
            case "${codename,,}" in
                stretch|trusty ) arch_list="${arch_list},ppc64el" ;;
            esac

            echo -e "# ${db_name} ${db_version} repository list\n# http://downloads.mariadb.org/mariadb/repositories/\ndeb [arch=${arch_list}] ${repo_mirror_url}/${db_name,,}/repo/${db_version}/${distro_name} ${codename} main\ndeb-src ${repo_mirror_url}/${db_name,,}/repo/${db_version}/${distro_name} ${codename} main" > "${repo_path}"
            funcOperationProcedureResultStatement "${repo_path}"

            funcInstallationProcedureStatement 'gpg'
            funcPackageManagerOperation 'install' "software-properties-common"
            # debian >=9 need dirmngr, used for GnuPG
            # [[ "${distro_name}" == 'debian' && "${version_id%%.*}" -ge 9 ]]
            funcCommandExistCheck 'dirmngr' || funcPackageManagerOperation 'install' 'dirmngr'

            apt-key adv --recv-keys --keyserver keyserver.ubuntu.com "${gpg_keyid}" &> /dev/null
            # apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db/0xF1656F24C74CD1D8
            funcOperationProcedureResultStatement "${gpg_keyid}"

            # https://stackoverflow.com/questions/23358918/preconfigure-an-empty-password-for-mysql-via-debconf-set-selections
            # https://askubuntu.com/questions/79257/how-do-i-install-mysql-without-a-password-prompt
            export DEBIAN_FRONTEND=noninteractive

            # funcCommandExistCheck 'debconf-set-selections' || funcPackageManagerOperation 'install' 'debconf-utils'

            # setting root password during installation via command debconf-set-selections
            # debconf-set-selections <<< 'mariadb-server-'"${db_version}"' mysql-server/root_password password '"${mysql_pass}"''
            # debconf-set-selections <<< 'mariadb-server-'"${db_version}"' mysql-server/root_password_again password '"${mysql_pass}"''

            funcInstallationProcedureStatement 'pack'
            local pack_name_list=${pack_name_list:-'mariadb-server'}
            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            funcOperationProcedureResultStatement "${pack_name_list}"

            service_name='mariadb'
            unset DEBIAN_FRONTEND
            ;;
    esac    # end case distro_name

}

funcMySQLOperation(){
    # https://dev.mysql.com/downloads/repo/yum/
    # https://dev.mysql.com/downloads/repo/suse/
    # https://dev.mysql.com/downloads/repo/apt/

    # https://dev.mysql.com/doc/refman/5.7/en/using-systemd.html
    # /etc/my.cnf or /etc/mysql/my.cnf (RPM platforms)
    # /etc/mysql/mysql.conf.d/mysqld.cnf (Debian platforms)

    case "${distro_name}" in
        rhel|centos|fedora|sles )
            # for centos, error info may be saved in /var/log/messages
            funcInstallationProcedureStatement 'gpg'
            # - GnuPG importing
            local repo_path=${repo_path:-'/etc/yum.repos.d/mysql-community.repo'}
            # https://dev.mysql.com/doc/refman/5.7/en/checking-gpg-signature.html
            local gpg_path=${gpg_path:-'/etc/pki/rpm-gpg/RPM-GPG-KEY-mysql'}

            if [[ "${distro_name}" == 'sles' ]]; then
                repo_path='/etc/zypp/repos.d/mysql-community.repo'
                gpg_path='/etc/RPM-GPG-KEY-mysql'
            fi

            if [[ ! -f "${gpg_path}" ]]; then
                # - method 1
                $download_tool 'https://repo.mysql.com/RPM-GPG-KEY-mysql' > "${gpg_path}"
                # - method 2
                [[ -s "${gpg_path}" ]] || $download_tool 'https://dev.mysql.com/doc/refman/5.7/en/checking-gpg-signature.html' | sed -r -n '/BEGIN PGP/,/END PGP/{s@[[:space:]]*<[^>]*>[[:space:]]*@@g;p}' > "${gpg_path}"
                # - method 3
                [[ -s "${gpg_path}" ]] || rpm --import 'http://dev.mysql.com/doc/refman/5.7/en/checking-gpg-signature.html'

                # - method 4
                # gpg --import mysql_pubkey.asc
                #
                # gpg --keyserver pgp.mit.edu --recv-keys 5072E1F5
                # gpg -a --export 5072E1F5 --output mysql_pubkey.asc
                # rpm --import mysql_pubkey.asc       #  import the key into your RPM configuration to validate RPM install packages
            else
                rpm --import "${gpg_path}" &> /dev/null
            fi
            funcOperationProcedureResultStatement "${gpg_path}"

            # - Repo generation
            funcInstallationProcedureStatement 'repo'
            version_id=${version_id%%.*}
            local releasever_basearch=${releasever_basearch:-}

            case "${distro_name}" in
                rhel|centos ) releasever_basearch="el/${version_id}" ;;
                fedora ) releasever_basearch="fc/\$releasever" ;;
                sles ) releasever_basearch="sles/${version_id}" ;;
            esac

            local extra_paras=${extra_paras:-}
            [[ "${distro_name}" == 'sles' ]] && extra_paras="autorefresh=0\ntype=rpm-md\n"

            echo -e "[mysql-connectors-community]\nname=MySQL Connectors Community\nbaseurl=http://repo.mysql.com/yum/mysql-connectors-community/${releasever_basearch}/\$basearch/\nenabled=1\n${extra_paras}gpgcheck=1\ngpgkey=file://${gpg_path}\n" > "${repo_path}"

            echo -e "[mysql-tools-community]\nname=MySQL Tools Community\nbaseurl=http://repo.mysql.com/yum/mysql-tools-community/${releasever_basearch}/\$basearch/\nenabled=1\n${extra_paras}gpgcheck=1\ngpgkey=file://${gpg_path}\n" >> "${repo_path}"

            # MySQL Community Version
            echo -e "[mysql${db_version//.}-community]\nname=MySQL ${db_version} Community Server\nbaseurl=http://repo.mysql.com/yum/mysql-${db_version}-community/${releasever_basearch}/\$basearch/\nenabled=1\n${extra_paras}gpgcheck=1\ngpgkey=file://${gpg_path}\n"  >> "${repo_path}"
            funcOperationProcedureResultStatement "${repo_path}"

            funcInstallationProcedureStatement 'pack'
            local pack_name_list=${pack_name_list:-'mysql-community-server'}
            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            funcOperationProcedureResultStatement "${pack_name_list}"

            service_name='mysqld'
            [[ "${distro_name}" == 'sles' ]] && service_name='mysql'
            ;;
        debian|ubuntu )
            # Method 1 - install gpg & sources file via official package, appear prompt, not recommend
            # local mysql_official_site=${mysql_official_site:-'https://dev.mysql.com'}
            # local apt_config_url=${apt_config_url:-}
            # apt_config_url=$($download_tool_origin $($download_tool_origin "${mysql_official_site}/downloads/repo/apt/" | sed -r -n '/button03/{s@.*href="([^"]*)".*@'"${mysql_official_site}"'\1@g;p}') | sed -r -n '/No thanks/{s@.*href="(.*)".*@'"${mysql_official_site}"'\1@g;p}')
            #
            # # curl -fsL $(curl -fsL https://dev.mysql.com/downloads/repo/apt/ | sed -r -n '/button03/{s@.*href="([^"]*)".*@https://dev.mysql.com\1@g;p}') | sed -r -n '/No thanks/{s@.*href="(.*)".*@https://dev.mysql.com\1@g;p}'
            # # https://dev.mysql.com/get/mysql-apt-config_0.8.7-1_all.deb
            #
            # if [[ -n "${apt_config_url}" ]]; then
            #     local apt_config_pack_name=${apt_config_pack_name:-}
            #     apt_config_pack_name=${apt_config_url##*/}
            #     local apt_config_pack_save_path=${apt_config_pack_save_path:-"/tmp/${apt_config_pack_name}"}
            #     $download_tool_origin "${apt_config_url}" > "${apt_config_pack_save_path}"
            #
            #     [[ -s "${apt_config_pack_save_path}" ]] && dpkg -i "${apt_config_pack_save_path}"
            # fi

            funcInstallationProcedureStatement 'repo'
            # Method 1 - Manually operation
            local repo_path=${repo_path:-'/etc/apt/sources.list.d/mysql.list'}

            # deb http://repo.mysql.com/apt/{debian|ubuntu}/ {jessie|wheezy|trusty|utopic|vivid} {mysql-5.6|mysql-5.7|workbench-6.2|utilities-1.4|connector-python-2.0}

            echo -e "deb http://repo.mysql.com/apt/${distro_name}/ ${codename} mysql-tools\ndeb http://repo.mysql.com/apt/${distro_name}/ ${codename} mysql-${db_version}\ndeb-src http://repo.mysql.com/apt/${distro_name}/ ${codename} mysql-${db_version}" > "${repo_path}"
            funcOperationProcedureResultStatement "${repo_path}"

            # Use command 'dpkg-reconfigure mysql-apt-config' as root for modifications.
            # deb http://repo.mysql.com/apt/debian/ stretch mysql-apt-config

            # - GnuPG importing
            funcInstallationProcedureStatement 'gpg'
            # apt-key adv --keyserver pgp.mit.edu --recv-keys 5072E1F5
            # apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 5072E1F5

            local gpg_path=${gpg_path:-}
            gpg_path=$(mktemp -t Temp_XXXXXX.txt)       # mysql_gpg.asc
            # - method 1
            $download_tool 'https://repo.mysql.com/RPM-GPG-KEY-mysql' > "${gpg_path}"
            # - method 2
            [[ -s "${gpg_path}" ]] || $download_tool 'https://dev.mysql.com/doc/refman/5.7/en/checking-gpg-signature.html' | sed -r -n '/BEGIN PGP/,/END PGP/{s@[[:space:]]*<[^>]*>[[:space:]]*@@g;p}' > "${gpg_path}"

            apt-key add "${gpg_path}" &> /dev/null
            # apt-key list |& grep 'MySQL Release Engineering'
            [[ -f "${gpg_path}" ]] && rm -f "${gpg_path}"
            funcOperationProcedureResultStatement 'RPM-GPG-KEY-mysql'

            export DEBIAN_FRONTEND=noninteractive

            # funcCommandExistCheck 'debconf-set-selections' || funcPackageManagerOperation 'install' 'debconf-utils'
            # debconf-set-selections <<< 'mysql-server mysql-server/root_password password '"${mysql_pass}"''
            # debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password '"${mysql_pass}"''

            funcInstallationProcedureStatement 'pack'
            local pack_name_list=${pack_name_list:-'mysql-server'}
            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            # https://dev.mysql.com/doc/mysql-apt-repo-quick-guide/en/#updating-apt-repo-client-lib
            # Special Notes on Upgrading the Shared Client Libraries
            funcPackageManagerOperation 'install' "libmysqlclient20"
            funcOperationProcedureResultStatement "${pack_name_list}"

            service_name='mysql'
            unset DEBIAN_FRONTEND
            ;;
    esac    # end case distro_name

}

funcPerconaOperation(){
    # https://www.percona.com/doc/percona-server/LATEST/installation/yum_repo.html
    # https://www.percona.com/doc/percona-server/LATEST/installation/apt_repo.html
    # https://www.percona.com/blog/2016/10/13/new-signing-key-for-percona-debian-and-ubuntu-packages/

    case "${distro_name}" in
        rhel|centos )
            funcInstallationProcedureStatement 'gpg'
            local repo_path=${repo_path:-'/etc/yum.repos.d/percona-release.repo'}
            # https://dev.mysql.com/doc/refman/5.7/en/checking-gpg-signature.html
            local gpg_path=${gpg_path:-'/etc/pki/rpm-gpg/RPM-GPG-KEY-Percona'}

            # - GnuPG importing
            [[ -s "${gpg_path}" ]] || $download_tool 'https://www.percona.com/downloads/RPM-GPG-KEY-percona' > "${gpg_path}"
            funcOperationProcedureResultStatement 'RPM-GPG-KEY-Percona'

            # - repo generation
            funcInstallationProcedureStatement 'repo'
            echo -e "[percona-release-\$basearch]\nname = Percona-Release YUM repository - \$basearch\nbaseurl = http://repo.percona.com/release/\$releasever/RPMS/\$basearch\nenabled = 1\ngpgcheck = 1\ngpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Percona\n" > "${repo_path}"

            echo -e "[percona-release-noarch]\nname = Percona-Release YUM repository - noarch\nbaseurl = http://repo.percona.com/release/\$releasever/RPMS/noarch\nenabled = 1\ngpgcheck = 1\ngpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Percona" >> "${repo_path}"

            # [percona-release-$basearch]
            # name = Percona-Release YUM repository - $basearch
            # baseurl = http://repo.percona.com/release/$releasever/RPMS/$basearch
            # enabled = 1
            # gpgcheck = 1
            # gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Percona
            #
            # [percona-release-noarch]
            # name = Percona-Release YUM repository - noarch
            # baseurl = http://repo.percona.com/release/$releasever/RPMS/noarch
            # enabled = 1
            # gpgcheck = 1
            # gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Percona
            funcOperationProcedureResultStatement "${repo_path}"

            # yum install Percona-Server-server-{57,56,55}
            funcInstallationProcedureStatement 'pack'
            local pack_name_list=${pack_name_list:-"Percona-Server-server-${db_version//.}"}
            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            funcOperationProcedureResultStatement "${pack_name_list}"

            service_name='mysqld'
            ;;
        debian|ubuntu )
            funcInstallationProcedureStatement 'repo'
            # Method 1 - Via official .deb package
            # # https://repo.percona.com/apt/percona-release_0.1-4.stretch.deb
            # local apt_repo_url=${apt_repo_url:-'https://repo.percona.com/apt/'}
            # local repo_pack_name=${repo_pack_name:-"percona-release_0.1-4.$(lsb_release -sc)_all.deb"}
            # repo_pack_name=$($download_tool "${apt_repo_url}" | awk 'match($0,/'"${codename}"'/){a=gensub(/.*href="([^"]*)".*/,"\\1","g",$0);}END{print a}')
            # local repo_pack_save_path=${repo_pack_save_path:-"/tmp/${repo_pack_name}"}
            #
            # $download_tool "${apt_repo_url}${repo_pack_name}" > "${repo_pack_save_path}"
            # dpkg -i "${repo_pack_save_path}"
            # [[ -f "${repo_pack_save_path}" ]] && rm -f "${repo_pack_save_path}"


            # Method 2 - Manually setting
            local repo_path=${repo_path:-'/etc/apt/sources.list.d/percona-release.list'}

            # deb http://repo.percona.com/apt stretch {main,testing,experimental}
            # deb-src http://repo.percona.com/apt stretch {main,testing,experimental}
            echo -e "# Percona releases, stable\ndeb http://repo.percona.com/apt ${codename} main\ndeb-src http://repo.percona.com/apt ${codename} main\n" > "${repo_path}"
            funcOperationProcedureResultStatement "${repo_path}"

            # - GnuPG importing
            funcInstallationProcedureStatement 'gpg'
            funcCommandExistCheck 'dirmngr' || funcPackageManagerOperation 'install' 'dirmngr'
            # https://www.percona.com/blog/2016/10/13/new-signing-key-for-percona-debian-and-ubuntu-packages/
            # old gpg key
            apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 8507EFA5 &> /dev/null
            # new gpg key
            apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 9334A25F8507EFA5 &> /dev/null
            funcOperationProcedureResultStatement '8507EFA5 / 9334A25F8507EFA5'

            export DEBIAN_FRONTEND=noninteractive

            funcInstallationProcedureStatement 'pack'
            local pack_name_list=${pack_name_list:-"percona-server-server-${db_version} percona-server-common-${db_version} libdbd-mysql-perl"}
            funcPackageManagerOperation     # just make cache
            funcPackageManagerOperation 'install' "${pack_name_list}"
            funcOperationProcedureResultStatement "percona-server-server"

            service_name='mysql'
            unset DEBIAN_FRONTEND
            ;;
    esac    # end case distro_name
}

funcDBInstallation(){
    funcOperationPhaseStatement 'Initialization Installation'
    func"${db_name}"Operation
    funcDBServiceStatusOperation "${service_name}" 'start'
    funcDBServiceStatusOperation "${service_name}" 'restart'
}

############# 2-3. MySQL Post-installation Configuration #############
funcRootPasswordConfiguration(){
    funcOperationProcedureStatement 'Root password'
    # https://dev.mysql.com/doc/refman/5.7/en/alter-user.html#alter-user-authentication
    # -- MySQL 5.7
    # sudo grep 'temporary password' /var/log/mysqld.log
    #                                /var/log/mysql/mysqld.log
    # mysql -uroot -p
    # ALTER USER 'root'@'localhost' IDENTIFIED BY 'MyNewPass4!';
    #
    # -- MySQL 5.6
    # mysql_secure_installation
    local l_login_user_my_cnf
    l_login_user_my_cnf="${l_login_user_my_cnf:-"${login_user_cnf_path}"}"

    [[ -f "${l_login_user_my_cnf}" ]] && rm -f "${l_login_user_my_cnf}"

    # generate strong random password for mysql user root@localhost
    funcStrongRandomPasswordGeneration

    case "${db_name}" in
        MariaDB )
            mysql -e "set password for 'root'@'localhost' = PASSWORD('${root_password_new}');"
            ;;
        MySQL|Percona )
            case "${db_version}" in
                5.5|5.6 )
                    mysql -e "set password for 'root'@'localhost' = PASSWORD('${root_password_new}');"
                    ;;
                * )
                    # 5.7 +
                    case "${distro_name}" in
                        debian|ubuntu )
                            mysql -e "alter user 'root'@'localhost' identified with mysql_native_password by '${root_password_new}';"
                            ;;
                        * )
                            # https://dev.mysql.com/doc/mysql-sles-repo-quick-guide/en/
                            local error_log_file=${error_log_file:-'/var/log/mysqld.log'}
                            [[ -s '/var/log/mysql/mysqld.log' ]] && error_log_file='/var/log/mysql/mysqld.log'

                            local tempRootPassword=${tempRootPassword:-}
                            tempRootPassword=$(awk '$0~/temporary password/{a=$NF}END{print a}' "${error_log_file}")
                            # Please use --connect-expired-password option or invoke mysql in interactive mode.
                            mysql -uroot -p"${tempRootPassword}" --connect-expired-password -e "alter user 'root'@'localhost' identified with mysql_native_password by '${root_password_new}';" 2> /dev/null
                            ;;
                    esac    # end case distro_name
                    ;;
            esac    # end case db_version
            ;;
    esac    # end case db_name

    # https://dev.mysql.com/doc/refman/5.7/en/mysql-commands.html

    # ~/.my.cnf
    # prompt=(\\u@\\h) [\\d]>\\_
    # prompt=MariaDB/Percona/MySQL [\\d]>\\_

    db_version_no_new=$(mysql -uroot -p"${root_password_new}" -Bse "select version();" 2> /dev/null)

    if [[ -n "${db_version_no_new}" ]]; then
        # https://dev.mysql.com/doc/refman/5.7/en/password-security-user.html
        if [[ -n "${l_login_user_my_cnf}" ]]; then
            # echo  -e "[client]\nuser=root\npassword=${root_password_new}\n\n[mysql]\nprompt=(\\u@\\h) [\\d]>\\_" > "${login_user_home}/.my.cnf"
            echo  -e "[client]\nuser=root\npassword=\"${root_password_new}\"\n\n[mysql]\nprompt=${db_name%%-*} [\\d]>\\_" > "${l_login_user_my_cnf}"
            chown "${login_user}" "${l_login_user_my_cnf}"
            chmod 400 "${l_login_user_my_cnf}"
            funcOperationProcedureResultStatement "${l_login_user_my_cnf}"
        fi
    else
        funcOperationProcedureResultStatement "${l_login_user_my_cnf}" 1
        funcExitStatement "\n${c_redb}Sorry${c_normal}: fail to install ${c_yellow}${db_name} ${db_version}${c_normal}."
    fi
}

# mysql_secure_installation
funcMySQLSecureInstallationConfiguration(){
    # https://dev.mysql.com/doc/refman/5.7/en/default-privileges.html
    local l_mysql_command="${l_mysql_command:-"${mysql_custom_command}"}"

    # extract from /usr/bin/mysql_secure_installation
    # - set_root_password
    # UPDATE mysql.user SET Password=PASSWORD('$esc_pass') WHERE User='root';

    if [[ -n "${l_mysql_command}" ]]; then
        funcOperationProcedureStatement 'mysql_secure_installation'
        # - remove_anonymous_users
        ${l_mysql_command} -e "DELETE FROM mysql.user WHERE User='';"
        # - remove_remote_root
        ${l_mysql_command} -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
        # - remove_test_database
        ${l_mysql_command} -e "DROP DATABASE IF EXISTS test;"
        # - reload_privilege_tables
        ${l_mysql_command} -e "FLUSH PRIVILEGES;"

        funcOperationProcedureResultStatement
    fi
}

# ~/.mysql_history ==> /dev/null
funcUserHistoryLogPathConfiguration(){
    local l_mysql_command="${l_mysql_command:-"${mysql_custom_command}"}"

    if [[ -n "${l_mysql_command}" ]]; then
        funcOperationProcedureStatement 'User Logging History'
        # https://dev.mysql.com/doc/refman/5.7/en/mysql-logging.html
        local login_user_mysql_history=${login_user_mysql_history:-"${login_user_home}/.mysql_history"}
        [[ -f "${login_user_mysql_history}" ]] && rm -f "${login_user_mysql_history}"
        ln -s /dev/null "${login_user_mysql_history}"

        funcOperationProcedureResultStatement "${login_user_mysql_history} ==> /dev/null"
    fi
}

# mysql_tzinfo_to_sql
funcTimeZoneInfoImport(){
    # https://dev.mysql.com/downloads/timezones.html
    # https://mariadb.com/kb/en/library/mysql_tzinfo_to_sql/
    # https://dev.mysql.com/doc/refman/5.7/en/time-zone-support.html
    # https://dev.mysql.com/doc/refman/5.7/en/mysql-tzinfo-to-sql.html
    local l_mysql_command="${l_mysql_command:-"${mysql_custom_command}"}"

    if [[ -n "${l_mysql_command}" && -d '/usr/share/zoneinfo' ]]; then
        if funcCommandExistCheck 'mysql_tzinfo_to_sql'; then
            funcOperationProcedureStatement 'Import time zone'
            mysql_tzinfo_to_sql /usr/share/zoneinfo 2> /dev/null | ${l_mysql_command} mysql
            funcOperationProcedureResultStatement 'mysql_tzinfo_to_sql'
        fi
    fi
}

# UDF (User Defined Function), just for Percona
funcUserDefinedFunctionForPercona(){
    # Percona Server is distributed with several useful UDF (User Defined Function) from Percona Toolkit.
    local l_mysql_command="${l_mysql_command:-"${mysql_custom_command}"}"

    if [[ "${db_name}" == 'Percona' && -n "${l_mysql_command}" ]]; then
        funcOperationProcedureStatement 'User Defined Function'
        $l_mysql_command -e "CREATE FUNCTION fnv1a_64 RETURNS INTEGER SONAME 'libfnv1a_udf.so'"
        $l_mysql_command -e "CREATE FUNCTION fnv_64 RETURNS INTEGER SONAME 'libfnv_udf.so'"
        $l_mysql_command -e "CREATE FUNCTION murmur_hash RETURNS INTEGER SONAME 'libmurmur_udf.so'"
        funcOperationProcedureResultStatement 'For Percona'
    fi
}


########## 2-4. MySQL Config File Configuration ##########
funcNewDatadirOperation(){
    if [[ -n "${data_dir}" && "${data_dir}" != "${data_dir_default}" ]]; then
        funcOperationPhaseStatement 'Data dir operation'

        if [[ -d "${data_dir}" ]]; then
            funcOperationProcedureStatement 'Check if is checked'
            local data_dir_temp=${data_dir_temp:-"${data_dir}.$(date +'%s').old"}
            mv "${data_dir}" "${data_dir_temp}"
            funcOperationProcedureResultStatement "${data_dir} ==> ${data_dir_temp}"
            # echo -e "${c_red}Attention: ${c_normal}Existed dir ${c_blue}${data_dir}${c_normal} has been rename to ${c_blue}${data_dir_temp}${c_normal}."
        fi

        funcOperationProcedureStatement 'Relocate data dir'
        [[ -d "${data_dir}" ]] && rm -rf "${data_dir}"
        mkdir -p "${data_dir}"
        chmod --reference=${data_dir_default} "${data_dir}"
        cp -R ${data_dir_default}/. "${data_dir}"
        chown -R mysql:mysql "${data_dir}"
        funcOperationProcedureResultStatement "${data_dir_default} ==> ${data_dir}"
        # funcInstallationProcedureStatement "Relocating from ${data_dir_default} to ${data_dir}"
    fi
}

funcConfigFileConfiguration(){
    funcOperationPhaseStatement 'Config File Operation'

    # 1 - detect default config file path - conf_path
    funcOperationProcedureStatement 'Config path detection'
    case "${db_name,,}" in
        mysql )
            # https://dev.mysql.com/doc/refman/5.7/en/cannot-create.html
            case "${distro_name}" in
                rhel|centos|fedora|sles )
                    conf_path="${conf_path_default}"
                    # Don't change socket path, or it will prompt   ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/lib/mysql/mysql.sock' (2)
                    ;;
                debian|ubuntu ) conf_path='/etc/mysql/mysql.conf.d/mysqld.cnf' ;;
            esac
            ;;
        percona )
            case "${distro_name}" in
                rhel|centos )
                    conf_path="${conf_path_default}"
                    [[ $(echo "${db_version} >= 5.7" | bc) == 1 ]] && conf_path='/etc/percona-server.conf.d/mysqld.cnf'
                    ;;
                debian|ubuntu )
                    conf_path='/etc/mysql/my.cnf'
                    [[ $(echo "${db_version} >= 5.7" | bc) == 1 ]] && conf_path='/etc/mysql/percona-server.conf.d/mysqld.cnf'
                    ;;
            esac
            ;;
        mariadb )
            case "${distro_name}" in
                rhel|centos|fedora|opensuse ) conf_path="${conf_path_default}" ;;
                debian|ubuntu ) conf_path='/etc/mysql/my.cnf' ;;
            esac
            ;;
    esac
    if [[ -f "${conf_path}" ]]; then
        funcOperationProcedureResultStatement "${conf_path}"
    else
        funcOperationProcedureResultStatement "${conf_path}" 1
        funcExitStatement "${c_redb}Sorry${c_normal}: fail to locate MySQL config file ${c_yellow}${conf_path}${c_normal}!"
    fi

    # 2 - config file configuration
    funcOperationProcedureStatement 'Directives configuration'
    # 2.1 - backup origin conf file
    local l_origin_conf_bak_path
    l_origin_conf_bak_path="${conf_path}${bak_suffix}"
    [[ -f "${l_origin_conf_bak_path}" ]] || cp -fp "${conf_path}" "${l_origin_conf_bak_path}"
    # 2.2 - download my.cnf template
    $download_tool "${mysqld_cnf_url}" > "${conf_path}"
    # 2.3 - replace parater mysqlvariant --> ${db_name,,}
    sed -r -i 's@mysqlvariant@'"${db_name,,}"'@g;' "${conf_path}"
    # 2.4 - log dir configuration, name rule setting in my.cnf
    mysql_log_dir="/var/log/${db_name,,}"
    if [[ ! -d "${mysql_log_dir}" ]]; then
        mkdir -p "${mysql_log_dir}"
        chown -R mysql:mysql "${mysql_log_dir}"
    fi

    # 2.5 -  replace original val to new conf
    # 2.5.1 - pid_file
    local pid_file_val_origin
    pid_file_val_origin=$(sed -r -n '/\[mysqld\]/,${/^pid_file[[:space:]]*=/{s@^([^=]+=[[:space:]]*)([^[:space:]]+)(.*)$@\2@g;p}}' "${l_origin_conf_bak_path}")

    if [[ -n "${pid_file_val_origin}" ]]; then
        funcConfDirectiveConfiguration "${conf_path}" 'pid_file' "${pid_file_val_origin}"
        [[ "${pid_file_val_origin}" =~ ^/var/run/ ]] && mysql_run_dir=$(dirname "${pid_file_val_origin}")
    fi

    # 2.5.2 - socket
    local socket_val_origin
    socket_val_origin=$(sed -r -n '/\[mysqld\]/,${/^socket[[:space:]]*=/{s@^([^=]+=[[:space:]]*)([^[:space:]]+)(.*)$@\2@g;p}}' "${l_origin_conf_bak_path}")
    [[ -n "${socket_val_origin}" ]] && funcConfDirectiveConfiguration "${conf_path}" 'socket' "${socket_val_origin}"

    # 2.5.3 - datadir
    local datadir_val_origin
    datadir_val_origin=$(sed -r -n '/\[mysqld\]/,${/^datadir[[:space:]]*=/{s@^([^=]+=[[:space:]]*)([^[:space:]]+)(.*)$@\2@g;p}}' "${l_origin_conf_bak_path}")
    if [[ -n "${datadir_val_origin}" ]]; then
        funcConfDirectiveConfiguration "${conf_path}" 'datadir' "${datadir_val_origin}"
    fi
    funcOperationProcedureResultStatement

    # 3 - config file optimization
    funcOperationProcedureStatement 'Directives optimization'
    # innodb_log_file_size = 256M
    # Bigger means more write throughput but longer recovery time
    # allow 1~2h worth of writes to be buffered in transaction logs, log sequence number
    # > pager grep seq
    # > show engine innodb status\G sleep(60); show engine innodb status\G
    # > nopager
    # > select (114172321602-114172162446)*60/1024/1024;

    # 3.1 - server_id    not change default val right now
    # funcConfDirectiveConfiguration "${conf_path}" 'server_id' 'delete'
    funcConfDirectiveConfiguration "${conf_path}" 'server_id' "${ip_local##*.}"

    # 3.2 master/slave mode
    case "${slave_mode}" in
        1 )
            sed -r -i '/Relay Log/,/Relay Log End/{/=/{s@^#?[[:space:]]*@@g;}}' "${conf_path}"
            sed -r -i '/Binary Log/,/Binary Log End/{/=/{s@^#?[[:space:]]*@# @g;}}' "${conf_path}"
            sed -r -i '/replicate-ignore-db/{s@^#?[[:space:]]*@@g;}' "${conf_path}"
            ;;
        0|* )
            sed -r -i '/Binary Log/,/Binary Log End/{/=/{s@^#?[[:space:]]*@@g;}}' "${conf_path}"
            sed -r -i '/Relay Log/,/Relay Log End/{/=/{s@^#?[[:space:]]*@# @g;}}' "${conf_path}"
            sed -r -i '/replicate-ignore-db/{s@^#?[[:space:]]*@# @g;}' "${conf_path}"
            ;;
    esac

    # 3.3 - For Specific Variant
    # 3.3.1 - Just for MariaDB
    if [[ "${db_name}" == 'MariaDB' ]]; then
        funcConfDirectiveConfiguration "${conf_path}" 'log_timestamps' 'delete'
        funcConfDirectiveConfiguration "${conf_path}" 'innodb_page_cleaners' 'delete'
        funcConfDirectiveConfiguration "${conf_path}" 'innodb_adaptive_hash_index_parts' 'delete'

        # sed -r -i '/log_timestamps/d' "${conf_path}"
        # sed -r -i '/innodb_page_cleaners/d' "${conf_path}"
        # sed -r -i '/innodb_adaptive_hash_index_parts/d' "${conf_path}"
        case "${distro_name}" in
            rhel|centos|fedora )
                # sed -r -i '/pid_file/d' "${conf_path}"
                funcConfDirectiveConfiguration "${conf_path}" 'pid_file' 'delete'
                ;;
        esac
    fi
    # 3.3.2 - Just for Percona
    if [[ "${db_name}" == 'Percona' ]]; then
        sed -r -i '/Percona Server only/{s@^#?[[:space:]]*@@g;}' "${conf_path}"
    else
        sed -r -i '/Percona Server only/d' "${conf_path}"
    fi
    # 3.3.3 - For MySQL/Percona
    case "${db_name}" in
        MySQL|Percona )
            if [[  $(echo "${db_version} >= 5.6" | bc) == 1 ]]; then
                sed -r -i '/MySQL 5.6 or newer/{s@^#?[[:space:]]*@@g;}' "${conf_path}"
            else
                sed -r -i '/MySQL 5.6 or newer/d' "${conf_path}"
            fi

            # https://dev.mysql.com/doc/refman/5.7/en/group-by-handling.html
            if [[ $(echo "${db_version} < 5.7" | bc) == 1 ]]; then
                sed -r -i '/sql_mode/{s@ONLY_FULL_GROUP_BY,@@g;}' "${conf_path}"
            fi

            if [[ $(echo "${db_version} == 5.7" | bc) == 1 ]]; then
                sed -r -i '/MySQL 5.7 only/{s@^#?[[:space:]]*@@g;}' "${conf_path}"
            else
                sed -r -i '/MySQL 5.7 only/d' "${conf_path}"
            fi

            if [[  $(echo "${db_version} >= 5.7" | bc) == 1 ]]; then
                sed -r -i '/MySQL 5.7 or newer/{s@^#?[[:space:]]*@@g;}' "${conf_path}"
            else
                sed -r -i '/MySQL 5.7 or newer/d' "${conf_path}"
            fi

            if [[ $(echo "${db_version} > 5.7" | bc) == 1 ]]; then
                funcConfDirectiveConfiguration "${conf_path}" 'query_cache_type' 'delete'
                funcConfDirectiveConfiguration "${conf_path}" 'query_cache_size' 'delete'
                funcConfDirectiveConfiguration "${conf_path}" 'log_warnings' 'delete'

                # sed -r -i '/^#?[[:space:]]*query_cache_type[[:space:]]*=/d' "${conf_path}"
                # sed -r -i '/^#?[[:space:]]*query_cache_size[[:space:]]*=/d' "${conf_path}"
                # sed -r -i '/^#?[[:space:]]*log_warnings[[:space:]]*=/d' "${conf_path}"
            fi
            ;;
    esac
    funcOperationProcedureResultStatement
}

funcSecurityUtilityRulesConfiguration(){
    funcOperationPhaseStatement 'Security Utilities Configuration'

    # 1 - Firewall
    if [[ "${enable_firewall}" -eq 1 ]]; then
        funcOperationProcedureStatement 'Firewall configuration'
        # $download_tool "${firewall_configuration_script}" | bash -s -- -p "${mysql_port}" -H "${remote_host_ip}" -s
        $download_tool "${firewall_configuration_script}" | bash -s -- -p "${mysql_port}" -s

        local l_firewall_type=''
        case "${pack_manager}" in
            apt-get ) l_firewall_type='ufw' ;;
            zypper ) l_firewall_type='SuSEfirewall2' ;;
            dnf|yum ) [[ $("${pack_manager}" info firewalld 2>&1 | awk -F": " 'match($1,/^Name/){print $NF;exit}') == 'firewalld' ]] && l_firewall_type='firewalld' || l_firewall_type='iptables' ;;
        esac

        funcOperationProcedureResultStatement "${l_firewall_type}"
    fi

    # 2 - SElinux
    # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/chap-managing_confined_services-mariadb

    # Be careful of SELinux
    # [Warning] Can't create test file /data/mysql/centos.lower-test
    # https://phe1129.wordpress.com/2012/04/02/change-mysql-data-folder-on-selinux/
    # https://dba.stackexchange.com/questions/80232/mysql-cant-create-test-file-error-on-centos
    if funcCommandExistCheck 'getenforce'; then
        funcOperationProcedureStatement 'SELinux configuration'
        # semanage port -a -t mysqld_port_t -p tcp 3307
        funcSELinuxSemanageOperation 'mysqld_port_t' "${mysql_port_default}" 'port' 'add' 'tcp'
        [[ -n "${mysql_port}" && "${mysql_port}" != "${mysql_port_default}" ]] && funcSELinuxSemanageOperation 'mysqld_port_t' "${mysql_port}" 'port' 'add' 'tcp'

        # semanage fcontext -a -t mysqld_db_t "/var/lib/mysql(/.*)?"
        funcSELinuxSemanageOperation 'mysqld_db_t' "${data_dir}" 'fcontext' 'add'
        [[ -d "${data_dir_default}" ]] && funcSELinuxSemanageOperation 'mysqld_db_t' "${data_dir_default}" 'fcontext' 'add'

        # mysqld_etc_t /etc/my.cnf, /etc/mysql/
        [[ -f "${conf_path_default}" ]] && funcSELinuxSemanageOperation 'mysqld_etc_t' "${conf_path_default}" 'fcontext' 'add'
        if [[ -f "${conf_path}" && "${conf_path}" != "${conf_path_default}" ]]; then
            local l_conf_dir
            l_conf_dir=$(dirname "${conf_path}")
            [[ "${l_conf_dir}" == '/etc' ]] || funcSELinuxSemanageOperation 'mysqld_etc_t' "${l_conf_dir}" 'fcontext' 'add'
        fi

        # mysqld_exec_t /usr/libexec/mysqld, /usr/sbin/mysqld

        # mysqld_unit_file_t /usr/lib/systemd/system/mysqld.service

        # semanage fcontext -a -t mysqld_log_t "/data/log(/.*)?"
        [[ -d "${mysql_log_dir}" ]] && funcSELinuxSemanageOperation 'mysqld_log_t' "${mysql_log_dir}" 'fcontext' 'add'

        # semanage fcontext -a -t mysqld_var_run_t "var/run/mysqld(/.*)?"
        funcSELinuxSemanageOperation 'mysqld_var_run_t' "${mysql_run_dir}" 'fcontext' 'add'
        funcOperationProcedureResultStatement
    fi


    # 3 - Apparmor
    if [[ "${db_name,,}" == 'mysql' ]]; then
        funcOperationProcedureStatement 'Apparmor configuration'

        case "${distro_name}" in
            # rhel|centos|fedora|sles ) ;;
            debian|ubuntu )
                # https://dba.stackexchange.com/questions/106085/cant-create-file-var-lib-mysql-user-lower-test
                local apparmor_mysqld_path=${apparmor_mysqld_path:-'/etc/apparmor.d/usr.sbin.mysqld'}
                [[ -s "${apparmor_mysqld_path}" ]] && sed -r -i '/Allow data dir access/,/^$/{s@'"${data_dir_default}/"'@'"${data_dir}/"'@g}' "${apparmor_mysqld_path}"
                ;;
        esac
        funcOperationProcedureResultStatement
    fi
}

funcPostInstallationOperation(){
    funcOperationPhaseStatement 'MySQL Secure Configuration'
    funcRootPasswordConfiguration
    funcMySQLSecureInstallationConfiguration
    funcDBServiceStatusOperation "${service_name}" 'stop'
    funcNewDatadirOperation
    funcConfigFileConfiguration

    funcSecurityUtilityRulesConfiguration
    funcConfDirectiveConfiguration "${conf_path}" 'datadir' "${data_dir}"
    funcConfDirectiveConfiguration "${conf_path}" 'port' "${mysql_port}"
    funcDBServiceStatusOperation "${service_name}" 'start'

    # empty general log
    local l_general_log=${l_general_log:-"/var/log/${db_name,,}/${db_name,,}_general.log"}
    [[ -s "${l_general_log}" ]] && echo '' > "${l_general_log}"

    echo -e "\nSuccessfully installing ${c_yellow}${db_name} ${db_version_no_new}${c_normal}, account info stores in ${c_yellow}~/.my.cnf${c_normal}!\n\nVersion info:\n\n${c_yellow}$(mysql --version)${c_normal}\n"
}

#########  3. Executing Process  #########
funcInitializationCheck
funcInternetConnectionCheck
funcDownloadToolCheck
funcPackageManagerDetection
funcOSInfoDetection

funcExistedDetection
funcPortAndDatadirVerification
funcV2SelectionListGeneration
funcDBInstallation
funcPostInstallationOperation


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null

    unset bak_suffix
    unset auto_installation
    unset root_password_new
    unset mysql_variant_type
    unset variant_version
    unset enable_firewall
    unset slave_mode
    unset proxy_server
    unset conf_path
    unset data_dir
    unset mysql_port
    unset mysql_log_dir
    unset mysql_run_dir
    unset db_name
    unset db_version
    unset db_version_no_new
    unset service_name
    unset flag
    unset procedure_start_time
    unset procedure_end_time
}

trap funcTrapEXIT EXIT


# APT interrupt install operation will occur the following condition :
# E: Could not get lock /var/lib/dpkg/lock - open (11: Resource temporarily unavailable)
# E: Unable to lock the administration directory (/var/lib/dpkg/), is another process using it?
# solution is :
# rm -rf /var/lib/dpkg/lock /var/cache/apt/archives/lock
# dpkg --configure -a

# ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'mypass';
# ALTER USER 'root'@'localhost' IDENTIFIED BY 'MyNewPass4!';

# sudo apt-get purge MariaDB* mariadb* Percona* mysql* -yq
# sudo apt-get autoremove -yq
# sudo rm -rf .my.cnf* .mysql_history /var/log/mysqld.log /var/log/mysql /var/lib/mysql/ /data/ /etc/mysql* /etc/my.cnf*

# - Security Relevant
# https://dev.mysql.com/doc/refman/5.7/en/security-plugins.html
# local-infile=0   https://dev.mysql.com/doc/refman/5.7/en/load-data-local.html

# https://dev.mysql.com/doc/refman/5.7/en/information-schema.html
# https://dev.mysql.com/doc/refman/5.7/en/tables-table.html

# https://dev.mysql.com/doc/refman/5.7/en/group-by-handling.html
# sql_mode: ONLY_FULL_GROUP_BY will result in "ERROR 1055 (42000): 'xx.xx.xx' isn't in GROUP BY" while use clause group by
# sql_mode=ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION


# -- export database (master --> slave)
# mysqldump --databases database1 database2 database3 ... | gzip > /tmp/mysql_export.sql.gz

# -- import database (slave --> master)
# set autocommit=0;
# set foreign_key_checks=0;
# mysql < /tmp/mysql_export.sql
# set autocommit=1;
# set foreign_key_checks=1;

# -- mm - master  192.168.8.8
# grant replication slave on *.* to 'repl_slave'@'192.168.8.9' identified by 'mysql_slave@2018';
# show master status\G

# -- mm - slave  192.168.8.9
# stop slave;
# reset slave;
# change master to master_host='192.168.8.8',master_user='repl_slave',master_password='mysql_slave@2018',master_log_file='mysql-bin.000005',master_log_pos=860239165;
# start slave;
# show slave status\G

# -- List per storage engine size
# SELECT engine, count(*) as 'table', concat(round(sum(table_rows)/1000,3),' K') as rows , concat(round(sum(data_length)/(1024*1024),3),' MB') as data_size, concat(round(sum(index_length)/(1024*1024),3),' MB') as index_size, concat(round(sum(data_length+index_length)/(1024*1024*1024),3),' GB') as total_size, round(sum(index_length)/sum(data_length),2) idxfrac FROM information_schema.TABLES WHERE table_schema not in ('mysql','performance_schema','information_schema') GROUP BY engine HAVING engine is not NULL ORDER BY table_rows DESC;

# -- List per database size
# SELECT table_schema as 'database', concat(round(sum(table_rows)/1000,3),' K') rows, concat(round(sum(data_length+index_length)/(1024*1024*1024),3),' GB') total_size, round(sum(index_length)/sum(data_length),2) idxfrac FROM information_schema.TABLES WHERE table_schema not in ('mysql', 'performance_schema', 'information_schema') GROUP BY table_schema ORDER BY sum(data_length+index_length) DESC;

# -- List per InnoDB table
# SELECT concat(table_schema,'.',table_name) as 'table', engine, concat(round(table_rows/1000,3),'K') rows, concat(round(data_length/(1024*1024),3),' MB') data_size, concat(round(index_length/(1024*1024),3),' MB') index_size, concat(round((data_length+index_length)/(1024*1024*1024),3),'GB') total_size, round(index_length/data_length,2) idxfrac FROM information_schema.TABLES WHERE engine = 'InnoDB' AND table_schema not in ('mysql', 'performance_schema', 'information_schema') ORDER BY table_rows DESC;


# Script End
