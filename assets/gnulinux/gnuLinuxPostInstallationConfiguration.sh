#!/usr/bin/env bash
# shellcheck disable=SC2016
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Post Initialization Setting On Freshly Installed GNU Linux (RHEL/CentOS/Fedora/Debian/Ubuntu/OpenSUSE and variants)
#Writer: MaxdSre
#Date: Feb 02, 2018 15:47 Fri +0800 - Optimization, security enhancement, add USB block, umask determining...
#Reconfiguration Date:
# - July 11, 2017 13:12 Tue ~ July 12, 2017 16:33 Wed +0800
# - July 27, 2017 17:26 Thu +0800
# - Aug 16, 2017 18:25 Wed +0800
# - Sep 05, 2017 13:49 Tue +0800
# - Oct 17, 2017 11:50 Tue +0800
# - Oct 26, 2017 19:10 Thu +0800
# - Nov 09, 2017 18:23 Thu +0800
# - Nov 14, 2017 15:30 Tue +0800
# - Nov 24, 2017 17:36 Fri +0800
# - Dec 05, 2017 11:05 Fri +0800
# - Dec 25, 2017 13:47 Mon +0800 - Change output style
# - Jan 02, 2018 14:51 Tue +0800 - Optimization, add security/audit utilities
# - Jan 05, 2018 18:59 Fri +0800 - Optimization, add cron task
# - Jan 08, 2018 16:09 Mon +0800 - sysstat optimization, add SELinux
# - Jan 16, 2018 16:02 Tue +0800 - Optimization, add tripwire, nikto
# - Jan 17, 2018 15:51 Wed +0800 - SELinux tunning under SUSE/OpenSUSE
# - Jan 18, 2018 18:21 Thu +0800 - Auditd tunning, add compress command
# - Jan 19, 2018 18:45 Fri +0800 - Auditd tunning, add custom rules
# - Jan 23, 2018 16:43 Tue +0800 - Add timezone autodetection, disable 'sudo su -', add readonly-removables rule
# - Jan 24, 2018 19:28 Wed +0800 - ssh directive configuation optimization
# - Jan 28, 2018 12:39 Sun +0800 - THP ooptimization, ~/.bashrc add alias fro system update, older kernel remove
# - Feb 01, 2018 18:04 Thu +0800 - Optimization, security enhancement, add cron task for rkhunter, aide, clamav

#Docker Script https://get.docker.com/
#Gitlab Script https://packages.gitlab.com/gitlab/gitlab-ce/install

# Harden Security
# https://wiki.mozilla.org/Security


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'PICTemp_XXXXXX'}
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
readonly c_red="$(tput setaf 1)"     # c_red='\e[31;1m'
readonly c_green="$(tput setaf 2)"    # c_blue='\e[32m'
readonly c_yellow="$(tput setaf 3)"    # c_blue='\e[33m'
readonly c_blue="$(tput setaf 4)"    # c_blue='\e[34m'
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup
pass_change_minday=${pass_change_minday:-0}    # minimum days need for a password change
pass_change_maxday=${pass_change_maxday:-60}   # maximum days the password is valid
pass_change_warnningday=${pass_change_warnningday:-7}  # password expiry advanced warning days
readonly umask_default='027'
readonly github_raw_url='https://raw.githubusercontent.com'
readonly custom_shellscript_url="${github_raw_url}/MaxdSre/ShellScript"
readonly vim_url="${custom_shellscript_url}/master/configs/vim/vimrc"
readonly sysctl_url="${custom_shellscript_url}/master/configs/sysctl.conf"
readonly os_check_script="${custom_shellscript_url}/master/assets/gnulinux/gnuLinuxDistroVersionDetection.sh"
readonly firewall_configuration_script="${custom_shellscript_url}/master/assets/gnulinux/gnuLinuxFirewallRuleConfiguration.sh"
readonly auditd_custom_rule="${custom_shellscript_url}/master/configs/auditd/custom.rules"

zypper_selinux=${zypper_selinux:-0}
readonly default_timezone=${default_timezone:-'Asia/Singapore'}
readonly default_grub_timeout=${default_grub_timeout:-2}
disable_ssh_root=${disable_ssh_root:-0}
enable_sshd=${enable_sshd:-0}
ssh_port_default=${ssh_port_default:-22}
ssh_port=${ssh_port:-"${ssh_port_default}"}
change_repository=${change_repository:-0}
just_keygen=${just_keygen:-0}
restrict_remote_login=${restrict_remote_login:-0}
grub_timeout=${grub_timeout:-2}
hostname_specify=${hostname_specify:-}
username_specify=${username_specify:-}
timezone_specify=${timezone_specify:-}
tmpfs_enable=${tmpfs_enable:-0}
grant_sudo=${grant_sudo:-0}
log_user_session=${log_user_session:-0}
administrator_utility=${administrator_utility:-0}
security_enhance=${security_enhance:-0}
remove_unneeded_pack=${remove_unneeded_pack:-0}
cron_task=${cron_task:-0}
kernel_upgrade=${kernel_upgrade:-0}
selinux_setting=${selinux_setting:-0}
boost_enable=${boost_enable:-0}
proxy_server=${proxy_server:-}
flag=1    # used for funcOperationPhaseStatement
procedure_start_time=${procedure_start_time:-}
procedure_end_time=${procedure_end_time:-}

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
            printf "%$((printf_val - item_width / 2))s ${c_bold}${c_red}%s${c_normal}\n" "${item}:" "${val}"
        fi    # end if val

    fi
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
    # 2 - specified for RHEL/Debian/SLES/Amazon Linux
    [[ -s '/etc/os-release' || -s '/etc/redhat-release' || -s '/etc/debian_version' || -s '/etc/SuSE-release' ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script just support RHEL/CentOS/Debian/Ubuntu/OpenSUSE derivates!"
    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}curl${c_normal} command found!"

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"

    # used for SSH configuration
    funcCommandExistCheck 'man' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}man${c_normal} command found!"

    # 4 - current login user detection
    #$USER exist && $SUDO_USER not exist, then use $USER
    [[ -n "${USER:-}" && -z "${SUDO_USER:-}" ]] && login_user="$USER" || login_user="$SUDO_USER"
    login_user_home=${login_user_home:-}
    login_user_home=$(awk -F: 'match($1,/^'"${login_user}"'$/){print $(NF-1)}' /etc/passwd)

    login_user_ip=${login_user_ip:-}
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        login_user_ip=$(echo "${SSH_CLIENT}" | awk '{print $1}')
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        login_user_ip=$(echo "${SSH_CONNECTION}" | awk '{print $1}')
    else
        login_user_ip=$(who | sed -r -n '$s@.*\(([^\)]+)\).*@\1@gp')
        # [[ "${login_user_ip}" == ":0" ]] && login_user_ip='127.0.0.1'
    fi

    mem_totoal_size=${mem_totoal_size:-0}
    if funcCommandExistCheck 'free'; then
        mem_totoal_size=$(free -k | sed -r -n '/^Mem:/{s@^[^[:digit:]]*([[:digit:]]+).*@\1@g;p}')
    elif [[ -s '/proc/meminfo' ]]; then
        mem_totoal_size=$(sed -r -n '/MemTotal/{s@^[^[:digit:]]*([[:digit:]]+).*$@\1@g;p}' /proc/meminfo)
    fi
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

    elif funcCommandExistCheck 'wget'; then
        download_tool_origin="wget -qO-"
        download_tool="${download_tool_origin} --tries=${retry_times} --waitretry=${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-http-keep-alive --referer=${referrer_page}" # wget -q URL -O /PATH/FILE
        # --user-agent=${user_agent}

        # local version_no=$(wget --version | sed -r -n '1s@^[^[:digit:]]*([[:digit:].]*).*@\1@p')
        if [[ -n "${proxy_server}" ]]; then
            if [[ "${p_proto}" == 'https' ]]; then
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
            # export DEBIAN_PRIORITY=low

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

            unset DEBIAN_FRONTEND
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
}

funcOSInfoDetection(){
    local osinfo=${osinfo:-}
    osinfo=$($download_tool "${os_check_script}" | bash -s -- -j | sed -r -n 's@[{}]@@g;s@","@\n@g;s@":"@|@g;s@(^"|"$)@@g;p')

    if [[ -z "${osinfo}" ]]; then
        funcExitStatement "${c_red}Fatal${c_normal}, fail to extract os info!"
    elif [[ -n $(echo "${osinfo}" | sed -n -r '/^error\|/p') ]]; then
        funcExitStatement "${c_red}Fatal${c_normal}, this script doesn't support your system!"
    fi

    is_eol=${eol_date:-0}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^is_eol\|/p') ]] && is_eol=$(echo "${osinfo}" | awk -F\| 'match($1,/^is_eol$/){print $NF}')

    [[ "${is_eol}" -eq 1 ]] && funcExitStatement "${c_red}Sorry${c_normal}: your system ${c_blue}${distro_fullname}${c_normal} is obsoleted!"

    distro_name=${distro_name:-}
    if [[ -n $(echo "${osinfo}" | sed -n -r '/^distro_name\|/p') ]]; then
        distro_name=$(echo "${osinfo}" | awk -F\| 'match($1,/^distro_name$/){print $NF}')
        distro_name=${distro_name%%-*}    # rhel/centos/fedora/debian/ubuntu/sles/opensuse
    fi

    codename=${codename:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^codename\|/p') ]] && codename=$(echo "${osinfo}" | awk -F\| 'match($1,/^codename$/){print $NF}')

    distro_fullname=${distro_fullname:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^pretty_name\|/p') ]] && distro_fullname=$(echo "${osinfo}" | awk -F\| 'match($1,/^pretty_name$/){print $NF}')

    version_id=${version_id:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^version_id\|/p') ]] && version_id=$(echo "${osinfo}" | awk -F\| 'match($1,/^version_id$/){print $NF}')

    ip_local=${ip_local:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_local\|/p') ]] && ip_local=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_local$/){print $NF}')

    ip_public=${ip_public:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_public\|/p') ]] && ip_public=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_public$/){print $NF}')

    ip_public_locate=${ip_public_locate:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_public_locate\|/p') ]] && ip_public_locate=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_public_locate$/){print $NF}')

    ip_public_country_code=${ip_public_country_code:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_public_country_code\|/p') ]] && ip_public_country_code=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_public_country_code$/){print $NF}')

    ip_public_timezone=${ip_public_timezone:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^ip_public_timezone\|/p') ]] && ip_public_timezone=$(echo "${osinfo}" | awk -F\| 'match($1,/^ip_public_timezone$/){print $NF}')

    release_date=${release_date:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^release_date\|/p') ]] && release_date=$(echo "${osinfo}" | awk -F\| 'match($1,/^release_date$/){print $NF}')

    eol_date=${eol_date:-}
    [[ -n $(echo "${osinfo}" | sed -n -r '/^eol_date\|/p') ]] && eol_date=$(echo "${osinfo}" | awk -F\| 'match($1,/^eol_date$/){print $NF}')

    funcCentralOutput '=========================================='
    funcCentralOutput 'GNU/Linux Distribution Information'
    funcCentralOutput '=========================================='
    echo ''

    [[ -z "${distro_fullname}" ]] || funcCentralOutput 'Full Name' "${distro_fullname}"
    [[ -z "${distro_name}" ]] || funcCentralOutput 'Distro Name' "${distro_name}"
    [[ -z "${version_id}" ]] || funcCentralOutput 'Version ID' "${version_id}"
    [[ -z "${codename}" ]] || funcCentralOutput "Code Name" "${codename}"
    [[ -z "${release_date}" ]] || funcCentralOutput 'Release Date' "${release_date}"
    [[ -z "${eol_date}" ]] || funcCentralOutput 'EOL Date' "${eol_date}"

    if [[ -n "${ip_public}" ]]; then
        [[ -n "${ip_local}" && "${ip_public}" != "${ip_local}" ]] && funcCentralOutput 'Internal IP' "${ip_local}"
        funcCentralOutput 'External IP' "${ip_public} (${ip_public_country_code}.${ip_public_locate})"
    fi

    version_id=${version_id%%.*}

    # Operation Bar
    echo ''
    funcCentralOutput '=========================================='
    funcCentralOutput 'Operation Processing, Just Be Patient'
    funcCentralOutput '=========================================='
    echo ''


    # if [[ -d '/dev/' ]]; then
    #     # https://major.io/icanhazip-com-faq/
    #     exec 5<> /dev/tcp/icanhazip.com/80
    #     echo -e 'GET / HTTP/1.0\r\nHost: icanhazip.com\r\n\r' >&5
    #     while read -r i; do [[ -n "$i" ]] && ip_country_code="$i" ; done <&5
    #     exec 5>&-
    #
    #     if [[ -z "${ip_country_code}" ]]; then
    #         exec 6<> /dev/tcp/ipinfo.io/80
    #         echo -e 'GET / HTTP/1.0\r\nHost: ipinfo.io\r\n\r' >&6
    #         ip_country_code=$(cat 0<&6 | sed -r -n '/^\{/,/^\}/{/\"country\"/{s@[[:space:],]*@@g;s@[^:]*:"([^"]*)"@\1@g;p}}')
    #         exec 6>&-
    #     fi
    #
    # fi
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


#########  1-2 getopts Operation  #########
start_time=$(date +'%s')    # Start Time Of Operation

funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...

Post Installation Configuring RHEL/CentOS/Fedora/Amazon Linux/Debian/Ubuntu/OpenSUSE!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -r    --replace repository source, for China mainland only
    -u username    --add user, create new normal user, password is 'Username@year', e.g. user maxdsre, this year is 2017, then password is 'Maxdsre@2017'
    -S    --sudo, grant user sudo privilege which is specified by '-u'
    -H hostname    --hostname, set hostname
    -T timezone    --timezone, set timezone (eg. America/New_York, Asia/Hong_Kong)
    -s    --ssh, enable sshd service (server side), default start on system startup
    -d    --disable root user remoting login (eg: via ssh)
    -k    --keygen, sshd service only allow ssh keygen, disable password, along with '-s'
    -R    --restrict remote login from specific ip (current login host), use with caution
    -g time    --grub timeout, set timeout num (second)
    -t    --enable tmpfs filesystem for dir '/tmp' provided by systemd, only if physical memory size > 6GB, default allocate 1GB
    -l    --enable login user session log via built command 'script'
    -a    --install system administration utility, e.g. iproute, procps, dstat, dnsutils ...
    -E    --install security relavant utilities, e.g. nikto, rkhunter, aide, clamav, [tripwire] ...
    -e    --remove unneeded utilities, e.g. game, media player, gnome utilities
    -c    --add cron task, e.g. system update, anti-virus sacn, intrusion detection scan
    -K    --kernel upgrade, install latest mailline kernel version
    -Z selinux_type    --SELinux configuation(0/permissive, 1/enforcing, 2/disabled), default is 0/Permissive, not suggest deploy on Debian/Ubuntu, it may cause problems
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
${c_normal}
EOF
exit
}

while getopts "ru:SH:T:sdkRg:p:tlaEecKZ:bh" option "$@"; do
    case "$option" in
        r ) change_repository=1 ;;
        u ) username_specify="$OPTARG" ;;
        S ) grant_sudo=1 ;;
        H ) hostname_specify="$OPTARG" ;;
        T ) timezone_specify="$OPTARG" ;;
        s ) enable_sshd=1 ;;
        d ) disable_ssh_root=1 ;;
        k ) just_keygen=1 ;;
        R ) restrict_remote_login=1 ;;
        g ) grub_timeout="$OPTARG" ;;
        t ) tmpfs_enable=1 ;;
        l ) log_user_session=1 ;;
        a ) administrator_utility=1 ;;
        E ) security_enhance=1 ;;
        e ) remove_unneeded_pack=1 ;;
        c ) cron_task=1 ;;
        K ) kernel_upgrade=1 ;;
        Z ) selinux_setting="$OPTARG" ;;
        b ) boost_enable=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo ;;
    esac
done


#########  2-1. Package Repository Setting & System Update  #########
funcRepositoryYUM(){
    local repo_dir=${repo_dir:-'/etc/yum.repos.d'}
    if [[ "${distro_name}" == 'centos' && "${ip_public_country_code^^}" == 'CN' ]]; then
        local repo_dir_backup="${repo_dir}${bak_suffix}"
        if [[ ! -d "${repo_dir_backup}" ]]; then
            mkdir -p "${repo_dir_backup}"
            mv -f "${repo_dir}"/CentOS*.repo "${repo_dir_backup}"
        fi

        # http://mirrors.163.com/.help/centos.html
        local repo_savename="${repo_dir}/CentOS-Base.repo"
        [[ -f "${repo_savename}" ]] || $download_tool "http://mirrors.163.com/.help/CentOS${version_id}-Base-163.repo" > "$repo_savename"
    fi

    # Installing EPEL Repository
    if [[ ! -f "${repo_dir}/epel.repo" ]]; then
        local rpm_gpg_dir='/etc/pki/rpm-gpg/'
        [[ -f "${rpm_gpg_dir}RPM-GPG-KEY-EPEL-${version_id}" ]] || $download_tool "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-${version_id}" > "${rpm_gpg_dir}RPM-GPG-KEY-EPEL-${version_id}"
        funcPackageManagerOperation 'install' "epel-release"
        # https://support.rackspace.com/how-to/install-epel-and-additional-repositories-on-centos-and-red-hat/
        [[ -f "${repo_dir}/epel.repo" ]] || funcPackageManagerOperation 'install' "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${version_id}.noarch.rpm"
        [[ -f "${repo_dir}/epel-testing.repo" ]] && rm -f "${repo_dir}/epel-testing.repo"
    fi

    # Yum plugin which chooses fastest repository from a mirrorlist
    [[ -z $(rpm -qa yum-plugin-fastestmirror 2> /dev/null) ]] && funcPackageManagerOperation 'install' 'yum-plugin-fastestmirror'
}

funcRepositoryDNF(){
    if [[ "${distro_name}" == 'fedora' && "${ip_public_country_code^^}" == 'CN' ]]; then
        local repo_dir=${repo_dir:-'/etc/yum.repos.d/'}
        local repo_dir_backup="${repo_dir}${bak_suffix}"
        if [[ ! -d "${repo_dir_backup}" ]]; then
            mkdir -p "${repo_dir_backup}"
            mv -f "${repo_dir}*.repo" "${repo_dir_backup}"
        fi

        # http://mirrors.163.com/.help/fedora.html
        local repo_fedora_savename="${repo_dir}Fedora.repo"
        [[ -f "${repo_fedora_savename}" ]] || $download_tool "http://mirrors.163.com/.help/fedora-163.repo" > "$repo_fedora_savename"

        local repo_fedora_updates_savename="${repo_dir}Fedora-Updates.repo"
        [[ -f "${repo_fedora_updates_savename}" ]] || $download_tool "http://mirrors.163.com/.help/fedora-updates-163.repo" > "$repo_fedora_updates_savename"
    fi
}

funcRepositoryAPT(){
    if [[ "${ip_public_country_code}" == 'CN'  ]]; then
        local repo_path=${repo_path:-'/etc/apt/sources.list'}
        [[ -f "${repo_path}${bak_suffix}" ]] || cp -fp "${repo_path}" "${repo_path}${bak_suffix}"
        local repo_site='http://mirrors.163.com'
        case "${distro_name,,}" in
            debian )
                echo -e "deb $repo_site/$distro_name/ $codename main non-free contrib\ndeb-src $repo_site/$distro_name/ $codename main non-free contrib\n\ndeb $repo_site/$distro_name/ $codename-updates main non-free contrib\ndeb-src $repo_site/$distro_name/ $codename-updates main non-free contrib\n\ndeb $repo_site/$distro_name/ $codename-backports main non-free contrib\ndeb-src $repo_site/$distro_name/ $codename-backports main non-free contrib\n\ndeb $repo_site/$distro_name-security/ $codename/updates main non-free contrib\ndeb-src $repo_site/$distro_name-security/ $codename/updates main non-free contrib\n" > "${repo_path}"
                ;;
            ubuntu )
                echo -e "deb $repo_site/$distro_name/ $codename main restricted universe multiverse\ndeb-src $repo_site/$distro_name/ $codename main restricted universe multiverse\n\ndeb $repo_site/$distro_name/ $codename-security main restricted universe multiverse\ndeb-src $repo_site/$distro_name/ $codename-security main restricted universe multiverse\n\ndeb $repo_site/$distro_name/ $codename-updates main restricted universe multiverse\ndeb-src $repo_site/$distro_name/ $codename-updates main restricted universe multiverse\n\ndeb $repo_site/$distro_name/ $codename-proposed main restricted universe multiverse\ndeb-src $repo_site/$distro_name/ $codename-proposed main restricted universe multiverse\n\n" > "${repo_path}"
                echo -e "deb $repo_site/$distro_name/ $codename-backports main restricted universe multiverse\ndeb-src $repo_site/$distro_name/ $codename-backports main restricted universe multiverse\n" >> "${repo_path}"
                ;;
        esac
    fi
}

funcRepositoryZYPPER(){
    if [[ "${distro_name}" == 'opensuse' ]]; then
        for i in $(zypper lr | awk -F\| 'match($1,/[[:digit:]]/){print gensub(/[[:blank:]]/,"","g",$1)}'); do zypper rr "$i" &> /dev/null ; done

        local repo_keyword=${repo_keyword:-"${version_id}"}
        [[ "${version_id%%.*}" -ge 42 ]] && repo_keyword="leap/${version_id}"

        local repo_url=${repo_url:-'http://download.opensuse.org'}
        local repo_alias=${repo_alias:-'OpenSUSE'}
        if [[ "${ip_public_country_code}" == 'CN' ]]; then
            repo_url="https://mirrors.ustc.edu.cn/${distro_name}"
            repo_alias='USTC'
        fi

        zypper ar -fcg "${repo_url}/distribution/${repo_keyword}/repo/oss" "${repo_alias}:${repo_keyword##*/}:OSS" &> /dev/null
        zypper ar -fcg "${repo_url}/distribution/${repo_keyword}/repo/non-oss" "${repo_alias}:${repo_keyword##*/}:NON-OSS" &> /dev/null
        zypper ar -fcg "${repo_url}/update/${repo_keyword}/oss" "${repo_alias}:${repo_keyword##*/}:UPDATE-OSS" &> /dev/null
        zypper ar -fcg "${repo_url}/update/${repo_keyword}/non-oss" "${repo_alias}:${repo_keyword##*/}:UPDATE-NON-OSS" &> /dev/null

        # For selinux-policy
        # https://software.opensuse.org/download.html?project=security%3ASELinux&package=selinux-policy
        local selinux_distro_version=${selinux_distro_version:-"${version_id}"}

        [[ $(echo "${version_id} >= 42.2" | bc) == 1 ]] && selinux_distro_version='42.2'
        zypper ar -fcg http://download.opensuse.org/repositories/security:/SELinux/openSUSE_Leap_"${selinux_distro_version}"/ OpenSUSE:"${selinux_distro_version}":SELinux

        # zypper ar -fcg https://mirrors.ustc.edu.cn/opensuse/distribution/leap/42.3/repo/oss USTC:42.3:OSS
        # zypper ar -fcg https://mirrors.ustc.edu.cn/opensuse/distribution/leap/42.3/repo/non-oss USTC:42.3:NON-OSS
        # zypper ar -fcg https://mirrors.ustc.edu.cn/opensuse/update/leap/42.3/oss USTC:42.3:UPDATE-OSS
        # zypper ar -fcg https://mirrors.ustc.edu.cn/opensuse/update/leap/42.3/non-oss USTC:42.3:UPDATE-NON-OSS

        # zypper ar -fcg http://download.opensuse.org/distribution/leap/42.3/repo/oss/ OpenSUSE:42.3:OSS
        # zypper ar -fcg http://download.opensuse.org/distribution/leap/42.3/repo/non-oss/ OpenSUSE:42.3:NON-OSS
        # zypper ar -fcg http://download.opensuse.org/update/leap/42.3/oss/ OpenSUSE:42.3:UPDATE-OSS
        # zypper ar -fcg http://download.opensuse.org/update/leap/42.3/non-oss/ OpenSUSE:42.3:UPDATE-NON-OSS
        # zypper ar -dcg http://download.opensuse.org/source/distribution/leap/42.3/repo/oss/ OpenSUSE:42.3:SOURCE-OSS
        # zypper ar -dcg http://download.opensuse.org/distribution/leap/42.3/repo/non-oss/ OpenSUSE:42.3:SOURCE-NON-OSS
        # zypper ar -dcg http://download.opensuse.org/debug/distribution/leap/42.3/repo/oss/ OpenSUSE:42.3:DEBUG-OSS
        # zypper ar -dcg http://download.opensuse.org/debug/update/leap/42.3/oss/ OpenSUSE:42.3:DEBUG-UPDATE-OSS
    fi
}

funcKernelUpgrade(){
    case "${pack_manager}" in
        apt-get )
            case "${distro_name}" in
                ubuntu )
                    # linux-generic-hwe-16.04
                    local l_hwe_name
                    l_hwe_name=$(apt-cache search linux-generic-hwe 2> /dev/null | sed -r -n '1{s@^([^[:space:]]+).*$@\1@g;p}')
                    [[ -n "${l_hwe_name}" ]] && funcPackageManagerOperation 'install' "${l_hwe_name}"
                    ;;
                debian )
                    # http://jensd.be/818/linux/install-a-newer-kernel-in-debian-9-stretch-stable
                    funcCommandExistCheck 'apt-get' && apt-get -t "${codename}"-backports -y -q upgrade 2> /dev/null
                    ;;
            esac
            ;;
        zypper )
            # http://pvdm.xs4all.nl/wiki/index.php/How_to_have_the_latest_kernel_in_openSUSE
            if [[ "${distro_name}" == 'opensuse' ]]; then
                if [[ -s '/etc/zypp/zypp.conf' ]]; then
                    # multiversion = provides:multiversion(kernel)
                    # multiversion.kernels = latest,latest-1,running
                    zypper ar -fcg http://download.opensuse.org/repositories/Kernel:/HEAD/standard/ kernel-repo &> /dev/null
                    zypper dup -r kernel-repo &> /dev/null
                fi
            fi
            ;;
        yum )
            # https://www.tecmint.com/install-upgrade-kernel-version-in-centos-7/
            # ELRepo
            if [[ ! -f '/etc/yum.repos./elrepo.repo' ]]; then
                local elrepo_info
                elrepo_info=$($download_tool https://elrepo.org/tiki/tiki-index.php | sed -r -n '/rpm (--import|-Uvh)/{s@<[^>]*>@@g;s@.*(http.*)$@\1@g;p}' | sed ':a;N;$!ba;s@\n@|@g;')
                # https://www.elrepo.org/RPM-GPG-KEY-elrepo.org|http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm|http://www.elrepo.org/elrepo-release-6-8.el6.elrepo.noarch.rpm
                rpm --import "${elrepo_info%%|*}" 2> /dev/null
                elrepo_info="${elrepo_info#*|}"
                case "${version_id}" in
                    7 ) elrepo_info="${elrepo_info%%|*}" ;;
                    6 ) elrepo_info="${elrepo_info##*|}" ;;
                esac

                funcPackageManagerOperation 'install' "${elrepo_info}"

                # Long term support kernel package name is kernel-lt version
                # Mainline stable kernel package name is kernel-ml version

                # yum --disablerepo='*' --enablerepo='elrepo-kernel' list available
                # yum --disablerepo='*' --enablerepo='elrepo-kernel' -y -q install kernel-lt
                yum --disablerepo='*' --enablerepo='elrepo-kernel' -y -q install kernel-ml &> /dev/null

                case "${version_id}" in
                    7 )
                        # egrep ^menuentry /etc/grub2.cfg | cut -f 2 -d \'
                        funcCommandExistCheck 'grub2-set-default' && grub2-set-default 0 2> /dev/null
                    ;;
                    6 )
                        [[ -s '/etc/grub.conf' ]] && sed -r -i '/default=/{s@^([^+]+=).*$@\10@g;}' /etc/grub.conf
                    ;;
                esac
            fi
            ;;
    esac
}

funcPackRepositoryOperation(){
    funcOperationPhaseStatement 'Package Management'
    # apt-get|yum|dnf|zypper
    local pack_func_name=${pack_manager%%-*}
    # Repository Setting
    if [[ "${change_repository}" -eq 1 ]]; then
        funcOperationProcedureStatement "Repository configuration"
        funcRepository"${pack_func_name^^}"
        funcOperationProcedureResultStatement "${pack_func_name}"
    fi

    # package update
    funcOperationProcedureStatement 'Packages update'
    funcPackageManagerOperation
    funcPackageManagerOperation "upgrade"
    funcOperationProcedureResultStatement

    # install latest kernel
    if [[ "${kernel_upgrade}" -eq 1 ]]; then
        funcOperationProcedureStatement 'Kernel upgrade'
        funcKernelUpgrade
        funcOperationProcedureResultStatement
    fi
}


#########  2-2. SELinux Configuration #########
funcSELinuxConfiguration(){
    funcOperationPhaseStatement "Mandatory Access Control - SELinux"
    # Permissive SELinux defaultly
    # 0 - Permissive / 1 - Enforcing / 2 - Disabled

    # https://giunchi.net/how-to-enable-selinux-on-debian-stretch-9

    local l_selinux_state=''
    case "${selinux_setting,,}" in
        2|disabled|d ) l_selinux_state='disabled' ;;
        1|enforcing|e ) l_selinux_state='enforcing' ;;
        0|permissive|p|* ) l_selinux_state='permissive' ;;
    esac

    # - install packages
    if [[ "${pack_manager}" == 'apt-get' ]]; then
        echo "${c_bold}${c_red}Not suggest deploy SELinux on ${distro_fullname}, it may cause system problems.${c_normal}"
    elif [[ "${l_selinux_state}" != 'disabled' ]]; then
        if ! funcCommandExistCheck 'getenforce'; then
            funcOperationProcedureStatement "SELinux Utilities"
            local l_selinux_pack_list=''
            case "${pack_manager}" in
                # apt-get )
                #     # https://wiki.debian.org/SELinux/Setup
                #     l_selinux_pack_list='selinux-basics selinux-utils setools selinux-policy-default'
                #     [[ "${distro_name}" == 'ubuntu' ]] && l_selinux_pack_list="${l_selinux_pack_list} selinux"
                #     funcPackageManagerOperation 'install' "${l_selinux_pack_list}"
                #     selinux-activate &> /dev/null ;;
                # ;;
                dnf|yum )
                    l_selinux_pack_list='policycoreutils policycoreutils-python selinux-policy selinux-policy-targeted libselinux-utils setroubleshoot-server setools setools-console mcstrans'
                ;;
                zypper )
                    # https://en.opensuse.org/SDB:SELinux
                    # https://doc.opensuse.org/documentation/leap/security/html/book.security/cha.selinux.html
                    zypper_selinux=1
                    l_selinux_pack_list='selinux-policy selinux-policy-minimum selinux-policy-devel libselinux1 libselinux-devel libselinux-devel-static selinux-tools selinux-doc python-selinux checkpolicy policycoreutils policycoreutils-python mcstrans'
                ;;
            esac

            [[ -n "${l_selinux_pack_list}" ]] && funcPackageManagerOperation 'install' "${l_selinux_pack_list}"

            funcOperationProcedureResultStatement 'installation'
        fi
    fi

    # - configuration
    if [[ "${l_selinux_state}" != 'disabled' ]]; then
        case "${pack_manager}" in
            dnf|yum )
                [[ -f '/.autorelabel' ]] || touch '/.autorelabel'
            ;;
            zypper )
                # selinux-policy-minimum
                # /etc/selinux/minimum/contexts/files/file_contexts

                if [[ "${zypper_selinux}" -eq 1 ]]; then
                    local l_grub=${l_grub:-'/etc/default/grub'}
                    if [[ -s "${l_grub}" ]]; then
                        # yast2 bootloader
                        # System › Boot Loader › Kernel Parameters. (Alt + P), add the following parameters to the Optional Kernel Command Line Parameters: 'security=selinux selinux=1 enforcing=0'
                        sed -r -i '/GRUB_CMDLINE_LINUX_DEFAULT=/d' "${l_grub}"
                        sed -r -i '$a GRUB_CMDLINE_LINUX_DEFAULT="security=selinux selinux=1 enforcing=0"' "${l_grub}"

                        # via function funcGRUBConfiguring
                        # grub2-mkconfig -o /boot/grub2/grub.cfg &> /dev/null
                    fi

                    # Note that you cannot start restorecond until you boot a kernel with the parameters mentioned above, so let's just enable it for now, without starting.
                    funcCommandExistCheck 'systemctl' && systemctl enable restorecond &> /dev/null
                fi

                # after reboot, execute the following command , file system labeling
                # funcCommandExistCheck 'restorecon' && restorecon -Rp /

                # selinux check
                # selinux-ready
            ;;
        esac
    fi

    # - policy modification
    local l_selinux_config=${l_selinux_config:-'/etc/selinux/config'}
    if [[ -f "${l_selinux_config}" ]]; then
        funcOperationProcedureStatement "Directives configuration"
        [[ -f "${l_selinux_config}${bak_suffix}" ]] || cp -fp "${l_selinux_config}" "${l_selinux_config}${bak_suffix}"
        # 0 - Permissive / 1 - Enforcing / 2 - Disabled

        # ☆ SUSE/OpenSUSE just use SELINUXTYPE=minimum because package selinux-policy-minimum
        local l_selinux_type=${l_selinux_type:-'targeted'}
        if [[ "${zypper_selinux}" -eq 1 ]]; then
            l_selinux_state='permissive'
            l_selinux_type='minimum'
        fi
        [[ "${pack_manager}" == 'zypper' ]] && l_selinux_type='minimum'

        sed -r -i '/^#?[[:space:]]*SELINUX=[^[:space:]]+/{s@^#?[[:space:]]*(SELINUX=).*$@\1'"${l_selinux_state}"'@g}' "${l_selinux_config}"

        if [[ "${l_selinux_state}" == 'disabled' ]]; then
            sed -r -i '/^#?[[:space:]]*SELINUXTYPE=[^[:space:]]+/{s@^#?[[:space:]]*(SELINUXTYPE=).*$@#\1'"${l_selinux_type}"'@g}' "${l_selinux_config}"
        else
            sed -r -i '/^#?[[:space:]]*SELINUXTYPE=[^[:space:]]+/{s@^#?[[:space:]]*(SELINUXTYPE=).*$@\1'"${l_selinux_type}"'@g}' "${l_selinux_config}"
        fi
        funcOperationProcedureResultStatement "${l_selinux_state^}"
    fi
}

#########  2-3. GRUB Configuring  #########
funcGRUBConfiguring(){
    funcOperationPhaseStatement 'GRUB Configuration'
    # cat /proc/cmdline

    funcOperationProcedureStatement 'GRUB_TIMEOUT'

    local grub_regexp='^[-+]?[0-9]{1,}(\.[0-9]*)?$'
    if [[ "${grub_timeout}" =~ $grub_regexp ]]; then
        grub_timeout=${grub_timeout/[-+]}
        grub_timeout=${grub_timeout%%.*}
        [[ "${grub_timeout}" -gt 4 ]] && grub_timeout=4
    else
        grub_timeout="${default_grub_timeout}"
    fi

    if [[ -f /etc/default/grub ]]; then
        sed -r -i '/^GRUB_TIMEOUT=/s@^(GRUB_TIMEOUT=).*@\1'"${grub_timeout}"'@g' /etc/default/grub

        case "${pack_manager}" in
            apt-get )
                funcCommandExistCheck 'update-grub' && update-grub &> /dev/null
                ;;
            zypper|dnf|yum )
                if [[ -f "/boot/efi/EFI/${distro_name}/grub.cfg" ]]; then
                    # UEFI-based machines
                    grub2-mkconfig -o "/boot/efi/EFI/${distro_name}/grub.cfg" &> /dev/null
                else
                    # BIOS-based machines
                    grub2-mkconfig -o /boot/grub2/grub.cfg &> /dev/null
                fi
                ;;
        esac

    elif [[ -f /etc/grub.conf ]]; then
        sed -r -i '/^timeout=/s@^(timeout=).*@\1'"$grub_timeout"'@g' /etc/grub.conf
    fi

    funcOperationProcedureResultStatement "${grub_timeout}s"
}


#########  2-4. Hostname & Timezone Setting  #########
funcTimezoneDetection(){
    local l_new_timezone=${1:-''}
    local l_timezone=${l_timezone:-''}

    if [[ -n "${l_new_timezone}" ]]; then
        if [[ -f "/usr/share/zoneinfo/${l_new_timezone}" ]]; then
            l_timezone="${l_new_timezone}"
        else
            l_timezone=$(funcTimezoneDetection)
        fi
    else
        l_timezone="${ip_public_timezone}"
        [[ -z "${l_timezone}" ]] && l_timezone="${default_timezone}"
    fi
    echo "${l_timezone}"
}

funcHostnameTimezoneSetting(){
    funcOperationPhaseStatement "Hostname & Timezone"

    # - Hostname Setting
    funcOperationProcedureStatement "Hostname configuration"
    local current_existed_hostname=${current_existed_hostname:-}
    current_existed_hostname=$(hostname)

    if [[ -z "${hostname_specify}" ]]; then
        if [[ -n "${codename}" ]]; then
            hostname_specify="${codename^}"
        elif [[ -n "${distro_name}" ]]; then
            hostname_specify="${distro_name^}"
        fi

        local l_host_ip
        # prefer internal ip
        if [[ -n "${ip_local}" ]]; then
            l_host_ip="${ip_local}"
        elif [[ -n "${ip_public}" && "${ip_public}" =~ ^([0-9]{1,3}.){3}[0-9]{1,3}$ ]]; then
            l_host_ip="${ip_public}"
        else
            l_host_ip="$RANDOM"
        fi

        l_host_ip="${l_host_ip//./-}"

        if [[ "${codename}" == 'wheezy' ]]; then
            hostname_specify="${hostname_specify}${l_host_ip}"
        else
            hostname_specify="${hostname_specify}-${l_host_ip}"
        fi    # end if codename

    fi    # end if hostname_specify

    if funcCommandExistCheck 'hostnamectl'; then
        hostnamectl set-hostname "${hostname_specify}"
    else
        hostname "${hostname_specify}" &> /dev/null   # temporarily change, when reboot, it will recover
        if [[ -f '/etc/sysconfig/network' ]]; then
            sed -r -i '/^HOSTNAME=/s@^(HOSTNAME=).*@\1'"${hostname_specify}"'@g' /etc/sysconfig/network #RHEL
        elif [[ -f '/etc/hostname' ]]; then
            echo "${hostname_specify}" > /etc/hostname  #Debian/OpenSUSE
        fi
    fi

    local hosts_path=${hosts_path:-'/etc/hosts'}
    if [[ -f "${hosts_path}" ]]; then
        sed -r -i '/^(127.0.0.1|::1)/s@ '"${current_existed_hostname}"'@ '"${hostname_specify}"'@g' "${hosts_path}"

        if [[ -z $(sed -r -n '/^127.0.0.1/{/'"${hostname_specify}"'/p}' "${hosts_path}") ]]; then
            if [[ -z $(sed -r -n '/^127.0.0.1/p' "${hosts_path}") ]]; then
                sed -i '$a 127.0.0.1 '"${hostname_specify}"'' "${hosts_path}"
            else
                sed -i '/^127.0.0.1/a 127.0.0.1 '"${hostname_specify}"'' "${hosts_path}"
            fi
        fi
    fi
    funcOperationProcedureResultStatement "${hostname_specify}"

    # - Timezone Setting
    funcOperationProcedureStatement "Timezone configuration"

    new_timezone=$(funcTimezoneDetection "${timezone_specify}")

    if funcCommandExistCheck 'timedatectl'; then
        timedatectl set-timezone "${new_timezone}"
        timedatectl set-local-rtc false
        timedatectl set-ntp true
    else
        if [[ "${pack_manager}" == 'apt-get' ]]; then
            echo "${new_timezone}" > /etc/timezone
            funcCommandExistCheck 'dpkg-reconfigure' && dpkg-reconfigure -f noninteractive tzdata &> /dev/null
        else
            # RHEL/OpenSUSE
            local localtime_path='/etc/localtime'
            local new_timezone_path="/usr/share/zoneinfo/${new_timezone}"
            [[ -f "${localtime_path}" ]] && rm -f "${localtime_path}"
            ln -fs "${new_timezone_path}" "${localtime_path}"
        fi
    fi
    funcOperationProcedureResultStatement "${new_timezone}"
}


#########  2-5. Login User Configuration  #########
funcLoginDirectivesConfiguration(){
    local l_item="${1:-}"
    local l_val="${2:-}"
    local l_path="${3:-}"
    local l_type="${4:-'login'}"

    # - login: /etc/login.defs
    # - passwd: /etc/security/pwquality.conf

    if [[ -n "${l_item}" && -n "${l_val}" && -s "${l_path}" ]]; then
        case "${l_type,,}" in
            l|login ) sed -r -i '/^'"${l_item}"'[[:space:]]+/{s@^([^[:space:]]+[[:space:]]+).*$@\1'"${l_val}"'@g;}' "${l_path}" 2> /dev/null ;;
            p|passwd|password ) sed -r -i '/^#?[[:space:]]*'"${l_item}"'[[:space:]]=/{s@^#?[[:space:]]*([^[:space:]]+[[:space:]]*=[[:space:]]*).*@\1'"${l_val}"'@g;}' "${l_path}" 2> /dev/null ;;
        esac
    fi
}

funcSystemUserConfiguration(){
    funcOperationPhaseStatement "System User Management"

    [[ "${pack_manager}" == 'apt-get' && ! -f '/lib/x86_64-linux-gnu/security/pam_pwquality.so' ]] && funcPackageManagerOperation 'install' 'libpam-pwquality'


    local l_pwquaility_path=${l_pwquaility_path:-'/etc/security/pwquality.conf'}
    if [[ -s "${l_pwquaility_path}" ]]; then
        funcOperationProcedureStatement "Password quality configuration"
        funcLoginDirectivesConfiguration 'difok' '5' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'minlen' '10' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'minclass' '4' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'maxrepeat' '0' "${l_pwquaility_path}" 'passwd'
        # The check is disabled if the value is 0.
        funcLoginDirectivesConfiguration 'maxclassrepeat' '0' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'lcredit' '0' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'ucredit' '0' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'dcredit' '0' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'ocredit' '0' "${l_pwquaility_path}" 'passwd'
        funcLoginDirectivesConfiguration 'gecoscheck' '0' "${l_pwquaility_path}" 'passwd'
        funcOperationProcedureResultStatement "${l_pwquaility_path}"
    fi

    # - Shadow password configuration
    local l_login_defs=${l_login_defs:-'/etc/login.defs'}
    if [[ -s "${l_login_defs}" ]]; then
        funcOperationProcedureStatement "Shadow password configuration"
        # https://www.poftut.com/linux-etc-login-defs-configuration-examples/
        funcLoginDirectivesConfiguration 'PASS_MAX_DAYS' "${pass_change_maxday}" "${l_login_defs}"
        funcLoginDirectivesConfiguration 'PASS_MIN_DAYS' "${pass_change_minday}" "${l_login_defs}"
        funcLoginDirectivesConfiguration 'PASS_WARN_AGE' "${pass_change_warnningday}" "${l_login_defs}"
        # funcLoginDirectivesConfiguration 'UMASK' "${umask_default}" "${l_login_defs}"
        funcLoginDirectivesConfiguration 'ENCRYPT_METHOD' 'SHA512' "${l_login_defs}"
        funcLoginDirectivesConfiguration 'LOG_UNKFAIL_ENAB' 'no' "${l_login_defs}"
        funcOperationProcedureResultStatement "${l_login_defs}"
    fi

    # - sudoers file configuration
    funcCommandExistCheck 'sudo' || funcPackageManagerOperation 'install' "sudo"
    local user_if_existed=${user_if_existed:-0}
    local sudo_config_path=${sudo_config_path:-'/etc/sudoers'}

    # add normal user into group sudo/wheel without prompt password
    if [[ -n "${username_specify}" && -f "${sudo_config_path}" ]]; then
        funcOperationProcedureStatement "sudoers config file"
        [[ -f "${sudo_config_path}${bak_suffix}" ]] || cp -fp "${sudo_config_path}" "${sudo_config_path}${bak_suffix}"

        # disable sudo su - / sudo su root
        if [[ "${pack_manager}" == 'apt-get' ]]; then
            sed -r -i 's@#*[[:space:]]*(%sudo[[:space:]]+ALL=\(ALL:ALL\)[[:space:]]+ALL)@# \1@;/%sudo ALL=NOPASSWD:ALL/d;/group sudo/a %sudo ALL=NOPASSWD:ALL,!/bin/su' "${sudo_config_path}"
        else
            sed -r -i 's@#*[[:space:]]*(%wheel[[:space:]]+ALL=\(ALL\)[[:space:]]+ALL)@# \1@;s@#*[[:space:]]*(%wheel[[:space:]]+ALL=\(ALL\)[[:space:]]+NOPASSWD: ALL).*@\1,!/bin/su@' "${sudo_config_path}"
        fi
        funcOperationProcedureResultStatement "${sudo_config_path}"
    fi

    # - Normal user add/configuration
    if [[ -n "${username_specify}" ]]; then
        funcOperationProcedureStatement "Normal user"
        # Debian/Ubuntu: sudo      RHEL/OpenSUSE: wheel
        local sudo_group_name=${sudo_group_name:-'wheel'}
        [[ "${pack_manager}" == 'apt-get' ]] && sudo_group_name='sudo'

        if [[ -z $(awk -F: 'match($1,/^'"${username_specify}"'$/){print}' /etc/passwd) ]]; then
            # type 1 - create new user and add it into group wheel/sudo
            if [[ "${grant_sudo}" -eq 1 ]]; then
                useradd -mN -G "${sudo_group_name}" "${username_specify}" &> /dev/null
            else
                useradd -mN "${username_specify}" &> /dev/null
            fi

            # user: 'root', passwd: 'Root@2017'
            local new_password
            new_password="${username_specify^}@$(date +'%Y')"

            # Debian/SUSE not support --stdin
            case "${pack_manager}" in
                # https://debian-administration.org/article/668/Changing_a_users_password_inside_a_script
                apt-get ) echo "${username_specify}:${new_password}" | chpasswd &> /dev/null ;;
                dnf|yum ) echo "${new_password}" | passwd --stdin "${username_specify}" &> /dev/null ;;
                # https://stackoverflow.com/questions/27837674/changing-a-linux-password-via-script#answer-27837785
                zypper ) echo -e "${new_password}\n${new_password}" | passwd "${username_specify}" &> /dev/null ;;
            esac

            # setting user password expired date
            passwd -n "${pass_change_minday}" -x "${pass_change_maxday}" -w "${pass_change_warnningday}" "${username_specify}"  &> /dev/null
            chage -d0 "${username_specify}" &> /dev/null  # new created user have to change passwd when first login
        else
            # type 2 - user has been existed
            # gpasswd -a "${username_specify}"  "${sudo_group_name}" 1> /dev/null
            [[ "${grant_sudo}" -eq 1 ]] && usermod -a -G "${sudo_group_name}" "${username_specify}" 2> /dev/null
            local user_if_existed=1
        fi

        if [[ "${grant_sudo}" -eq 1 ]]; then
            if [[ "${user_if_existed}" -eq 1 ]]; then
                funcOperationProcedureResultStatement "${username_specify} (existed) ∈ ${sudo_group_name}"
            else
                funcOperationProcedureResultStatement "${username_specify} ∈ ${sudo_group_name}, initial password ${new_password}"
            fi
        else
            if [[ "${user_if_existed}" -eq 1 ]]; then
                funcOperationProcedureResultStatement "${username_specify} (existed)"
            else
                funcOperationProcedureResultStatement "${username_specify}, initial password ${new_password}"
            fi
        fi    # end if grant_sudo

    fi    # end if username_specify

    # Just for personal preference via '-b'
    if [[ "${boost_enable}" -eq 1 ]]; then
        local l_target_user_home=${l_target_user_home:-"${login_user_home}"}
        local l_target_user=${l_target_user:-"${login_user}"}
        if [[ -n "${username_specify}" && "${login_user}" == 'root' && "${login_user}" != "${username_specify}" ]]; then
            l_target_user="${username_specify}"
            l_target_user_home="/home/${username_specify}"
        fi

        # ~/.bashrc
        local l_bashrc_path=${l_bashrc_path:-"${l_target_user_home}/.bashrc"}
        if [[ -s "${l_bashrc_path}" ]]; then
            sed -r -i '/Custom Setting Start/,/Custom Setting End/d' "${l_bashrc_path}" &> /dev/null
            $download_tool "${custom_shellscript_url}/master/configs/preferences/bashrc" >> "${l_bashrc_path}"

            # system update for specific distro
            sed -r -i '/Custom Setting Start/,/Custom Setting End/{/_distro_update=/{/'"${pack_manager}"'/!d;s@^#?[[:space:]]*@@g;}}' "${l_bashrc_path}"
            # remove older version kernel
            sed -r -i '/Custom Setting Start/,/Custom Setting End/{/_distro_old_kernel=/{/'"${pack_manager}"'/!d;s@^#?[[:space:]]*@@g;}}' "${l_bashrc_path}"
        fi

        # ~/.ssh
        local l_ssh_dir=${l_ssh_dir:-"${l_target_user_home}/.ssh"}
        local l_ssh_config_path=${l_ssh_config_path:-"${l_ssh_dir}/config"}
        [[ -d "${l_ssh_dir}" ]] || mkdir -p "${l_ssh_dir}"
        if [[ ! -d "${l_ssh_dir}/sockets" ]]; then
            mkdir -p "${l_ssh_dir}/sockets"
            chmod 700 "${l_ssh_dir}/sockets"
        fi
        [[ -s "${l_ssh_config_path}" ]] || $download_tool "${custom_shellscript_url}/master/configs/preferences/ssh_config" > "${l_ssh_config_path}"
        chmod 600 "${l_ssh_config_path}"
        chmod 700 "${l_ssh_dir}"
        chown -R "${l_target_user}" "${l_ssh_dir}"
    fi    # end if boost_enable

}


#########  2-6. Essential/Administration Packages Installation  #########
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

funcEssentialPackInstallation(){
    funcOperationPhaseStatement "Essential Packages Installation"

    if [[ "${pack_manager}" == 'apt-get' ]]; then
        funcCommandExistCheck 'systemctl' || funcPackageOperationProcedureStatement 'install' "sysv-rc-conf" # same to chkconfig
        # https://github.com/koalaman/shellcheck/wiki/SC2143
        if ! dpkg --list | grep -q 'firmware-linux-nonfree'; then
            funcPackageOperationProcedureStatement 'install' 'firmware-linux-nonfree'
        fi
        funcPackageOperationProcedureStatement 'install' 'apt-show-versions debsums'
    fi

    [[ -s '/usr/share/bash-completion/bash_completion' || -s '/etc/profile.d/bash_completion.sh' ]] || funcPackageOperationProcedureStatement 'install' "bash-completion"
    funcCommandExistCheck 'bc' || funcPackageOperationProcedureStatement 'install' 'bc'

    # https://en.wikipedia.org/wiki/Util-linux
    # util-linux is a standard package distributed by the Linux Kernel Organization for use as part of the Linux operating system.
    local util_linux=${util_linux:-'util-linux'}
    [[ "${pack_manager}" == 'yum' ]] && util_linux='util-linux-ng'
    funcCommandExistCheck 'getopt' || funcPackageOperationProcedureStatement 'install' "${util_linux}"

    # - Haveged Installation for random num generation
    local rng_config_path=${rng_config_path:-'/etc/default/rng-tools'}
    if [[ ! -f "${rng_config_path}" ]]; then
        funcPackageOperationProcedureStatement 'install' "rng-tools haveged"
        if [[ -f "${rng_config_path}" ]]; then
            [[ -f "${rng_config_path}${bak_suffix}" ]] || cp -fp "${rng_config_path}" "${rng_config_path}${bak_suffix}"
            sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' "${rng_config_path}"
        fi
    fi

    # - Chrony
    case "${pack_manager}" in
        apt-get )
            # https://github.com/koalaman/shellcheck/wiki/SC2143
            if dpkg --list | grep -q 'ntp'; then
                funcPackageOperationProcedureStatement 'remove' "ntp"
            fi

            if ! dpkg --list | grep -q 'chrony'; then
                funcPackageOperationProcedureStatement 'install' "chrony"
                funcSystemServiceManager 'chrony' 'enable'
            fi
            ;;
        dnf|yum )
            [[ $(rpm -qa | awk -F- 'match($1,/^ntp$/){print $1}') == 'ntp' ]] && funcPackageOperationProcedureStatement "remove" "ntp"
            if [[ $(rpm -qa | awk -F- 'match($1,/^chrony$/){print $1}') == 'chrony' ]]; then
                funcPackageOperationProcedureStatement 'install' "chrony"
                funcSystemServiceManager 'chronyd' 'enable'
            fi
            ;;
        zypper )
            # zypper packages -i 操作較爲耗時，約2.5s
            [[ -z $(zypper packages -i | awk -F\| 'match($3,/^[[:space:]]*ntp[[:space:]]*$/){print}') ]] || funcPackageOperationProcedureStatement "remove" "ntp"

            if [[ -z $(zypper packages -i | awk -F\| 'match($3,/^[[:space:]]*chrony[[:space:]]*$/){print}') ]]; then
                funcPackageOperationProcedureStatement 'install' "chrony"
                [[ -f '/etc/ntp.conf.rpmsave' ]] && rm -f '/etc/ntp.conf.rpmsave'
                funcSystemServiceManager 'chronyd' 'enable'
            fi
            ;;
    esac

    # - Filesystem
    # mlocate: locate   /etc/cron.daily/mlocate
    funcCommandExistCheck 'locate' || funcPackageOperationProcedureStatement 'install' 'mlocate' 'locate'
    funcCommandExistCheck 'tree' || funcPackageOperationProcedureStatement 'install' "tree"

    #  - Compress & Decompress
    funcCommandExistCheck 'tar' || funcPackageOperationProcedureStatement 'install' "tar"
    # .tar.gz
    funcCommandExistCheck 'gzip' || funcPackageOperationProcedureStatement 'install' "gzip"
    # .tar.bz2
    funcCommandExistCheck 'bzip2' || funcPackageOperationProcedureStatement 'install' "bzip2"
    # .tar.xz
    local l_xz_name=${l_xz_name:-'xz'}
    [[ "${pack_manager}" == 'apt-get' ]] && l_xz_name='xz-utils'
    funcCommandExistCheck 'xz' || funcPackageOperationProcedureStatement 'install' "${l_xz_name}"

    # - VIM text editor
    local l_install_vim=${l_install_vim:-1}
    funcCommandExistCheck 'vim' && l_install_vim=0
    if [[ "${l_install_vim}" -eq 1 ]]; then
        funcOperationProcedureStatement "VIM text editor"

        local vim_pack_name=${vim_pack_name:-'vim'}
        case "${pack_manager}" in
            dnf|yum ) vim_pack_name='vim-enhanced' ;;
        esac
        funcPackageManagerOperation 'install' "${vim_pack_name}"

        local vim_config=${vim_config:-'/etc/vimrc'}
        [[ -f '/etc/vim/vimrc' ]] && vim_config='/etc/vim/vimrc'

        if [[ -f "${vim_config}" ]]; then
            [[ -f "${vim_config}${bak_suffix}" ]] || cp -fp "${vim_config}" "${vim_config}${bak_suffix}"
            sed -i -r '/custom configuration start/,/custom configuration end/d' "${vim_config}"
            $download_tool "$vim_url" >> "${vim_config}"
        fi

        # https://www.cyberciti.biz/faq/vim-vi-text-editor-save-file-without-root-permission/
        # :w !sudo tee %
        # command W :execute ':silent w !sudo tee % > /dev/null' | :edit!

        # vim cut&paste not working in Stretch / Debian 9
        # https://unix.stackexchange.com/questions/318824/vim-cutpaste-not-working-in-stretch-debian-9
        # set mouse-=a
        if [[ "${distro_name}" == 'debian' && "${codename}" == 'stretch' ]]; then
            local vim_defaults=${vim_defaults:-'/usr/share/vim/vim80/defaults.vim'}
            [[ -s "${vim_defaults}" ]] && sed -i -r "/^if has\('mouse'\)/,+2{s@^@\"@g}" "${vim_defaults}"
        fi
        funcOperationProcedureResultStatement
    fi

    # - Remove unneeded packages
    if [[ "${remove_unneeded_pack}" -eq 1 ]]; then
        funcOperationProcedureStatement "Remove unneeded utilities"

        # if [[ "${pack_manager}" == 'apt-get' ]]; then
        #     dpkg -l 2>&1 | awk 'match($1,/^rc$/){print $2}' | xargs dpkg --purge 2> /dev/null
        # fi

        funcCommandExistCheck 'gnome-shell' && funcPackageManagerOperation 'remove' 'evolution totem rhythmbox empathy brasero bijiben gnome-maps gnome-music gnome-clocks gnome-contacts gnome-weather'

        if [[ $(find /usr/share/applications -type f -name '*.desktop' -print 2>/dev/null | wc -l) -gt 0 ]]; then
            # - Game
            local game_pack_list=${game_pack_list:-}
            game_pack_list=$(grep Game /usr/share/applications/*.desktop | awk -F: '{!a[$1]++}END{for(i in a) print i}' | while read -r line; do sed -r -n '/Exec/{s@.*=([^[:space:]]+).*@\1@g;p}' "${line}" | awk '{!a[$0]++}END{print}'; done | sed ':a;N;s@\n@ @g;t a;')
            [[ -z "${game_pack_list}" ]] || funcPackageManagerOperation 'remove' "${game_pack_list}"

            # grep Game /usr/share/applications/*.desktop | awk -F: '{!a[$1]++}END{for(i in a) print i}' | while read -r line;do sed -r -n '/Exec/{s@.*=([^[:space:]]+).*@\1@g;p}' "${line}" | awk '{if($0=="sol"){$0="aisleriot"};!a[$0]++}END{print}'; done | xargs -- sudo zypper rm -yu
        fi
        funcOperationProcedureResultStatement
    fi
}

funcAdministrationPackInstallation(){
    funcOperationPhaseStatement "Administration Packages Installation"
    # https://www.cyberciti.biz/tips/top-linux-monitoring-tools.html

    # - parallel computing
    # pssh - Parallel versions of SSH-based tools
    # https://www.virtualconfusion.net/articles/use-pssh-to-manage-several-servers
    local l_pssh_name='pssh'
    [[ "${pack_manager}" == 'apt-get' ]] && l_pssh_name='parallel-ssh'
    if ! funcCommandExistCheck "${l_pssh_name}"; then
        funcOperationProcedureStatement "parallel SSH tools"
        funcPackageManagerOperation 'install' 'pssh'
        funcOperationProcedureResultStatement "${l_pssh_name}"
    fi
    # pdsh - issue commands to groups of hosts in parallel
    funcCommandExistCheck 'pdsh' || funcPackageOperationProcedureStatement 'install' "pdsh"
    # - parallel - build and execute command lines from standard input in parallel
    if ! funcCommandExistCheck 'parallel'; then
        local parallel_name=${parallel_name:-'parallel'}
        # SLES repo in AWK has no parallel utility
        [[ "${pack_manager}" == 'zypper' ]] && parallel_name='gnu_parallel'

        # sudo parallel --bibtex ==> Type: 'will cite' and press enter.
        funcCommandExistCheck 'parallel' && echo 'will cite' | parallel --bibtex &> /dev/null
        funcPackageOperationProcedureStatement 'install' "${parallel_name}"
    fi

    # ☆ sysstat - Collection of performance monitoring tools for Linux
    # The sysstat package contains the following system performance tools:
    # - sar: collects and reports system activity information;
    # - iostat: reports CPU utilization and disk I/O statistics;
    # - tapestat: reports statistics for tapes connected to the system;
    # - mpstat: reports global and per-processor statistics;
    # - pidstat: reports statistics for Linux tasks (processes);
    # - sadf: displays data collected by sar in various formats;
    # - cifsiostat: reports I/O statistics for CIFS filesystems.
    #
    # The statistics reported by sar deal with I/O transfer rates, paging activity, process-related activities, interrupts, network activity, memory and swap space utilization, CPU utilization, kernel activities and TTY statistics, among others. Both UP and SMP machines are fully supported.

    # - read log in /var/log/sa/
    # sar -f /var/log/sa/sa04
    # - see all statistics
    # sar -A
    # mpstat -P ALL

    if ! funcCommandExistCheck 'iostat'; then
        funcOperationProcedureStatement 'sysstat utility'
        funcPackageManagerOperation 'install' 'sysstat'

        local l_sysstat_path='/etc/sysconfig/sysstat'
        [[ -s "${l_sysstat_path}" ]] || l_sysstat_path='/etc/sysstat/sysstat'
        if [[ -s "${l_sysstat_path}" ]]; then
            sed -r -i '/^#?[[:space:]]*HISTORY=/{s@^#?[[:space:]]*([^=]+=).*$@\128@g}' "${l_sysstat_path}"
            sed -r -i '/^#?[[:space:]]*REPORTS=/{s@^#?[[:space:]]*([^=]+=).*$@\1true@g}' "${l_sysstat_path}"
        fi

        # https://www.crybit.com/sysstat-sar-on-ubuntu-debian/
        # https://www.server-world.info/en/note?os=Ubuntu_16.04&p=sysstat
        if [[ "${pack_manager}" == 'apt-get' ]]; then
            local l_default_sysstat='/etc/default/sysstat'
            [[ -s "${l_default_sysstat}" ]] && sed -r -i '/^ENABLED=/{s@^([^"]+").*(")$@\1true\2@g}' "${l_default_sysstat}"

            local l_cron_sysstat='/etc/cron.d/sysstat'
            # Generate a daily summary of process accounting at 23:53
            # 53 23 * * * root command -v sa2 > /dev/null && sa2 -A
            if [[ -s "${l_cron_sysstat}" ]]; then
                sed -r -i '/Generate a daily summary/,+1{d}' "${l_cron_sysstat}"
                sed -r -i '$a # Generate a daily summary of process accounting at 23:53\n53 23 * * * root command -v sa2 > /dev/null && sa2 -A' "${l_cron_sysstat}"
            fi
        fi

        funcSystemServiceManager 'sysstat' 'enable'
        funcSystemServiceManager 'sysstat' 'restart'
        funcOperationProcedureResultStatement 'sar/iostat/mpstat/pidstat'
    fi

    # ☆ nmon - systems administrator, tuner, benchmark tool.
    funcCommandExistCheck 'nmon' || funcPackageOperationProcedureStatement 'install' 'nmon'
    # ☆ glances - CLI curses based monitoring tool
    # funcCommandExistCheck 'glances' || funcPackageOperationProcedureStatement 'install' 'glances'
    # nmap - Network exploration tool and security / port scanner
    funcCommandExistCheck 'nmap' || funcPackageOperationProcedureStatement 'install' 'nmap'

    # - Network
    #  iproute: ip, ss, bridge, rtacct, rtmon, tc, ctstat, lnstat, nstat, routef, routel, rtstat, tipc, arpd and devlink
    if ! funcCommandExistCheck 'ss'; then
        local iproute_name=${iproute_name:-'iproute'}
        case "${pack_manager}" in
            apt-get|zypper ) iproute_name='iproute2' ;;
            dnf|yum ) iproute_name='iproute' ;;
        esac
        funcPackageOperationProcedureStatement 'install' "${iproute_name}" 'ip/ss/bridge/...'
    fi

    # ☆ iptraf-ng - Interactive Colorful IP LAN Monitor
    funcCommandExistCheck 'iptraf-ng' || funcPackageOperationProcedureStatement 'install' 'iptraf-ng'
    # iftop - displays bandwidth usage information on an network interface
    funcCommandExistCheck 'iftop' || funcPackageOperationProcedureStatement 'install' 'iftop'
    # ☆ tcpdump - dump traffic on a network
    funcCommandExistCheck 'tcpdump' || funcPackageOperationProcedureStatement 'install' 'tcpdump'
    # whois - Searches for an object in a RFC 3912 database.
    funcCommandExistCheck 'whois' || funcPackageOperationProcedureStatement 'install' 'whois'
    # hping
    local hping_name=${hping_name:-'hping'}
    case "${pack_manager}" in
        apt-get|zypper ) hping_name='hping3' ;;
        * ) hping_name='hping' ;;
    esac
    funcCommandExistCheck "${hping_name}" || funcPackageOperationProcedureStatement 'install' "${hping_name}"

    # dnsutils/bind-utils: dig nslookup nsupdate
    if ! funcCommandExistCheck 'dig'; then
        local dns_utils=${dns_utils:-'dnsutils'}
        [[ "${pack_manager}" != 'apt-get' ]] && dns_utils='bind-utils'
        funcPackageOperationProcedureStatement 'install' "${dns_utils}" 'dig/nslookup/nsupdate'
    fi

    # traceroute - Traces the route taken by packets over an IPv4/IPv6 network
    funcCommandExistCheck 'traceroute' || funcPackageOperationProcedureStatement 'install' 'traceroute'
    # ☆ mtr - a network diagnostic tool
    funcCommandExistCheck 'mtr' || funcPackageOperationProcedureStatement 'install' 'mtr'

    # nmcli - Network Manager Command Line Interface
    # NetworkManager stores all network configuration as "connections", which are collections of data (Layer2 details, IP addressing, etc.) that describe how to create or connect to a  network. A connection is "active" when a device uses that connection\'s configuration to create or connect to a network. There may be multiple connections that apply to a device, but only one of them can be active on that device at any given time. The additional connections can be used to allow quick switching between different networks and configurations.

    # nmcli general status
    # nmcli dev status
    # nmcli con/connection show [-a]
    # nmcli con add type ethernet con-name ${NAME_OF_CONNECTION} ifname ${interface-name} ip4 ${IP_ADDRESS} gw4 ${GW_ADDRESS}
    # nmcli con add type ethernet con-name static2 ifname enp0s3 ip4 192.168.1.50/24 gw4 192.168.1.1
    # nmcli con mod static2 ipv4.dns “8.8.8.8 8.8.4.4”
    # nmcli con down static1 ; nmcli con up static2
    # https://www.tecmint.com/configure-network-connections-using-nmcli-tool-in-linux/
    local nmcli_pack_name='NetworkManager'
    [[ "${pack_manager}" == 'apt-get' ]] && nmcli_pack_name='network-manager'
    funcCommandExistCheck 'nmcli' || funcPackageOperationProcedureStatement 'install' "${nmcli_pack_name}" 'nmcli'


    # - Process /proc
    # ☆ htop - interactive process viewer
    funcCommandExistCheck 'htop' || funcPackageOperationProcedureStatement 'install' 'htop'
    # ☆ atop - Advanced System & Process Monitor
    funcCommandExistCheck 'atop' || funcPackageOperationProcedureStatement 'install' 'atop'
    # psmisc: pstree/prtstat/peekfd/killall/fuser
    funcCommandExistCheck 'pstree' || funcPackageOperationProcedureStatement 'install' 'psmisc' 'pstree/prtstat/killall/...'

    # procps: free, kill, pkill, pgrep, pmap, ps, pwdx, skill, slabtop, snice, sysctl, tload, top, uptime, vmstat, w, and watch.
    # pmap: reports the memory map of a process or processes
    # pmap -d 6382
    if ! funcCommandExistCheck 'pkill'; then
        local procps_name=${procps_name:-'procps'}
        [[ "${pack_manager}" == 'dnf' ]] && procps_name='procps-ng'
        funcPackageOperationProcedureStatement 'install' "${procps_name}" 'free/kill/ps/top/...'
    fi

    # - Disk I/O
    # ☆ dstat: a versatile replacement for vmstat, iostat and ifstat.
    # versatile tool for generating system resource statistics
    funcCommandExistCheck 'dstat' || funcPackageOperationProcedureStatement 'install' 'dstat'
    # iotop - simple top-like I/O monitor
    funcCommandExistCheck 'iotop' || funcPackageOperationProcedureStatement 'install' 'iotop'

    # - System call
    # strace - trace system calls and signals
    # https://www.tecmint.com/strace-commands-for-troubleshooting-and-debugging-linux/
    funcCommandExistCheck 'strace' || funcPackageOperationProcedureStatement 'install' 'strace'
}


#########  2-7. OpenSSH Configuration  #########
funcOpenSSHDirectiveSetting(){
    local l_item="${1:-}"
    local l_val="${2:-}"
    # sshd_config directive lists
    local l_list="${3:-}"
    local l_path=${l_path:-'/etc/ssh/sshd_config'}

    if [[ -n "${l_item}" && -n "${l_val}" && -s "${l_path}" && -n $(sed -n '/^'"${l_item}"'$/p' "${l_list}" 2> /dev/null) ]]; then
        local l_record_origin=${l_record_origin:-}
        # if result has more then one line, use double quote "" wrap it
        # - whole line start with keyword, format 'PermitEmptyPasswords no'
        l_record_origin=$(sed -r -n '/^'"${l_item}"'[[:space:]]+/{s@[[:space:]]*$@@g;p}' "${l_path}")
        # - whole line inclue keyword start with "#", format '#PermitEmptyPasswords no'
        record_origin_comment=$(sed -r -n '/^#[[:space:]]*'"${l_item}"'[[:space:]]+/{s@[[:space:]]*$@@g;p}' "${l_path}")

        if [[ -z "${l_record_origin}" ]]; then
            if [[ -z "${record_origin_comment}" ]]; then
                # append at the end of file
                sed -i -r '$a '"${l_item} ${l_val}"'' "${l_path}"
            else
                # append at the end of the directive which is commented by #
                sed -i -r '/^#[[:space:]]*'"${l_item}"'[[:space:]]+/a '"${l_item} ${l_val}"'' "${l_path}"
            fi
        else
            [[ "${l_record_origin##* }" == "${l_val}" ]] || sed -i -r '/^'"${l_item}"'[[:space:]]+/{s@.*@'"${l_item} ${l_val}"'@;}' "${l_path}"
        fi

    fi

}

funcOpenSSHInstallation(){
    funcOperationProcedureStatement "Server & client utility"
    # - client side
    if ! funcCommandExistCheck 'ssh'; then
        local ssh_client_pname=${ssh_client_pname:-}
        case "${pack_manager}" in
            apt-get ) ssh_client_pname='openssh-client' ;;
            dnf|yum ) ssh_client_pname='openssh-clients' ;;
            zypper ) ssh_client_pname='openssh' ;;
        esac
        funcPackageManagerOperation 'install' "${ssh_client_pname}"
    fi

    # - server side
    if [[ "${enable_sshd}" -eq 1 ]]; then
        if ! funcCommandExistCheck 'sshd'; then
            local ssh_server_pname=${ssh_server_pname:-'openssh-server'}
            [[ "${pack_manager}" == 'zypper' ]] && ssh_server_pname='openssh'
            funcPackageManagerOperation 'install' "${ssh_server_pname}"

            local sshd_service_name=${sshd_service_name:-'sshd'}
            [[ "${pack_manager}" == 'apt-get' ]] && sshd_service_name='ssh'
            funcCommandExistCheck 'sshd' && funcSystemServiceManager "${sshd_service_name}" 'enable'
        fi
    fi
    funcOperationProcedureResultStatement 'OpenSSH'
}

funcOpenSSHConfiguration(){
    # OpenSUSE merge client & service side into one package 'openssh'
    local ssh_config=${ssh_config:-'/etc/ssh/ssh_config'}
    local sshd_config=${sshd_config:-'/etc/ssh/sshd_config'}

    funcOperationProcedureStatement "Directives configuration"
    [[ ! -f "${ssh_config}${bak_suffix}" && -f "${ssh_config}" ]] && cp -pf "${ssh_config}" "${ssh_config}${bak_suffix}"
    [[ ! -f "${sshd_config}${bak_suffix}" && -f "${sshd_config}" ]] && cp -pf "${sshd_config}" "${sshd_config}${bak_suffix}"

    # sshd port detection
    sshd_existed=${sshd_existed:-0}
    if [[ -s "${sshd_config}" ]]; then
        sshd_existed=1
        ssh_port=$(sed -r -n '/^#?Port/s@^#?Port[[:space:]]*(.*)@\1@p' "${sshd_config}" 2> /dev/null)
        # selinux
        [[ "${ssh_port}" -eq "${ssh_port_default}" ]] || funcSELinuxSemanageOperation 'ssh_port_t' "${ssh_port}" 'port' 'add' 'tcp'
        # https://blog.tinned-software.net/ssh-key-authentication-is-not-working-selinux/
        # semanage fcontext -a -t ssh_home_t "${login_user_home}/.ssh/"
        # restorecon -v "${login_user_home}/.ssh/"
        [[ "${login_user}" != 'root' && -d "${login_user_home}/.ssh/" ]] && funcSELinuxSemanageOperation 'ssh_home_t' "${login_user_home}/.ssh(/.*)?" 'fcontext' 'add'
    fi

    # sshd_config configuration
    if [[ -s "${sshd_config}" ]]; then
        # 7.2, 6.7, 5.3
        local ssh_version=${ssh_version:-0}
        ssh_version=$(ssh -V 2>&1 | sed -r -n 's@.*_([[:digit:].]{3}).*@\1@p')
        # sshd_config directive lists
        local l_sshd_directive_list
        l_sshd_directive_list=$(mktemp -t "${mktemp_format}")
        man sshd_config | sed -r -n '/^[[:space:]]{1,8}[[:upper:]]{1}[[:alpha:]]+[[:space:]]*/{s@^[[:space:]]*([[:alpha:]]+).*@\1@g;p}' > "${l_sshd_directive_list}"

        # - Banner
        # before login /etc/issue, Setting 'Banner' in /etc/ssh/sshd_config
        # after login /etc/motd
        funcOpenSSHDirectiveSetting 'PrintMotd' 'yes' "${l_sshd_directive_list}"
        # Last login: Fri Jan  5 16:19:01 2018 from 13.125.75.217
        funcOpenSSHDirectiveSetting 'PrintLastLog' 'no' "${l_sshd_directive_list}"
        local l_ssh_banner='/etc/ssh/sshd_banner'
        [[ -s "${l_ssh_banner}" ]] || echo -e "#################################################################\n##                 Welcome to GNU/Linux World                  ##\n##         All connections are monitored and recorded          ##\n##   Unauthorized user is prohibited, Disconnect immediately   ##\n#################################################################\n" > "${l_ssh_banner}"
        chmod 644 "${l_ssh_banner}"
        funcOpenSSHDirectiveSetting 'Banner' "${l_ssh_banner}" "${l_sshd_directive_list}"

        # Only Use SSH Protocol 2
        # sed -i -r 's@^#?(Protocol 2)@\1@' "${sshd_config}"
        funcOpenSSHDirectiveSetting 'Protocol' '2' "${l_sshd_directive_list}"

        # Just allow ipv4
        # Specifies which address family should be used by sshd(8).  Valid arguments are 'any', 'inet' (use IPv4 only), or 'inet6' (use IPv6 only).  The default is 'any'.
        funcOpenSSHDirectiveSetting 'AddressFamily' 'inet' "${l_sshd_directive_list}"

        # Specifies whether compression is enabled after the user has authenticated successfully. [yes|delayed|no]
        funcOpenSSHDirectiveSetting 'Compression' 'delayed' "${l_sshd_directive_list}"

        # AllowGroups : This keyword can be followed by a list of group name patterns, separated by spaces.
        local group_allow_name
        group_allow_name=${group_allow_name:-'ssh_group_allow'}
        local group_path='/etc/gshadow'
        [[ "${pack_manager}" == 'zypper' ]] && group_path='/etc/group'
        [[ -z $(sed -n '/^'"${group_allow_name}"':/{s@^([^:]+).*$@\1@g;p}' "${group_path}" 2> /dev/null) ]] && groupadd "${group_allow_name}" &>/dev/null
        funcOpenSSHDirectiveSetting 'AllowGroups' "${group_allow_name}" "${l_sshd_directive_list}"
        gpasswd -a "${login_user}" "${group_allow_name}" &>/dev/null

        [[ -n "${username_specify}" ]] && gpasswd -a "${username_specify}" "${group_allow_name}" &>/dev/null

        # Disable root Login via SSH PermitRootLogin {yes,without-password,forced-commands-only,no}
        if [[ "${disable_ssh_root}" -eq 1 ]]; then
            if [[ "${login_user}" != 'root' || ("${login_user}" == 'root' && -n "${username_specify}") ]]; then
                gpasswd -d root "${group_allow_name}" &>/dev/null
                funcOpenSSHDirectiveSetting 'PermitRootLogin' 'no' "${l_sshd_directive_list}"
            fi
        fi

        # Disallow forward
        # funcOpenSSHDirectiveSetting 'AllowTcpForwarding' 'no'
        funcOpenSSHDirectiveSetting 'X11Forwarding' 'no' "${l_sshd_directive_list}"
        funcOpenSSHDirectiveSetting 'AllowAgentForwarding' 'no' "${l_sshd_directive_list}"

        # Disabling sshd DNS Checks
        funcOpenSSHDirectiveSetting 'UseDNS' 'no' "${l_sshd_directive_list}"
        # Log Out Timeout Interval, just work for Protocol 2
        funcOpenSSHDirectiveSetting 'ClientAliveCountMax' '2' "${l_sshd_directive_list}"
        funcOpenSSHDirectiveSetting 'ClientAliveInterval' '180' "${l_sshd_directive_list}"
        # MaxAuthTries
        funcOpenSSHDirectiveSetting 'MaxAuthTries' '2' "${l_sshd_directive_list}"
        # MaxSessions
        funcOpenSSHDirectiveSetting 'MaxSessions' '2' "${l_sshd_directive_list}"
        # Disallow the system send TCP keepalive messages to the other side
        funcOpenSSHDirectiveSetting 'TCPKeepAlive' 'no' "${l_sshd_directive_list}"
        # Don't read the user's ~/.rhosts and ~/.shosts files
        funcOpenSSHDirectiveSetting 'IgnoreRhosts' 'yes' "${l_sshd_directive_list}"
        # Disable Host-Based Authentication
        funcOpenSSHDirectiveSetting 'HostbasedAuthentication' 'no' "${l_sshd_directive_list}"
        # Disallow Empty Password Login
        funcOpenSSHDirectiveSetting 'PermitEmptyPasswords' 'no' "${l_sshd_directive_list}"
        # https://unix.stackexchange.com/questions/115839/change-sshd-logging-file-location-on-centos
        funcOpenSSHDirectiveSetting 'SyslogFacility' 'AUTHPRIV' "${l_sshd_directive_list}"
        # Enable Logging Message {QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, DEBUG3}
        funcOpenSSHDirectiveSetting 'LogLevel' 'VERBOSE' "${l_sshd_directive_list}"
        # Check file modes and ownership of the user's files and home directory before accepting login
        funcOpenSSHDirectiveSetting 'StrictModes' 'yes' "${l_sshd_directive_list}"

        # Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
        # https://unix.stackexchange.com/questions/61580/sftp-gives-an-error-received-message-too-long-and-what-is-the-reason#answer-327284
        # https://serverfault.com/questions/660160/openssh-difference-between-internal-sftp-and-sftp-server
        sed -i -r '/^#?Subsystem[[:space:]]*sftp/d' "${sshd_config}"
        sed -i -r '$a Subsystem sftp internal-sftp -l INFO' "${sshd_config}"

        # Checks whether the account has been locked with passwd -l
        # AWS EC2
        local l_usepamchecklocks=${l_usepamchecklocks:-'yes'}
        [[ "${distro_name}" == 'sles' ]] && l_usepamchecklocks='no'
        funcOpenSSHDirectiveSetting 'UsePAMCheckLocks' "${l_usepamchecklocks}" "${l_sshd_directive_list}"

        # Supported HostKey algorithms by order of preference
        sed -i -r 's@^#?(HostKey /etc/ssh/ssh_host_rsa_key)$@\1@' "${sshd_config}"
        sed -i -r 's@^#?(HostKey /etc/ssh/ssh_host_ecdsa_key)$@\1@' "${sshd_config}"

        # https://wiki.mozilla.org/Security/Guidelines/OpenSSH
        local l_sshd_keyalgorithms=${l_sshd_keyalgorithms:-'diffie-hellman-group-exchange-sha256'}
        local l_sshd_ciphers=${l_sshd_ciphers:-'aes256-ctr,aes192-ctr,aes128-ctr'}
        local l_sshd_macs=${l_sshd_macs:-'hmac-sha2-512,hmac-sha2-256'}

        if [[ $(echo "${ssh_version} > 6.7" | bc) == 1 ]]; then
            sed -i -r 's@^#?(HostKey /etc/ssh/ssh_host_ec25519_key)$@\1@' "${sshd_config}"
            # Turn on privilege separation  yes/sandbox
            funcOpenSSHDirectiveSetting 'UsePrivilegeSeparation' 'sandbox' "${l_sshd_directive_list}"

            l_sshd_keyalgorithms='curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256'
            l_sshd_ciphers='chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
            l_sshd_macs='hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com'
        fi

        # Specifies the available KEX (Key Exchange) algorithms
        funcOpenSSHDirectiveSetting 'KexAlgorithms' "${l_sshd_keyalgorithms}" "${l_sshd_directive_list}"
        # Ciphers Setting
        funcOpenSSHDirectiveSetting 'Ciphers' "${l_sshd_ciphers}" "${l_sshd_directive_list}"
        # Message authentication codes (MACs) Setting
        funcOpenSSHDirectiveSetting 'MACs' "${l_sshd_macs}" "${l_sshd_directive_list}"

        # Using PAM, the follow `ChallengeResponseAuthentication` and `PasswordAuthentication` used by PAM authentication
        funcOpenSSHDirectiveSetting 'UsePAM' 'yes' "${l_sshd_directive_list}"
        # Disable Challenge-response Authentication
        funcOpenSSHDirectiveSetting 'ChallengeResponseAuthentication' 'no' "${l_sshd_directive_list}"

        if [[ "${just_keygen}" -eq 1 && -s "${login_user_home}/.ssh/authorized_keys" ]]; then
            # Disable Password Authentication
            funcOpenSSHDirectiveSetting 'PasswordAuthentication' 'no' "${l_sshd_directive_list}"
            # Use Public Key Based Authentication
            funcOpenSSHDirectiveSetting 'PubkeyAuthentication' 'yes' "${l_sshd_directive_list}"

            # Specify File Containing Public Key Allowed Authentication Login
            # AuthorizedKeysFile  .ssh/authorized_keys
            funcOpenSSHDirectiveSetting 'AuthorizedKeysFile' '%h/.ssh/authorized_keys' "${l_sshd_directive_list}"

            # Just Allow Public Key Authentication Login
            if [[ $(echo "${ssh_version} > 6.7" | bc) == 1 ]]; then
                funcOpenSSHDirectiveSetting 'AuthenticationMethods' 'publickey' "${l_sshd_directive_list}"
            fi

            # publickey (SSH key), password publickey (password), keyboard-interactive (verification code)
            # funcOpenSSHDirectiveSetting 'AuthenticationMethods' 'publickey,password publickey,keyboard-interactive' "${l_sshd_directive_list}"
        else
            funcOpenSSHDirectiveSetting 'PasswordAuthentication' 'yes'
        fi

    fi

    if [[ -z "${ssh_version:-}" ]]; then
        funcOperationProcedureResultStatement
    else
        funcOperationProcedureResultStatement "v${ssh_version}"
    fi

    if [[ "${login_user}" == 'root' && -f "${login_user_home}/.ssh/authorized_keys" && -n "${username_specify}" && "${just_keygen}" -eq 1 ]]; then
        funcOperationProcedureStatement "authorized_keys"
        # add authorized_keys to new created user
        local newuser_home=${newuser_home:-}
        newuser_home=$(awk -F: 'match($0,/^'"${username_specify}"'/){print $6}' /etc/passwd)
        if [[ -n "${newuser_home}" ]]; then
            (umask 077; [[ -d "${newuser_home}/.ssh" ]] || mkdir -p "${newuser_home}/.ssh"; cat "${login_user_home}/.ssh/authorized_keys" >> "${newuser_home}/.ssh/authorized_keys"; chown -R "${username_specify}" "${newuser_home}/.ssh")
            [[ -d "${newuser_home}/.ssh/" ]] && funcSELinuxSemanageOperation 'ssh_home_t' "${newuser_home}/.ssh/" 'fcontext' 'add'
        fi
        funcOperationProcedureResultStatement "${username_specify} <= ${login_user}"
    fi
}

funcOpenBSDSecureShellOperation(){
    funcOperationPhaseStatement 'OpenBSD Secure Shell'
    funcOpenSSHInstallation
    funcOpenSSHConfiguration
}

#########  2-8. Firewall Setting - firewalld/iptables/ufw/SuSEfirewall2  #########
# Block Top 10 Known-bad IPs
# $download_tool https://isc.sans.edu/top10.html | sed -r -n '/ipdetails.html/{s@.*?ip=([^"]+)".*@\1@g;s@^0+@@g;s@\.0+@.@g;p}'
funcFirewallSetting(){
    funcOperationPhaseStatement "Firewall Application"
    funcOperationProcedureStatement "Firewall for ${distro_name}"

    if [[ "${restrict_remote_login}" -eq 1 && -n "${login_user_ip}" ]]; then
        $download_tool "${firewall_configuration_script}" | bash -s -- -p "${ssh_port}" -H "${login_user_ip}" -s
    else
        $download_tool "${firewall_configuration_script}" | bash -s -- -p "${ssh_port}" -s
    fi

    local l_firewall_type=''
    case "${pack_manager}" in
        apt-get ) l_firewall_type='ufw' ;;
        zypper ) l_firewall_type='SuSEfirewall2' ;;
        dnf|yum ) [[ $("${pack_manager}" info firewalld 2>&1 | awk -F": " 'match($1,/^Name/){print $NF;exit}') == 'firewalld' ]] && l_firewall_type='firewalld' || l_firewall_type='iptables' ;;
    esac

    funcOperationProcedureResultStatement "${l_firewall_type}"
}


#########  2-9. tmpfs filesystem for /tmp provided by systemd  #########
# use command df to list partition filesystem info
funcTmpfsSystemSetting(){
    if [[ "${tmpfs_enable}" -eq 1 ]]; then
        # just for systemd
        if funcCommandExistCheck 'systemctl'; then
            # 6GB == 6 * 1024 * 1024 == 6291456 KB
            if [[ "${mem_totoal_size}" -ge 6291456 ]]; then
                funcOperationPhaseStatement "TMPFS Filesystem"
                funcOperationProcedureStatement "tmpfs filesystem for /tmp"
                # for debian / suse
                local tmp_mount_source_path=${tmp_mount_source_path:-'/usr/share/systemd/tmp.mount'}
                # for rhel
                [[ -s '/lib/systemd/system/tmp.mount' ]] && tmp_mount_source_path='/lib/systemd/system/tmp.mount'
                local tmp_mount_target_path=${tmp_mount_target_path:-'/etc/systemd/system/tmp.mount'}

                if [[ -s "${tmp_mount_source_path}" && ! -s "${tmp_mount_target_path}" ]]; then
                    cp -f "${tmp_mount_source_path}" "${tmp_mount_target_path}"
                    local tmpfs_mem_size=${tmpfs_mem_size:-1}
                    # Options=size=1g,mode=1777,strictatime,nosuid,nodev
                    sed -r -i '/^Options=/{s@(Options=).*@\1size='"${tmpfs_mem_size}"'g,mode=1777,strictatime,nosuid,nodev@g;}' "${tmp_mount_target_path}"
                    funcSystemServiceManager 'tmp.mount' 'enable'

                    funcOperationProcedureResultStatement "${tmpfs_mem_size}g"
                fi    # end if configure tmp.mount

            fi    # end if mem_totoal_size
        fi    # end if check systemctl exists or not

    fi   # end if tmpfs_enable
}


#########  2-10. Security & Audit  #########
funcKernelOptimization(){
    local sysctl_config=${sysctl_config:-'/etc/sysctl.conf'}

    # - Kernel parameters    /etc/sysctl.conf
    # https://www.frozentux.net/ipsysctl-tutorial/
    # https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
    funcOperationProcedureStatement 'Kernel parameters'
    # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-securing_network_access
    if [[ -f "${sysctl_config}" ]]; then
        [[ -f "${sysctl_config}${bak_suffix}" ]] || cp -fp "${sysctl_config}" "${sysctl_config}${bak_suffix}"

        if [[ -z $(sed -r -n '/Kernel Parameters Setting/p' "${sysctl_config}" 2> /dev/null) ]]; then
            sed -i '/Kernel Parameters Setting Start/,/Kernel Parameters Setting End/d' "${sysctl_config}"
            $download_tool "${sysctl_url}" >> "${sysctl_config}"
            sed -r -i '/Parameters Setting Start/,/Parameters Setting End/{/^#[[:space:]]+/{/Parameters Setting/!d}}' "${sysctl_config}" 2> /dev/null
        fi

        # swappiness
        # 16GB == 16 * 1024 * 1024 == 16777216 KB
        [[ "${mem_totoal_size}" -le 16777216 ]] && sed -r -i '/^vm.swappiness/d' "${sysctl_config}"
    fi
    funcOperationProcedureResultStatement '/etc/sysctl.conf'


    # - enable TCP BBR congestion control  >= 4.9
    # https://cloudplatform.googleblog.com/2017/07/TCP-BBR-congestion-control-comes-to-GCP-your-Internet-just-got-faster.html

    # egrep 'CONFIG_TCP_CONG_BBR|CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    # /etc/sysctl.conf
    # net.core.default_qdisc=fq
    # net.ipv4.tcp_congestion_control=bbr

    if [[ -s '/etc/sysctl.conf' ]]; then
        kernel_version=$(uname -r | sed -r -n 's@^([[:digit:]]+.[[:digit:]]+)..*$@\1@g;p')
        kernel_major=${kernel_version%%.*}
        kernel_minor=${kernel_version##*.}
        enable_bbr=${enable_bbr:-0}
        if [[ "${kernel_major}" -gt 4 ]]; then
            enable_bbr=1
        elif [[ "${kernel_major}" -eq 4 && "${kernel_minor}" -ge 9 ]]; then
            enable_bbr=1
        fi

        sed -r -i '/(BBR Congestion|net.core.default_qdisc|net.ipv4.tcp_congestion_control)/d' /etc/sysctl.conf 2> /dev/null

        if [[ "${enable_bbr}" -eq 1  ]]; then
            sed -r -i '/Kernel Parameters Setting End/i # TCP BBR Congestion Control\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf 2> /dev/null
        fi
        sysctl --system &> /dev/null
    fi

}

funcSystemHardeningOperation(){
    # Lynis is an open source security auditing tool.   https://cisofy.com/lynis/

    # https://highon.coffee/blog/security-harden-centos-7/
    # https://www.safecomputing.umich.edu/protect-the-u/protect-your-unit/hardening/secure-linux-unix-server
    # https://www.slideshare.net/brendangregg/how-netflix-tunes-ec2-instances-for-performance
    # https://www.cyberciti.biz/tips/linux-security.html

    # /etc/fstab
    # mount -o defults,noatime,discard,nobarrier

    # - Disable firewire ohci driver
    funcOperationProcedureStatement 'Disable firewire ohci driver'
    [[ -z $(sed -r -n '/blacklist firewire_ohci/{p}' /etc/modprobe.d/blacklist.conf 2> /dev/null)  ]] && echo 'blacklist firewire_ohci' >> /etc/modprobe.d/blacklist.conf
    funcOperationProcedureResultStatement '/etc/modprobe.d/'

    # - Disable thunderbolt
    # funcOperationProcedureStatement 'Disable Intel thunderbolt interface'
    # [[ -z $(sed -r -n '/blacklist thunderbolt/{p}' /etc/modprobe.d/blacklist.conf 2> /dev/null)  ]] && echo 'blacklist thunderbolt' >> /etc/modprobe.d/blacklist.conf
    # funcOperationProcedureResultStatement '/etc/modprobe.d/'

    # - Disable USB storage devices
    funcOperationProcedureStatement 'Disable USB storage devices'
    # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using-usbguard
    # http://linuxtechlab.com/disable-usb-storage-linux/
    # https://www.cyberciti.biz/faq/linux-disable-modprobe-loading-of-usb-storage-driver/

    # Method 1 – Fake install
    # rhel/centos 5.x or older  /etc/modprobe.conf
    # [[ -z $(sed -r -n '/install usb-storage/{p}' /etc/modprobe.conf 2> /dev/null) ]] &&  echo 'install usb-storage : ' >> /etc/modprobe.conf
    # rhel/centos 6.x, 7.x
    # echo 'install usb-storage /bin/true' > /etc/modprobe.d/disable-usb-storage.conf
    echo 'install usb-storage /bin/true' > /etc/modprobe.d/disable-usb-storage.conf"${bak_suffix}"

    # Method 2 – Removing the USB driver
    # find /lib/modules/$(uname -r) -name *usb-storage*

    # Method 3- Blacklisting USB-storage   not work on centos7
    # load/unload usb-storage module    modprobe [-r] usb-storage
    [[ -z $(sed -r -n '/blacklist usb-storage/{p}' /etc/modprobe.d/blacklist.conf 2> /dev/null)  ]] && echo -e 'blacklist usb_storage\nblacklist usb-storage' >> /etc/modprobe.d/blacklist.conf
    funcOperationProcedureResultStatement '/etc/modprobe.d/'


    # - Determining default umask
    funcOperationProcedureStatement 'Determining default umask'
    # /etc/login.defs
    [[ -s '/etc/login.defs' ]] && sed -r -i '/^UMASK[[:space:]]+/{s@^([^[:space:]]+[[:space:]]+).*$@\1'${umask_default}'@g;}' /etc/login.defs &> /dev/null
    # /etc/init.d/functions
    [[ -s '/etc/init.d/functions' ]] && sed -r -i '/^#?[[:space:]]*umask[[:space:]]+/{s@^#?[[:space:]]*(umask[[:space:]]+).*$@\1'"${umask_default}"'@g;}' /etc/init.d/functions &> /dev/null
    # /etc/profile
    if [[ -s '/etc/profile' ]]; then
        sed -r -i '/umask[[:space:]]*002/{s@^([[:space:]]+umask[[:space:]]+).*$@\1007@g;}' /etc/profile &> /dev/null
        sed -r -i '/umask[[:space:]]*022/{s@^([[:space:]]+umask[[:space:]]+).*$@\1'"${umask_default}"'@g;p}' /etc/profile &> /dev/null
    fi
    # /etc/bashrc
    if [[ -s '/etc/bashrc' ]]; then
        sed -r -i '/umask[[:space:]]*002/{s@^([[:space:]]+umask[[:space:]]+).*$@\1007@g;}' /etc/bashrc &> /dev/null
        sed -r -i '/umask[[:space:]]*022/{s@^([[:space:]]+umask[[:space:]]+).*$@\1'"${umask_default}"'@g;p}' /etc/bashrc &> /dev/null
    fi
    funcOperationProcedureResultStatement "${umask_default}"


    # - File descriptor    /etc/security/limits.conf
    funcOperationProcedureStatement 'File descriptor'
    local l_nofile_num=${l_nofile_num:-655360}
    local l_proc_num=${l_proc_num:-65535}
    local security_limit_config=${security_limit_config:-'/etc/security/limits.conf'}

    if [[ -f "${security_limit_config}" ]]; then
        [[ -f "${security_limit_config}${bak_suffix}" ]] || cp -fp "${security_limit_config}" "${security_limit_config}${bak_suffix}"
        sed -i -r '/^\* (soft|hard) nofile /d;/End of file/d' "${security_limit_config}"

        echo -e "* soft nofile ${l_nofile_num}\n* hard nofile ${l_nofile_num}\n* soft nproc ${l_proc_num}\n* hard nproc ${l_proc_num}# End of file\n" >> "${security_limit_config}"
    fi

    # If use Gnome desktop, systemd not read /etc/security/limits.conf
    # https://stackoverflow.com/questions/46441602/how-to-change-open-files-ulimit-n-permanently-for-normal-user-in-debian-stret/47404791#47404791
    # https://bugzilla.redhat.com/show_bug.cgi?id=1364332
    if funcCommandExistCheck 'gnome-shell'; then
        if [[ "${pack_manager}" == 'apt-get' ]]; then
            if funcCommandExistCheck 'systemctl'; then
                local limit_service_dir=${limit_service_dir:-'/etc/systemd/system/user@.service.d'}
                [[ -d "${limit_service_dir}" ]] || mkdir -p "${limit_service_dir}"
                echo -e "[Service]\nLimitNOFILE=${l_nofile_num}\nLimitNPROC=${l_proc_num}" > "${limit_service_dir}"/limit.conf
                systemctl daemon-reload 1> /dev/null
            fi
        fi
    fi
    funcOperationProcedureResultStatement "${security_limit_config}"

    # - Transparent Huge Pages (THP)
    # THP is a Linux memory management system that reduces the overhead of Translation Lookaside Buffer (TLB) lookups on machines with large amounts of memory by using larger memory pages. You should disable THP on Linux machines to ensure best performance. However it will turn on on system restart. In order to disable them on system startup, you need to add Unit file with script that will disable THP.
    # https://docs.mongodb.com/manual/tutorial/transparent-huge-pages/
    # https://unix.stackexchange.com/questions/99154/disable-transparent-hugepages
    # https://access.redhat.com/solutions/46111
    # https://www.thegeekdiary.com/centos-rhel-7-how-to-disable-transparent-huge-pages-thp/
    funcOperationProcedureStatement 'Transparent Huge Pages (THP)'

    # - check system-wide THP usage
    # grep AnonHugePages /proc/meminfo
    # grep -i HugePages_Total /proc/meminfo
    # egrep 'trans|thp' /proc/vmstat
    # cat /sys/kernel/mm/transparent_hugepage/defrag
    # cat /sys/kernel/mm/transparent_hugepage/enabled

    local transparent_hugepage_dir=${transparent_hugepage_dir:-'/sys/kernel/mm/transparent_hugepage'}
    [[ -d '/sys/kernel/mm/redhat_transparent_hugepage' ]] && transparent_hugepage_dir='/sys/kernel/mm/redhat_transparent_hugepage'
    local khugepaged_defrag_path=${khugepaged_defrag_path:-"${transparent_hugepage_dir}/khugepaged/defrag"}
    if [[ -s "${khugepaged_defrag_path}" ]]; then
        # rhel 6 -- no
        local khugepaged_defrag_val=${khugepaged_defrag_val:-0}
        [[ $(cat "${khugepaged_defrag_path}") =~ ^[0-1]+$ ]] || khugepaged_defrag_val='no'
    fi

    local l_disable_thp_service_path=${l_disable_thp_service_path:-'/etc/systemd/system/disable-thp.service'}

    if funcCommandExistCheck 'systemctl'; then
        [[ -s "${l_disable_thp_service_path}" ]] || echo "[Unit]|Description=Disable Transparent Huge Pages (THP)||[Service]|Type=simple|ExecStart=/bin/bash -c \"echo 'never' > transparent_hugepage_dir/enabled 2> /dev/null; echo 'never' > transparent_hugepage_dir/defrag 2> /dev/null; echo 'khugepaged_defrag_val' > khugepaged_defrag_path 2> /dev/null\"||[Install]|WantedBy=multi-user.target" > "${l_disable_thp_service_path}"
    else
        l_disable_thp_service_path='/etc/init.d/disable-thp'
        [[ -s "${l_disable_thp_service_path}" ]] || echo "#!/usr/bin/env bash|# Provides:          disable-transparent-hugepages|# Required-Start:    \$local_fs|# Required-Stop:|# Default-Start:     2 3 4 5|# Default-Stop:      0 1 6|# Short-Description: Disable Linux transparent huge pages|# Description:       Disable Linux transparent huge pages, to improve system performance.||case \"\$1\" in|    start )|        echo 'never' > transparent_hugepage_dir/enabled 2> /dev/null|        echo 'never' > transparent_hugepage_dir/defrag 2> /dev/null|        echo 'khugepaged_defrag_val' > khugepaged_defrag_path 2> /dev/null|        ;;|esac" "${l_disable_thp_service_path}"
    fi

    sed -i 's@|@\n@g' "${l_disable_thp_service_path}"
    sed -r -i 's@transparent_hugepage_dir@'"${transparent_hugepage_dir}"'@g;' "${l_disable_thp_service_path}"
    sed -r -i 's@khugepaged_defrag_val@'"${khugepaged_defrag_val}"'@g;' "${l_disable_thp_service_path}"
    sed -r -i 's@khugepaged_defrag_path@'"${khugepaged_defrag_path}"'@g;' "${l_disable_thp_service_path}"
    funcSystemServiceManager "${l_disable_thp_service_path##*/}" 'enable'
    funcOperationProcedureResultStatement "${l_disable_thp_service_path}"


    # - Storage I/O
    funcOperationProcedureStatement 'Storage I/O'
    find /sys/block/* -print | while IFS="" read -r line; do
        if [[ -d "${line}" ]]; then
            local block_queue_dir="${line}"
            [[ -s "${block_queue_dir}/queue/rq_affinity" ]] && echo 2 > "${block_queue_dir}"/queue/rq_affinity 2> /dev/null
            [[ -s "${block_queue_dir}/queue/scheduler" ]] && echo 'noop' > "${block_queue_dir}"/queue/scheduler 2> /dev/null
            [[ -s "${block_queue_dir}/queue/nr_requests" ]] && echo 256 > "${block_queue_dir}"/queue/nr_requests 2> /dev/null
            [[ -s "${block_queue_dir}/queue/read_ahead_kb" ]] && echo 256 > "${block_queue_dir}"/queue/read_ahead_kb 2> /dev/null
        fi
    done
    funcOperationProcedureResultStatement '/sys/block/'

    #  - ip addr resolver
    # http://www.tldp.org/LDP/solrhe/Securing-Optimizing-Linux-RH-Edition-v1.3/chap5sec39.html
    #  Linux uses a resolver library to obtain the IP address corresponding to a host name. The /etc/host.conf file specifies how names are resolved.
    local l_hosts_conf='/etc/host.conf'
    if [[ -s "${l_hosts_conf}" ]]; then
        funcOperationProcedureStatement 'Ip addr resolver'
        sed -r -i '/^#?[[:space:]]*multi[[:space:]]+/{s@^.*$@multi on@g}' "${l_hosts_conf}"
        sed -r -i '/^#?[[:space:]]*order[[:space:]]+/{s@^.*$@order bind,hosts@g}' "${l_hosts_conf}"
        sed -r -i '/^#?[[:space:]]*nospoof[[:space:]]+/{s@^.*$@nospoof on@g}' "${l_hosts_conf}"
        sed -r -i '/^#?[[:space:]]*spoofalert[[:space:]]+/{s@^.*$@spoofalert on@g}' "${l_hosts_conf}"
        sed -r -i '/^#?[[:space:]]*spoof[[:space:]]+/{s@^.*$@spoof warn@g}' "${l_hosts_conf}"
        funcOperationProcedureResultStatement "${l_hosts_conf}"
    fi


    # - enforcing read-only mounting of removable media
    # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-hardening_your_system_with_tools_and_services#sect-Security_Guide-Workstation_Security-Enforcing_Read-Only_Mounting_of_Removable_Media
    if [[ -d '/etc/udev/rules.d' ]]; then
        local l_80_rule=${l_80_rule:-'/etc/udev/rules.d/80-readonly-removables.rules'}
        if [[ ! -s "${l_80_rule}" ]]; then
            funcOperationProcedureStatement "Enforcing read-only mounting of removable media"
            echo "SUBSYSTEM==\"block\",ATTRS{removable}==\"1\",RUN{program}=\"/sbin/blockdev --setro %N\"" > "${l_80_rule}"

            if funcCommandExistCheck 'udevadm'; then
                udevadm trigger &> /dev/null
                udevadm control --reload &> /dev/null
            fi
            funcOperationProcedureResultStatement
        fi    # end if l_80_rule
    fi


    # - bash TMOUT
    local bash_configuration_profile=${bash_configuration_profile:-'/etc/bashrc'}
    [[ -s '/etc/bash.bashrc' ]] && bash_configuration_profile='/etc/bash.bashrc'
    if [[ -s "${bash_configuration_profile}" ]]; then
        funcOperationProcedureStatement 'Bash shell'
        sed -r -i '/Bash custom setting start/,/Bash custom setting end/d' "${bash_configuration_profile}"
        # append
        local l_timeout=${l_timeout:-360}
        echo -e "# Bash custom setting start\n# automatic logout timeout (seconds)\nTMOUT=${l_timeout}\n# Bash custom setting end" >> "${bash_configuration_profile}"
        funcOperationProcedureResultStatement "${bash_configuration_profile}"
    fi

    # - Disable Ctrl+Alt+Del
    # https://www.linuxtechi.com/disable-reboot-using-ctrl-alt-del-keys/
    funcOperationProcedureStatement 'Disable Ctrl+Alt+Del'
    if funcCommandExistCheck 'systemctl'; then
        [[ $(systemctl is-enabled ctrl-alt-del.target) != 'masked' ]] && systemctl mask ctrl-alt-del.target &> /dev/null
        # systemctl daemon-reload
    elif [[ -s '/etc/init/control-alt-delete.conf' ]]; then
        # rhel/centos 6
        if [[ ! -s '/etc/init/control-alt-delete.override' ]]; then
            cp -f /etc/init/control-alt-delete.conf /etc/init/control-alt-delete.override
            echo -e "exec /usr/bin/logger -p authpriv.notice -t init \"Ctrl-Alt-Del has been disabled\"" > /etc/init/control-alt-delete.override
        fi
    elif [[ -s '/etc/inittab' ]]; then
        # rhel/centos 5
        sed -r -i '/^ca::ctrlaltdel:\/sbin\/shutdown/{s@^@#@g;}' /etc/inittab &> /dev/null
        sed -r -i '/ca::ctrlaltdel:\/sbin\/shutdown/a ca::ctrlaltdel:/bin/logger -p authpriv.warning -t init "Console-invoked Ctrl-Alt-Del has been disabled"' /etc/inittab &> /dev/null
    fi
    funcOperationProcedureResultStatement


    # - Disable Zeroconf Networking   169.254.0.0/16
    # http://blog.omotech.com/?p=1005
    if [[ -s '/etc/sysconfig/network' ]]; then
        funcOperationProcedureStatement 'Disable zeroconf networking'
        # append
        echo "NOZEROCONF=yes" >> /etc/sysconfig/network
        funcOperationProcedureResultStatement '/etc/sysconfig/network'
    fi

    # - Partition mount options
    local l_fstab_path=${l_fstab_path:-'/etc/fstab'}
    if [[ -s "${l_fstab_path}" ]]; then
        funcOperationProcedureStatement 'Partition mount options'
        # /boot, /tmp, /var/tmp, /var/log    defaults,nosuid,noexec,nodev
        sed -r -i '/[[:space:]]+\/(boot|tmp|var\/tmp|var\/log)[[:space:]]+.*defaults/{s@(defaults)([[:space:]]+)@\1,nosuid,noexec,nodev\2@g;}' "${l_fstab_path}" &> /dev/null
        # /var   defaults,nosuid
        sed -r -i '/[[:space:]]+\/(var)[[:space:]]+.*defaults/{s@(defaults)([[:space:]]+)@\1,nosuid\2@g;}' "${l_fstab_path}" &> /dev/null
        funcOperationProcedureResultStatement "${l_fstab_path}"
    fi


    #  - Just allow root login via local terminal
    # if [[ -s '/etc/securetty' && ! -s "/etc/securetty${bak_suffix}" ]]; then
    #     funcOperationProcedureStatement 'Just allow root login via local terminal'
    #     cp /etc/securetty "/etc/securetty${bak_suffix}"
    #     echo "tty1" > /etc/securetty
    #     chmod 700 /root &> /dev/null
    #     funcOperationProcedureResultStatement '/etc/securetty'
    # fi

    #  - TCP Wrappers
    # block all but SSH
    # echo "ALL:ALL" >> /etc/hosts.deny
    # echo "sshd:ALL" >> /etc/hosts.allow
}


funcRecordUserLoginSessionInfo(){
    # http://www.2daygeek.com/automatically-record-all-users-terminal-sessions-activity-linux-script-command
    # https://unix.stackexchange.com/questions/25639/how-to-automatically-record-all-your-terminal-sessions-with-script-utility

    # **Attention** This setting may results in utility "rsync" not work, prompt the following error:
    # protocol version mismatch -- is your shell clean?
    # (see the rsync man page for an explanation)
    # rsync error: protocol incompatibility (code 2) at compat.c(178) [sender=3.1.2]

    funcOperationProcedureStatement 'Record user login session'
    local session_record_dir=${session_record_dir:-'/var/log/session'}
    if [[ ! -d "${session_record_dir}" ]]; then
        mkdir -p "${session_record_dir}"
        chmod 1777 "${session_record_dir}"
        chattr +a "${session_record_dir}"
    fi

    local session_record_profile=${session_record_profile:-'/etc/bashrc'}
    [[ -s '/etc/bash.bashrc' ]] && session_record_profile='/etc/bash.bashrc'
    sed -r -i '/Record terminal sessions start/,/Record terminal sessions end/d' "${session_record_profile}"

    # append
    # tee -a "${session_record_profile}" 1>/dev/null <<EOF
    # cat >> "${session_record_profile}" <<EOF
    echo -e "# Record terminal sessions start\nlogin_ip=\${login_ip:-}\nif [[ -n \"\${SSH_CLIENT:-}\" ]]; then\n    login_ip=\"\${SSH_CLIENT%% *}\"\nelif [[ -n \"\${SSH_CONNECTION:-}\" ]]; then\n    login_ip=\"\${SSH_CONNECTION%% *}\"\nelse\n    login_ip=\$(who | sed -r -n '\$s@.*\(([^\)]+)\).*@\1@gp')\n    [[ \"\${login_ip}\" == \":0\" ]] && login_ip='127.0.0.1'\nfi\n\nif [[ \"X\${SESSION_RECORD:-}\" == 'X' ]]; then\n    login_timestamp=\$(date +\"%Y%m%d-%a-%H%M%S\")\n    # \$\$ current bash process ID (PID)\n    if [[ -z \"\${login_ip}\" ]]; then\n        record_output_path=\"/var/log/session/\${login_timestamp}_\${USER}_r\${RANDOM}.log\"\n    else\n        record_output_path=\"/var/log/session/\${login_timestamp}_\${USER}_\${login_ip}_r\${RANDOM}.log\"\n    fi\n\n    SESSION_RECORD='start'\n    export SESSION_RECORD\n    # /usr/bin/script blongs to package util-linux or util-linux-ng\n    script -t -f -q 2>\"\${record_output_path}.timing\" \"\${record_output_path}\"\n    exit\nfi\n\n# ps -ocommand= -p \$PPID\n# Record terminal sessions end" >> "${session_record_profile}"

    funcOperationProcedureResultStatement "${session_record_dir}"
}

funcAuditdDirectiveSetting(){
    local l_item="${1:-}"
    local l_val="${2:-}"
    local l_config="${3:-'/etc/audit/auditd.conf'}"
    if [[ -n "${l_item}" && -n "${l_val}" && -s "${l_config}" ]]; then
        sed -r -i '/^[[:space:]]*#?[[:space:]]*'"${l_item}"'[[:space:]]*=/{s@^[[:space:]]*#?[[:space:]]*([^[:space:]]+[[:space:]]*=).*@\1 '"${l_val}"'@g;}' "${l_config}"
    fi
}

funcAuditOperation(){
    # - Record All User Terminal Sessions
    [[ "${log_user_session}" -eq 1 ]] && funcRecordUserLoginSessionInfo

    #  - Log
    # rsyslog - reliable system and kernel logging daemon
    # /etc/rsyslog.conf
    # change SyslogFacility val from INFO --> AUTHPRIV in /etc/ssh/sshd_config
    # authpriv.* /var/log/secure   in /etc/rsyslog.conf
    funcCommandExistCheck 'rsyslogd' || funcPackageOperationProcedureStatement 'install' 'rsyslog' 'rsyslogd'

    # ARP monitoring - arpon,arpwatch;   arpwatch: arpwatch / arpsnmp
    local arp_name=${arp_name:-'arpon'}
    [[ "${pack_manager}" != 'apt-get' ]] && arp_name='arpwatch'
    if ! funcCommandExistCheck "${arp_name}"; then
        funcOperationProcedureStatement "ARP monitoring"
        funcPackageManagerOperation 'install' "${arp_name}"
        funcSystemServiceManager "${arp_name}" 'enable'
        funcOperationProcedureResultStatement "${arp_name}"
    fi

    # - User-specific process accounting
    # http://mewbies.com/how_to_use_acct_process_system_accouting_tutorial.htm
    # ac, lastcomm, accton and sa
    if ! funcCommandExistCheck 'ac'; then
        funcOperationProcedureStatement 'User-specific process accounting'
        local acct_name
        local acct_record_file
        case "${pack_manager}" in
            dnf|yum )
                acct_name='psacct'
                acct_record_file='/var/account/pacct'
            ;;
            * )
                acct_name='acct'
                acct_record_file='/var/log/account/pacct'
            ;;
        esac
        # read record file via command dump-acct, e.g. dump-acct /var/log/account/pacct
        funcPackageManagerOperation 'install' "${acct_name}"
        # ac / lastcomm / accton / sa / last / lastb
        # /etc/default/acct    /etc/cron.daily/acct
        [[ -s '/usr/bin/ac' ]] && chmod 750 '/usr/bin/ac'
        funcSystemServiceManager "${acct_name}" 'enable'
        [[ -f "${acct_record_file}" ]] && rm -f "${acct_record_file}"
        funcSystemServiceManager "${acct_name}" 'restart'
        # Activate process accounting and use default file
        funcCommandExistCheck 'accton' && accton on &> /dev/null
        funcOperationProcedureResultStatement "${acct_name} ${acct_record_file}"
    fi

    # - Network traffic monitor
    # vnstat - a console-based network traffic monitor
    # vnstati - png image output support for vnStat
    # vnstat --create -i enp0s25
    if ! funcCommandExistCheck 'vnstat'; then
        # https://www.cyberciti.biz/faq/centos-redhat-fedora-linux-install-vnstat-bandwidth-monitor/
        funcOperationProcedureStatement 'Network traffic monitor'
        local l_vnstat_list='vnstat'
        [[ "${pack_manager}" == 'apt-get' ]] && l_vnstat_list="${l_vnstat_list} vnstati"
        funcPackageManagerOperation 'install' "${l_vnstat_list}"
        funcSystemServiceManager 'vnstat' 'enable'
        # conf path - /etc/vnstat.conf
        # log dir - /var/lib/vnstat/
        # vnstati -s/-h -i eth0 -o /tmp/network-log.png
        funcOperationProcedureResultStatement 'vnstat'
    fi

    # - User space tool for kernel auditing
    # audit/auditd: audispd/auditctl/auditd/aulast/aulastlog/aureport/ausearch/ausyscall/autrace/auvirt
    local l_auditd_install=${l_auditd_install:-1}
    if [[ "${l_auditd_install}" -eq 1 ]]; then
        funcOperationProcedureStatement 'User space tools for kernel auditing'
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference#sec-Audit_Events_Fields

        # http://man7.org/linux/man-pages/man2/seccomp.2.html
        # https://en.wikipedia.org/wiki/Seccomp
        # ausearch -m seccomp --raw | aureport --event --summary -i
        # strace -S calls -c -p

        local l_audit_name=${l_audit_name:-'auditd'}
        [[ "${pack_manager}" != 'apt-get' ]] && l_audit_name='audit'
        funcCommandExistCheck 'auditd' || funcPackageManagerOperation 'install' "${l_audit_name}"
        # auditctl -v 2>&1 | sed -r -n 's@^[^[:digit:]]+([[:digit:].]+)@\1@g;p'

        # - auditd.conf configuration
        local l_audit_conf=${l_audit_conf:-'/etc/audit/auditd.conf'}
        if [[ -s "${l_audit_conf}" ]]; then
            # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-configuring_the_audit_service
            # log_file = /var/log/audit/audit.log
            funcAuditdDirectiveSetting 'num_logs' '16' "${l_audit_conf}"
            # log_format raw/nolog
            funcAuditdDirectiveSetting 'log_format' 'raw' "${l_audit_conf}"
            # the maximum size of a single Audit log file
            funcAuditdDirectiveSetting 'max_log_file' '128' "${l_audit_conf}"
            funcAuditdDirectiveSetting 'max_log_file_action' 'keep_logs' "${l_audit_conf}"
            # space_left(xxx) must be larger than admin_space_left(xxx)
            funcAuditdDirectiveSetting 'space_left' '512' "${l_audit_conf}"
            # default is 'SYSLOG'. It is recommended to set the space_left_action parameter to 'email' or 'exec' with an appropriate notification method.
            funcAuditdDirectiveSetting 'space_left_action' 'email' "${l_audit_conf}"
            funcAuditdDirectiveSetting 'action_mail_acct' 'root' "${l_audit_conf}"
            funcAuditdDirectiveSetting 'admin_space_left' '256' "${l_audit_conf}"
            # Should be set to 'single' to put the system into single-user mode and allow the administrator to free up some disk space.
            funcAuditdDirectiveSetting 'admin_space_left_action' 'single' "${l_audit_conf}"
            # Specifies an action that is triggered when no free space is available on the partition that holds the Audit log files, must be set to 'halt' or 'single'.
            funcAuditdDirectiveSetting 'disk_full_action' 'single' "${l_audit_conf}"
            # Specifies an action that is triggered in case an error is detected on the partition that holds the Audit log files, must be set to 'syslog', 'single', or 'halt'.
            funcAuditdDirectiveSetting 'disk_error_action' 'single' "${l_audit_conf}"
            funcAuditdDirectiveSetting 'flush' 'incremental_async' "${l_audit_conf}"
        fi

        # - audit rules
        # Control rules: Allow the Audit system\'s behavior and some of its configuration to be modified.
        # File system rules: Also known as file watches, allow the auditing of access to a particular file or a directory.
        # System call rules: Allow logging of system calls that any specified program makes.

        # file system rule:   auditctl -w path_to_file -p permissions -k key_name
        # systemctl call rule:   auditctl -a action,filter -S system_call -F field=value -k key_name
        # system call rule:  auditctl -a action,filter -S system_call -F field=value -k key_name

        # nispom.rules -- Information System Security chapter of the National Industrial Security Program Operating Manual.
        # stig.rules -- Security Technical Implementation Guides (STIG).
        # pci-dss-v31.rules -- Payment Card Industry Data Security Standard (PCI DSS) v3.1.

        # stig / nispom
        # local l_rule_specify=${l_rule_specify:-'stig'}

        local l_rule_dir=${l_rule_dir:-'/etc/audit/rules.d'}
        local l_rule_path=${l_rule_path:-'/etc/audit/audit.rules'}
        local l_custome_rule_path

        # suse: /usr/share/doc/packages/audit
            # capp.rules  lspp.rules	nispom.rules  stig.rules
        # rhel/centos: /usr/share/doc/audit-2.7.6/rules
            # 30-nispom.rules  30-pci-dss-v31.rules  30-stig.rules
        # debian: /usr/share/doc/auditd/examples/rules
            # 30-nispom.rules.gz  30-pci-dss-v31.rules.gz  30-stig.rules.gz
        # ubuntu: /usr/share/doc/auditd/examples
            # capp.rules.gz lspp.rules.gz nispom.rules.gz stig.rules.gz

        case "${distro_name}" in
            centos|rhel|fedora|amzn )
                # put specified rule under /etc/audit/rules.d/
                l_custome_rule_path="${l_rule_dir}/${auditd_custom_rule##*/}"
                ;;
            debian )
                # put specified rule under /etc/audit/rules.d/
                l_custome_rule_path="${l_rule_dir}/${auditd_custom_rule##*/}"
                ;;
            ubuntu )
                # overwite /etc/audit/audit.rules
                l_custome_rule_path="${l_rule_path}"
                ;;
            opensuse|sles )
                # overwite /etc/audit/audit.rules
                l_custome_rule_path="${l_rule_path}"
                ;;
        esac

        [[ -n "${l_custome_rule_path}" ]] && $download_tool "${auditd_custom_rule}" > "${l_custome_rule_path}"
        [[ -d '/etc/sysconfig/network-scripts' ]] && sed -r -i '/\/etc\/sysconfig\/network-scripts/{s@^#@@g;}' "${l_custome_rule_path}"

        funcSystemServiceManager 'auditd' 'restart'

        # augenrules --load
        # ausearch -m LOGIN --start today -i
        # ausearch -a 27020
        # ausearch -f /etc/passwd [-i]
        # aureport -x --summary
        # aureport --failed
        # autrace /usr/bin/sudo
        # ausearch -i -p 28278
        # ausearch –start recent -p 21023 –raw | aureport –file –summary
        funcOperationProcedureResultStatement "${l_audit_name}"
    fi
}


funcRkhunterDirectiveSetting(){
    local l_config="${1:-}"
    local l_item="${2:-}"
    local l_val="${3:-}"

    if [[ -s "${l_config}" && -n "${l_item}" ]]; then
        if [[ -n "${l_val}" ]]; then
            sed -r -i '/^#?[[:space:]]*'"${l_item}"'=/{s@^#?[[:space:]]*([^=]*=).*$@\1'"${l_val}"'@g;}' "${l_config}" &> /dev/null
        else
            sed -r -i '/^#?[[:space:]]*'"${l_item}"'=/{s@^#?[[:space:]]*(.*)$@\1@g;}' "${l_config}" &> /dev/null
        fi
    fi
}

funcAideDirectiveSetting(){
    local l_config="${1:-}"
    local l_item="${2:-}"
    local l_val="${3:-}"

    if [[ -s "${l_config}" && -n "${l_item}" ]]; then
        if [[ -n "${l_val}" ]]; then
            sed -r -i '/^#?[[:space:]]*'"${l_item}"'=/{s@^#?[[:space:]]*([^=]*=).*$@\1'"${l_val}"'@g;}' "${l_config}" &> /dev/null
        else
            sed -r -i '/^#?[[:space:]]*'"${l_item}"'=/{s@^#?[[:space:]]*(.*)$@\1@g;}' "${l_config}" &> /dev/null
        fi
    fi
}

funcSecurityOperation(){
    # - Web server scanner
    if ! funcCommandExistCheck 'nikto'; then
        funcOperationProcedureStatement 'Web server scanner'
        funcPackageManagerOperation 'install' 'nikto'
        nikto -update &> /dev/null
        funcOperationProcedureResultStatement 'nikto'

        # nikto -C all -h https://www.google.com -p 443
    fi

    # Rootkit Detection    /etc/cron.*/rkhunter
    if ! funcCommandExistCheck 'rkhunter'; then
        # https://www.digitalocean.com/community/tutorials/how-to-use-rkhunter-to-guard-against-rootkits-on-an-ubuntu-vps
        # /etc/rkhunter.conf    /etc/default/rkhunter
        # /var/log/rkhunter/rkhunter.log      /var/log/rkhunter.log
        funcOperationProcedureStatement "Rootkit detection"
        local rootkit_name=${rootkit_name:-'rkhunter'}
        funcPackageManagerOperation 'install' "${rootkit_name}"
        rkhunter --update -q &> /dev/null

        local l_rkhunter_conf=${l_rkhunter_conf:-'/etc/rkhunter.conf'}
        if [[ -s "${l_rkhunter_conf}" ]]; then
            # mail to
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'MAIL-ON-WARNING' 'root'
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'MAIL_CMD'
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'ALLOW_SSH_PROT_V1' '0'
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'SSH_CONFIG_DIR'

            local l_ssh_permit_root_login=${l_ssh_permit_root_login:-}
            [[ -s '/etc/ssh/sshd_config' ]] && l_ssh_permit_root_login=$(sed -r -n '/^[[:space:]]*PermitRootLogin/{s@^[[:space:]]*[^[:space:]]*[[:space:]]*(.*)$@\1@g;p}' /etc/ssh/sshd_config 2> /dev/null)
            [[ -n "${l_ssh_permit_root_login}" ]] && funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'ALLOW_SSH_ROOT_USER' "${l_ssh_permit_root_login}"
        fi

        # /etc/cron.*/rkhunter and /etc/apt/apt.conf.d/90rkhunter
        local l_rkhunter_cron_conf=${l_rkhunter_cron_conf:-'/etc/default/rkhunter'}
        if [[ "${cron_task}" -eq 1 && -s "${l_rkhunter_cron_conf}" ]]; then
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'CRON_DAILY_RUN' "\"yes\""
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'CRON_DB_UPDATE' "\"yes\""
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'DB_UPDATE_EMAIL' "\"yes\""
            # email to
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'REPORT_EMAIL' "\"root\""
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'APT_AUTOGEN' "\"yes\""
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'NICE' "\"-5\""
            funcRkhunterDirectiveSetting "${l_rkhunter_conf}" 'RUN_CHECK_ON_BATTERY' "\"false\""
        fi

        # For rhel/centos
        # /etc/sysconfig/rkhunter

        # rkhunter -C
        # rkhunter --propupd
        # rkhunter -c --sk [--rwo]
        # rkhunter -c --enable all --disable none [--rwo]

        # --sk means skip to push Enter key
        # --rwo means display only warnings

        funcOperationProcedureResultStatement "${rootkit_name}"
    fi

    # clamav: Clam AntiVirus is an anti-virus toolkit for UNIX. The main purpose of this software is the integration with mail servers (attachment scanning).
    if funcCommandExistCheck 'systemctl'; then
        if ! funcCommandExistCheck 'freshclam'; then
            funcOperationProcedureStatement "Anti-virus toolkit"
            # https://guylabs.ch/2013/09/18/install-clamav-antivirus-in-ubuntu-server-and-client/
            # https://hostpresto.com/community/tutorials/how-to-install-clamav-on-centos-7/
            local clam_name='clamav'
            local clam_service_name=''
            case "${pack_manager}" in
                apt-get )
                    # https://askubuntu.com/questions/589318/freshclam-error-clamd-conf-file-not-found/632911
                    clam_service_name='clamav-freshclam'
                    # clamav-daemon is used to create file /etc/clamav/clamd.conf
                    # /etc/clamav/freshclam.conf -- 'NotifyClamd /etc/clamav/clamd.conf'
                    funcPackageManagerOperation 'install' 'clamav clamav-daemon clamav-freshclam'
                    if [[ -s '/etc/clamav/freshclam.conf' ]]; then
                        # Check for new database 6 times a day
                        sed -r -i '/^#?[[:space:]]*Checks/{s@^#?[[:space:]]*([^[:space:]]*[[:space:]]).*$@\16@g;p}' /etc/clamav/freshclam.conf
                    fi
                    ;;
                dnf|yum )
                    clam_service_name='clamd@scan'
                    funcPackageManagerOperation 'install' 'clamav clamav-scanner clamav-server clamav-devel clamav-update clamav-scanner-systemd clamav-scanner-systemd clamav-scanner-sysvinit clamav-server-sysvinit'

                    if [[ -s '/etc/clamd.d/scan.conf' ]]; then
                        sed -r -i '/^Example$/{s@^#?@#@g;}' /etc/clamd.d/scan.conf
                        sed -r -i '/LocalSocket[[:space:]]+/{s@^#?@@g;}' /etc/clamd.d/scan.conf
                    fi

                    if [[ -s '/etc/freshclam.conf' ]]; then
                        sed -r -i '/^Example$/{s@^#?@#@g;}' /etc/freshclam.conf
                    fi
                    ;;
                zypper )
                    clam_service_name='freshclam'
                    funcPackageManagerOperation 'install' "${clam_name}"
                    [[ -s '/etc/clamd.conf' ]] && sed -r -i '/LocalSocket[[:space:]]+/{s@^#?@@g;}' /etc/clamd.conf
                    ;;
            esac

            if funcCommandExistCheck 'freshclam'; then
                # SELinux configuation
                funcSELinuxSemanageOperation 'antivirus_can_scan_system' 'on' 'boolean'
                funcSELinuxSemanageOperation 'clamd_use_jit' 'on' 'boolean'

                funcSystemServiceManager "${clam_service_name}" 'stop'
                freshclam &> /dev/null
                funcSystemServiceManager "${clam_service_name}" 'enable'
            fi
            # usage: clamscan -r --bell -i /etc
            funcOperationProcedureResultStatement "${clam_name}"
        fi
    fi

    # aide - Advanced Intrusion Detection Environment    /etc/cron.daily/aide
    if ! funcCommandExistCheck 'aide'; then
        # https://www.tecmint.com/check-integrity-of-file-and-directory-using-aide-in-linux/
        funcOperationProcedureStatement "Intrusion detection environment"

        local aide_name='aide'
        local aide_dbname_init
        local aide_dbname_new

        # /etc/default/aide    /etc/aide/aide.conf
        if [[ "${pack_manager}" == 'apt-get' ]]; then
            # auto install email client postfix/exim4

            # https://major.io/2015/10/14/what-i-learned-while-securing-ubuntu/
            # http://sysblog.sund.org/using-aide-on-ubuntu/
            # https://hungred.com/how-to/install-aide-intrusion-detection-system-ubuntu/
            aide_dbname_init='/var/lib/aide/aide.db.new'
            aide_dbname_new='/var/lib/aide/aide.db'
            funcPackageManagerOperation 'install' "${aide_name}"
            aideinit -f &> /dev/null
            [[ -s "${aide_dbname_new}" ]] && rm -f "${aide_dbname_new}"
            [[ -s "${aide_dbname_init}" ]] && mv "${aide_dbname_init}" "${aide_dbname_new}"
            # usege: aide.wrapper -C / --check
        else
            aide_dbname_init='/var/lib/aide/aide.db.new.gz'
            aide_dbname_new='/var/lib/aide/aide.db.gz'
            funcPackageManagerOperation 'install' "${aide_name}"
            aide -i &> /dev/null
            [[ -s "${aide_dbname_new}" ]] && rm -f "${aide_dbname_new}"
            [[ -s "${aide_dbname_init}" ]] && mv "${aide_dbname_init}" "${aide_dbname_new}"
            # usage: aide --check / -C
        fi

        # /etc/cron.daily/aide for APT
        local l_aide_cron_conf=${l_aide_cron_conf:-'/etc/default/aide'}
        if [[ "${cron_task}" -eq 1 && -s "${l_aide_cron_conf}" ]]; then
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'CRON_DAILY_RUN' 'yes'
            # email to
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'MAILTO' 'root'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'QUIETREPORTS' 'yes'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'COPYNEWDB' 'no'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'TRUNCATEDETAILS' 'no'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'FILTERUPDATES' 'yes'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'FILTERINSTALLATIONS' 'yes'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'LINES' '2000'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'UPAC_CONFDIR'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'UPAC_CONFD'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'UPAC_SETTINGSD'
            funcAideDirectiveSetting "${l_aide_cron_conf}" 'CRONEXITHOOK' "\"fatal\""

            funcCommandExistCheck 'update-aide.conf' && update-aide.conf &> /dev/null
        fi

        funcOperationProcedureResultStatement "${aide_name}"
    fi


    # tripwire - a file integrity checker for UNIX systems
    # As tripwire need to install postfix and config site_key & local_key passphrase, it will prompt interactive window which will disrupt script execution process, so if you wanna install tripwire, please manually execute the following commands
    if funcCommandExistCheck 'tripwireNO'; then
        # Tripwire is a tool that aids system administrators and users in monitoring a designated set of files for any changes.
        # https://www.server-world.info/en/note?os=Ubuntu_16.04&p=tripwire
        # https://www.howtoforge.com/tutorial/how-to-monitor-and-detect-modified-files-using-tripwire-on-ubuntu-1604/

        # yum
        yum install -y -q epel-release
        yum install -y -q tripwire
        tripwire-setup-keyfiles
        # apt
        apt-get -yq install tripwire

        # - configuation file
        # /etc/tripwire/twcfg.txt
        # /etc/tripwire/twpol.txt

        # - check directory not exist, run 'tripwire --init' will prompt error
        # tripwire --check 2>&1 | grep 'Filename' > /tmp/no-directory.txt

        # - config file setting
        local l_twpol
        l_twpol='/etc/tripwire/twpol.txt'
        if [[ -s "${l_twpol}" ]]; then
            # Boot Scripts
            sed -r -i '/rc.boot[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1#@g;}' "${l_twpol}"
            # System boot changes
            sed -r -i '/\/var\/lock[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1#@g;}' "${l_twpol}"
            sed -r -i '/\/var\/run[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1#@g;}' "${l_twpol}"
            # Root config files
            sed -r -i '/\/root[[:space:]]+/,/}/{s@^([[:space:]]+)#*[[:space:]]*@\1#@g;}' "${l_twpol}"
            sed -r -i '/\/root[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1@g;}' "${l_twpol}"
            sed -r -i '/\/root\/.bashrc[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1@g;}' "${l_twpol}"
            sed -r -i '/\/root\/.bash_history[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1@g;}' "${l_twpol}"
            # Devices & Kernel information
            sed -r -i '/\/dev\/[^[:space:]]+[[:space:]]+/d' "${l_twpol}"
            sed -r -i '/\/dev[[:space:]]+/a /dev/pts        -> $(Device);\n/dev/shm        -> $(Device);\n/dev/hugepages  -> $(Device);\n/dev/mqueue     -> $(Device);' "${l_twpol}"
            sed -r -i '/\/proc[[:space:]]+/{s@^([[:space:]]+)#*[[:space:]]*@\1#@g;}' "${l_twpol}"
            sed -r -i '/\/proc\/[^[:space:]]+[[:space:]]+/d' "${l_twpol}"
            sed -r -i '/\/proc[[:space:]]+/a /proc/devices           -> $(Device) ;\n/proc/net               -> $(Device) ;\n/proc/tty               -> $(Device) ;\n/proc/cpuinfo           -> $(Device) ;\n/proc/modules           -> $(Device) ;\n/proc/mounts            -> $(Device) ;\n/proc/dma               -> $(Device) ;\n/proc/filesystems       -> $(Device) ;\n/proc/interrupts        -> $(Device) ;\n/proc/ioports           -> $(Device) ;\n/proc/kcore             -> $(Device) ;\n/proc/self              -> $(Device) ;\n/proc/kmsg              -> $(Device) ;\n/proc/stat              -> $(Device) ;\n/proc/loadavg           -> $(Device) ;\n/proc/uptime            -> $(Device) ;\n/proc/locks             -> $(Device) ;\n/proc/meminfo           -> $(Device) ;\n/proc/misc              -> $(Device) ;' "${l_twpol}"
            [[ -d /proc/scsi ]] && sed -r -i '/\/proc[[:space:]]+/a /proc/scsi              -> $(Device) ;' "${l_twpol}"
            sed -r -i '/\/dev[[:space:]]+/,/}/{/[^}]/{s@^[[:space:]]*@    @g;}}' "${l_twpol}"
            # Critical system boot files
            sed -r -i '/\/boot\/[^[:space:]]+[[:space:]]+/d' "${l_twpol}"
            [[ -d /boot/efi ]] && sed -r -i '/\/boot[[:space:]]+/a /boot/efi       -> $(SEC_CRIT) ;' "${l_twpol}"
            sed -r -i '/\/boot[[:space:]]+/,/}/{/[^}]/{s@^[[:space:]]*@    @g;}}' "${l_twpol}"
        fi

        # - recreating the encrypted policy file: /etc/tripwire/tw.pol
        twadmin -m P "${l_twpol}"
        # - initialize database
        tripwire --init

        # - check command
        # sudo tripwire --check
        # sudo tripwire --check --interactive

        # - print report
        # twprint --print-report --twrfile /var/lib/tripwire/report/centos7-20180116-151815.twr > /tmp/report.txt

        # - cron task
        # 30 3 * * * /usr/sbin/tripwire --check | mail -s "Tripwire report for `uname -n`" your_email@domain.com
    fi

}


funcUnwantedServiceSetting(){
    local l_service_name="${1:-}"
    local l_description="${2:-}"
    local l_result="${3:-}"

    local l_continue=${l_continue:-0}
    if [[ -n "${l_service_name}" ]]; then
        if [[ -s "/lib/systemd/system/${l_service_name}.service" ]]; then
            [[ $(systemctl is-enabled "${l_service_name}") == 'enabled' ]] && l_continue=1
        elif [[ -s "/etc/init.d/${l_service_name}" ]]; then
            local l_sysv_command
            if funcCommandExistCheck 'chkconfig'; then
                l_sysv_command='chkconfig'  # for RedHat/OpenSUSE
            elif funcCommandExistCheck 'sysv-rc-conf'; then
                l_sysv_command='sysv-rc-conf'   # for Debian
            fi

            [[ -n "${l_sysv_command}" && -n $(${l_sysv_command} --list "${l_service_name}" | sed -r -n '/3:on/{p}') ]] && l_continue=1

        elif funcCommandExistCheck "${l_service_name}"; then
            l_continue=1
        fi
    fi

    if [[ "${l_continue}" -eq 1 ]]; then
        funcOperationProcedureStatement "Disable ${l_description} service"
        funcSystemServiceManager "${l_service_name}" 'disable'
        funcOperationProcedureResultStatement "${l_result}"
    fi
}

funcUnwantedServiceOperation(){
     # chkconfig --list | grep '3:on'
    # systemctl list-unit-files --state=enabled
    # systemctl list-units --type service
    # systemd-cgtop
    # systemctl list-dependencies graphical.target

    if [[ "${pack_manager}" == 'apt-get' ]]; then
        funcUnwantedServiceSetting 'apt-daily' 'apt-daily'
        funcUnwantedServiceSetting 'apt-daily-upgrade' 'apt-daily-upgrade'
    fi

    funcUnwantedServiceSetting 'bluetooth' 'Bluetooth'

    # minissdpd - daemon keeping track of UPnP devices up
    # minissdpd listen for SSDP traffic and keeps track of what are the UPnP devices  up on the network. The list of the UPnP devices is accessed by programs looking for devices, skipping the UPnP discovery process.
    funcUnwantedServiceSetting 'minissdpd' 'Universal Plug and Play (UPnP)'

    # avahi-daemon - The Avahi mDNS/DNS-SD daemon
    # The Avahi daemon implements the DNS Service Discovery and Multicast DNS protocols, which provide service and host discovery on a network. It allows a system to automatically identify resources on the network, such as printers or web servers. If you removed Avahi daemon and your network connections crashed and you need to manually configure Network Interface Card again.
    # funcPackageManagerOperation 'remove' 'avahi'
    funcUnwantedServiceSetting 'avahi-daemon' 'Avahi daemon'

    # anacron - runs commands periodically
    # Anacron can be used to execute commands periodically, with a frequency specified in days. Unlike cron(8), it does not assume that the machine is running continuously. Hence, it can be used on machines that aren't running 24 hours a day, to control daily, weekly, and monthly jobs that are usually controlled by cron.
    # /etc/anacrontab
    funcUnwantedServiceSetting 'anacron' 'Anacron'

    # Service control for the automounter
    # autofs controls the operation of the automount(8) daemon(s) running on the Linux system. Usually autofs is invoked at system boot time with the start parameter and at shutdown time with the  stop parameter. Service control actions can also be manually invoked by the system administrator to shut down, restart, reload or obtain service status.
    funcUnwantedServiceSetting 'autofs' 'autofs'

    # pcscd - PC/SC Smart Card Daemon
    # pcscd is the daemon program for pcsc-lite. It is a resource manager that coordinates communications with smart card readers and smart cards and cryptographic tokens that are connected to the system.
    funcUnwantedServiceSetting 'pcscd' 'PC/SC Smart Card Daemon'

    # CUPS printing system
    # funcPackageManagerOperation 'remove' 'cupsd'
    funcUnwantedServiceSetting 'cups' 'CUPS' 'port 631'

    # Universal Addresses to RPC Program Number Mapper
    # Securing rpcbind only affects NFSv2 and NFSv3 implementations, since NFSv4 no longer requires it. If you plan to implement an NFSv2 or NFSv3 server, then rpcbind is required.
    # funcPackageManagerOperation 'remove' 'rpcbind'
    funcUnwantedServiceSetting 'rpcbind' 'RPC' 'port 111'

    # Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL), TLS
    # funcPackageManagerOperation 'remove' 'postfix'
    # funcUnwantedServiceSetting 'postfix' 'Postfix' 'port 25'

    # exim4 - a Mail Transfer Agent
    # funcPackageManagerOperation 'remove' 'exim4'
    # funcUnwantedServiceSetting 'exim4' 'Exim (v4)' 'port 25'
}

funcSecuritySummaryOperation(){
    funcOperationPhaseStatement 'Kernel Optimization'
    funcKernelOptimization

    funcOperationPhaseStatement 'System Hardening'
    funcSystemHardeningOperation

    funcOperationPhaseStatement 'System Audit'
    funcAuditOperation
    # https://www.safecomputing.umich.edu/protect-the-u/protect-your-unit/hardening/secure-linux-unix-server
    if [[ "${security_enhance}" -eq 1 ]]; then
        funcOperationPhaseStatement 'System Security'
        funcSecurityOperation
    fi

    funcOperationPhaseStatement 'Unwanted Service'
    funcUnwantedServiceOperation
}


#########  2-11. Cron Task  #########
funcCronTaskConfiguration(){
    funcOperationPhaseStatement "Cron Scheduled Task"

    # set cron task at hour 4 in the morning
    local l_crontab=${l_crontab:-'/etc/crontab'}
    if [[ -s "${l_crontab}" ]]; then
        local l_hour_choose=${l_hour_choose:-4}
        sed -r -i '/bin\/anacron/{s@^([[:digit:]]{1,2}[[:space:]]*)[[:digit:]]{1,2}(.*)$@\1'"${l_hour_choose}"' \2@g;}' "${l_crontab}"
    fi

    # - system update weekly
    local system_update_path="/etc/cron.weekly/${pack_manager%%-*}_update"
    if [[ ! -s "${system_update_path}" ]]; then
        funcOperationProcedureStatement 'system update'
        echo -e "#!/usr/bin/env bash\n#system update weekly\n" > "${system_update_path}"
        case "${pack_manager}" in
            apt-get ) echo -e "/usr/bin/apt-get -yq clean all &> /dev/null\n/usr/bin/apt-get -yq update &> /dev/null\n/usr/bin/apt-get -yq upgrade &> /dev/null\n/usr/bin/apt-get -yq dist-upgrade &> /dev/null\n/usr/bin/apt-get -yq autoremove &> /dev/null\n" >> "${system_update_path}" ;;
            dnf ) echo -e "/usr/bin/dnf -yq clean all &> /dev/null\n/usr/bin/dnf -yq makecache &> /dev/null\n/usr/bin/dnf -yq upgrade &> /dev/null\n/usr/bin/dnf -yq autoremove &> /dev/null\n" >> "${system_update_path}" ;;
            yum ) echo -e "/usr/bin/yum -y -q clean all &> /dev/null\n/usr/bin/yum -y -q makecache fast &> /dev/null\n/usr/bin/yum -y -q update &> /dev/null\n/usr/bin/yum -y -q upgrade &> /dev/null\n/usr/bin/yum -y -q autoremove &> /dev/null\n"  >> "${system_update_path}" ;;
            zypper ) echo -e "/usr/bin/zypper clean -a &> /dev/null\n/usr/bin/zypper ref -f &> /dev/null\n/usr/bin/zypper up -yl &> /dev/null\n/usr/bin/zypper dup -yl &> /dev/null\n/usr/bin/zypper patch -yl &> /dev/null\n/usr/bin/zypper packages --unneeded | awk -F\| 'match(\$1,/^i/){print \$3}' | /usr/bin/xargs /usr/bin/zypper rm -yu &> /dev/null\n" >> "${system_update_path}" ;;
        esac
        echo -e "#Script end" >> "${system_update_path}"
        chmod 750 "${system_update_path}"
        funcOperationProcedureResultStatement "${system_update_path}"
    fi

    # - clamav daily
    if funcCommandExistCheck 'clamscan'; then
        local clamav_scan_path=${clamav_scan_path:-'/etc/cron.daily/clamav_scan'}
        if [[ ! -s "${clamav_scan_path}" ]]; then
            funcOperationProcedureStatement 'clam antiVirus scan'
            echo -e "#!/usr/bin/env bash\n#clamav scan daily\n" > "${clamav_scan_path}"
            echo -e "name='clamscan'\nlog_path=\"/var/log/clamav/dailyscan-\$(date +'%F').log\"\nexecuting_path=\$(which \$name 2> /dev/null || command -v \$name 2> /dev/null)\n[[ -z \"\${executing_path}\" ]] && executing_path='/usr/bin/clamscan'\nfreshclam &> /dev/null\n\${executing_path} -r --bell -i --quiet --max-filesize=1024M --enable-stats --exclude-dir=/sys/* / > \"\${log_path}\"\nmail -s \"Daily Clam AntiVirus report for \$(hostname -f)\" root < \"\${log_path}\"\n" >> "${clamav_scan_path}"
            echo -e "#Script end" >> "${clamav_scan_path}"
            chmod 750 "${clamav_scan_path}"
            funcOperationProcedureResultStatement "${clamav_scan_path}"
        fi
    fi

    # - aide daily
    if funcCommandExistCheck 'aide'; then
        # for rhel/centos
        local aide_scan_path=${aide_scan_path:-'/etc/cron.daily/aide'}
        if [[ ! -s "${aide_scan_path}" ]]; then
            funcOperationProcedureStatement 'aide check'
            echo -e "#!/usr/bin/env bash\n#Aide check daily\n" > "${aide_scan_path}"
            echo -e "name='aide'\nlog_path=\"/tmp/aide-check-\$(date +'%F').log\"\nexecuting_path=\$(which \$name 2> /dev/null || command -v \$name 2> /dev/null)\n[[ -z \"\${executing_path}\" ]] && executing_path='/sbin/aide'\n# aide --update &> /dev/null\n\${executing_path} --check &> \"\${log_path}\"\nmail -s \"Daily AIDE report for \$(hostname -f)\" root < \"\${log_path}\"\n\n[[ -f \"\${log_path}\" ]] && rm -f \"\${log_path}\"\n" >> "${aide_scan_path}"
            echo -e "#Script end" >> "${aide_scan_path}"
            chmod 750 "${aide_scan_path}"
            funcOperationProcedureResultStatement "${aide_scan_path}"
        fi
    fi

}


#########  3. Operation Time Cost  #########
funcOperationTimeCost(){
    finish_time=$(date +'%s')        # processing end time
    total_time_cost=$((finish_time-start_time))   # time costing

    printf "\nTotal time cost is ${c_red}%s${c_normal} seconds!\n" "${total_time_cost}"
    printf "\nTo make configuration effect, please ${c_red}%s${c_normal} your system!\n" "reboot"

    remove_old_kernel=${remove_old_kernel:-}

    case "${pack_manager}" in
        yum )
            if funcCommandExistCheck 'package-cleanup'; then
                # keep an older kernel
                remove_old_kernel='package-cleanup --oldkernels --count=1'
            else
                remove_old_kernel="${pack_manager} remove \$(rpm -qa | awk -v verinfo=\$(uname -r) 'BEGIN{gsub(\".?el[0-9].*$\",\"\",verinfo)}match(\$0,/^kernel/){if(\$0!~verinfo) print \$0}' | sed '1d')"
            fi
            ;;
        dnf )
            remove_old_kernel="${pack_manager} remove \$(rpm -qa | awk -v verinfo=\$(uname -r) 'BEGIN{gsub(\".?el[0-9].*$\",\"\",verinfo)}match(\$0,/^kernel/){if(\$0!~verinfo) print \$0}' | sed '1d')"
            ;;
        apt-get )
            remove_old_kernel="${pack_manager} purge \$(dpkg -l | awk -v verinfo=\$(uname -r) 'match(\$0,/linux-image-/){if(\$0!~/-hwe/&&\$2!~verinfo) print \$2}' | sed '1d')"
            ;;
        zypper )
            [[ $(rpm -qa | grep -c ^kernel-default) -gt 1 ]] && remove_old_kernel="${pack_manager} remove \$(zypper packages --installed-only | awk -F\| -v verinfo=\$(uname -r) 'BEGIN{OFS=\"-\"}match(\$1,/^i/)&&match(\$0,/kernel-default/){gsub(\"-default\",\"\",verinfo);gsub(\" \",\"\",\$0);if(\$4!~verinfo){print\$3,\$4}}')"
            ;;
    esac

    [[ -z "${remove_old_kernel}" ]] || printf "\nTo remove old version kernel, executing the following commands: \n\n${c_yellow}%s${c_normal}\n\n" "sudo ${remove_old_kernel}"

    if [[ "${zypper_selinux}" -eq 1 ]]; then
        funcCommandExistCheck 'restorecon' && echo -e "\nAfter reboot, executing the following commands to configure SELinux:\n\n${c_yellow}sudo restorecon -Rp /\n\nsudo sed -r -i '/^#?[[:space:]]*SELINUX=[^[:space:]]+/{s@^#?[[:space:]]*(SELINUX=).*\$@\1enforcing@g}' /etc/selinux/config\n\nsudo yast2 bootloader${c_normal}\n\n"
    fi
}


#########  4. Executing Process  #########
funcInitializationCheck
funcInternetConnectionCheck
funcDownloadToolCheck
funcPackageManagerDetection
funcOSInfoDetection

funcPackRepositoryOperation
funcSELinuxConfiguration
funcGRUBConfiguring
funcHostnameTimezoneSetting
funcSystemUserConfiguration
funcEssentialPackInstallation
[[ "${administrator_utility}" -eq 1 ]] && funcAdministrationPackInstallation
funcOpenBSDSecureShellOperation
funcFirewallSetting
funcTmpfsSystemSetting
funcSecuritySummaryOperation
[[ "${cron_task}" -eq 1 ]] && funcCronTaskConfiguration

funcOperationTimeCost


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    unset bak_suffix
    unset pass_change_minday
    unset pass_change_maxday
    unset pass_change_warnningday
    unset zypper_selinux
    unset disable_ssh_root
    unset enable_sshd
    unset ssh_port_default
    unset ssh_port
    unset change_repository
    unset just_keygen
    unset restrict_remote_login
    unset grub_timeout
    unset hostname_specify
    unset username_specify
    unset timezone_specify
    unset tmpfs_enable
    unset grant_sudo
    unset log_user_session
    unset administrator_utility
    unset security_enhance
    unset remove_unneeded_pack
    unset cron_task
    unset kernel_upgrade
    unset proxy_server
    unset flag
    unset procedure_start_time
    unset procedure_end_time
    unset distro_fullname
    unset distro_name
    unset codename
    unset version_id
    unset ip_local
    unset ip_public
    unset start_time
    unset sshd_existed
    unset tmpfs_enable
    unset finish_time
    unset total_time_cost
    unset remove_old_kernel
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
}

trap funcTrapEXIT EXIT



# # sudo selinux-ready
# Start checking your system if it is selinux-ready or not:
# 	check_dir: OK. /selinux exists.
# 	check_dir: OK. /sys/fs/selinux exists.
# 	check_filesystem: OK. Filesystem 'securityfs' exists.
# 	check_filesystem: OK. Filesystem 'selinuxfs' exists.
# 	check_boot: Assuming GRUB2 as bootloader.
# 	check_boot: OK. Current kernel 'vmlinuz-4.4.103-6.38-default' has boot-parameters 'security=selinux selinux=1'
# 	check_boot: OK. Other kernels with correct parameters:
# 	check_mkinitrd: OK. Your initrd seems to be correct.
# 	check_packages: OK. All essential packages are installed
# 	check_config: OK. Config file seems to be there.
# 	check_config: OK. SELINUX is set to 'permissive'.
# 	check_pam: OK. Your PAM configuration seems to be correct.
# 	check_runlevel: OK. restorecond is enabled on your system


# Script End
