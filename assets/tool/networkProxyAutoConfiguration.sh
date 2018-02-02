#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Configuration Network Proxy For GNOME/Utility Desktop Enviroment In GNU/Linux
#Writer: MaxdSre
#Date: Nov 25, 2017 14:18 Sat +0800


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'NPCTemp_XXXXXX'}

# trap '' HUP	#overlook SIGHUP when internet interrupted or terminal shell closed
# trap '' INT   #overlook SIGINT when enter Ctrl+C, QUIT is triggered by Ctrl+\
trap funcTrapINTQUIT INT QUIT

funcTrapINTQUIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    printf "Detect $(tput setaf 1)%s$(tput sgr0) or $(tput setaf 1)%s$(tput sgr0), begin to exit shell\n" "CTRL+C" "CTRL+\\"
    exit
}

#########  0-2. Variables Setting  #########
readonly c_bold="$(tput bold)"
readonly c_normal="$(tput sgr0)"
# black 0, red 1, green 2, yellow 3, blue 4, magenta 5, cyan 6, gray 7
readonly c_red="${c_bold}$(tput setaf 1)"
readonly c_blue="$(tput setaf 4)"

proxy_mode=${proxy_mode:-'none'}   # none/manual/auto
proxy_type=${proxy_type:-'socks'}   # ftp/http/https/socks for manual mode
proxy_server=${proxy_server:-''}
ssh_socks_use=${ssh_socks_use:-0}


#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | bash -s -- [options] ...

Configuring Network Proxy For GNOME/Utility Desktop Enviroment In GNU/Linux (RHEL/SUSE/Debian)

Running as normal user.

[available option]
    -h    --help, show help info
    -t proxy_type    --specify proxy type (ftp/http/https/socks), default is 'socks'
    -p ip:port    --specify proxy host info, e.g. '8.8.8.8:8888', default is ''
    -s    --use socks proxy created via ssh tunnel in local host, e.g. '127.0.0.1:56789'
EOF
    # -m proxy_mode    --specify proxy mode (none/manual/auto), default is 'none'
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
    # [[ "$UID" -ne 0 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script requires superuser privileges (eg. root, su)."

    # 2 - OS support check
    [[ -s /etc/os-release || -s /etc/SuSE-release || -s /etc/redhat-release || (-s /etc/debian_version && -s /etc/issue.net) ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script doesn't support your system!"

    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    # [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    # 4 - current login user detection
    #$USER exist && $SUDO_USER not exist, then use $USER
    [[ -n "${USER:-}" && -z "${SUDO_USER:-}" ]] && login_user="$USER" || login_user="$SUDO_USER"
    login_user_home=${login_user_home:-}
    login_user_home=$(awk -F: 'match($1,/^'"${login_user}"'$/){print $(NF-1)}' /etc/passwd)

    # 5 -  Check essential command
    if [[ "${login_user}" != 'root' ]]; then
        funcCommandExistCheck 'sudo' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}sudo${c_normal} command found!"
    fi

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"
}

funcInternetConnectionCheck(){
    # CentOS: iproute Debian/OpenSUSE: iproute2
    local gateway_ip=${gateway_ip:-}
    if funcCommandExistCheck 'ip'; then
        gateway_ip=$(ip route | awk 'match($1,/^default/){print $3}')
    elif funcCommandExistCheck 'netstat'; then
        gateway_ip=$(netstat -rn | awk 'match($1,/^Destination/){getline;print $2;exit}')
    else
        funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}ip${c_normal} or ${c_blue}netstat${c_normal} command found, please install it!"
    fi

    ! ping -q -w 1 -c 1 "$gateway_ip" &> /dev/null && funcExitStatement "${c_red}Error${c_normal}: No internet connection detected, disable ICMP? please check it!"   # Check Internet Connection
}

#########  1-2 getopts Operation  #########
while getopts "hm:t:p:s" option "$@"; do
    case "$option" in
        # m ) proxy_mode="$OPTARG" ;;
        t ) proxy_type="$OPTARG" ;;
        p ) proxy_server="$OPTARG" ;;
        s ) ssh_socks_use=1 ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2-1. Parameters Processing  #########
funcParametersProcessing(){
    # ssh_socks_use
    if [[ "${ssh_socks_use}" -eq 1 ]]; then
        local ssh_proxy_info=${ssh_proxy_info:-}
        local use_sudo=${use_sudo:-}
        [[ "${login_user}" == 'root' ]] && use_sudo='sudo'
        # https://stackoverflow.com/questions/14126705/setting-proxy-through-bash-script-in-ubuntu
        funcCommandExistCheck 'ss' && ssh_proxy_info=$(${use_sudo} bash -c 'ss -tnlp' | awk 'match($NF,/"ssh"/)&&match($4,/^127.0.0.1/){print $4; exit}')

        if [[ -z "${ssh_proxy_info}" ]]; then
            funcCommandExistCheck 'netstat' && ssh_proxy_info=$(${use_sudo} bash -c 'netstat -tnlp 2>&1' | awk 'match($NF,/\/ssh$/)&&match($4,/^127.0.0.1/){print $4;exit}')
        fi

        if [[ -n "${ssh_proxy_info}" ]]; then
            proxy_mode='manual'
            proxy_type='socks'
            proxy_server="${ssh_proxy_info}"
        else
            funcExitStatement "${c_red}Error${c_normal}: fail to detect ssh proxy info in local host!"
        fi
    #  proxy_server
    elif [[ -n "${proxy_server}" ]]; then
        local proxy_pattern="^([0-9]{1,3}.){3}[0-9]{1,3}:[0-9]{1,5}$"

        if [[ "${proxy_server}" =~ $proxy_pattern ]]; then
            case "${proxy_type,,}" in
                ftp|http|https|socks )
                    proxy_mode='manual'
                    proxy_type="${proxy_type,,}"
                    ;;
                * ) funcExitStatement "${c_red}Error${c_normal}: please specify correspond proxy type (ftp/http/https/socks)!" ;;
            esac

        else
            funcExitStatement "${c_red}Error${c_normal}: please specify right proxy host info like ${c_blue}ip:port${c_normal}!"
        fi    # end if proxy_server

    fi    # end if
}

#########  2-2. gsettings Configuration  #########
funcGsettingsConfiguration(){
    funcCommandExistCheck 'gsettings' || funcExitStatement "${c_red}Error${c_normal}: fail to find command ${c_blue}gsettings${c_normal} to configure network proxy!"

    funcParametersProcessing

    case "${proxy_mode}" in
        'none' )
            gsettings set org.gnome.system.proxy mode 'none'
            ;;
        'manual' )
            local proxy_host=${proxy_host:-''}
            local proxy_port=${proxy_port:-0}
            proxy_host="${proxy_server%%:*}"
            proxy_port="${proxy_server##*:}"

            if [[ -n "${proxy_port}" && "${proxy_port}" -gt 0 && "${proxy_port}" -le 65535 ]]; then
                gsettings set org.gnome.system.proxy.${proxy_type} host "${proxy_host}"
                gsettings set org.gnome.system.proxy.${proxy_type} port "${proxy_port}"
                # gsettings get org.gnome.system.proxy.${proxy_type} host
                # gsettings get org.gnome.system.proxy.${proxy_type} port

                gsettings set org.gnome.system.proxy mode 'manual'
            else
                gsettings set org.gnome.system.proxy mode 'none'
                funcExitStatement "${c_red}Error${c_normal}: proxy ${c_blue}${proxy_server}${c_normal} you specify is illegal!"
            fi
            ;;
    esac
}


#########  3. Executing Process  #########
funcInitializationCheck
funcInternetConnectionCheck
funcGsettingsConfiguration


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset proxy_mode
    unset proxy_type
    unset proxy_server
    unset ssh_socks_use
}

trap funcTrapEXIT EXIT

# Script End
