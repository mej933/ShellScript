#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #used in loop,  Internal Field Separator

#Target: Generation Random Unused Port (System/User/Ephemeral) On GNU/Linux
#Writer: MaxdSre
#Date: Dec 30, 2017 11:46 Sat +0800    - Performance optimization
#Update Time:
# - Sep 08, 2016 23:00 Thu +0800
# - Nov 01, 2016 11:23 Thu +0800
# - Dec 21, 2016 15:56 Wed +0800
# - Feb 27, 2017 09:59 Mon +0800
# - May 6, 2017 17:53 Sat -0400
# - June 08, 2017 14:01 Thu +0800
# - Dec 02, 2017 20:30 Sat +0800

# Service Name and Transport Protocol Port Number Registry
# https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
# https://tools.ietf.org/html/rfc6335

# Port numbers are assigned in various ways, based on three ranges:
# 1. System Ports (0-1023)      need root privilege
# 2. User Ports (1024-49151)    not need root privilege
# 3. Dynamic and/or Private Ports (49152-65535)    ephemeral port


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'RUPGTemp_XXXXXX'}
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
readonly c_normal="$(tput sgr0)"     # c_normal='\e[0m'
# black 0, red 1, green 2, yellow 3, blue 4, magenta 5, cyan 6, gray 7
readonly c_red="${c_bold}$(tput setaf 1)"     # c_red='\e[31;1m'
readonly c_blue="$(tput setaf 4)"    # c_blue='\e[34m'

output_format=${output_format:-0}
port_type=${port_type:-'h'}
simple_format=${simple_format:-0}
port_start=${port_start:-}
port_end=${port_end:-}
generate_type=${generate_type:-}


#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...
Generating Random Unused Port (System/User/Ephemeral/High ephemeral) On GNU/Linux!

[available option]
    -h    --help, show help info
    -j    --json, output result via json format
    -t port_type    --specify port type(r/n/e/h), 'r' is system ports (0,1023], 'n' is user ports [1024,32767], e is regular ephemeral port [32768,49151], 'h' is high ephemeral port [49152,65535]. Default is 'h'.
    -s    --simple output, just output port generated
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
    # - OS support check
    [[ -s /etc/os-release || -s /etc/SuSE-release || -s /etc/redhat-release || (-s /etc/debian_version && -s /etc/issue.net) ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script doesn't support your system!"

    # - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    if funcCommandExistCheck 'ss'; then
        check_tool='ss'   # ss -tuanp
        port_field='5'   # awk field $5
        state_field='2'   # awk field $2
    elif funcCommandExistCheck 'netstat'; then
        check_tool='netstat' # netstat -tuanp
        port_field='4'   # awk field $4
        state_field='6'   # awk field $6
    else
        funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}ss${c_normal} or ${c_blue}netstat${c_normal} command found!"
    fi  # End if

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"
}

#########  1-2 getopts Operation  #########
while getopts "hjt:s" option "$@"; do
    case "$option" in
        j ) output_format=1 ;;
        t ) port_type="$OPTARG" ;;
        s ) simple_format=1 ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  Core Processing Procedure  #########
# - Usable Ports Range Check
funcAvailablePortRangeCheck(){
    # http://www.ncftp.com/ncftpd/doc/misc/ephemeral_ports.html
    # Kernel parameter 'ip_local_port_range' control ephemeral port range in GNU/Linux

    case "${port_type,,}" in
        r )
            generate_type='system'
            port_start=1
            port_end=1023
            ;;
        n )
            generate_type='user'
            port_start=1024
            port_end=32767
            ;;
        e)
            generate_type='ephemeral'
            port_start=32768
            port_end=49151
            ;;
        h|* )
            generate_type='high ephemeral'
            port_start=49152
            port_end=65535
            ;;
    esac
}

# - Used Port Check
funcUsedPortCheck(){
    port_used_list=$(mktemp -t "${mktemp_format}") #temporary file
    # 1 - list ports being used by system
    "${check_tool}" -tuanp | awk 'match($1,/^(tcp|udp)/)&&match($'"${state_field}"',/(LISTEN|ESTAB|UNCONN|FIN-WAIT)/){port=gensub(/.*:(.*)/,"\\1","g",$'"${port_field}"'); a[port]++}END{for(i in a) print i}' > "${port_used_list}"

    # 2 - list ports being assigned from file /etc/services, appent unique ports to temporary file
    if [[ -s '/etc/services' ]]; then
        awk 'match($1,/^[^#]/){port=gensub(/([[:digit:]]+)\/.*/,"\\1","g",$2); a[port]++}END{for(i in a) print i}' /etc/services >> "${port_used_list}"
        # sed -n -r 's@.*[[:space:]]+([0-9]+)/.*@\1@p' /etc/services
    fi
}

# - Generate Random Port Unused
funcGenerateRandomPort(){
    local l_port_used_list="$1"
    local l_port_from="$2"
    local l_port_to="$3"
    local random_num
    random_num=$(head -n 25 /dev/urandom | cksum)    # 1503747052 5549
    random_num=${random_num%% *}    # 1503747052
    # https://github.com/koalaman/shellcheck/wiki/Sc2004
    local l_port_generated
    l_port_generated=$((random_num%l_port_to))

    [[ $(grep -c -w "${l_port_generated}" "${l_port_used_list}") -gt 0 || "${l_port_generated}" -lt "${l_port_from}" ]] && l_port_generated=$(funcGenerateRandomPort "${l_port_used_list}" "${l_port_from}" "${l_port_to}") # function iteration
    echo "${l_port_generated}"
}

# - Port Generation & Output
funcPortGenerationAndOutput(){
    local generated_port=${generated_port:-}
    generated_port=$(funcGenerateRandomPort "${port_used_list}" "${port_start}" "${port_end}")    # invoke function

    if [[ "${output_format}" -eq 1 ]]; then
        local l_output_json
        l_output_json='{'
        l_output_json=${l_output_json}"\"generate_type\":\"${generate_type}\","
        [[ "${simple_format}" -eq 1 ]] || l_output_json=${l_output_json}"\"port_range\":\"${port_start}-${port_end}\","
        l_output_json=${l_output_json}"\"port_no\":\"${generated_port}\","
        l_output_json=${l_output_json%,*}
        l_output_json=${l_output_json}'}'
        echo "${l_output_json}"
    else
        if [[ "${simple_format}" -eq 1 ]]; then
            echo "${c_red}${generated_port}${c_normal}"
        else
            printf "Newly gengeated ${c_red}%s${c_normal} port num is ${c_blue}%s${c_normal}.\n" "${generate_type}" "${generated_port}"
        fi
    fi

    [[ -f "${port_used_list}" ]] && rm -f "${port_used_list}"
}


#########  3. Executing Process  #########
funcInitializationCheck
funcAvailablePortRangeCheck
funcUsedPortCheck
funcPortGenerationAndOutput


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    unset output_format
    unset port_type
    unset simple_format
    unset port_start
    unset port_end
    unset generate_type
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
}

trap funcTrapEXIT EXIT
# Script End
