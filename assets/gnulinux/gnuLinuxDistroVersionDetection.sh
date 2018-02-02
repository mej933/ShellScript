#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Detection GNU/Linux Distribution Info
#Note: Be Used For RHEL, Debian, SLES and veriants Distribution
#Writer: MaxdSre
#Date: Jan 23 , 2018 15:58 Tue +0800 - Add timezone detection
#Reconfiguration Date:
# - Oct 19, 2016 10:45 Wed +0800
# - Feb 23, 2017 14:50~17:01 +0800
# - Mar 11, 2017 10:48~12.27 +0800
# - May 5, 2017 20:08 Fri -0400
# - June 6, 2017 21:02 Tue +0800
# - Aug 17, 2017 14:37 Thu +0800
# - Aug 30, 2017 11:58 Wed +0800
# - Dec 30, 2017 19:41 Sat +0800 - Change output style

#Docker Script https://get.docker.com/
#Gitlab Script https://packages.gitlab.com/gitlab/gitlab-ce/install

# lsb_release -a
# lsb-release/redhat-lsb

#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'GLDVDTemp_XXXXXX'}
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

readonly github_raw_url='https://raw.githubusercontent.com'
readonly custom_shellscript_url="${github_raw_url}/MaxdSre/ShellScript"
readonly distro_release_date_list="${custom_shellscript_url}/master/sources/gnulinuxDistroReleaseDateList.txt"

output_format=${output_format:-0}
ip_detection_disable=${ip_detection_disable:-0}
proxy_server=${proxy_server:-''}
ip_public=${ip_public:-''}
ip_public_locate=${ip_public_locate:-''}
ip_public_country_code=${ip_public_country_code:-''}
ip_public_timezone=${ip_public_timezone:-''}
ip_proxy=${ip_proxy:-''}
ip_proxy_locate=${ip_proxy_locate:-''}
ip_proxy_country_code=${ip_proxy_country_code:-''}
ip_proxy_timezone=${ip_proxy_timezone:-''}


#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...

Detect GNU/Linux Distribution System Info!

[available option]
    -h    --help, show help info
    -i    --disabe ip info detection, default enable ip info detection
    -j    --json, output result via json format
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
${c_normal}
EOF
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

funcInternetConnectionCheck(){
    local gateway_ip=${gateway_ip:-}
    # CentOS: iproute Debian/OpenSUSE: iproute2
    if funcCommandExistCheck 'ip'; then
        local net_command='ip'
        gateway_ip=$(ip route | awk 'match($1,/^default/){print $3}')
    elif funcCommandExistCheck 'netstat'; then
        local net_command='netstat'
        gateway_ip=$(netstat -rn | awk 'match($1,/^Destination/){getline;print $2;exit}')
    else
        funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}ip${c_normal} or ${c_blue}netstat${c_normal} command found, please install it!"
    fi

    if [[ -n "${gateway_ip}" ]] && ping -q -w 1 -c 1 "${gateway_ip}" &> /dev/null; then
        [[ "${net_command}" == 'ip' ]] && ip_local=$(ip route get 1 | sed -r -n '1{s@.*src[[:space:]]*([^[:space:]]+).*$@\1@g;p}')
    fi
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
    local referrer_page=${referrer_page:-"https://duckduckgo.com/?q=github"}
    # local user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6.4) AppleWebKit/537.29.20 (KHTML, like Gecko) Chrome/60.0.3030.92 Safari/537.29.20"

    download_tool_origin=${download_tool_origin:-}

    if funcCommandExistCheck 'curl'; then
        download_tool="curl -fsL --retry ${retry_times} --retry-delay ${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-keepalive --referer ${referrer_page}"   # curl -s URL -o /PATH/FILE； -fsSL
        # --user-agent ${user_agent}
        download_tool_origin="${download_tool}"

        if [[ -n "$proxy_server" ]]; then
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
        download_tool_origin="${download_tool}"

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

funcIPInfoExtraction(){
    local l_ip=${1:-}
    local l_ip_info=${l_ip_info:-}

    if [[ "${l_ip}" =~ ^([0-9]{1,3}.){3}[0-9]{1,3}$ ]]; then
        l_ip="/${l_ip}"
    else
        l_ip=''
    fi

    l_ip_info=$($download_tool ipinfo.io"${l_ip}" 2> /dev/null | sed -r -n '/(ip|city|region|country)/{s@^[^:]+:[[:space:]]*[[:punct:]]*([^"]+).*$@\1@g;p}' | sed ':a;N;$!ba;s@\n@|@g')
    # 172.217.24.142|Mountain View|California|US

    if [[ -n "${l_ip_info}" ]]; then
        local l_ip_timezone=${l_ip_timezone:-}
        l_ip_timezone=$($download_tool https://ipsidekick.com"${l_ip}"/json 2> /dev/null | sed -r -n 's@^.*timeZone[[:punct:]]*name[[:punct:]]*([^"]+).*$@\1@g;p')
        [[ -n "${l_ip_timezone}" ]] && l_ip_info="${l_ip_info}|${l_ip_timezone}"
        # 172.217.24.142|Mountain View|California|US|America/Los_Angeles
    else
        l_ip_info=$($download_tool https://ipsidekick.com"${l_ip}"/json 2> /dev/null | sed 's@},@\n@g;' | sed -r -n '/"country"/{s@.*code[[:punct:]]*([^[:punct:]]+).*@\1@g;p}; /"timeZone"/{s@.*name[[:punct:]]*([^"]+).*@\1@g;p}; /"ip"/{s@.*:[[:punct:]]*([^"]+).*@\1@g;p}' | sed ':a;N;$!ba;s@\n@|@g' | awk -F\| '{printf("%s|||%s|%s\n",$3,$1,$2)}')
        # 172.217.24.142|||US|America/Los_Angeles
    fi

    echo "${l_ip_info}"
    # ip|city|region|country_code|timezone
}

funcIPInfoDetection(){
    # https://stackoverflow.com/questions/14594151/methods-to-detect-public-ip-address-in-bash
    # https://www.gnu.org/software/bash/manual/html_node/Redirections.html
    # if [[ -d "/dev" ]]; then
    #     # https://major.io/icanhazip-com-faq/
    #     # exec 6<> /dev/tcp/icanhazip.com/80
    #     # echo -e 'GET / HTTP/1.0\r\nHost: icanhazip.com\r\n\r' >&6
    #     # while read i; do [[ -n "$i" ]] && ip_public="$i" ; done <&6
    #     # exec 6>&-
    #
    #     exec 6<> /dev/tcp/ipinfo.io/80
    #     echo -e 'GET / HTTP/1.0\r\nHost: ipinfo.io\r\n\r' >&6
    #     # echo -e 'GET /ip HTTP/1.0\r\nHost: ipinfo.io\r\n\r' >&6
    #     # echo -e 'GET /country HTTP/1.0\r\nHost: ipinfo.io\r\n\r' >&6
    #
    #     # ip_public=$(cat 0<&6 | sed -r -n '/^\{/,/^\}/{/\"ip\"/{s@[[:space:],]*@@g;s@[^:]*:"([^"]*)"@\1@g;p}}')
    #     detect_ip_info=$(cat 0<&6 | sed -r -n '/^\{/,/^\}/p')
    #     exec 6>&-
    # fi    # end if /dev

    # - Detect Real External IP
    local dig_ip=${dig_ip:-}
    local dig_ip_info=${dig_ip_info:-}
    local dig_ip_timezone=${dig_ip_timezone:-}
    local dig_ip_country_code=${dig_ip_country_code:-}
    local dig_ip_region=${dig_ip_region:-}
    local dig_ip_city=${dig_ip_city:-}

    # - dig ip     get real public ip via dig
    if funcCommandExistCheck 'dig'; then
        dig_ip=$(dig +short myip.opendns.com @resolver1.opendns.com)
        if [[ "${dig_ip}" =~ ^([0-9]{1,3}.){3}[0-9]{1,3}$ ]]; then
            dig_ip_info=$(funcIPInfoExtraction "${dig_ip}")
            if [[ -n "${dig_ip_info}" ]]; then
                dig_ip_city=$(echo "${dig_ip_info}" | awk -F\| '{print $2}')
                dig_ip_region=$(echo "${dig_ip_info}" | awk -F\| '{print $3}')
                dig_ip_country_code=$(echo "${dig_ip_info}" | awk -F\| '{print $4}')
                dig_ip_timezone=$(echo "${dig_ip_info}" | awk -F\| '{print $5}')
            fi    # end if dig_ip_info
        fi    # end if dig_ip
    fi

    # - detected ip
    local detect_ip_info=${detect_ip_info:-}
    local detect_ip_timezone=${detect_ip_timezone:-}
    local detect_ip_country_code=${detect_ip_country_code:-}
    local detect_ip_region=${detect_ip_region:-}
    local detect_ip_city=${detect_ip_city:-}
    local detect_ip=${detect_ip:-}

    detect_ip_info=$(funcIPInfoExtraction)
    if [[ -n "${detect_ip_info}" ]]; then
        detect_ip=$(echo "${detect_ip_info}" | awk -F\| '{print $1}')
        detect_ip_city=$(echo "${detect_ip_info}" | awk -F\| '{print $2}')
        detect_ip_region=$(echo "${detect_ip_info}" | awk -F\| '{print $3}')
        detect_ip_country_code=$(echo "${detect_ip_info}" | awk -F\| '{print $4}')
        detect_ip_timezone=$(echo "${detect_ip_info}" | awk -F\| '{print $5}')
    fi    # end if detect_ip_info

    if [[ -z "${dig_ip}" ]]; then
        ip_public="${detect_ip}"
        ip_public_country_code="${detect_ip_country_code}"
        ip_public_locate="${detect_ip_region}.${detect_ip_city}"
        ip_public_timezone="${detect_ip_timezone}"
    else

        if [[ "${dig_ip}" == "${detect_ip}" ]]; then
            # use detect_ip, not use dig ip
            ip_public="${detect_ip}"
            ip_public_country_code="${detect_ip_country_code}"
            ip_public_locate="${detect_ip_region}.${detect_ip_city}"
            ip_public_timezone="${detect_ip_timezone}"
        else
            ip_proxy="${detect_ip}"
            ip_proxy_country_code="${detect_ip_country_code}"
            ip_proxy_locate="${detect_ip_region}.${detect_ip_city}"
            ip_proxy_timezone="${detect_ip_timezone}"

            ip_public="${dig_ip}"
            ip_public_country_code="${dig_ip_country_code}"
            ip_public_locate="${dig_ip_region}.${dig_ip_city}"
            ip_public_timezone="${dig_ip_timezone}"
        fi
    fi    # end if dig_ip

}

#########  1-2 getopts Operation  #########
# http://wiki.bash-hackers.org/howto/getopts_tutorial
# https://www.mkssoftware.com/docs/man1/getopts.1.asp
while getopts "hjip:" option "$@"; do
    case "$option" in
        j ) output_format=1 ;;
        i ) ip_detection_disable=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2 Core Processing Procedure  #########
funcOSDetectionProcess(){
    local release_file=${release_file:-}
    local distro_name=${distro_name:-}
    local version_id=${version_id:-}
    local distro_fullname=${distro_fullname:-}
    local distro_family_own=${distro_family_own:-}
    local official_site=${official_site:-}
    local codename=${codename:-}

    # CentOS 5, CentOS 6, Debian 6 has no file /etc/os-release
    if [[ -s '/etc/os-release' ]]; then
        release_file='/etc/os-release'
        #distro name，eg: centos/rhel/fedora,debian/ubuntu,opensuse/sles
        distro_name=$(sed -r -n '/^ID=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
        #version id, eg: 7/8, 16.04/16.10, 13.2/42.2
        if [[ "$distro_name" == 'debian' && -s /etc/debian_version ]]; then
            version_id=$(cat /etc/debian_version)
        elif [[ "$distro_name" == 'ubuntu' && -s /etc/debian_version ]]; then
            version_id=$(sed -r -n '/^VERSION=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
            version_id="${version_id%% *}"
        else
            version_id=$(sed -r -n '/^VERSION_ID=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
            if [[ "${distro_name}" == 'centos' && version_id -eq 7 ]]; then
                [[ -s '/etc/redhat-release' ]] && version_id=$(sed -r -n 's@.*release[[:space:]]*([^[:space:]]+).*@\1@g;s@\.[[:digit:]]+\.@.@g;p' /etc/redhat-release)
            fi
        fi

        #distro full pretty name, for CentOS ,file redhat-release is more detailed
        if [[ -s '/etc/redhat-release' ]]; then
            distro_fullname=$(cat /etc/redhat-release)
        else
            distro_fullname=$(sed -r -n '/^PRETTY_NAME=/s@.*="?([^"]*)"?@\1@p' "${release_file}")
        fi
        # Fedora, Debian，SUSE has no parameter ID_LIKE, only has ID
        # Amazon Linux ID_LIKE v1 'rhel fedora'; v2 'centos rhel fedora'
        # distro_family_own=$(. "${release_file}" && echo "${ID_LIKE:-}")
        distro_family_own=$(sed -r -n '/^ID_LIKE=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")
        [[ "$distro_family_own" == '' ]] && distro_family_own="$distro_name"
        # For Amazon Linux
        [[ "${distro_name}" == 'amzn' ]] && distro_family_own='rhel'
        # GNU/Linux distribution official site
        # official_site=$(. "${release_file}" && echo "${HOME_URL:-}")
        official_site=$(sed -r -n '/^HOME_URL=/s@.*="?([^"]*)"?@\L\1@p' "${release_file}")

        case "${distro_name}" in
            debian|ubuntu ) codename=$(sed -r -n '/^VERSION=/s@.*[,(][[:space:]]?([^[:space:]\)]+).*@\L\1@p' "${release_file}") ;;
            opensuse ) codename=$(sed -r -n '/CODENAME/s@.*=[[:space:]]?(.*)@\L\1@p' /etc/SuSE-release) ;;
            * ) codename='' ;;
        esac    # End case

    elif [[ -s '/etc/redhat-release' ]]; then  # for CentOS 5, CentOS 6
        release_file='/etc/redhat-release'
        distro_name=$(rpm -q --qf "%{name}" -f "${release_file}") #centos-release,fedora-release
        distro_name=${distro_name%%-*}    # centos, fedora
        # version_id=$(sed -r -n 's@[^[:digit:]]*([[:digit:]]{1}).*@\1@p' "${release_file}") # 5/6
        version_id=$(sed -r -n 's@.*release[[:space:]]*([^[:space:]]+).*@\1@g;p' "${release_file}")
        distro_fullname=$(cat "${release_file}")
        distro_family_own='rhel'   # family is rhel (RedHat)

    elif [[ -s /etc/debian_version && -s /etc/issue.net ]]; then    # for Debian 6
        release_file='/etc/issue.net'   #Debian GNU/Linux 6.0
        distro_name=$(sed -r -n 's@([^[:space:]]*).*@\L\1@p' "${release_file}")
        version_id=$(sed -r -n 's@[^[:digit:]]*([[:digit:]]{1}).*@\1@p' "${release_file}") #6
        distro_fullname=$(cat "${release_file}")
        distro_family_own='debian'   # family is debian (Debian)

        case "${version_id}" in
            6 ) codename='squeeze' ;;
            * ) codename='' ;;
        esac    # End case

    else
        if [[ "${output_format}" -eq 1 ]]; then
            output_json="{"
            output_json=${output_json}"\"error\":\"this script can't detect your system\""
            output_json=${output_json}"}"
            echo "${output_json}"
        else
            echo "Sorry, this script can't detect your system!"
        fi  # End if
        exit
    fi      # End if

    # Convert family name
    case "${distro_family_own,,}" in
        debian ) local distro_family_own='Debian' ;;
        suse|sles ) local distro_family_own='SUSE' ;;
        rhel|'rhel fedora'|fedora|centos ) local distro_family_own='RedHat' ;;
        * ) local distro_family_own='Unknown' ;;
    esac    # End case

    # - Retrieve release date & eol date
    distro_release_date=$(mktemp -t "${mktemp_format}")
    $download_tool "${distro_release_date_list}" | sed -r -n '/^'"${distro_name}"'\|/{p}' > "${distro_release_date}"

    # distro name|version|codename|release date|eol date|is eol
    local release_info
    local release_date
    local eol_date
    local is_eol

    release_info=$(awk -F\| 'match($1,/^'"${distro_name}"'$/)&&match($2,/^'"${version_id}"'$/){print}' "${distro_release_date}")

    release_date=$(echo "${release_info}" | awk -F\| '{print $4}')
    eol_date=$(echo "${release_info}" | awk -F\| '{print $5}')
    is_eol=$(echo "${release_info}" | awk -F\| '{print $6}')

    # - Output
    if [[ "${output_format}" -eq 1 ]]; then
        output_json="{"
        output_json=${output_json}"\"pretty_name\":\"${distro_fullname}\","
        output_json=${output_json}"\"distro_name\":\"${distro_name}\","
        [[ -n "${codename}" ]] && output_json=${output_json}"\"codename\":\"${codename}\","
        output_json=${output_json}"\"version_id\":\"${version_id}\","
        output_json=${output_json}"\"family_name\":\"${distro_family_own}\","
        [[ -n "$official_site" ]] && output_json=${output_json}"\"official_site\":\"${official_site}\","
        [[ -n "${release_date}" ]] && output_json=${output_json}"\"release_date\":\"${release_date}\","
        [[ -n "${eol_date}" ]] && output_json=${output_json}"\"eol_date\":\"${eol_date}\","
        [[ -n "${is_eol}" ]] && output_json=${output_json}"\"is_eol\":\"${is_eol}\","
        [[ -n "${ip_local}" && "${ip_local}" != "${ip_public}" ]] && output_json=${output_json}"\"ip_local\":\"${ip_local}\","
        [[ -n "${ip_public}" ]] && output_json=${output_json}"\"ip_public\":\"${ip_public}\","
        [[ -n "${ip_public_timezone}" ]] && output_json=${output_json}"\"ip_public_timezone\":\"${ip_public_timezone}\","
        [[ -n "${ip_public_country_code}" ]] && output_json=${output_json}"\"ip_public_country_code\":\"${ip_public_country_code}\","
        [[ -n "${ip_public_locate}" ]] && output_json=${output_json}"\"ip_public_locate\":\"${ip_public_locate}\","
        [[ -n "${ip_proxy}" ]] && output_json=${output_json}"\"ip_proxy\":\"${ip_proxy}\","
        [[ -n "${ip_proxy_timezone}" ]] && output_json=${output_json}"\"ip_proxy_timezone\":\"${ip_proxy_timezone}\","
        [[ -n "${ip_proxy_country_code}" ]] && output_json=${output_json}"\"ip_proxy_country_code\":\"${ip_proxy_country_code}\","
        [[ -n "${ip_proxy_locate}" ]] && output_json=${output_json}"\"ip_proxy_locate\":\"${ip_proxy_locate}\","
        output_json=${output_json%,*}
        output_json=${output_json}"}"
        echo "${output_json}"
    else
        funcCentralOutput 'Pretty Name' "${distro_fullname}"
        funcCentralOutput 'Distro Name' "${distro_name}"
        [[ -n "${codename}" ]] && funcCentralOutput 'Code Name' "${codename}"
        funcCentralOutput 'Version ID' "${version_id}"
        funcCentralOutput 'Family Name' "${distro_family_own}"
        [[ -n "${official_site}" ]] && funcCentralOutput 'Official Site' "${official_site}"
        [[ -n "${release_date}" ]] && funcCentralOutput 'Release Date' "$release_date"
        [[ -n "${eol_date}" ]] && funcCentralOutput 'End Of Life' "${eol_date}"
        [[ -n "${ip_local}" && "${ip_local}" != "${ip_public}" ]] && funcCentralOutput 'Local IP Addr' "${ip_local}"
        [[ -n "${ip_public}" ]] && funcCentralOutput 'Public IP Addr' "${ip_public} (${ip_public_locate})"
        [[ -n "${ip_proxy}" ]] && funcCentralOutput 'Proxy IP Addr' "${ip_proxy} (${ip_proxy_locate})"
    fi  # End if
}


#########  3. Executing Process  #########
funcInternetConnectionCheck
funcDownloadToolCheck
[[ "${ip_detection_disable}" -eq 1 ]] || funcIPInfoDetection
funcOSDetectionProcess


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset output_format
    unset proxy_server
    unset ip_public
    unset ip_public_locate
    unset ip_public_country_code
    unset ip_public_timezone
    unset ip_proxy
    unset ip_proxy_locate
    unset ip_proxy_country_code
    unset ip_proxy_timezone
    unset output_json

    unset http_proxy
    unset HTTPS_PROXY
    unset download_tool
    unset download_tool_origin
}

trap funcTrapEXIT EXIT

# Script End
