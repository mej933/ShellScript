#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails

#Official Site:
# - http://www.oracle.com/technetwork/java/index.html
# - http://jdk.java.net/
#Installation:
# - http://www.oracle.com/technetwork/java/javase/downloads/index.html
#Target: Automatically Install & Configuring Oracle SE (Standard Edition)
#Writer: MaxdSre
#Date: Oct 30, 2017 23:53 Sat +0800 - add alternative mode, change output style
#Update Time:
# - Aug 18, 2017 13:41 Fri +0800
# - Sep 22, 2017 16:59 Fri +0800
# - Oct 19, 2017 12:36 Thu +0800

#####################################################
#       Java Development Kit (JDK)                  #
#       Java Runtime Environment (JRE)              #
#       Java SE Runtime Environment (Server JRE)    #
#####################################################

#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'OSEJTemp_XXXXXX'}
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
readonly c_red="$(tput setaf 1)"
readonly c_green="$(tput setaf 2)"    # c_blue='\e[32m'
readonly c_yellow="$(tput setaf 3)"    # c_blue='\e[33m'
readonly c_blue="$(tput setaf 4)"
readonly c_blueb="${c_bold}${c_blue}"

oracle_official_site=${oracle_official_site:-'http://www.oracle.com'}
# http://www.oracle.com/technetwork/java/javase/downloads/index.html
oracle_java_se_page=${oracle_java_se_page:-"${oracle_official_site}/technetwork/java/javase/downloads/index.html"}

software_fullname=${software_fullname:-'Oracle JDK'}
application_name=${application_name:-'OracleJDK'}
installation_dir="/opt/${application_name}"      # Decompression & Installation Path Of Package
readonly temp_save_path='/tmp'      # Save Path Of Downloaded Packages

oracle_jdk_include_path=${oracle_jdk_include_path:-'/usr/local/include/oracle_se_jdk'}
oracle_jdk_lib_path=${oracle_jdk_lib_path:-'/etc/ld.so.conf.d/oracle_se_jdk.conf'}
oracle_jdk_execute_path=${oracle_jdk_execute_path:-'/etc/profile.d/oracle_se_jdk.sh'}

is_existed=${is_existed:-0}      # Default value is 0， check if system has installed Oracle JDK
version_check=${version_check:-0}
version_specify=${version_specify:-}
source_pack_path=${source_pack_path:-}
alternative_mode=${alternative_mode:-0}
is_uninstall=${is_uninstall:-0}
proxy_server=${proxy_server:-}
alternative_command=${alternative_command:-}


#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
script [options] ...
script | sudo bash -s -- [options] ...

Installing / Configuring Oracle SE JDK On GNU/Linux!
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -c    --check, check Oracle JDK installed or not
    -f pack_path    --specify latest release package absolute path in system (e.g. /PATH/*.tar.gz)
    -v version    --specify specific Oracle JDK version (e.g. 8, 9)
    -A    --using alternatives mode (alternatives/update-alternatives), default is using environment variables '$PATH'
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
    -u    --uninstall, uninstall software installed
${c_normal}
EOF
# -t pack_type    --choose packge type (jdk/jre/server jre), default is jdk
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

    # 2 - OS support check
    [[ -s /etc/os-release || -s /etc/SuSE-release || -s /etc/redhat-release || (-s /etc/debian_version && -s /etc/issue.net) ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script doesn't support your system!"

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}curl${c_normal} command found!"

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"

    # CentOS/Debian/OpenSUSE: gzip
    funcCommandExistCheck 'gzip' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gzip${c_normal} command found, please install it (CentOS/Debian/OpenSUSE: gzip)!"

    funcCommandExistCheck 'tar' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}tar${c_normal} command find to decompress .tar.gz file!"

    # shellcheck source=/dev/null
    [[ -f "${oracle_jdk_execute_path}" ]] && source "${oracle_jdk_execute_path}"

    # alternatives / update-alternatives
    if funcCommandExistCheck 'alternatives'; then
        alternative_command='alternatives'
    elif funcCommandExistCheck 'update-alternatives'; then
        alternative_command='update-alternatives'
    fi
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
    local referrer_page=${referrer_page:-'https://duckduckgo.com/?q=oracle'}

    if funcCommandExistCheck 'curl'; then
        download_tool="curl -fsL --retry ${retry_times} --retry-delay ${retry_delay_time} --connect-timeout ${connect_timeout_time} --no-keepalive --referer ${referrer_page}"   # curl -s URL -o /PATH/FILE； -fsSL

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
    else
        funcExitStatement "${c_red}Error${c_normal}: can't find command ${c_blue}curl${c_normal}!"
    fi
}

funcOperationProcedureStatement(){
    local l_item="${1:-}"
    if [[ -n "${l_item}" ]]; then
        echo -n -e "${c_yellow}procedure${c_normal} - ${l_item} ..."
    fi
}

funcOperationProcedureResultStatement(){
    local l_item="${1:-0}"

    case "${l_item,,}" in
        0|'ok' ) l_item='ok' ;;
        1|'fail'|* ) l_item='fail' ;;
    esac

    local l_color="${c_green}"
    [[ "${l_item}" == 'fail' ]] && l_color="${c_red}"

    echo -e "... [${l_color}${l_item}${c_normal}]"
}


#########  1-2 getopts Operation  #########
start_time=$(date +'%s')    # Start Time Of Operation

while getopts "hcf:p:v:Au" option "$@"; do
    case "$option" in
        c ) version_check=1 ;;
        f ) source_pack_path="$OPTARG" ;;
        u ) is_uninstall=1 ;;
        v ) version_specify="$OPTARG" ;;
        A ) alternative_mode=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2-1. Latest & Local Version Check  #########
funcVersionLocalCheck(){
    current_version_local=${current_version_local:-}
    # 9.0.1 / 8u151 / 8u152

    if [[ -d "${installation_dir}" ]]; then
        is_existed=1
        if [[ -s "${installation_dir}/relese" ]]; then
            current_version_local=$(sed -r -n '/^JAVA_VERSION/{s@[^"]*"([^"]*)".*@\1@g;p}' "${installation_dir}/relese")
        elif [[ -s "${installation_dir}/bin/java" ]]; then
            current_version_local=$("${installation_dir}/bin/java" -version 2>&1 | sed -r -n '1s@.*"([^"]*)"@\1@p')
        else
            is_existed=0
        fi    # end if

    elif funcCommandExistCheck 'java'; then
        #openjdk 1.8.0_141
        current_version_local=$(java -version |& sed -r -n '1{s@([^[:space:]]*)[[:space:]]*version[[:space:]]*"([^"]*)"@\1 \2@g;p}')
    fi

    if [[ "${is_existed}" -eq 1 ]]; then
        printf "${software_fullname} detected in your system is ${c_blue}%s${c_normal}!\n" "${current_version_local}"
    else
        if [[ -n "${current_version_local}" ]]; then
            printf "No ${software_fullname} finds. Java environment existed is ${c_blue}%s${c_normal}!\n" "${current_version_local}"
        else
            if [[ "${is_uninstall}" -eq 1 ]]; then
                funcExitStatement "No Java Environment finds in your system!"
            else
                printf "No Java Environment finds in your system!\n"
            fi    # end if
        fi    # end if
    fi    # end if
}

funcVersionOnlineInfo(){
    oracle_jdk_info=$(mktemp -t "${mktemp_format}")
    [[ -f "${oracle_jdk_info}" ]] && rm -f "${oracle_jdk_info}"

    # JDK9|/technetwork/java/javase/downloads/jdk9-downloads-3848520.html|Java SE 9.0.1
    # JDK8|/technetwork/java/javase/downloads/jdk8-downloads-2133151.html|Java SE 8u151/ 8u152

    $download_tool "${oracle_java_se_page}" | sed -r -n '/javasejdk/{s@<\/?h3[^>]*>@\n&@g;p}' | sed -r -n '/javasejdk/{/href=/!d;s@.*name="([^"]+)"[[:space:]]*href="([^"]+)">([^<]+)<.*$@\1|\2|\3@g;p}' | while IFS="|" read -r jdk_type download_page_url version_info; do
        major_version="${jdk_type//JDK/}"
        # http://www.oracle.com/technetwork/java/javase/downloads/jdk9-downloads-3848520.html
        [[ "${download_page_url}" =~ ^/ ]] && download_page_url="http://www.oracle.com${download_page_url}"

        # remove prefix "Java SE "
        pattern_list=${pattern_list:-}
        pattern_list=$(echo "${version_info}" | sed -r 's@^[^[:digit:]]*@@g;')

        # 8u151/ 8u152 ==> 8u151|8u152
        [[ "${pattern_list}" =~ / ]] && pattern_list=$(echo "${pattern_list}" | sed -r -n 's@[[:space:]]*@@g;s@\/@|@g;p')

        # title | size | filepath |sha256
        # Linux x64|180.99 MB|http://download.oracle.com/otn-pub/java/jdk/8u152-b16/aa0333dd3019491ca4f6ddbe78cdb6d0/jdk-8u152-linux-x64.tar.gz|218b3b340c3f6d05d940b817d0270dfe0cfd657a636bad074dcabe0c111961bf

        # shellcheck disable=SC2034
        $download_tool "${download_page_url}" | sed -r -n '/linux-x64.*tar.gz/{/demos?/d;/('"${pattern_list}"')/{s@.*=@@g;s@\{@@g;s@,@\n@g;s@\};?@\n---@g;p}}' | sed -r '/MD5/d;s@[^:]+:[^"]*"([^"]*)".*@\1@g;s@\n@|@g;$d' | sed -r ':a;N;$!ba;s@\n@|@g;s@\|?---\|?@\n@g;' | sort -b -t"|" -k 3r,3 | while IFS="|" read -r title size filepath sha256_dgst; do
            local l_pack_name=${l_pack_name:-}
            l_pack_name="${filepath##*/}"
            local l_version_name=${l_version_name:-}
            l_version_name=$(echo "${l_pack_name}" | sed -r 's@_@-@g;s@jdk-([^-]+).*@\1@g')

            # major_version|version_name|download_page_url|pack_name|pack_download_link|pack_sha256_dgst
            echo "${major_version}|${l_version_name}|${download_page_url}|${l_pack_name}|${filepath}|${sha256_dgst}" >> "${oracle_jdk_info}"
        done  # end while

    done   # end while

    # 8|8u151|http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html|jdk-8u151-linux-x64.tar.gz|http://download.oracle.com/otn-pub/java/jdk/8u151-b12/e758a0de34e24606bca991d704f6dcbf/jdk-8u151-linux-x64.tar.gz|c78200ce409367b296ec39be4427f020e2c585470c4eed01021feada576f027f

    if [[ "${version_check}" -eq 1 ]]; then
        if [[ "${is_existed}" -eq 1 ]]; then
            echo -e "\n${c_red}Local Version Detail Info${c_normal}:\n"
            java -version
        fi
        # major_version|version_name|download_page_url|pack_name|pack_download_link|pack_sha256_dgst
        local l_version_list=''
        l_version_list=$(awk -F\| '{print $2}' "${oracle_jdk_info}" | sed ':a;N;$!ba;s@\n@, @g;')
        [[ -n "${l_version_list}" ]] && echo -e "\n${c_red}Latest Release Version Available${c_normal}: ${c_blue}${l_version_list}${c_normal}\n"
        exit
    fi

    # Compare Local Version With Online Version
    if [[ "${is_existed}" -eq 1 && -n "${current_version_local}" ]]; then
        # 9 / 1.8.0_144 ==> 8u144
        if [[ -z $(awk -F\| 'match($2,/'"${current_version_local//1.8.0_/8u}"'/){print $1}' "${oracle_jdk_info}") ]]; then
            funcExitStatement "${c_red}Attention${c_normal}: local version ${c_blue}${current_version_local}${c_normal} is not same as latest release version shown on Oracle official site! Strongly recommend uninstall existed version via ${c_blue}-u${c_normal}, then reinstall newer version via this script!"
        else
            funcExitStatement "${c_red}Configuration${c_normal}: latest release version has been existed in your system.!"
        fi    # end if
    fi    # end if

}


#########  2-1. Version List Selection Menu  #########
# global variable
# - choose_version
funcVersionSelectionMenu(){
    local IFS_BAK=${IFS_BAK:-"$IFS"}  # Backup IFS
    IFS="|" # Setting temporary IFS

    echo "${c_blueb}Available Product Version List: ${c_normal}"
    PS3="${c_yellow}Choose version number(e.g. 1, 2,...): ${c_normal}"

    choose_version=${choose_version:-}
    select item in $(awk -F\| 'BEGIN{ORS="|"}{print $2}' "${oracle_jdk_info}"); do
        choose_version="${item}"
        [[ -n "${choose_version}" ]] && break
    done < /dev/tty

    IFS=${IFS_BAK}  # Restore IFS
    unset IFS_BAK
    printf "\nProduct version you choose is ${c_bold}${c_red}%s${c_normal}.\n\n" "${choose_version}"
}

funcAlternativeModeConfiguration(){
    local l_command="${1:-}"
    local l_action="${2:-'install'}"
    local l_dir="${3:-"${installation_dir}"}"

    if [[ -n "${l_dir}" && -n "${alternative_command}" ]]; then
        local l_command_path
        l_command_path="${l_dir}/bin/${l_command}"

        case "${l_action}" in
            install )
                if [[ -s "${l_command_path}" ]]; then
                    ${alternative_command} --install /usr/bin/"${l_command}" "${l_command}" "${l_command_path}" 99 &> /dev/null
                    ${alternative_command} --set "${l_command}" "${l_command_path}" &> /dev/null
                fi
                ;;
            remove|* )
                if [[ -s "${l_command_path}" ]]; then
                    ${alternative_command} --remove "${l_command}" "${l_command_path}" &> /dev/null
                fi
                ;;
        esac
    fi
}


#########  2-2. Uninstall  #########
funcUninstallOperation(){
    if [[ -d "${installation_dir}" ]]; then
        funcAlternativeModeConfiguration 'java' 'remove'
        funcAlternativeModeConfiguration 'javac' 'remove'
        funcAlternativeModeConfiguration 'jar' 'remove'
        [[ -f "${oracle_jdk_include_path}" ]] && rm -f "${oracle_jdk_include_path}"
        [[ -f "${oracle_jdk_lib_path}" ]] && rm -f "${oracle_jdk_lib_path}"
        [[ -f "${oracle_jdk_execute_path}" ]] && rm -f "${oracle_jdk_execute_path}"
        rm -rf "${installation_dir}"
    else
        funcExitStatement "${c_red}Attention${c_normal}: No ${software_fullname} finds in your system!"
    fi

    [[ -d "${installation_dir}" ]] || funcExitStatement "${software_fullname} (v ${c_red}${current_version_local}${c_normal}) is successfully removed from your system!"
}


#########  2-3. Download & Decompress Latest Software  #########
funcDownloadAndDecompressOperation(){
    # major_version|version_name|download_page_url|pack_name|pack_download_link|pack_sha256_dgst

    # 1 - Installation Methods
    local pack_name=${pack_name:-}
    local pack_download_link=${pack_download_link:-}
    local pack_sha256_dgst=${pack_sha256_dgst:-}

    # 1.1- manually specify jdk package path in system
    if [[ "${source_pack_path}" =~ .tar.gz$ && -s "${source_pack_path}" ]]; then
        local local_pack_name=${local_pack_name:-}
        local_pack_name="${source_pack_path##*/}"

        pack_sha256_dgst=$(awk -F\| 'match($4,/^'"${local_pack_name}"'$/){print $6}' "${oracle_jdk_info}")
        [[ -z "${pack_sha256_dgst}" ]] && funcExitStatement "Please specify latest release package path with origin name in your system!"

        if [[ -n "${pack_sha256_dgst}" && $(sha256sum "${source_pack_path}" | awk '{print $1}') == "${pack_sha256_dgst}" ]]; then
            printf "Package ${c_blue}%s${c_normal} approves SHA256 check!\n" "${source_pack_path}"

            pack_name=$(awk -F\| 'match($5,/^'"${local_pack_name}"'$/){print $5}' "${oracle_jdk_info}")
        else
            funcExitStatement "Package ${source_pack_path} fails via SHA256 check!"
        fi    # end if

    # 1.2 - manually specify jdk major version
    elif [[ "${version_specify}" =~ ^[1-9] && -n $(awk -F\| 'match($1,/^'"${version_specify}"'$/){print}' "${oracle_jdk_info}") ]]; then
        # version_specify == major_version
        pack_name=$(awk -F\| 'match($1,/^'"${version_specify}"'$/){print $4;exit}' "${oracle_jdk_info}")
        pack_download_link=$(awk -F\| 'match($1,/^'"${version_specify}"'$/){print $5;exit}' "${oracle_jdk_info}")
        pack_sha256_dgst=$(awk -F\| 'match($1,/^'"${version_specify}"'$/){print $6;exit}' "${oracle_jdk_info}")

    # 1.3 - version choose from selection menu list
    else
        funcVersionSelectionMenu

        if [[ -n "${choose_version}" ]]; then
            pack_name=$(awk -F\| 'match($2,/^'"${choose_version}"'$/){print $4}' "${oracle_jdk_info}")
            pack_download_link=$(awk -F\| 'match($2,/^'"${choose_version}"'$/){print $5}' "${oracle_jdk_info}")
            pack_sha256_dgst=$(awk -F\| 'match($2,/^'"${choose_version}"'$/){print $6}' "${oracle_jdk_info}")
        fi    # end if

    fi    # end if installation method

    # 2 - Download Directly From Oracle Official Site
    local pack_save_path=${pack_save_path:-}
    if [[ -z "${source_pack_path}" ]]; then
        funcOperationProcedureStatement "Download ${c_red}${pack_name}${c_normal}"
        # printf "Begin to download ${c_blue}%s${c_normal}, just be patient!\n" "${pack_name}"
        pack_save_path="${temp_save_path}/${pack_name}"
        [[ -f "${pack_save_path}" ]] && rm -f "${pack_save_path}"

        # https://www.tecmint.com/install-java-jdk-jre-in-linux/
        # https://gist.github.com/P7h/9741922
        # curl -fL --cookie/-H "oraclelicense=accept-securebackup-cookie" -O "${pack_download_link}"
        $download_tool -H "Cookie: oraclelicense=accept-securebackup-cookie" "${pack_download_link}" > "${pack_save_path}"

        if [[ -s "${pack_save_path}" ]]; then
            funcOperationProcedureResultStatement 'ok'
        else
            funcOperationProcedureResultStatement 'fail'
            funcExitStatement "${c_red}Sorry${c_normal}: fail to download package ${c_blue}${pack_name}${c_normal} from Oracle official site.!"
        fi

        # [[ -s "${pack_save_path}" ]] || funcExitStatement "${c_red}Sorry${c_normal}: fail to download package ${c_blue}${pack_name}${c_normal} from Oracle official site.!"

        funcOperationProcedureStatement 'SHA256 dgst verification'
        if [[ $(sha256sum "${pack_save_path}" | awk '{print $1}') == "${pack_sha256_dgst}" ]]; then
            funcOperationProcedureResultStatement 'ok'
            # printf "Package ${c_blue}%s${c_normal} approves SHA256 check!\n" "${pack_name}"
        else
            funcOperationProcedureResultStatement 'fail'
            funcExitStatement "Package ${pack_name} fails via SHA256 check!"
        fi

        # use variable "source_pack_path" to execute decompress operation, variable "pack_save_path" used for delete temporary download package
        source_pack_path="${pack_save_path}"
    fi

    # 3 - Decompress & Extract
    funcOperationProcedureStatement "Installation ${c_red}${installation_dir}${c_normal}"
    # printf "Begin to install ${c_blue}%s${c_normal}, just be patient!\n" "${pack_name}"
    [[ -d "${installation_dir}" ]] && rm -rf "${installation_dir}"
    [[ -d "${installation_dir}" ]] || mkdir -p "${installation_dir}"     # Create Installation Directory
    tar xf "${source_pack_path}" -C "${installation_dir}" --strip-components=1

    if [[ -s "${installation_dir}/bin/java" ]]; then
        funcOperationProcedureResultStatement 'ok'
    else
        funcOperationProcedureResultStatement 'fail'
        [[ -d "${installation_dir}" ]] && rm -rf "${installation_dir}"
        funcExitStatement "Fail to decompress package ${c_blue}${pack_name}${c_normal} to target directory ${c_blue}${installation_dir}${c_normal}!"
    fi

    chown -R root:root "${installation_dir}"

    [[ -f "${pack_save_path}" ]] && rm -f "${pack_save_path}"
}

#########  2-4. Execution PATH Configurarion  #########
funcExecutaionPathConfiguration(){
    funcOperationProcedureStatement "Configurarion ${c_red}${oracle_jdk_execute_path}${c_normal}"
    # - add to PATH execution path
    echo "export JAVA_HOME=${installation_dir}" > "${oracle_jdk_execute_path}"
    [[ -d "${installation_dir}/jre" ]] && echo "export JRE_HOME=${installation_dir}/jre" >> "${oracle_jdk_execute_path}"

    if [[ "${alternative_mode}" -eq 1 ]]; then
        funcAlternativeModeConfiguration 'java' 'install'
        funcAlternativeModeConfiguration 'javac' 'install'
        funcAlternativeModeConfiguration 'jar' 'install'
    else
        # - export include files
        [[ -d "${installation_dir}/include" ]] && ln -fsv "${installation_dir}/include" "${oracle_jdk_include_path}" 1> /dev/null

        # - export lib files
        if [[ -d "${installation_dir}/lib" ]]; then
            echo "${installation_dir}/lib" > "${oracle_jdk_lib_path}"
            # [[ -d "${installation_dir}/jre/lib" ]] && echo "${installation_dir}/jre/lib" >> "${oracle_jdk_lib_path}"
            ldconfig -v &> /dev/null
        fi

        echo "export PATH=${installation_dir}/bin:\$PATH" >> "${oracle_jdk_execute_path}"
    fi

    # if [[ -d "${installation_dir}/bin" ]]; then
        # if [[ -d "${installation_dir}/jre/bin" ]]; then
        #     echo "export JRE_HOME=${installation_dir}/jre" >> "${oracle_jdk_execute_path}"
        #     echo "export PATH=${installation_dir}/bin:${installation_dir}/jre/bin:\$PATH" >> "${oracle_jdk_execute_path}"
        # else
        #     echo "export PATH=${installation_dir}/bin:\$PATH" >> "${oracle_jdk_execute_path}"
        # fi    # end if
    # fi    # end if

    # https://github.com/koalaman/shellcheck/wiki/SC1090
    # shellcheck source=/dev/null
    source "${oracle_jdk_execute_path}" 1> /dev/null
    funcOperationProcedureResultStatement 'ok'
}


#########  3. Operation Time Cost  #########
funcTotalTimeCosting(){
    # pront java version info
    echo -e "\n${c_bold}${c_red}${software_fullname} version info:${c_normal}" && java -version

    if [[ "${alternative_mode}" -eq 1 ]]; then
        echo -e "\n${c_bold}${c_yellow}${alternative_command}${c_normal} ${c_red}mode info:${c_normal}"
        ${alternative_command} --display java
        echo
    fi

    if [[ "${is_existed}" -ne 1 ]]; then
        finish_time=$(date +'%s')        # End Time Of Operation
        total_time_cost=$((finish_time-start_time))   # Total Time Of Operation
        funcExitStatement "Total time cost is ${c_red}${total_time_cost}${c_normal} seconds!"
    fi    # end if
}


#########  4. Executing Process  #########
funcInitializationCheck
funcInternetConnectionCheck
funcDownloadToolCheck

funcVersionLocalCheck
[[ "${is_uninstall}" -eq 1 ]] && funcUninstallOperation
funcVersionOnlineInfo
funcDownloadAndDecompressOperation
funcExecutaionPathConfiguration
funcTotalTimeCosting


#########  4. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset oracle_official_site
    unset oracle_java_se_page
    unset software_fullname
    unset application_name
    unset installation_dir
    unset oracle_jdk_include_path
    unset oracle_jdk_lib_path
    unset oracle_jdk_execute_path
    unset is_existed
    unset version_check
    unset version_specify
    unset source_pack_path
    unset is_uninstall
    unset proxy_server
    unset current_version_local
    unset oracle_jdk_info
    unset choose_version
    unset start_time
    unset finish_time
    unset total_time_cost
}

trap funcTrapEXIT EXIT

# Script End
