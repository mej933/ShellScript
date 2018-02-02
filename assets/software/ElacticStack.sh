#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Elastic Stack Installation And Configuration On GNU/Linux (RHEL/CentOS/Fedora/Debian/Ubuntu/OpenSUSE and variants)
#Writer: MaxdSre
#Date: Jan 11, 2018 15:10 Wed +0800 - add logstash, combined adjusting, cost 3 days

#Update Time:
# - Jan 03, 2018 18:50 Wed +0800 - just elasticsearch
# - Jan 04, 2018 11:35 Thu +0800 - add kibana

# Document
# https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html

# https://www.elastic.co/guide/en/logstash/current/config-examples.html
# Logstash pipeline config dir is /etc/elastic/logstash/conf.d/, give a sample conf about syslog which is named 'logstash-syslog.conf.sample'

# sudo systemctl daemon-reload
# sudo systemctl start elastic_elasticsearch.service
# sudo systemctl status elastic_elasticsearch.service
# sudo systemctl start elastic_kibana.service
# sudo systemctl status elastic_kibana.service
# sudo systemctl start elastic_logstash.service
# sudo systemctl status elastic_logstash.service


#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'ELKTemp_XXXXX'}
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
readonly official_site='https://www.elastic.co'   #Official Site
readonly download_page="${official_site}/downloads"
readonly github_raw_url='https://raw.githubusercontent.com'
readonly custom_shellscript_url="${github_raw_url}/MaxdSre/ShellScript"
readonly online_config_file_sample_dir="${custom_shellscript_url}/master/configs/elastic/config"
readonly online_service_script_sample_dir="${custom_shellscript_url}/master/configs/elastic/initScript"

readonly temp_save_dir='/tmp'      # Save Path Of Downloaded Packages
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup
stack_name=${stack_name:-'elastic'}

installation_dir=${installation_dir:-"/opt/${stack_name}"}    # Decompression & Installation Path Of Package
config_dir=${config_dir:-"/etc/${stack_name}"}
log_dir=${log_dir:-"/var/log/${stack_name}"}
run_dir=${run_dir:-"/var/run/${stack_name}"}
readonly data_dir_default="/var/lib/${stack_name}"
data_dir=${data_dir:-"${data_dir_default}"}

readonly elasticsearch_name='elasticsearch'
readonly logstash_name='logstash'
readonly kibana_name='kibana'

user_name=${user_name:-'root'}
group_name=${group_name:-'root'}
pack_save_dir=${pack_save_dir:-"/usr/local/src/Packages"}
is_uninstall=${is_uninstall:-0}
proxy_server=${proxy_server:-}
restrict_mode=${restrict_mode:-0}
logstash_install=${logstash_name:-0}
kibana_install=${kibana_install:-0}
ip_local=${ip_local:-127.0.0.1}

#########  1-1 Initialization Prepatation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...
Elastic Stack Installation And Configuration On GNU Linux!
Default is just install elasticsearch.
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -d data_dir    --set data dir, default is /var/lib/elastic
    -S    --use strict mode (create user elastic, default use root), or delete config dir, data dir
    -D pack_dir    --specify package save dir, default is /usr/local/src/Packages
    -k    --install kibana, default is not install
    -l    --install logstash, default is not install
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

funcInitializationCheck(){
    # 1 - Check root or sudo privilege
    [[ "$UID" -ne 0 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script requires superuser privileges (eg. root, su)."

    # 2 - specified for RHEL/Debian/SLES
    [[ -f '/etc/os-release' || -f '/etc/redhat-release' || -f '/etc/debian_version' || -f '/etc/SuSE-release' ]] || funcExitStatement "${c_red}Sorry${c_normal}: this script just support RHEL/CentOS/Debian/Ubuntu/OpenSUSE derivates!"

    # 3 - bash version check  ${BASH_VERSINFO[@]} ${BASH_VERSION}
    # bash --version | sed -r -n '1s@[^[:digit:]]*([[:digit:].]*).*@\1@p'
    [[ "${BASH_VERSINFO[0]}" -lt 4 ]] && funcExitStatement "${c_red}Sorry${c_normal}: this script need BASH version 4+, your current version is ${c_blue}${BASH_VERSION%%-*}${c_normal}."

    # 4 - Java environment
    if funcCommandExistCheck 'java'; then
        JAVA_HOME=$(readlink -f /usr/bin/java | sed -r 's@(.*)/bin.*@\1@g')
        export JAVA_HOME
        [[ -z "${JAVA_HOME:-}" ]] && funcExitStatement "${c_red}Error${c_normal}, No environment variable ${c_blue}JAVA_HOME${c_normal} found!"
    else
        funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}java${c_normal} command found!"
    fi

    funcCommandExistCheck 'gawk' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gawk${c_normal} command found!"

    funcCommandExistCheck 'curl' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}curl${c_normal} command finds, please install it!"

    funcCommandExistCheck 'sha512sum' || funcExitStatement "${c_red}Error${c_normal}: No ${c_blue}sha512sum${c_normal} command finds, please install it!"

    funcCommandExistCheck 'gzip' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}gzip${c_normal} command found, please install it (CentOS/Debian/OpenSUSE: gzip)!"

    funcCommandExistCheck 'tar' || funcExitStatement "${c_red}Error${c_normal}, No ${c_blue}tar${c_normal} command found to decompress .tar.gz file!"

    # 5 - current login user detection
    #$USER exist && $SUDO_USER not exist, then use $USER
    [[ -n "${USER:-}" && -z "${SUDO_USER:-}" ]] && login_user="$USER" || login_user="$SUDO_USER"
    login_user_home=${login_user_home:-}
    login_user_home=$(awk -F: 'match($1,/^'"${login_user}"'$/){print $(NF-1)}' /etc/passwd)
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


#########  1-2 getopts Operation  #########
start_time=$(date +'%s')    # Start Time Of Operation

while getopts "hd:SD:klup:" option "$@"; do
    case "$option" in
        d ) data_dir="$OPTARG" ;;
        S ) restrict_mode=1 ;;
        D ) pack_save_dir="$OPTARG" ;;
        k ) kibana_install=1 ;;
        l ) logstash_install=1 ;;
        u ) is_uninstall=1 ;;
        p ) proxy_server="$OPTARG" ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done


#########  2-1. Uninstall Operation  #########
funcUninstallOperation(){
    if [[ "${is_uninstall}" -eq 1 ]]; then

        if [[ -d "${installation_dir}" ]]; then
            local l_service_script_dir='/etc/init.d'
            funcCommandExistCheck 'systemctl' && l_service_script_dir='/etc/systemd/system'

            # - stop daemon running
            find "${l_service_script_dir}"/ -type f -name "${stack_name}*" -print | while IFS="" read -r line; do
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
            if [[ -s "${config_dir}/${elasticsearch_name}/${elasticsearch_name}.yml" ]]; then
                local elasticsearch_data_dir
                elasticsearch_data_dir=$(sed -r -n '/^path.data:/{s@.*:[[:space:]]([^[:space:]]+).*$@\1@g;p}' "${config_dir}/${elasticsearch_name}/${elasticsearch_name}".yml)
                [[ -n "${elasticsearch_data_dir}" && -d "${elasticsearch_data_dir}" ]] && rm -rf "${elasticsearch_data_dir}"
            fi

            if [[ "${restrict_mode}" -eq 1 ]]; then
                [[ -d "${config_dir}" ]] && rm -rf "${config_dir}"
                [[ -d "${data_dir}" ]] && rm -rf "${data_dir}"
            fi

            [[ -d "${log_dir}" ]] && rm -rf "${log_dir}"
            [[ -d "${run_dir}" ]] && rm -rf "${run_dir}"
            [[ -d "${installation_dir}" ]] && rm -rf "${installation_dir}"

            # - remove user and group - elastic
            if [[ -n $(sed -r -n '/^'"${stack_name}"':/{p}' /etc/passwd) ]]; then
                userdel -fr "${stack_name}" 2> /dev/null
                groupdel -f "${stack_name}" 2> /dev/null
            fi

            funcCommandExistCheck 'systemctl' && systemctl daemon-reload 2> /dev/null
            funcExitStatement "${stack_name} is successfully removed from your system!"
        else
            funcExitStatement "${c_blue}Note${c_normal}: no ${stack_name} is found in your system!"
        fi

    fi
}

#########  2-2. Extract Latest Package Info  #########
funcDatadirVerification(){
    if [[ -n "${data_dir}" && "${data_dir}" != "${data_dir_default}" ]]; then
        if [[ "${data_dir}" =~ ^/ ]]; then
            data_dir="${data_dir}/${stack_name}"
        else
            funcExitStatement "${c_red}Error${c_normal}: data dir ${c_blue}${data_dir}${c_normal} must be begin with slash ${c_blue}/${c_normal}."
        fi
    fi
}

funcLatestPacksInfoExtraction(){
    latest_online_packs_info=$(mktemp -t "${mktemp_format}")

    # - elasticsearch 9200 9300
    $download_tool ${download_page}/elasticsearch | sed -r -n '/Version:/{n;s@[^>]+>([^<]+)<.*@\1@g;p};/Release date:/{n;s@[^>]+>([^<]+)<.*@\1@g;p};/.tar.gz/{s@.*href="([^"]+)".*$@\1@g;p};' | sed ':a;N;$!ba;s@\n@|@g' | awk -F\| -v item='elasticsearch' 'BEGIN{OFS="|"}{"date --date=\""$2"\" +\"%F\"" | getline a; $2=a; print item,$0}' > "${latest_online_packs_info}"
    # name|release version|release date|tar.gz link|sha512 link
    # elasticsearch|6.1.1|2017-12-19|https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.1.1.tar.gz|https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.1.1.tar.gz.sha512

    # - logstash
    $download_tool ${download_page}/logstash | sed -r -n '/Version:/{n;s@[^>]+>([^<]+)<.*@\1@g;p};/Release date:/{n;s@[^>]+>([^<]+)<.*@\1@g;p};/.tar.gz/{s@.*href="([^"]+)".*$@\1@g;p};' | sed ':a;N;$!ba;s@\n@|@g' | awk -F\| -v item='logstash' 'BEGIN{OFS="|"}{"date --date=\""$2"\" +\"%F\"" | getline a; $2=a; print item,$0}' >> "${latest_online_packs_info}"

    # - kibana 5601
    $download_tool ${download_page}/kibana | sed -r -n '/Version:/{n;s@[^>]+>([^<]+)<.*@\1@g;p};/Release date:/{n;s@[^>]+>([^<]+)<.*@\1@g;p};/linux-x86_64.tar.gz/{s@.*href="([^"]+)".*$@\1@g;p};' | sed ':a;N;$!ba;s@\n@|@g' | awk -F\| -v item='kibana' 'BEGIN{OFS="|"}{"date --date=\""$2"\" +\"%F\"" | getline a; $2=a; print item,$0}' >> "${latest_online_packs_info}"
}

#########  2-3. Create User/Group For Elactic Stack  #########
funcSystemUserAndGroupOperation(){
    if [[ -z $(sed -r -n '/^'"${stack_name}"':/{p}' /etc/passwd) ]]; then
        if [[ "${restrict_mode}" -eq 1  ]]; then
            # create group
            groupadd -r "${stack_name}"
            # create user without login privilege
            useradd -r -g "${stack_name}" -s /sbin/nologin -d "${installation_dir}" -c "Elastic Stack" "${stack_name}"
            # add user to group adm for /var/log dir
            usermod -a -G adm "${stack_name}" 2> /dev/null
            user_name="${stack_name}"
            group_name="${stack_name}"
        fi
    else
        user_name="${stack_name}"
        group_name="${stack_name}"
    fi
}

#########  2-4. Download & Decompress Operation  #########
funcDirOperation(){
    local l_item="${1:-}"
    if [[ -n "${l_item}" ]]; then
        local l_user=${l_user:-"${user_name}"}
        local l_group=${l_group:-"${group_name}"}
        # local l_group=${l_group:-'root'}
        [[ -d "${l_item}" ]] || mkdir -p "${l_item}"
        chown "${l_user}":"${l_group}" "${l_item}"
        chmod 755 "${l_item}"
    fi
}

funcConfDirectiveOperation(){
    local l_item="${1:-}"
    local l_val="${2:-}"
    local l_path="${3:-}"
    if [[ -n "${l_item}" && -n "${l_val}" && -n "${l_path}" ]]; then
        [[ -s "${l_path}" ]] && sed -r -i '/^#?[[:space:]]*'"${l_item}"':/{s@^#?[[:space:]]*([^:]+:).*$@\1 '"${l_val}"'@g;}' "${l_path}"
    fi
}

funcCoreOperationProcedure(){
    local l_name="${1:-}"
    local l_release_info="${2:-}"

    # name|release version|release date|tar.gz link|sha512 link
    # local l_release_version
    # l_release_version=$(echo "${l_release_info}" | awk -F\| '{print $2}')
    # local l_release_date
    # l_release_date=$(echo "${l_release_info}" | awk -F\| '{print $3}')
    local l_pack_download_link
    l_pack_download_link=$(echo "${l_release_info}" | awk -F\| '{print $4}')
    local l_shadgst_download_link="${l_release_info##*|}"

    local l_pack_name="${l_pack_download_link##*/}"
    local l_pack_save_tmp_path="${temp_save_dir}/${l_pack_name}"
    local l_shadgst_name="${l_shadgst_download_link##*/}"
    local l_shadgst_save_tmp_path="${temp_save_dir}/${l_shadgst_name}"

    [[ -f "${l_pack_save_tmp_path}" ]] && rm -f "${l_pack_save_tmp_path}"
    pack_save_dir=${pack_save_dir%/}
    local l_pack_save_path="${pack_save_dir}/${l_pack_name}"
    if [[ ! -s "${l_pack_save_path}" ]]; then
        # remove older version package
        rm -f "${pack_save_dir}/${l_pack_name##-*}"*
        $download_tool "${l_pack_download_link}" > "${l_pack_save_path}"
    fi
    [[ -s "${l_pack_save_path}" ]] && cp -f "${l_pack_save_path}" "${l_pack_save_tmp_path}"

    # # - verification sha512
    $download_tool "${l_shadgst_download_link}" > "${l_shadgst_save_tmp_path}"

    # https://github.com/koalaman/shellcheck/wiki/SC2164
    cd "${temp_save_dir}" || exit
    grep "${l_pack_save_tmp_path##*/}" "${l_shadgst_save_tmp_path##*/}" | sha512sum -c -- &> /dev/null
    local l_return_val=$?
    [[ -f "${l_shadgst_save_tmp_path}" ]] && rm -f "${l_shadgst_save_tmp_path}"

    # printf "Package $c_blue%s$c_normal approves SHA-512 check!\n" "${l_pack_save_tmp_path##*/}"
    [[ "${l_return_val}" -eq 0 ]] || funcExitStatement "${c_red}Error${c_normal}, package ${c_blue}${l_pack_save_tmp_path##*/}${c_normal} SHA-512 check inconsistency! The package may not be integrated!"

    # - decompress && installation
    local l_install_path="${installation_dir}/${l_name}"

    local l_install_back_path="${l_install_path}${bak_suffix}"
    [[ -d "${l_install_back_path}" ]] && rm -rf "${l_install_back_path}"
    [[ -d "${l_install_path}" ]] && mv "${l_install_path}" "${l_install_back_path}"    # Backup Installation Directory
    [[ -d "${l_install_path}" ]] || mkdir -p "${l_install_path}"     # Create Installation Directory

    tar xf "${l_pack_save_tmp_path}" -C "${l_install_path}" --strip-components=1

    chown -R "${user_name}":"${group_name}" "${l_install_path}"
    find "${l_install_path}"/ -type d -exec chmod 750 {} \;
    [[ -d "${l_install_path}/bin" ]] && rm -f "${l_install_path}"/bin/{*.bat,*.exe}
    find "${l_install_path}"/bin/ -type f -exec chmod 750 {} \;

    local l_config_path="${config_dir}/${l_name}"
    if [[ ! -d "${l_config_path}" && -d "${l_install_path}/config" ]]; then
        mkdir -p "${l_config_path}"
        cp -f "${l_install_path}/config"/* "${l_config_path}"

        # Just for logstash
        if [[ "${l_name}" == "${logstash_name}" ]]; then
            # https://www.elastic.co/guide/en/logstash/current/configuration.html
            # https://www.elastic.co/guide/en/logstash/current/config-examples.html
            mkdir -p "${l_config_path}/conf.d"
            local l_sample_conf="${l_config_path}/conf.d/logstash-simple.conf.sample"
            echo "input { stdin { } }|output {|  elasticsearch { hosts => [\"127.0.0.1:9200\"] }|  stdout { codec => rubydebug }|}" > "${l_sample_conf}"
            sed -r -i 's@\|@\n@g;' "${l_sample_conf}"

            # syslog
            local l_syslog_conf="${l_config_path}/conf.d/logstash-syslog.conf.sample"
            echo "input {|  file {|    path => \"/var/log/syslog\"|    type => syslog|    start_position => \"beginning\"|  }|}||filter {|  if [type] == \"syslog\" {|    grok {|      match => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}\" }|      add_field => [ \"received_at\", \"%{@timestamp}\" ]|      add_field => [ \"received_from\", \"%{host}\" ]|    }|    date {|      match => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ]|    }|  }|}||output {|  elasticsearch {|    hosts => [\"127.0.0.1:9200\"]|    index => \"syslog-%{+YYYY.MM.dd}\"|  }|  stdout { codec => rubydebug }|}" > "${l_syslog_conf}"
            sed -r -i 's@\|@\n@g;' "${l_syslog_conf}"
        fi

        chown -R "${user_name}":"${group_name}" "${l_config_path}"
        find "${l_config_path}"/ -type f -exec chmod 640 {} \;
    fi

    # remove backup dir , temporary file
    if [[ -d "${l_install_path}/bin" ]]; then
        echo "Successfully install utility ${c_red}${l_name}${c_normal}."
        [[ -d "${l_install_back_path}" ]] && rm -rf "${l_install_back_path}"
    fi
    [[ -f "${l_pack_save_tmp_path}" ]] && rm -f "${l_pack_save_tmp_path}"
}

funcConfigElasticsearch(){
    local release_info
    release_info=$(sed -r -n '/^'"${elasticsearch_name}"'\|/{p}' "${latest_online_packs_info}")
    [[ -n "${release_info}" ]] || funcExitStatement "Fail to extract release info about ${c_blue}${elasticsearch_name}${c_normal}."
    local release_version_online
    release_version_online=$(echo "${release_info}" | awk -F\| '{print $2}')

    local release_version_local=''
    if [[ -d "${installation_dir}/${elasticsearch_name}" ]]; then
        release_version_local=$("${installation_dir}"/${elasticsearch_name}/bin/${elasticsearch_name} --version | sed -r 's@^[^[:digit:]]+([[:digit:].]+),?.*@\1@g;')
    fi

    if [[ -n "${release_version_local}" && "${release_version_online}" == "${release_version_local}" ]]; then
        echo "Latest ${c_blue}${elasticsearch_name}${c_normal} version ${c_red}${release_version_local}${c_normal} existed on your system!"
    else
        funcCoreOperationProcedure "${elasticsearch_name}" "${release_info}"

        funcDirOperation "${config_dir}"
        funcDirOperation "${log_dir}"
        funcDirOperation "${run_dir}"
        funcDirOperation "${data_dir}"

        local l_config_dir="${config_dir}/${elasticsearch_name}"
        local l_config_path="${l_config_dir}/elasticsearch.yml"
        local l_log_dir="${log_dir}/${elasticsearch_name}"
        local l_data_dir="${data_dir}/${elasticsearch_name}"
        funcDirOperation "${l_config_dir}"
        funcDirOperation "${l_log_dir}"
        funcDirOperation "${l_data_dir}"
        funcDirOperation "${run_dir}"

        ### - elasticsearch.yml - ###
        [[ -s "${l_config_path}" && ! -s "${l_config_path}${bak_suffix}" ]] && mv "${l_config_path}" "${l_config_path}${bak_suffix}"

        $download_tool "${online_config_file_sample_dir}/${l_config_path##*/}" > "${l_config_path}"

        if [[ -s "${l_config_path}" ]]; then
            # - path
            sed -r -i '/Paths Setting Start/,/Paths Setting End/{/^#?[[:space:]]*path.data[[:space:]]*:/{s@.*@path.data: '"${l_data_dir}"'@g}}' "${l_config_path}"
            sed -r -i '/Paths Setting Start/,/Paths Setting End/{/^#?[[:space:]]*path.logs[[:space:]]*:/{s@.*@path.logs: '"${l_log_dir}"'@g}}' "${l_config_path}"

            # - name
            # A node can only join a cluster when it shares its cluster.name with all the other nodes in the cluster. The default name is elasticsearch.
            local l_cluster_name=${l_cluster_name:-'elastic-elk'}
            sed -r -i '/Cluster Setting Start/,/Cluster Setting End/{/^#?[[:space:]]*cluster.name[[:space:]]*:/{s@.*@cluster.name: '"${l_cluster_name}"'@g}}' "${l_config_path}"

            local l_node_name=${l_node_name:-"node-e-${ip_local//.}"}
            sed -r -i '/Node Setting Start/,/Node Setting End/{/^#?[[:space:]]*node.name[[:space:]]*:/{s@.*@node.name: '"${l_node_name}"'@g}}' "${l_config_path}"

            # - network
            local l_network_host='127.0.0.1'
            sed -r -i '/Network Setting Start/,/Network Setting End/{/^#?[[:space:]]*network.host[[:space:]]*:/{s@.*@network.host: '"${l_network_host}"'@g}}' "${l_config_path}"

            local l_http_port='9200-9299'
            sed -r -i '/Network Setting Start/,/Network Setting End/{/^#?[[:space:]]*http.port[[:space:]]*:/{s@.*@http.port: '"${l_http_port}"'@g}}' "${l_config_path}"

            local l_transport_tcp_port='9300-9399'
            sed -r -i '/Network Setting Start/,/Network Setting End/{/^#?[[:space:]]*transport.tcp.port[[:space:]]*:/{s@.*@transport.tcp.port: '"${l_transport_tcp_port}"'@g}}' "${l_config_path}"

            # - memory
            local memory_lock_boolen='true'
            sed -r -i '/Memory Setting Start/,/Memory Setting End/{/^#?[[:space:]]*bootstrap.memory_lock[[:space:]]*:/{s@.*@bootstrap.memory_lock: '"${memory_lock_boolen}"'@g}}' "${l_config_path}"
        fi

        ### - init script - ###
        local l_service_script_dir
        local l_service_script_link
        local l_service_script_path

        if funcCommandExistCheck 'systemctl'; then
            l_service_script_dir='/etc/systemd/system'
            l_service_script_link="${online_service_script_sample_dir}/${elasticsearch_name}.service"
            l_service_script_path="${l_service_script_dir}/${stack_name}_${elasticsearch_name}.service"

            [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

            $download_tool "${l_service_script_link}" > "${l_service_script_path}"
            sed -r -i '/^\[Service\]/,/^\[/{s@^(User=).*$@\1'"${user_name}"'@g;s@^(Group=).*$@\1'"${group_name}"'@g;}' "${l_service_script_path}"
            chmod 644 "${l_service_script_path}"
        else
            l_service_script_dir='/etc/init.d'
            l_service_script_path="${l_service_script_dir}/${stack_name}_${elasticsearch_name}"
            l_service_script_link="${online_service_script_sample_dir}/${elasticsearch_name}.init"
            [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

            $download_tool "${l_service_script_link}" > "${l_service_script_path}"
            sed -r -i '/Configuraton Start/,/Configuraton End/{s@^(USER=).*$@\1'"${user_name}"'@g;s@^(GROUP=).*$@\1'"${group_name}"'@g;}' "${l_service_script_path}"
            chmod 755 "${l_service_script_path}"
        fi

        chown -R "${user_name}":"${group_name}" "${l_config_dir}" "${l_log_dir}" "${l_data_dir}"

        # [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'start'

        # curl -XGET 'localhost:9200/?pretty'
    fi
}

funcConfigKibana(){
    local release_info
    release_info=$(sed -r -n '/^'"${kibana_name}"'\|/{p}' "${latest_online_packs_info}")
    [[ -n "${release_info}" ]] || funcExitStatement "Fail to extract release info about ${c_blue}${kibana_name}${c_normal}."
    local release_version_online
    release_version_online=$(echo "${release_info}" | awk -F\| '{print $2}')

    local release_version_local=''
    if [[ -d "${installation_dir}/${kibana_name}" ]]; then
        release_version_local=$("${installation_dir}"/${kibana_name}/bin/${kibana_name} --version | sed -r 's@^[^[:digit:]]+([[:digit:].]+),?.*@\1@g;')
    fi

    if [[ -n "${release_version_local}" && "${release_version_online}" == "${release_version_local}" ]]; then
        echo "Latest ${c_blue}${kibana_name}${c_normal} version ${c_red}${release_version_local}${c_normal} existed on your system!"
    else
        funcCoreOperationProcedure "${kibana_name}" "${release_info}"

        local l_config_dir="${config_dir}/${kibana_name}"
        local l_config_path="${l_config_dir}/kibana.yml"
        local l_log_dir="${log_dir}/${kibana_name}"
        local l_data_dir="${data_dir}/${kibana_name}"

        funcDirOperation "${l_config_dir}"
        funcDirOperation "${l_log_dir}"
        funcDirOperation "${l_data_dir}"
        funcDirOperation "${run_dir}"

        ### - kibana.yml - ###
        [[ -s "${l_config_path}" && ! -s "${l_config_path}${bak_suffix}" ]] && cp "${l_config_path}" "${l_config_path}${bak_suffix}"

        # not need this step  # $download_tool "${online_config_file_sample_dir}/${l_config_path##*/}" > "${l_config_path}"

        # https://www.elastic.co/guide/en/kibana/6.1/settings.html

        if [[ -s "${l_config_path}" ]]; then
            # - server.port: 5601
            funcConfDirectiveOperation 'server.port' '5601' "${l_config_path}"
            # - server.host: "localhost"
            funcConfDirectiveOperation 'server.host' "\"localhost\"" "${l_config_path}"
            # - server.basePath: ""
            # - server.maxPayloadBytes: 1048576
            funcConfDirectiveOperation 'server.maxPayloadBytes' '1048576' "${l_config_path}"
            # - server.name: "your-hostname"
            funcConfDirectiveOperation 'server.name' "\"${stack_name}_${kibana_name}_${ip_local//.}\"" "${l_config_path}"
            # - elasticsearch.url: "http://localhost:9200"
            funcConfDirectiveOperation 'elasticsearch.url' "\"http://localhost:9200\"" "${l_config_path}"
            # - elasticsearch.preserveHost   default true, use server.host setting.
            funcConfDirectiveOperation 'elasticsearch.preserveHost' 'true' "${l_config_path}"
            # - kibana.index: ".kibana"
            # funcConfDirectiveOperation 'kibana.indext' "\".kibana\"" "${l_config_path}"

            # - kibana.defaultAppId: "home"
            funcConfDirectiveOperation 'kibana.defaultAppId' "\"discover\"" "${l_config_path}"
            # - elasticsearch.username: "user"
            # - elasticsearch.password: "pass"
            # - server.ssl.enabled: false
            # - server.ssl.certificate: /path/to/your/server.crt
            # - server.ssl.key: /path/to/your/server.key
            # - elasticsearch.ssl.certificate: /path/to/your/client.crt
            # - elasticsearch.ssl.key: /path/to/your/client.key
            # - elasticsearch.ssl.certificateAuthorities: [ "/path/to/your/CA.pem" ]
            # - elasticsearch.ssl.verificationMode: full
            # - elasticsearch.pingTimeout: 1500
            # - elasticsearch.requestTimeout: 30000
            # - elasticsearch.requestHeadersWhitelist: [ authorization ]
            # - elasticsearch.customHeaders: {}
            # - elasticsearch.shardTimeout: 0
            # - elasticsearch.startupTimeout: 5000
            # - pid.file: /var/run/kibana.pid
            funcConfDirectiveOperation 'pid.file' "${run_dir}/${kibana_name}.pid" "${l_config_path}"

            # - logging.dest: stdout
            # - logging.silent: false
            # - logging.quiet: false
            # - logging.verbose: false
            # - ops.interval: 5000
            # - i18n.defaultLocale: "en"
        fi

        ### - init script - ###
        local l_service_script_dir
        local l_service_script_link
        local l_service_script_path

        if funcCommandExistCheck 'systemctl'; then
            l_service_script_dir='/etc/systemd/system'
            l_service_script_link="${online_service_script_sample_dir}/${kibana_name}.service"
            l_service_script_path="${l_service_script_dir}/${stack_name}_${kibana_name}.service"

            [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

            $download_tool "${l_service_script_link}" > "${l_service_script_path}"
            sed -r -i '/^\[Service\]/,/^\[/{s@^(User=).*$@\1'"${user_name}"'@g;s@^(Group=).*$@\1'"${group_name}"'@g;}' "${l_service_script_path}"
            sed -r -i '/^\[Service\]/,/^\[/{s@^(ExecStart=).*$@\1'"${installation_dir}/${kibana_name}/bin/${kibana_name} \"-c ${l_config_path}\""'@g;}' "${l_service_script_path}"
            chmod 644 "${l_service_script_path}"
        else
            l_service_script_dir='/etc/init.d'
            l_service_script_path="${l_service_script_dir}/${stack_name}_${kibana_name}"
            l_service_script_link="${online_service_script_sample_dir}/${kibana_name}.init"
            [[ -f "${l_service_script_path}" ]] && funcSystemServiceManager "${l_service_script_path##*/}" 'stop'

            $download_tool "${l_service_script_link}" > "${l_service_script_path}"
            sed -r -i '/Configuraton Start/,/Configuraton End/{s@^(USER=).*$@\1'"${user_name}"'@g;s@^(GROUP=).*$@\1'"${group_name}"'@g;}' "${l_service_script_path}"
            chmod 755 "${l_service_script_path}"
        fi
    fi
}

funcConfigLogstash(){
    local release_info
    release_info=$(sed -r -n '/^'"${logstash_name}"'\|/{p}' "${latest_online_packs_info}")
    [[ -n "${release_info}" ]] || funcExitStatement "Fail to extract release info about ${c_blue}${logstash_name}${c_normal}."
    local release_version_online
    release_version_online=$(echo "${release_info}" | awk -F\| '{print $2}')

    local release_version_local=''
    if [[ -d "${installation_dir}/${logstash_name}" ]]; then
        release_version_local=$("${installation_dir}"/${logstash_name}/bin/${logstash_name} --version | sed -r 's@^[^[:digit:]]+([[:digit:].]+),?.*@\1@g;')
    fi

    if [[ -n "${release_version_local}" && "${release_version_online}" == "${release_version_local}" ]]; then
        echo "Latest ${c_blue}${logstash_name}${c_normal} version ${c_red}${release_version_local}${c_normal} existed on your system!"
    else
        funcCoreOperationProcedure "${logstash_name}" "${release_info}"

        local l_config_dir="${config_dir}/${logstash_name}"
        local l_config_path="${l_config_dir}/logstash.yml"
        local l_log_dir="${log_dir}/${logstash_name}"
        local l_data_dir="${data_dir}/${logstash_name}"

        funcDirOperation "${l_config_dir}"
        funcDirOperation "${l_log_dir}"
        funcDirOperation "${l_data_dir}"
        funcDirOperation "${run_dir}"

        ### - logstash.yml - ###
        # https://www.elastic.co/guide/en/logstash/current/performance-troubleshooting.html
        # https://www.elastic.co/guide/en/logstash/current/tuning-logstash.html
        # https://www.elastic.co/guide/en/logstash/current/logstash-settings-file.html
        if [[ -s "${l_config_path}" ]]; then
            # node.name: test
            funcConfDirectiveOperation 'node.name' "node-l-${ip_local//.}" "${l_config_path}"

            # - path.data
            funcConfDirectiveOperation 'path.data' "${l_data_dir}" "${l_config_path}"
            # ☆ - path.config  very important, must setting correctly
            # Where to fetch the pipeline configuration for the main pipeline
            # path.config: /etc/logstash/conf.d/*.conf
            funcConfDirectiveOperation 'path.config' "${l_config_dir}/conf.d/*.conf" "${l_config_path}"
            # - path.logs
            funcConfDirectiveOperation 'path.logs' "${l_log_dir}" "${l_config_path}"
            # - log.level: info
            funcConfDirectiveOperation 'path.level' 'info' "${l_config_path}"

            # - http.host: "127.0.0.1"
            funcConfDirectiveOperation 'http.host' "\"127.0.0.1\"" "${l_config_path}"
            # - http.port: 9600-9700
            funcConfDirectiveOperation 'http.port' '9600-9700' "${l_config_path}"

            # config.test_and_exit: false
            funcConfDirectiveOperation 'config.test_and_exit' 'false' "${l_config_path}"
            # config.reload.automatic: false
            funcConfDirectiveOperation 'config.reload.automatic' 'true' "${l_config_path}"
            # config.reload.interval: 3s
            funcConfDirectiveOperation 'config.reload.interval' '20s' "${l_config_path}"
            # config.support_escapes: false
            funcConfDirectiveOperation 'config.support_escapes' 'true' "${l_config_path}"

            # pipeline.workers: 2
            funcConfDirectiveOperation 'pipeline.workers' '2' "${l_config_path}"
            # pipeline.output.workers: 1
            funcConfDirectiveOperation 'pipeline.output.workers' '1' "${l_config_path}"
            # pipeline.batch.size: 125
            funcConfDirectiveOperation 'pipeline.batch.size' '150' "${l_config_path}"
            # pipeline.batch.delay: 5   milliseconds
            funcConfDirectiveOperation 'pipeline.batch.delay' '20' "${l_config_path}"
            # pipeline.unsafe_shutdown: false

            # Internal queuing model, "memory" for legacy in-memory based queuing and "persisted" for disk-based acked queueing. Defaults is memory
            # queue.type: memory
            funcConfDirectiveOperation 'queue.type' 'persisted' "${l_config_path}"

            local l_enable_persist=0
            [[ -n $(sed -r -n '/^queue.type:[[:space:]]*persisted$/{p}' "${l_config_path}") ]] && l_enable_persist=1

            # - Only for queue.type: persisted  start
            if [[ "${l_enable_persist}" -eq 1 ]]; then
                # path.queue:   Default is path.data/queue
                # queue.page_capacity: 250mb     Default is 250mb
                funcConfDirectiveOperation 'queue.page_capacity' '250mb' "${l_config_path}"
                # queue.max_events: 0            Default is 0 (unlimited)
                funcConfDirectiveOperation 'queue.max_events' '120' "${l_config_path}"
                # queue.max_bytes: 1024mb        Default is 1024mb or 1gb
                funcConfDirectiveOperation 'queue.max_bytes' '1024mb' "${l_config_path}"
                # queue.checkpoint.acks: 1024   Default is 1024, 0 for unlimited
                funcConfDirectiveOperation 'queue.checkpoint.acks' '1024' "${l_config_path}"
                # queue.checkpoint.writes: 1024  Default is 1024, 0 for unlimited
                funcConfDirectiveOperation 'queue.checkpoint.writes' '1024' "${l_config_path}"
                # queue.checkpoint.interval: 1000  Default is 1000, 0 for no periodic checkpoint.  milliseconds
                funcConfDirectiveOperation 'queue.checkpoint.interval' '1200' "${l_config_path}"
            fi
            # - Only for queue.type: persisted end

            # dead_letter_queue.enable: false
            # - Only for dead_letter_queue.enable: true  start
            # dead_letter_queue.max_bytes: 1024mb
            # path.dead_letter_queue:   Default is path.data/dead_letter_queue
            # - Only for dead_letter_queue.enable: true  end
        fi

        ### - startup.options - ###
        # is used by $LS_HOME/bin/system-install to create a custom startup script for Logstash.
        local l_install_startup_option_path="${installation_dir}/${logstash_name}/config/startup.options"
        local l_startup_option="${l_config_dir}/startup.options"

        if [[ -s "${l_startup_option}" ]]; then
            # JAVACMD=/usr/bin/java
            # local l_java_path='/usr/bin/java'
            # sed -r -i '/^#?[[:space:]]*JAVACMD=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_java_path}"'@g;}' "${l_startup_option}"
            # LS_HOME=/usr/share/logstash
            local l_ls_home="${installation_dir}/${logstash_name}"
            sed -r -i '/^#?[[:space:]]*LS_HOME=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_ls_home}"'@g;}' "${l_startup_option}"
            # LS_SETTINGS_DIR=/etc/logstash
            sed -r -i '/^#?[[:space:]]*LS_SETTINGS_DIR=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_config_dir}"'@g;}' "${l_startup_option}"

            # LS_OPTS="--path.settings ${LS_SETTINGS_DIR}"
            # local l_ls_opts="--path.settings ${LS_SETTINGS_DIR} -f"
            # sed -r -i '/^#?[[:space:]]*LS_OPTS=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_ls_opts}"'@g;}' "${l_startup_option}"

            # LS_JAVA_OPTS=""

            # LS_PIDFILE=/var/run/logstash.pid
            # pidfiles aren't used the same way for upstart and systemd; this is for sysv users.
            local l_pid_file="${run_dir}/${logstash_name}.pid"
            sed -r -i '/^#?[[:space:]]*LS_PIDFILE=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_pid_file}"'@g;}' "${l_startup_option}"

            # LS_USER=logstash
            # LS_GROUP=logstash
            sed -r -i '/^#?[[:space:]]*LS_USER=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${user_name}"'@g;}' "${l_startup_option}"
            sed -r -i '/^#?[[:space:]]*LS_GROUP=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${group_name}"'@g;}' "${l_startup_option}"

            # LS_GC_LOG_FILE=/var/log/logstash/gc.log
            # Enable GC logging by uncommenting the appropriate lines in the GC logging section in jvm.options
            local l_gc_log_path="${l_log_dir}/gc.log"
            sed -r -i '/^#?[[:space:]]*LS_GC_LOG_FILE=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_gc_log_path}"'@g;}' "${l_startup_option}"
            # LS_OPEN_FILES=16384
            local l_open_files='65535'
            sed -r -i '/^#?[[:space:]]*LS_OPEN_FILES=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_open_files}"'@g;}' "${l_startup_option}"
            # LS_NICE=19
            local l_nice='19'
            sed -r -i '/^#?[[:space:]]*LS_NICE=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"${l_nice}"'@g;}' "${l_startup_option}"

            # SERVICE_NAME="logstash"
            # SERVICE_DESCRIPTION="logstash"
            # Change these to have the init script named and described differently
            # This is useful when running multiple instances of Logstash on the same physical box or vm
            local l_service_name="${stack_name}_${logstash_name}"
            local l_description="${logstash_name^}"
            sed -r -i '/^#?[[:space:]]*SERVICE_NAME=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"\"${l_service_name}\""'@g;}' "${l_startup_option}"
            sed -r -i '/^#?[[:space:]]*SERVICE_DESCRIPTION=/{s@^#?[[:space:]]*([^=]+=).*$@\1'"\"${l_description}\""'@g;}' "${l_startup_option}"
        fi

        cp -f "${l_startup_option}" "${l_install_startup_option_path}"

        # - generate service script
        local l_generator_path="${installation_dir}/${logstash_name}/bin/system-install"
        [[ -s "${l_generator_path}" ]] && bash "${l_generator_path}" &> /dev/null

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

funcUninstallOperation
funcDatadirVerification
funcLatestPacksInfoExtraction
funcSystemUserAndGroupOperation
funcConfig${elasticsearch_name^}
[[ "${kibana_install}" -eq 1 ]] && funcConfig${kibana_name^}
[[ "${logstash_install}" -eq 1 ]] && funcConfig${logstash_name^}

funcTotalTimeCosting


#########  5. EXIT Singal Processing  #########
# trap "commands" EXIT # execute command when exit from shell
funcTrapEXIT(){
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
    unset bak_suffix
    unset stack_name
    unset installation_dir
    unset config_dir
    unset log_dir
    unset run_dir
    unset data_dir
    unset user_name
    unset group_name
    unset pack_save_dir
    unset is_uninstall
    unset proxy_server
    unset restrict_mode
    unset logstash_install
    unset kibana_install
    unset ip_local
    unset start_time
    unset finish_time
    unset total_time_cost
}

trap funcTrapEXIT EXIT


# Elastic Search delete index
# https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-delete-index.html
# curl -XDELETE 'localhost:9200/twitter?pretty'
# curl -XGET 'localhost:9200/twitter?pretty'

# https://www.elastic.co/guide/en/logstash/current/config-examples.html


# Script End
