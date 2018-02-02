#!/usr/bin/env bash
set -u  #Detect undefined variable
set -o pipefail #Return return code in pipeline fails
# IFS=$'\n\t' #IFS  Internal Field Separator

#Target: Firewall(ufw/SuSEfirewall2/firewalld/iptables) Rule Configuration On GNU/Linux
#Writer: MaxdSre
#Date: Jan 30, 2018 19:04 Tue +0800 - add icmp configuation, disable icmp except localhost
#Reconfiguration Date:
# - Nov 09, 2017 16:58 Thu +0800

#########  0-1. Singal Setting  #########
mktemp_format=${mktemp_format:-'GLFWCemp_XXXXX'}
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
bak_suffix=${bak_suffix:-'_bak'}     # suffix word for file backup

check_approved=${check_approved:-0}

port_no_specified=${port_no_specified:-}
allow_inbound=${allow_inbound:-1}
deny_inbound=${deny_inbound:-0}
delete_rule=${delete_rule:-}
host_ip_specified=${host_ip_specified:-}
restrict_ssh_login=${restrict_ssh_login:-0}
restrict_login_host=${restrict_login_host:-}
silent_output=${silent_output:-0}

pack_manager=${pack_manager:-}
distro_name=${distro_name:-}
version_id=${version_id:-}
distro_family_own=${distro_family_own:-}
codename=${codename:-}
login_user_ip=${login_user_ip:-}
ssh_port=${ssh_port:-22}

firewall_type=${firewall_type:-}

#########  1-1 Initialization Prepatation  #########
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

#########  1-2 getopts Operation  #########
funcHelpInfo(){
cat <<EOF
${c_blue}Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...
Installing / Configuring Firewall(ufw/SuSEfirewall2/firewalld/iptables) Rule On GNU/Linux!
This script requires superuser privileges (eg. root, su).
Default disable ICMP except local host.

[available option]
    -h    --help, show help info
    -p port    --specify port number, e.g. SSH 22, Apache/Nginx 80/443
    -a    --allow inbound (default), along with -p
    -d    --deny inbound, along with -p
    -D    --delete rule, along with -p
    -H host_ip    --specify single host ip or ip range for port specified by -p
    -r    --restrict remote login host, default is loging via SSH, just focus on first configuration
    -R login_host_ip    --restrict remote login host specified, just focus on first configuration
    -s    --silent output, default output firewall configuration detail
${c_normal}
EOF
}

while getopts "hp:adDH:rR:s" option "$@"; do
    case "$option" in
        p ) port_no_specified="$OPTARG" ;;
        a ) allow_inbound=1 ;;
        d ) deny_inbound=1 ;;
        D ) delete_rule=1 ;;
        H ) host_ip_specified="$OPTARG" ;;
        r ) restrict_ssh_login=1 ;;
        R ) restrict_login_host="$OPTARG" ;;
        s ) silent_output=1 ;;
        h|\? ) funcHelpInfo && exit ;;
    esac
done

#########  2-1. Essential Operation  #########
funcVitalInfoDetection(){
    # 1 - Check root or sudo privilege
    if [[ "$UID" -eq 0 ]]; then
        # 2 - specified for RHEL/Debian/SLES
        if [[ -s '/etc/redhat-release' || -s '/etc/debian_version' || -s '/etc/SuSE-release' ]]; then
            check_approved=1
        elif [[ $(sed -r -n '/^ID=/s@.*="?([^"]*)"?@\L\1@p' /etc/os-release) == 'amzn' ]]; then
            check_approved=1
        fi
    fi

    if [[ "${check_approved}" -eq 1 ]]; then
        # 3 - Package manager detection
        # OpenSUSE has utility apt-get, aptitude. Amazing
        if funcCommandExistCheck 'zypper'; then
            pack_manager='zypper'
        elif funcCommandExistCheck 'apt-get'; then
            pack_manager='apt-get'
        elif funcCommandExistCheck 'dnf'; then
            pack_manager='dnf'
        elif funcCommandExistCheck 'yum'; then
            pack_manager='yum'
        fi

        # 4 - Firewall type
        case "${pack_manager}" in
            apt-get ) firewall_type='ufw' ;;
            zypper ) firewall_type='SuSEfirewall2' ;;
            dnf|yum ) [[ $("${pack_manager}" info firewalld 2>&1 | awk -F": " 'match($1,/^Name/){print $NF;exit}') == 'firewalld' ]] && firewall_type='firewalld' || firewall_type='iptables' ;;
        esac

        # 6 - Remote Login User Information
        if [[ "${restrict_ssh_login}" -eq 1 ]]; then
            if [[ -n "${SSH_CLIENT:-}" ]]; then
                login_user_ip=$(echo "${SSH_CLIENT}" | awk '{print $1}')
            elif [[ -n "${SSH_CONNECTION:-}" ]]; then
                login_user_ip=$(echo "${SSH_CONNECTION}" | awk '{print $1}')
            else
                login_user_ip=$(who | sed -r -n '$s@.*\(([^\)]+)\).*@\1@gp')
                # [[ "${login_user_ip}" == ":0" ]] && login_user_ip='127.0.0.1'
            fi
        fi

        # 7 - SSH Port Check
        local sshd_config=${sshd_config:-'/etc/ssh/sshd_config'}
        if [[ -f "${sshd_config}" ]]; then
            ssh_port=$(sed -r -n '/^#?Port/s@^#?Port[[:space:]]*(.*)@\1@p' "${sshd_config}" 2> /dev/null)
            [[ -z "${ssh_port}" ]] && ssh_port=22
        fi
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

#########  2-2. Fierwall Installation  #########
funcFirewallInstallation(){
    case "${firewall_type}" in
        ufw )
            funcCommandExistCheck 'ufw' || funcPackageManagerOperation 'install' "ufw"
            ;;
        SuSEfirewall2 )
            funcCommandExistCheck 'SuSEfirewall2' || funcPackageManagerOperation 'install' "SuSEfirewall2"
            funcPackageManagerOperation 'install' "yast2-firewall"
            ;;
        firewalld )
            funcCommandExistCheck 'firewalld' || funcPackageManagerOperation 'install' "firewalld"
            ;;
        iptables )
            funcCommandExistCheck 'iptables' || funcPackageManagerOperation 'install' "iptables iptables-services"
            ;;
    esac
}

# Block Top 10 Known-bad IPs
# $download_tool https://isc.sans.edu/top10.html | sed -r -n '/ipdetails.html/{s@.*?ip=([^"]+)".*@\1@g;s@^0+@@g;s@\.0+@.@g;p}'

#########  3-1. Fierwall - Iptables  #########
funcIptablesRuleAdd(){
    local l_type=${l_type:-"${1:-}"}    # input/output
    local l_action=${l_action:-"${2:-}"}    # accept/drop
    local l_port=${l_port:-"${3:-}"}
    local l_host=${l_host:-"${4:-}"}

    local insert_pos=${insert_pos:-}
    insert_pos=$(iptables -L INPUT -n --line-num | awk '$2="ACCEPT"&&$3=="all"&&$0~/RELATED,ESTABLISHED/{print $1;exit}')

    if [[ -n "${insert_pos}" ]]; then
        # insert
        if [[ -n "${l_host}" ]]; then
            iptables -I "${l_type}" "${insert_pos}" -s "${l_host}" -m state --state NEW -m tcp -p tcp --dport "${l_port}" -j "${l_action}"
        else
            iptables -I "${l_type}" "${insert_pos}" -m state --state NEW -m tcp -p tcp --dport "${l_port}" -j "${l_action}"
        fi
    else
        # append
        if [[ -n "${l_host}" ]]; then
            iptables -A "${l_type}" -s "${l_host}" -m state --state NEW -m tcp -p tcp --dport "${l_port}" -j "${l_action}"
        else
            iptables -A "${l_type}" -m state --state NEW -m tcp -p tcp --dport "${l_port}" -j "${l_action}"
        fi
    fi    # end if insert_pos

}

funcIptablesRulesOperation(){
    local l_type=${l_type:-"${1:-'input'}"}    # input/output
    local l_action=${l_action:-"${2:-'accept'}"}    # accept/drop
    local l_port=${l_port:-"${3:-}"}
    local l_host=${l_host:-"${4:-}"}

    case "${l_type,,}" in
        output|o ) l_type='OUTPUT' ;;
        input|i|* ) l_type='INPUT' ;;
    esac

    case "${l_action,,}" in
        drop|d ) l_action='DROP' ;;
        accept|a|* ) l_action='ACCEPT' ;;
    esac

    if [[ -n "${l_port}" ]]; then
        local line_num_arr=()
        if [[ -n "${l_host}" ]]; then
            line_num_arr=( $(iptables -L INPUT -n --line-num | awk 'match($0,/:?'"${l_port}"'[[:blank:]]*$/){if($0~/[[:space:]]+'"${l_host}"'[[:space:]]+/) print $1}' | sort -rh) )
        else
            line_num_arr=( $(iptables -L INPUT -n --line-num | awk 'match($0,/:?'"${l_port}"'[[:blank:]]*$/){print $1}' | sort -rh) )
        fi

        local arr_item_count=${arr_item_count:-0}
        arr_item_count="${#line_num_arr[@]}"

        if [[ "${arr_item_count}" -eq 0 ]]; then
            [[ "${delete_rule}" -eq 1 ]] || funcIptablesRuleAdd "${l_type}" "${l_action}" "${l_port}" "${l_host}"
        else

            for (( i = 0; i < "${arr_item_count}"; i++ )); do
                [[ "${line_num_arr[$i]}" -gt 0 ]] && iptables -D INPUT "${line_num_arr[$i]}"
            done

            if [[ "${delete_rule}" -eq 1 ]]; then
                if [[ -n "${ssh_port}" && "${ssh_port}" -eq "${port_no_specified}" ]]; then
                    local ssh_rule_count=${ssh_rule_count:-0}
                    ssh_rule_count=$(iptables -L INPUT -n --line-num | awk 'BEGIN{count=0}match($0,/:?'"${l_port}"'[[:blank:]]*$/){count++}END{print count}')

                    [[ "${ssh_rule_count}" -eq 0 ]] && funcIptablesRuleAdd "${l_type}" "${l_action}" "${l_port}" "${l_host}"
                fi
            else
                funcIptablesRuleAdd "${l_type}" "${l_action}" "${l_port}" "${l_host}"
            fi
        fi

    fi    # end if l_port
}

funcFirewall_iptables(){
    # https://github.com/ismailtasdelen/Anti-DDOS
    local is_newly_installed=${is_newly_installed:-1}

    # start iptables servic first time will prompt "iptables: No config file." add a rule first
    if [[ -f /etc/sysconfig/iptables ]]; then
        is_newly_installed=0
    else
        # write temporarily rule to create this configuration file
        iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
        service iptables save 1> /dev/null
        funcSystemServiceManager 'iptables' 'enable'
    fi

    # iptables -nL --line-num
    # iptables -L -n -v
    # iptables -L INPUT -n --line-num

    if [[ "${is_newly_installed}" -eq 1 ]]; then
        iptables -P INPUT ACCEPT
        iptables -F    # -F Flush the selected chain
        iptables -X    # -X Delete the optional user-defined chain specified.
        iptables -Z    # -Z Zero the packet and byte counters in chains
        service iptables save 1> /dev/null

        # blocking null packets
        iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP
        # anti syn-flood attack
        iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
        iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP

        # Allow loopback interface to do anything.
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT

        # Just allow localhost use ping
        # iptables -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 1/s --limit-burst 2 -j ACCEPT
        iptables -A INPUT -p icmp -m icmp --icmp-type 8 -s 127.0.0.1 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p icmp --icmp-type 0 -s 0/0 -d 127.0.0.1 -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

        ## open http/https server port to all ##
        # iptables -A INPUT -m state --state NEW -p tcp -m multiport --dports 80,443 -j ACCEPT

        if [[ -n "${ssh_port}" && "${ssh_port}" -ne "${port_no_specified}" ]]; then
            local ssh_host_ip=${ssh_host_ip:-}
            if [[ "${restrict_ssh_login}" -eq 1 ]]; then
                ssh_host_ip="${login_user_ip}"
            elif [[ -n "${restrict_login_host}" ]]; then
                ssh_host_ip="${restrict_login_host}"
            fi
            funcIptablesRulesOperation "input" "accept" "${ssh_port}" "${ssh_host_ip}"
        fi

    fi    # end if is_newly_installed

    if [[ "${port_no_specified}" =~ ^[0-9]{1,5}$ && "${port_no_specified}" -gt 0 && "${port_no_specified}" -lt 65536 ]]; then
        if [[ -n "${host_ip_specified}" ]]; then
            [[ "${allow_inbound}" -eq 1 ]] && funcIptablesRulesOperation "input" "accept" "${port_no_specified}" "${host_ip_specified}"
            [[ "${deny_inbound}" -eq 1 ]] && funcIptablesRulesOperation "input" "drop" "${port_no_specified}" "${host_ip_specified}"
        else
            [[ "${allow_inbound}" -eq 1 ]] && funcIptablesRulesOperation "input" "accept" "${port_no_specified}"
            [[ "${deny_inbound}" -eq 1 ]] && funcIptablesRulesOperation "input" "drop" "${port_no_specified}"
        fi
    fi

    if [[ "${is_newly_installed}" -eq 1 ]]; then
        # Allow incoming connections related to existing allowed connections.
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        # Allow outgoing connections EXCEPT invalid
        iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -P INPUT DROP
    fi

    # iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "Someone knocked on port 22"

    service iptables save 1> /dev/null
    funcSystemServiceManager 'iptables' 'restart'

    [[ "${silent_output}" -eq 1 ]] || iptables -nL --line-num
}

#########  3-2. Fierwall - firewalld  #########
funcFirewall_firewalld(){
    # https://www.certdepot.net/rhel7-get-started-firewalld/
    # https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-7

    # firewall-cmd --get-default-zone
    # firewall-cmd --zone=public --permanent --list-ports
    # firewall-cmd --zone=public --permanent --list-rich-rule

    # firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.100.26" destination address=192.168.0.10/32 port port=8080-8090 protocol=tcp accept'

    # $(systemctl is-active firewalld) == 'inactive'
    [[ $(firewall-cmd --state 2>&1) == 'running' ]] || funcSystemServiceManager 'firewalld' 'enable'
    # set default zone
    [[ $(firewall-cmd --get-default-zone) == 'public' ]] || firewall-cmd --set-default-zone=public &> /dev/null

    # lockdown Rules
    # /etc/firewalld/firewalld.conf  Lockdown=yes
    # firewall-cmd --query-lockdown
    # firewall-cmd --lockdown-on/--lockdown-off
    [[ $(firewall-cmd --query-lockdown) == 'no' ]] && firewall-cmd --lockdown-on &> /dev/null

    # disable ping
    # firewall-cmd --add-icmp-block=echo-request --permanent &> /dev/null
    # firewall-cmd --get-icmptypes
    # firewall-cmd --list-icmp-blocks
    # firewall-cmd --zone=public --add-icmp-block=echo-reply
    # firewall-cmd --zone=public --query-icmp-block=echo-reply
    # https://serverfault.com/questions/677084/block-icmp-timestamp-timestamp-reply-with-firewalld
    firewall-cmd --zone=public --remove-icmp-block={echo-request,echo-reply,timestamp-reply,timestamp-request} --permanent &> /dev/null

    firewall-cmd --zone=public --add-icmp-block={echo-request,echo-reply,timestamp-reply,timestamp-request} --permanent &> /dev/null

    # firewall-cmd --zone=public --list-services --permanent
    # firewall-cmd --zone=public --permanent --add-service=ssh &> /dev/null
    firewall-cmd --zone=public --permanent --remove-service=ssh &> /dev/null

    if [[ -n "${ssh_port}" && "${ssh_port}" -ne "${port_no_specified}" ]]; then
        local ssh_host_ip=${ssh_host_ip:-}
        if [[ "${restrict_ssh_login}" -eq 1 ]]; then
            ssh_host_ip="${login_user_ip}"
        elif [[ -n "${restrict_login_host}" ]]; then
            ssh_host_ip="${restrict_login_host}"
        fi

        if [[ -n "${ssh_host_ip}" ]]; then
            firewall-cmd --zone=public --permanent --add-rich-rule='rule family="ipv4" source address="'"${ssh_host_ip}"'" port port='"${ssh_port}"' protocol="tcp" accept' 1> /dev/null
        else
            firewall-cmd --zone=public --permanent --add-port="${port_no_specified}"/tcp  &> /dev/null
        fi

    else
        firewall-cmd --zone=public --permanent --add-port="${port_no_specified}"/tcp  &> /dev/null
    fi

    if [[ "${port_no_specified}" =~ ^[0-9]{1,5}$ && "${port_no_specified}" -gt 0 && "${port_no_specified}" -lt 65536 ]]; then
        # remove existed
        if [[ -n "${host_ip_specified}" ]]; then
            firewall-cmd --zone=public --permanent --remove-rich-rule='rule family="ipv4" source address="'"${host_ip_specified}"'" port port='"${port_no_specified}"' protocol="tcp" accept' &> /dev/null
        else
            firewall-cmd --zone=public --permanent --list-rich-rule | awk 'match($0,/port="'"${port_no_specified}"'"/){ipinfo=gensub(/.*address="([^"]+)".*/,"\\1","g",$0);print ipinfo}' | while read -r line; do
                firewall-cmd --zone=public --permanent --remove-rich-rule='rule family="ipv4" source address="'"${line}"'" port port='"${port_no_specified}"' protocol="tcp" accept' 1> /dev/null
            done

            firewall-cmd --zone=public --permanent --remove-port="${port_no_specified}"/tcp  &> /dev/null
        fi

        # add new
        local add_rule_flag=${add_rule_flag:-0}
        if [[ "${delete_rule}" -ne 1 ]]; then
            add_rule_flag=1
        else
            if [[ -n "${ssh_port}" && "${port_no_specified}" -eq "${ssh_port}" ]]; then
                add_rule_flag=1
            fi
        fi

        if [[ "${add_rule_flag}" -eq 1 ]]; then
            if [[ -n "${host_ip_specified}" ]]; then
                firewall-cmd --zone=public --permanent --add-rich-rule='rule family="ipv4" source address="'"${host_ip_specified}"'" port port='"${port_no_specified}"' protocol="tcp" accept' 1> /dev/null
            else
                firewall-cmd --zone=public --permanent --add-port="${port_no_specified}"/tcp  &> /dev/null
            fi
        fi    # end if add_rule_flag

    fi

    firewall-cmd --reload 1> /dev/null

    [[ "${silent_output}" -eq 1 ]] || firewall-cmd --permanent --list-all
}

#########  3-3. Fierwall - ufw  #########
funcFirewall_ufw(){
    # https://help.ubuntu.com/community/UFW
    # https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands
    # https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-16-04
    # ufw status numbered
    # ufw allow ssh   # ufw delete allow ssh
    # ufw allow 6660:6670/tcp

    # ufw [delete] allow/deny from 192.168.100.0/24 1> /dev/null
    # ufw [delete] deny/allow in on eth0 [from 192.168.100.0/24] to any port 80 1> /dev/null
    # ufw [delete] allow/limit from 192.168.100.106/32 to any port 22 proto tcp 1> /dev/null
    # ufw [delete] allow 80,443/tcp 1> /dev/null   #ufw allow http/https, ufw deny 80/tcp
    # ufw [delete] allow proto tcp from any to any port 80,443 1> /dev/null
    # ufw allow from <target> to <destination> port <port number>

    # Disable ipv6
    [[ -f /etc/default/ufw ]] && sed -r -i '/^IPV6=/{s@(IPV6=).*@\1no@g;}' /etc/default/ufw
    funcSystemServiceManager 'ufw' 'enable'

    # https://serverfault.com/questions/790143/ufw-enable-requires-y-prompt-how-to-automate-with-bash-script
    # man ufw | sed -r -n '/REMOTE MANAGEMENT/,/APPLICATION INTEGRATION/p'
    # When running ufw enable or starting ufw via its initscript, ufw will flush its chains. This is required so ufw can maintain a consistent state, but it may drop existing connections (eg ssh).

    if [[ $(ufw status | sed -r -n '/^Status:/{s@.*:[[:space:]]*(.*)@\1@g;p}') == 'inactive' ]]; then
        # this rule will be flushed, but the ssh port still be open after enabling the firewall
        local l_restrict_host=${l_restrict_host:-'any'}
        [[ -n "${host_ip_specified}" ]] && l_restrict_host="${host_ip_specified}"
        ufw allow proto tcp from "${l_restrict_host}" to any port "${ssh_port}" 1> /dev/null
        ufw --force enable 1> /dev/null
    fi

    # # Just allow localhost use ping
    local before_rule_path=${before_rule_path:-'/etc/ufw/before.rules'}
    if [[ -s "${before_rule_path}" && $(sed -r -n '/ufw-before-input.*echo-request -j ACCEPT/{p}' "${before_rule_path}" | wc -l) -gt 0 ]]; then
        # input
        sed -r -i '/ufw-before-input.*echo-request -j ACCEPT/{s@(.* -j).*$@\1 DROP@g;}' "${before_rule_path}"
        sed -r -i '/ufw-before-input.*echo-request -j/i -A ufw-before-input -p icmp --icmp-type echo-request -s 127.0.0.1 -m state --state ESTABLISHED -j ACCEPT' "${before_rule_path}"

        # output
        sed -r -i '/ok icmp code for FORWARD/i # ok icmp codes for OUTPUT\n-A ufw-before-output -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT\n-A ufw-before-output -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT\n' "${before_rule_path}"
    fi

    local user_rule_path=${user_rule_path:-'/etc/ufw/user.rules'}
    [[ -s /lib/ufw/user.rules ]] && user_rule_path='/lib/ufw/user.rules'

    # awk 'BEGIN{count=0}/^#+[[:space:]]*RULES/,/^#+[[:space:]]*END RULES/{if(NF>0 && $0!~/^#/) {count++}}END{print count}' "${user_rule_path}"    # need install gawk, not just awk

    if [[ $(sed -r -n '/^#+[[:space:]]*RULES/,/^#+[[:space:]]*END RULES/{/^#/d;/^$/d;p}' "${user_rule_path}" | wc -l) -eq 0 ]]; then
        echo "y" | ufw reset 1> /dev/null
        ufw default deny incoming 1> /dev/null
        ufw default allow outgoing 1> /dev/null
        ufw logging on 1> /dev/null

        ufw delete limit ssh &> /dev/null
        ufw delete allow ssh &> /dev/null

        if [[ -n "${ssh_port}" && "${ssh_port}" -ne "${port_no_specified}" ]]; then
            local ssh_host_ip=${ssh_host_ip:-}
            if [[ "${restrict_ssh_login}" -eq 1 ]]; then
                ssh_host_ip="${login_user_ip}"
            elif [[ -n "${restrict_login_host}" ]]; then
                ssh_host_ip="${restrict_login_host}"
            fi

            if [[ -n "${ssh_host_ip}" ]]; then
                # ufw limit
                ufw allow from "${ssh_host_ip}" to any port "${ssh_port}" proto tcp 1> /dev/null
            else
                ufw allow "${ssh_port}"/tcp 1> /dev/null
            fi
        else
            ufw allow "${ssh_port}"/tcp 1> /dev/null
        fi

    fi

    if [[ "${port_no_specified}" =~ ^[0-9]{1,5}$ && "${port_no_specified}" -gt 0 && "${port_no_specified}" -lt 65536 ]]; then
        # remove existed
        local l_action=${l_action:-'allow'}
        [[ "${allow_inbound}" -eq 1 ]] && l_action='allow'
        [[ "${deny_inbound}" -eq 1 ]] && l_action='deny'

        if [[ -n "${host_ip_specified}" ]]; then
            ufw delete ${l_action} from "${host_ip_specified}" to any port "${port_no_specified}" proto tcp 1> /dev/null
        else
            # ufw delete ${l_action} "${port_no_specified}"/tcp &> /dev/null
            sed -r -i '/^#+[[:space:]]*RULES/,/^#+[[:space:]]*END RULES/{/^#+[[:space:]]*tuple.*(deny|allow) tcp '"${port_no_specified}"'[[:space:]]+/,+2{d}}' "${user_rule_path}"
        fi    # end if host_ip_specified

        # add new
        local add_rule_flag=${add_rule_flag:-0}
        if [[ "${delete_rule}" -ne 1 ]]; then
            add_rule_flag=1
        else
            if [[ -n "${ssh_port}" && "${port_no_specified}" -eq "${ssh_port}" ]]; then
                add_rule_flag=1
                l_action='allow'
            fi
        fi    # end if delete_rule

        if [[ "${add_rule_flag}" -eq 1 ]]; then
            if [[ -n "${host_ip_specified}" ]]; then
                ufw ${l_action} from "${host_ip_specified}" to any port "${port_no_specified}" proto tcp 1> /dev/null
            else
                ufw ${l_action} "${port_no_specified}"/tcp &> /dev/null
            fi
        fi    # end if add_rule_flag

    fi

    ufw reload 1> /dev/null
    [[ "${silent_output}" -eq 1 ]] || ufw status verbose
}

#########  3-4. Fierwall - SuSEfirewall2  #########
funcYast2FirewallOperation(){
    local l_port=${l_port:-"${1:-}"}
    local l_proto=${l_proto:-"${2:-'tcp'}"}
    local l_host=${l_host:-"${3:-}"}
    local l_config_path=${l_config_path:-'/etc/sysconfig/SuSEfirewall2'}

    local l_pattern_info=${l_pattern_info:-''}

    if [[ -n "${l_host}" ]]; then
        l_pattern_info="${l_host},${l_proto},${l_port}"
    else
        l_pattern_info="${l_proto},${l_port}"
        yast2 firewall services remove zone=EXT tcpport="${l_port}" 1> /dev/null
    fi

    local l_service_left=${l_service_left:-}
    l_service_left=$(sed -r -n '/^FW_SERVICES_ACCEPT_EXT=/{s@.*="([^"]*)".*@\1@g;s@[[:space:]]+@\n@g;p}' "${l_config_path}" | sed '/'"${l_pattern_info}"'$/d;/^$/d' | awk '!arr[$0]++' | sed ':a;N;$!ba;s@\n@ @g')

    sed -r -i '/^FW_SERVICES_ACCEPT_EXT=/{s@(.*=")[^"]*(")@\1'" ${l_service_left}"'\2@g;s@[[:space:]]*(")[[:space:]]*@\1@g}' "${l_config_path}"

    # add new
    local add_rule_flag=${add_rule_flag:-0}
    if [[ "${delete_rule}" -ne 1 ]]; then
        add_rule_flag=1
    else
        if [[ -n "${ssh_port}" && "${l_port}" -eq "${ssh_port}" ]]; then
            add_rule_flag=1
        fi
    fi    # end if delete_rule

    if [[ "${add_rule_flag}" -eq 1 ]]; then
        if [[ -n "${l_host}" ]]; then
            sed -r -i '/^FW_SERVICES_ACCEPT_EXT=/{s@^(.*="[^"]*)(")$@\1'" ${l_pattern_info}"'\2@g;s@[[:space:]]*(")[[:space:]]*@\1@g}' "${l_config_path}"
        else
            yast2 firewall services add zone=EXT tcpport="${l_port}" 1> /dev/null
        fi
    fi
}

funcFirewall_SuSEfirewall2(){
    # https://knowledgelayer.softlayer.com/procedure/configure-software-firewall-sles
    # https://release-8-16.about.gitlab.com/downloads/#opensuse421

    # INT - Internal Zone  |  DMZ - Demilitarized Zone  |  EXT - External Zone
    # /etc/sysconfig/SuSEfirewall2

    # yast2 firewall summary
    # yast2 firewall services show detailed
    # yast2 firewall interfaces/logging/startup show

    # yast2 firewall interfaces add interface=`ip a s dev eth0 | awk '/ether/{printf "eth-id-%s", $2}'` zone=INT
    # yast2 firewall interfaces add interface=`ip a s dev eth1 | awk '/ether/{printf "eth-id-%s", $2}'` zone=EXT

    # list in $(yast2 firewall services list)
    # FW_CONFIGURATIONS_EXT
    # yast2 firewall services add zone=EXT service=service:sshd

    # FW_SERVICES_EXT_TCP / FW_SERVICES_EXT_UDP
    # yast2 firewall services add zone=EXT tcpport=22
    # yast2 firewall services add zone=EXT udpport=53
    # yast2 firewall services add tcpport=80,443,22,25,465,587 udpport=80,443,22,25,465,587 zone=EXT

    # FW_SERVICES_ACCEPT_EXT
    #Custome Rule, space separated list of <source network>[,<protocol>,<destination port>,<source port>,<options>]
    # FW_SERVICES_ACCEPT_EXT="116.228.89.242,tcp,777 192.168.92.123,tcp,567,789 192.168.45.145,tcp,,85"

    # yast2 firewall startup atboot/manual
    # yast2 firewall startup manual

    # rcSuSEfirewall2 status/start/stop/restart

    local susefirewall2=${susefirewall2:-'/etc/sysconfig/SuSEfirewall2'}
    [[ -f "${susefirewall2}${bak_suffix}" ]] || cp -fp "${susefirewall2}" "${susefirewall2}${bak_suffix}"

    if [[ -n "${ssh_port}" && "${ssh_port}" -ne "${port_no_specified}" ]]; then
        local ssh_host_ip=${ssh_host_ip:-}
        if [[ "${restrict_ssh_login}" -eq 1 ]]; then
            ssh_host_ip="${login_user_ip}"
        elif [[ -n "${restrict_login_host}" ]]; then
            ssh_host_ip="${restrict_login_host}"
        fi
        funcYast2FirewallOperation "${ssh_port}" 'tcp' "${ssh_host_ip}"
    else
        yast2 firewall services add zone=EXT tcpport="${ssh_port}" 1> /dev/null
    fi

    if [[ "${port_no_specified}" =~ ^[0-9]{1,5}$ && "${port_no_specified}" -gt 0 && "${port_no_specified}" -lt 65536 ]]; then
        funcYast2FirewallOperation "${port_no_specified}" 'tcp' "${host_ip_specified}"
    fi

    yast2 firewall startup atboot 2> /dev/null
    yast2 firewall enable 1> /dev/null
    rcSuSEfirewall2 start 1> /dev/null

    if [[ "${silent_output}" -ne 1 ]]; then
        yast2 firewall services show
        sed -r -n '/^FW_SERVICES_ACCEPT_EXT=/p' /etc/sysconfig/SuSEfirewall2
    fi
}

#########  4. Executing Process  #########
funcCentralOperationProcess(){
    funcVitalInfoDetection
    if [[ "${check_approved}" -eq 1 ]]; then
        funcFirewallInstallation
        funcFirewall_"${firewall_type}"
    fi
}

funcCentralOperationProcess


#########  4. EXIT Singal Processing  #########
funcTrapEXIT(){
    unset bak_suffix
    unset check_approved
    unset port_no_specified
    unset allow_inbound
    unset deny_inbound
    unset delete_rule
    unset host_ip_specified
    unset restrict_ssh_login
    unset restrict_login_host
    unset silent_output
    unset pack_manager
    unset distro_name
    unset version_id
    unset distro_family_own
    unset codename
    unset login_user_ip
    unset ssh_port
    unset firewall_type
    rm -rf /tmp/"${mktemp_format%%_*}"* 2>/dev/null
}

trap funcTrapEXIT EXIT

# Script End
