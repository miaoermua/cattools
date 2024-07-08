#!/bin/bash
# env
DEFAULT_IP="192.168.1.4"
RELEASE="/etc/catwrt_release"
AMD64_REPO="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/amd64/distfeeds.conf"
MT798X_REPO="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/mt798x/distfeeds.conf"
AMD64_EFI_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_efi"
AMD64_BIOS_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_bios"

# Check ROOT & OpenWrt
if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root user"
    exit 1
fi

openwrt_release=$(cat /etc/openwrt_release)
if ! grep -q "OpenWrt" <<< "$openwrt_release"; then
    echo "Your system is not supported!"
    exit 1
fi

# Update
update_cattools() {
    echo "Please wait for the script to be updated."
    local temp_file=$(mktemp)
    local retries=3
    local success=false

    while [ $retries -gt 0 ]; do
        if curl --silent --connect-timeout 3 --max-time 9 -o "$temp_file" https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh; then
            echo "cattools update downloaded from the first URL."
            success=true
            break
        elif curl --silent --connect-timeout 3 --max-time 9 -o "$temp_file" https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/cattools.sh; then
            echo "cattools update downloaded from the second URL."
            success=true
            break
        else
            echo "Attempt $(3 - retries + 1) failed. Retrying..."
            retries=$((retries - 1))
        fi
    done

    if [ "$success" = false ]; then
        echo "Unable to download the latest version, continue to use the current offline version."
        echo ""
        rm -f "$temp_file"
        return
    fi

    mv "$temp_file" /usr/bin/cattools
    chmod +x /usr/bin/cattools
    echo "cattools updated successfully."
    echo ""
}

# Menu Function
menu() {
    echo ""
    echo "----------------------------------------------------------"
    echo "                         CatTools                         "
    echo "           https://github.com/miaoermua/cattools          "
    echo "----------------------------------------------------------"
    echo "1. SetIP                                   -  设置 IP"
    echo "2. network_wizard                          -  网络向导"
    echo "3. Debug                                   -  抓取日志"
    echo "4. catwrt_update                           -  检查更新"
    echo "5. apply_repo                              -  软件源配置"
    echo "6. diagnostics                             -  网络诊断"
    echo "7. sysupgrade                              -  系统更新"
    echo "8. enhancement                             -  实用增强"
    echo "0. Exit                                    -  退出"
    echo "----------------------------------------------------------"
    echo -n "请输入数字并回车(Please enter your choice): "
}

# Parameters
help() {
    echo "Usage: $0 [-help] [-update]"
    echo
    echo "Options:"
    echo "  -help or -h        帮助"
    echo "  -update or -u      跳过 Cattools 脚本更新检查"
    echo ""
    echo "HELP:"
    echo "遇到问题了? 请使用本工具菜单中的 debug 选项，尝试反馈以解决问题!"
    echo "https://github.com/miaoermua/CatWrt/issues/new?assignees=&labels=&projects=&template=report.md&title="
    echo "TG Guoup: t.me/miaoergroup  //  QQ Guoup: 669190476  // Blog: miaoer.xyz"
    exit 0
}

skip_update=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h) help ;;
        -help) help ;;
        -u) skip_update=true ;;
        -update) skip_update=true ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ "$skip_update" = false ]; then
    update_cattools
fi

# Setup
setip(){
    DEFAULT_IP="192.168.1.4"
    while true; do
        read -p "Please enter the IP Addr and press Enter /// 请输入 IP (默认为 $DEFAULT_IP): " input_ip
        if [ -z "$input_ip" ]; then
            input_ip=$DEFAULT_IP 
        fi

        if echo "$input_ip" | grep -Eo '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' > /dev/null; then
            break
        else
            echo "Invalid IP address format /// 非法的 IP 地址格式，请重新输入"
        fi
    done

    uci set network.lan.ipaddr=$input_ip 
    uci commit network
    /etc/init.d/network restart
    
    echo "默认 IP 已设置为 $input_ip"
}

# Network Wizard
network_wizard() {
    read -p "Do you want Network Wizard? /// 是否使用网络向导？(Enter 确认，按 0 退出): " use_wizard
    if [ "$use_wizard" == "0" ]; then
        echo "网络向导已退出。"
        return
    fi
    
    echo "CatWrt default IP is 192.168.1.4 /// 默认 CatWrt IP 为 192.168.1.4"
    read -p "是否修改 IP 地址？(Enter 确认，按 0 退出): " modify_ip
    if [ "$modify_ip" != "0" ]; then
        read -p "请输入 IP (默认为 $DEFAULT_IP): " input_ip
        if [[ -z $input_ip ]]; then
            input_ip=$DEFAULT_IP
        elif ! [[ $input_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "无效的 IP 地址"
            return
        fi

        uci set network.lan.ipaddr=$input_ip
        echo "IP 地址已设置为 $input_ip"
    fi
    
    echo "Recommended DNS: 223.6.6.6 119.29.29.99 /// 推荐使用的DNS: 223.6.6.6 119.29.29.99" 
    read -p "是否使用推荐的 DNS 服务器？(Enter 确认，按 0 退出): " use_dns
    if [ "$use_dns" != "0" ]; then
        read -p "请输入 DNS (默认为 $DEFAULT_DNS): " input_dns
        if [[ -z $input_dns ]]; then
            input_dns=$DEFAULT_DNS
        elif ! [[ $input_dns =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}( [0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "无效的 DNS 地址。"
            return
        fi

        uci set network.lan.dns="$input_dns"
        echo "DNS 服务器已设置为 $input_dns"
    fi
    
    echo "IPv6 is enabled by default /// IPv6 默认是开启的"
    read -p "是否禁用 IPv6 网络？(Enter 确认，按 1 禁用，按 0 退出): " disable_ipv6
    if [ "$disable_ipv6" == "1" ]; then
        uci delete dhcp.lan.dhcpv6 
        uci delete dhcp.lan.ra
        uci delete dhcp.lan.ra_management
        uci delete network.lan.ip6assign
        echo "IPv6 已禁用"
    fi
    
    echo "Default connection mode is DHCP /// 默认模式为 DHCP"
    read -p "是否进行 PPPoE 拨号？(Enter 确认，按 1 继续修改账号和密码，按 0 退出): " use_pppoe
    if [ "$use_pppoe" == "1" ]; then
        read -p "请输入宽带账号: " username
        read -s -p "请输入宽带密码: " password
        uci set network.wan.proto=pppoe
        uci set network.wan.username=$username
        uci set network.wan.password=$password
        echo "PPPoE 拨号配置已完成"
    fi
    
    read -p "Use recommended DNS servers 223.6.6.6 119.29.29.99? /// 使用推荐的 DNS 服务器 223.6.6.6 119.29.29.99 吗？(Enter 确认，按 0 退出): " use_dns
    if [ "$use_dns" = "0" ]; then
        exit 0
    elif [ -z "$use_dns" ]; then
        uci set network.lan.dns="223.6.6.6 119.29.29.99"
    else
        if [[ $use_dns =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\s+([0-9]{1,3}\.){3}[0-9]{1,3})*$ ]]; then
            uci set network.lan.dns="$use_dns"
        else
            echo "Invalid DNS format /// 无效的 DNS 格式"
            exit 1
        fi
    fi

    read -p "Do you want to change the DHCP IP pool range? (default: 30-200) /// 是否修改 IP 可用段？(默认: 30-200, 按 1 手动输入范围): " dhcp_choice
    if [ "$dhcp_choice" = "1" ]; then
        read -p "Enter the DHCP IP pool range (e.g., 40-210) /// 输入 DHCP IP 地址范围 (例如: 40-210): " dhcp_range
        if [[ $dhcp_range =~ ^([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
            dhcp_start=$(echo $dhcp_range | cut -d '-' -f 1)
            dhcp_limit=$(echo $dhcp_range | cut -d '-' -f 2)
            uci set dhcp.lan.start=$dhcp_start
            uci set dhcp.lan.limit=$dhcp_limit
        else
            echo "Invalid DHCP range format /// 无效的 DHCP 范围格式"
            exit 1
        fi
    else
        uci set dhcp.lan.start=30
        uci set dhcp.lan.limit=200
    fi

    echo "enable DHCP force /// 开启 DHCP 强制可以避免局域网收到 AP 吐地址的问题"
    read -p "是否开启强制 DHCP 模式？(Enter 确认，按 1 跳过): " force_dhcp
    if [ "$force_dhcp" != "1" ]; then
        uci set dhcp.lan.force=1
        echo "强制 DHCP 模式已开启"
    fi
    
    echo "Enable UPNP by default /// 默认开启 UPNP，可提升 BT/P2P 软件连接性，但客户端容易受到流氓软件滥用 P2P 网络导致上行带宽异常!"
    read -p "是否开启 UPNP？(Enter 确认，按 1 跳过): " enable_upnp
    if [ "$enable_upnp" != "1" ]; then
        uci set upnpd.config.enabled=1
        echo "UPNP 已开启"
    fi

    uci commit
    /etc/init.d/network restart
    /etc/init.d/dnsmasq restart
    /etc/init.d/firewall restart
    /etc/init.d/miniupnpd restart
    echo "Network configuration saved and applied. If you encounter any issues, please restart!"
    echo "网络配置已保存并应用，服务已重启，如遇到问题问题请手动重启!"
    echo ""
}

# Debug
debug() {
    if [ -f /www/logs.txt ]; then
        rm /www/logs.txt
    fi
    
    cat /etc/banner >> /www/logs.txt
    date >> /www/logs.txt

    echo "## RELEASE" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    cat /etc/catwrt_release >> /www/logs.txt
    echo ""
    
    echo "## STATUS" >> /www/logs.txt
    echo "=================" >> /www/logs.txt
    eval $UPTIME >> /www/logs.txt
    echo ""
    
    echo "## Memory Usage" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    free -h >> /www/logs.txt
    echo ""
    
    echo "## Disk Usage" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    df -h >> /www/logs.txt
    echo ""
    
    echo "## Application" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    opkg list_installed >> /www/logs.txt

    echo "## SYSLOG" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    logread >> /www/logs.txt
    echo ""
    
    echo "## DMESG" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    dmesg >> /www/logs.txt
    echo ""
    
    echo "## Plugins" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    cat /tmp/openclash.log >> /www/logs.txt
    cat /tmp/log/ssrplus.log >> /www/logs.txt
    cat /tmp/log/passwall.log >> /www/logs.txt
    cat /tmp/log/passwall2.log >> /www/logs.txt
    echo ""
    
    echo "## Task" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    top -b -n 1 >> /www/logs.txt
    echo ""
    
    echo "## Network Configuration" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    ifconfig -a >> /www/logs.txt
    echo ""
    
    echo "## UCI Network" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    uci show network >> /www/logs.txt
    echo ""
    
    echo "## Firewall" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    iptables -L -v -n >> /www/logs.txt
    ip6tables -L -v -n >> /www/logs.txt
    echo ""
    
    echo "## Routing Table" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    ip route >> /www/logs.txt
    ip -6 route >> /www/logs.txt
    echo ""
    
    lan_ip=$(uci get network.lan.ipaddr)

    echo "Finish!"
    echo "请使用浏览器访问此地址下载 LOG 文件  http://$lan_ip/logs.txt"
    echo "日志已收集到 /www/logs.txt 如果你使用 PPPoE 拨号请手动将宽带账密删除，再使用以下链接上传 Github issues 附件!"
    echo ""
    echo "https://github.com/miaoermua/CatWrt/issues/new?assignees=&labels=&projects=&template=report.md&title="
    echo "尽可能使用 Github 提交你的问题不会操作再使用社交软件 TG Guoup: t.me/miaoergroup  //  QQ Guoup: 669190476"
    echo ""
    exit
}

# catwrt_update
catwrt_update() {

    API_URL="https://api.miaoer.xyz/api/v2/snippets/catwrt/update"
    
    remote_error() {
        echo "Remote $1 get failed for arch: $arch_self, please check your network!"
        exit 1
    }
    
    local_error() {
        echo "Local $1 get failed, please check your /etc/catwrt-release!"
        exit 1
    }
    
    get_remote_hash() {
        arch_self=$1
        version_remote=$(curl -s "$API_URL" | jq -r ".$arch_self.version")
        hash_remote=$(curl -s "$API_URL" | jq -r ".$arch_self.hash")
    
        if [ $? -ne 0 ] || [ -z "$version_remote" ] || [ -z "$hash_remote" ]; then
            remote_error "version or hash"
        fi
    }
    
    init() {
        if [ ! -f "$RELEASE" ]; then
            local_error "version file"
        fi
    
        version_local=$(grep 'version' "$RELEASE" | cut -d '=' -f 2)
        hash_local=$(grep 'hash' "$RELEASE" | cut -d '=' -f 2)
        source_local=$(grep 'source' "$RELEASE" | cut -d '=' -f 2)
        arch_local=$(grep 'arch' "$RELEASE" | cut -d '=' -f 2)
    }
    
    contrast_version() {
        if [ "$version_remote" == "$version_local" ] && [ "$hash_remote" == "$hash_local" ]; then
            echo "======================================================="
            echo "              Your CatWrt is up to date!"
            echo "======================================================="
        else
            echo "======================================================="
            echo "Your CatWrt is out of date, you should upgrade it!"
            echo "Visit the blog for more information"
            echo "https://www.miaoer.xyz/posts/network/catwrt"
            echo "======================================================="
        fi
    }
    
    print_version() {
        echo "Local  Version : $version_local"
        echo "Remote Version : $version_remote"
        echo "Local  Hash    : $hash_local"
        echo "Remote Hash    : $hash_remote"
        echo "======================================================="
        echo ""
    }
    
    main() {
        init
        get_remote_hash "$arch_local"
        contrast_version
        print_version
    }
    main
    }

# Repo
apply_repo() {
    if [ -f /etc/catwrt_release ]; then
        source /etc/catwrt_release
    else
        # If the `/etc/catwrt_release` file does not exist, the `/etc/openwrt_release` file is read.
        if [ -f /etc/openwrt_release ]; then
            openwrt_version=$(grep DISTRIB_RELEASE /etc/openwrt_release | cut -d"'" -f2)
            arch=$(grep DISTRIB_TARGET /etc/openwrt_release | cut -d"/" -f1)
            case "$arch" in
                x86_64)
                    if grep -q "R22.11.11" /etc/openwrt_release; then
                        version="v22.12"
                    elif grep -q "R23.2" /etc/openwrt_release; then
                        version="v23.2"
                    else
                        echo "Unknown arch x86_64 /// 未知的 x86_64 版本"
                        exit 1
                    fi
                    ;;
                aarch64_generic)
                    if grep -q "R22.12.1" /etc/openwrt_release; then
                        version="v22.12"
                        arch="rkarm"
                    else
                        echo "Unknown arch aarch64_generic ///未知的 aarch64_generic 版本"
                        exit 1
                    fi
                    ;;
                *)
                    echo "Unknown arch $arch /// 未知的架构: $arch"
                    exit 1
                    ;;
            esac
        else
            echo "`/etc/catwrt_release` or `/etc/openwrt_release` Files do not exist /// 文件不存在或者系统损坏!"
            exit 1
        fi
    fi
    
    BASE_URL="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo"
    
    select_repo() {
        case "$arch" in
            amd64)
                if [ "$version" == "v23.8" ]; then
                    REPO_URL="$BASE_URL/amd64"
                elif [ "$version" == "v22.12" ]; then
                    REPO_URL="$BASE_URL/history/v22.12/amd64"
                elif [ "$version" == "v23.2" ]; then
                    REPO_URL="$BASE_URL/history/v23.2/amd64"
                elif [ "$version" == "v24.3" ]; then
                    REPO_URL="$BASE_URL/amd64"
                elif [ "$version" == "v24.8" ]; then
                    REPO_URL="$BASE_URL/amd64"
                else
                    echo "Unknown arch $arch /// 未知的架构: $arch"
                    exit 1
                fi
                ;;
            mt798x)
                if [ "$version" == "v23.8" ]; then
                    REPO_URL="$BASE_URL/mt798x"
                elif [ "$version" == "v22.12" ]; then
                    REPO_URL="$BASE_URL/history/v22.12/aarch64_cortex-a53"
                elif [ "$version" == "v23.2" ]; then
                    REPO_URL="$BASE_URL/history/v23.2/mt7986a"
                else
                    echo "Unknown arch mt798x /// 未知的 mt798x 版本"
                    exit 1
                fi
                ;;
            rkarm)
                if [ "$version" == "v22.12" ]; then
                    REPO_URL="$BASE_URL/rkarm"
                else
                    echo "Unknown arch rkarm /// 未知的 rkarm 版本"
                    exit 1
                fi
                ;;
            *)
                echo "Unknown arch $arch /// 未知的架构: $arch"
                exit 1
                ;;
        esac
    }
    
        echo ""
        echo "Warning:"
        echo "软件源纯属免费分享，赞助我们复制链接在浏览器打开，这对我们继续保持在线服务有很大影响。"
        echo "本人不对所有软件进行保证，我们没有第三方商业服务，风险需要自行承担。"
        echo "支持我们: https://www.miaoer.xyz/sponsor"
        echo "你需要同意 CatWrt 软件源用户协议,请确认是否继续 (10 秒内按 [Ctrl]+[C] 取消操作)"
        echo "=============================================================================="
    
    select_repo
    
    echo ""
    echo "请选择要使用的软件源:"
    echo "1) repo.miaoer.xyz (主站)"
    echo "2) cfnetlify"
    echo "3) netlify"
    echo "4) cfvercel"
    echo "5) vercel (默认)"
    
    read -t 10 -p "Please enter your choice /// 请输入选择 (1-5): " choice
    choice=${choice:-5}
    
    case $choice in
        1) conf_file="distfeeds.conf";;
        2) conf_file="cfnetlify.conf";;
        3) conf_file="netlify.conf";;
        4) conf_file="cfvercel.conf";;
        5) conf_file="vercel.conf";;
        *) conf_file="vercel.conf";;
    esac
    
    CONF_PATH="$REPO_URL/$conf_file"
    if curl --output /dev/null --silent --head --fail "$CONF_PATH"; then
        echo "使用 $CONF_PATH"
    else
        echo "源文件不存在: $CONF_PATH"
        exit 1
    fi
    
    curl -sL "$CONF_PATH" -o /etc/opkg/distfeeds.conf
    
    # fack istore_compat
    if [ -f /var/opkg-lists/istore_compat ]; then
        rm /var/opkg-lists/istore_compat
    fi
    
    opkg update
    
    echo "完成"
}
# catnd

catnd(){
    echo "$(date) - Starting CatWrt Network Diagnostics" 
    echo " "
    
    # Ping & PPPoE
    ping -c 3 223.5.5.5 > /dev/null
    if [ $? -eq 0 ]; then
        echo "[Ping] Network connection succeeded!"
        echo " "
    else
        ping -c 3 119.29.29.99 > /dev/null
        if [ $? -eq 0 ]; then
            echo "[Ping] Network connection succeeded,But there may be problems!"
            echo " "
        else
            pppoe_config=$(grep 'pppoe' /etc/config/network)
            if [ ! -z "$pppoe_config" ]; then
                echo "[PPPoE] Please check if your PPPoE account and password are correct."
                echo " "
            fi
            exit 1
        fi
    fi
    
    # DNS
    valid_dns="1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 223.6.6.6 223.5.5.5 180.76.76.76 208.67.222.222 208.67.220.220 119.29.29.99"
    
    dns_config=$(grep 'option dns' /etc/config/network)
    dns_servers=$(echo $dns_config | awk -F "'" '{print $2}')
    
    for ip in $dns_servers; do
      if ! [[ $valid_dns =~ (^|[ ])$ip($|[ ]) ]]; then
        echo "[DNS] Recommended to delete DNS $ip"
        echo " "
        exit 1
      fi
    done
    
    # Bad DNS
    echo "[DNS] DNS configuration looks good!"
    echo " "
    
    bad_dns="114.114.114.114 114.114.115.115 119.29.29.29"
    if [[ $dns_config =~ $bad_dns ]]; then
      echo "[DNS] DNS may be polluted or unreliable"
      echo " "
    fi
    
    # nslookup
    nslookup bilibili.com > /dev/null
    if [ $? -ne 0 ]; then
      nslookup www.miaoer.xyz > /dev/null
      if [ $? -eq 0 ]; then  
        echo "[DNS] DNS resolution succeeded"
        echo " "
      else
        echo "[DNS] NS resolution failed for 'www.miaoer.xyz'"
        echo "[DNS] Your DNS server may have issues"
        echo " "
      fi
    fi
    
    # Public IP
    echo CatWrt IPv4 Addr: $(curl --silent --connect-timeout 5 4.ipw.cn )
    echo " "
    
    curl 6.ipw.cn --connect-timeout 5 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
      echo "[IPv6] IPv6 network connection timed out"
      echo " "
    else
      echo CatWrt IPv6 Addr: $(curl --silent 6.ipw.cn) 
      echo " "
    fi
    
    # IPv6
    resp=$(curl --silent test.ipw.cn)
    
    if echo "$resp" | grep -q -E '240e|2408|2409|2401'; then
      echo "[IPv6] IPv6 access is preferred"
      echo " "
    else
      echo "[IPv6] IPv4 access is preferred" 
      echo " "
    fi
    
    # Default IP
    ipaddr_config=$(grep '192.168.1.4' /etc/config/network)
    
    if [ -z "$ipaddr_config" ]; then
      echo "[Default-IP] address is not the catwrt default 192.168.1.4"
      echo "Please configure your network at 'https://www.miaoer.xyz/posts/network/quickstart-catwrt'"
      echo " "
    fi
    
    # Bypass Gateway
    wan_config=$(grep 'config interface' /etc/config/network | grep 'wan')
    
    if [ -z "$wan_config" ]; then
      echo "[Bypass Gateway] No config for 'wan' interface found in /etc/config/network"
      echo "Please check if your device is set as a Bypass Gateway"
      echo " "
    fi
    
    # Rotuer Mode(PPPoE)
    pass_config=$(grep 'password' /etc/config/network)
    user_config=$(grep 'username' /etc/config/network)
    pppoe_config=$(grep 'pppoe' /etc/config/network)
    
    if [ -n "$pass_config" ] && [ -n "$user_config" ] && [ -n "$pppoe_config" ]; then
        echo "[PPPoE] PPPoE Rotuer Mode"
        echo " " 
    else
        echo "[PPPoE] DHCP protocol detected in WAN interface"
        echo "The device may not be in PPPoE Rotuer Mode"
        echo " " 
    fi
    
    # IPv6 WAN6
    grep 'config interface' /etc/config/network | grep 'wan6'  > /dev/null
    if [ $? -ne 0 ]; then
       echo "[wan6] Your IPv6 network may have issues"
       echo " "
    fi 
    
    grep 'dhcpv6' /etc/config/network > /dev/null
    if [ $? -ne 0 ]; then
       echo "[wan6] Your IPv6 network may have issues"
       echo " "
    fi
    
    # Tcping
    echo "[Tcping] Testing..."
    
    tcping -q -c 1 cn.bing.com
    [ $? -ne 0 ] && echo "Failed: cn.bing.com"
    
    tcping -q -c 1 bilibili.com
    [ $? -ne 0 ] && echo "Failed: bilibili.com"
    
    tcping -q -c 1 github.com
    [ $? -ne 0 ] && echo "Failed: github.com"
    
    tcping -q -c 1 google.com.hk
    [ $? -ne 0 ] && echo "Failed: google.com.hk"
    
    echo " "
    echo "$(date) - Network check completed!"
    echo " "
    echo "CatWrt Network Diagnostics by @miaoermua"
}

# Sysupgrade
sysupgrade(){
    if [ "$(uname -m)" != "x86_64" ]; then
        echo "仅有 x86_64 可以使用脚本进行系统升级。"
        exit 1
    fi
    
    echo ""

    disk_size=$(fdisk -l /dev/sda | grep "Disk /dev/sda:" | awk '{print $3}')
    if (( $(echo "$disk_size != 800.28" | bc -l) )); then
        echo "磁盘空间未修改或不匹配，无法继续升级。"
        exit 1
    fi

    efi_mode=0
    if [ -d /sys/firmware/efi ]; then
        efi_mode=1
    fi

    if [ -e /dev/sda128 ] || [ -e /dev/vda128 ] || [ -e /dev/nvme0n1p128 ] || [ $efi_mode -eq 1 ]; then
        firmware_url=$AMD64_EFI_SYSUP
    else
        firmware_url=$AMD64_BIOS_SYSUP
    fi
    
    echo ""
    echo "Warning:"
    echo "========================================================================="
    echo "即将升级系统，存在不可恢复风险请输入 ([1] 确认/[2] 取消)，15s 后将默认继续升级!"
    echo "该功能通过 OpenWrt sysupgrade 升级系统，不保证 100% 升级成功，请三思!"
    echo ""
    echo "+ 升级系统会导致启用软件源安装的所有软件被新固件覆盖"
    echo "+ ROOT 账户的密码可能被还原为默认密码: (password)"
    echo "+ 升级过程中会保留插件配置和预装插件以获得升级"
    echo "+ 会抹除 opkg 或手动方式安装的插件，可以通过后续在软件源中获取!"
    echo "+ 该更新同样会下载最新版本，应当更新前使用 Cattools 中的 catwrt_update 检查更新"

    read -t 30 -p "确认升级系统 (1 确认/2 取消)? " confirm_upgrade
    if [ -z "$confirm_upgrade" ] || [ "$confirm_upgrade" = "1" ]; then
        echo "是否需要加速下载？默认加速，按 2 跳过加速。"
        read -t 5 -p "选择: " use_accel
        if [ -z "$use_accel" ] || [ "$use_accel" != "2" ]; then
            if [ $efi_mode -eq 1 ]; then
                curl https://mirror.ghproxy.com/https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_efi | bash
            else
                curl https://mirror.ghproxy.com/https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_bios | bash
            fi
        else
            if [ $efi_mode -eq 1 ]; then
                curl https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_efi | bash
            else
                curl https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_bios | bash
            fi
        fi
    else
        echo "升级取消。"
    fi
}

# Enhancement MENU
enhancement_menu() {
    echo ""
    echo "增强配置"
    echo "========================"
    echo ""
    echo "1. Tailscale 配置"
    echo "2. TTYD 配置免密(危险)"
    echo "3. SSL/TLS 证书上传配置"
    echo "4. 重置 root 密码"
    echo "5. 恢复出厂设置(重置系统)"
    echo ""
    echo "0. 返回 Cattools 主菜单"
    echo
    read -p "请输入数字并回车(Please enter your choice):" choice
    case $choice in
        1) configure_tailscale ;;
        2) configure_ttyd ;;
        3) manual_deploy_uhttpd_ssl_cert ;;
        0) menu ;;
        *) echo "无效选项，请重试" && enhancement_menu ;;
    esac
}

configure_tailscale(){
    if ! grep -q -E "catwrt|repo.miaoer.xyz" /etc/opkg/distfeeds.conf && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]\.[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "[ERROR] 请先配置软件源"
        menu
        return
    fi

    if ! opkg list_installed | grep -q "tailscale" || ! opkg list_installed | grep -q "tailscaled"; then
        echo "正在安装 tailscale 和 tailscaled 软件包..."
        opkg install tailscale
        if [ $? -ne 0 ]; then
            echo "[ERROR] 安装 tailscale 失败，请先配置软件源。"
            menu
            return
        fi
    fi
    
    subnet=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -n 1)
    if [ -z "$subnet" ]; then
        echo "[ERROR] 无法获取当前子网。"
        menu
        return
    fi

    tailscale up --advertise-routes=$subnet --accept-routes --advertise-exit-node

    firewall_file="/etc/firewall.user"
    rules=("iptables -I FORWARD -i tailscale0 -j ACCEPT"
           "iptables -I FORWARD -o tailscale0 -j ACCEPT"
           "iptables -t nat -I POSTROUTING -o tailscale0 -j MASQUERADE")

    for rule in "${rules[@]}"; do
        if ! grep -q "^$rule$" $firewall_file; then
            echo $rule >> $firewall_file
        fi
    done

        lan_ip=$(uci get network.lan.ipaddr)
        
    echo ""
    echo "点击上面的 tailscale login 链接然后再进行以下配置"
    echo "========================================================================="
    echo ""
    echo "请在浏览器中访问 http://$lan_ip/cgi-bin/luci/admin/network/iface_add"
    echo "新增以下配置:"
    echo ""
    echo "新接口的名称: tailscale"
    echo "新接口的协议: 静态 (默认)"
    echo "包括以下接口: 以太网适配器: \"tailscale0\" (tailscale)"
    echo "提交 下一步"
    echo ""
    echo "## 接口 - TAILSCALE"
    echo "IPv4 地址: 输入 tailscale 中的 CatWrt 地址"
    echo "IPv4 子网掩码: 255.0.0.0"
    echo "保存 下一步"
    echo ""
    echo "##接口 - TAILSCALE - 防火墙设置"
    echo "创建/分配防火墙区域: LAN"
    echo "保存并应用"

    echo "Tailscale 配置部分，剩下的交给你了~"
    menu
}

# TTYD (NOT SAFETY)
configure_ttyd(){
    if ! opkg list_installed | grep -q "luci-app-ttyd" || ! opkg list_installed | grep -q "ttyd"; then
        echo "[ERROR]未安装 luci-app-ttyd 或 ttyd 软件包，请先配置软件源并安装这些软件包"
        menu
        return
    fi
    
    echo ""
    echo "Warning:"
    echo "========================================================================="
    echo "此操作将修改 TTYD 的配置以自动登录 root 用户，而且不需要密码"
    echo "这存在被远程执行的安全风险!仅适用于方便未放行端口时的调试，使用后请务必回到此处配置禁用。"
    echo "你确定要继续吗？ ([1] 确认/[2] 取消)"
    read -r confirmation
    if [ "$confirmation" != "1" ]; then
        echo "操作取消"
        menu
        return
    fi
    
    echo ""
    echo "你真的阅读了此警告吗，这非常主要!请务必使用此功能后将其禁用，以避免遭受远程执行命令!"
    echo "禁用只需要在 Cattools 里面再选一次此功能就可以完成禁用，这是我们的承诺哦!"
    echo "你确定要继续吗？ ([1] 确认/[2] 取消)"
    read -r second_confirmation
    if [ "$second_confirmation" != "1" ]; then
        echo "操作取消"
        menu
        return
    fi
    
    if grep -q "option command '/bin/login -f root'" /etc/config/ttyd; then
        sed -i "s/option command '\/bin\/login -f root'/option command '\/bin\/login'/" /etc/config/ttyd
        /etc/init.d/ttyd restart
            echo ""
            echo "TTYD 配置已还原为默认配置"
    else
        sed -i "s/option command '\/bin\/login'/option command '\/bin\/login -f root'/" /etc/config/ttyd
        /etc/init.d/ttyd restart
        echo ""
        echo "TTYD 配置已修改为自动登录 root"
        lan_ip=$(uci get network.lan.ipaddr)
        echo "TTYD 访问链接  http://$lan_ip:7681"
    fi
    
    menu
}

# Manual upload SSL/TLS
manual_deploy_uhttpd_ssl_cert() {
    if ! grep -q -E "catwrt|repo.miaoer.xyz" /etc/opkg/distfeeds.conf && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]+\.[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "[ERROR] 请先配置软件源"
        menu
        return
    fi

    if ! grep -q "option cert '/etc/uhttpd.crt'" /etc/config/uhttpd || ! grep -q "option key '/etc/uhttpd.key'" /etc/config/uhttpd; then
        echo "[ERROR] uhttpd 配置文件中的证书或密钥路径已被修改，无法继续执行!"
        echo "请检查 /etc/config/uhttpd"
        menu
        return
    fi

    if ! grep -q "list listen_http '0.0.0.0:80'" /etc/config/uhttpd || \
       ! grep -q "list listen_http '\[::\]:80'" /etc/config/uhttpd || \
       ! grep -q "list listen_https '0.0.0.0:443'" /etc/config/uhttpd || \
       ! grep -q "list listen_https '\[::\]:443'" /etc/config/uhttpd; then
        echo "[ERROR] uhttpd 配置文件中的监听端口配置已被修改，请检查!"
    fi

    if ! opkg list_installed | grep -q "unzip"; then
        echo "正在安装 unzip..."
        opkg update
        opkg install unzip
        if [ $? -ne 0 ]; then
            echo "[ERROR] 安装 unzip 失败。请检查软件源配置"
            menu
            return
        fi
    fi
        lan_ip=$(uci get network.lan.ipaddr)

    echo ""   
    echo "请在浏览器中访问 http://$lan_ip/cgi-bin/luci/admin/system/filetransfer 上传证书 zip 文件。"
    echo "仅支持 Aliyun / Tencent Cloud 创建的 Ngnix 和 apache SSL/TLS 证书"
    echo "本功能仅做手动证书部署，并不代表你的 DNS 已解析或者网页 (:80/:443 or:8080) 端口通畅"
    echo "不支持已安装 ngnix 的设备"
    echo "上传完成后，按 ([1] 确认/[2] 取消)"
    read -r confirmation
    if [ "$confirmation" != "1" ]; then
        echo "[ERROR] 上传未确认"
        menu
        return
    fi

    zip_files=($(ls /tmp/upload/*.zip 2>/dev/null))
    if [ ${#zip_files[@]} -gt 1 ]; then
        echo "[ERROR] 检测到多个 zip 文件，请仅上传一个 zip 文件"
        menu
        return
    elif [ ${#zip_files[@]} -eq 0 ]; then
        echo "[ERROR] 未找到上传的 zip 文件"
        menu
        return
    fi

    uploaded_zip=${zip_files[0]}

    if [ -f /etc/uhttpd.crt ]; then
        mv /etc/uhttpd.crt /etc/uhttpd.crt.bak
    fi
    if [ -f /etc/uhttpd.key ]; then
        mv /etc/uhttpd.key /etc/uhttpd.key.bak
    fi

    unzip -o "$uploaded_zip" -d /tmp/deploy_ssl
    if [ $? -ne 0 ]; then
        echo "[ERROR] 解压失败"
        menu
        return
    fi

    crt_file=$(find /tmp/deploy_ssl -name "*.crt" -o -name "*.pem" 2>/dev/null | head -n 1)
    key_file=$(find /tmp/deploy_ssl -name "*.key" 2>/dev/null | head -n 1)
    if [ -z "$crt_file" ] || [ -z "$key_file" ]; then
        echo "[ERROR] 未找到有效的证书文件或密钥文件"
        menu
        return
    fi

    cp "$crt_file" /etc/uhttpd.crt
    cp "$key_file" /etc/uhttpd.key

    rm -rf /tmp/deploy_ssl
    rm "$uploaded_zip"

    echo "证书部署完成，正在重启 UHTTPD"
    /etc/init.d/uhttpd restart
    menu
}

# Firstboot

openwrt_firstboot() {
    echo ""
    echo "Warning:"
    echo "========================================================================="
    echo "此操作将重置 OpenWrt 系统，删除所有配置并恢复出厂(原始固件)设置"
    echo "如遇到问题可以使用 Cattools 里面的 sysupgrade 进行完整包升级，下策才是重置系统"
    echo "你确定要继续吗？([1] 确认/[2] 取消)"
    read -r confirmation
    if [ "$confirmation" != "1" ]; then
        echo "操作取消"
        menu
        return
    fi
    
    echo ""
    echo "你真的阅读了此警告吗，这非常主要!你的系统即将重置!"
    echo "你将放弃 OpenWrt 中的一切，从头来过!"
    echo "你确定要继续吗？ ([1] 确认/[2] 取消)"
    read -r second_confirmation
    if [ "$second_confirmation" != "1" ]; then
        echo "操作取消"
        menu
        return
    fi
    firstboot && reboot
}

# Reset password
reset_root_password() {
    echo ""
    echo "此操作将重置 root 用户的密码"
    echo "你确定要继续吗？ ([1] 确认/[2] 取消)"
    read -r confirmation
    if [ "$confirmation" != "1" ]; then
        echo "操作取消"
        menu
        return
    fi
    password_hash='$1$V4UetPzk$CYXluq4wUazHjmCDBCqXF.'
    sed -i "s|^root:[^:]*:|root:$password_hash:|" /etc/shadow
    echo "Warning:"
    echo "========================================================================="
    echo "root 用户密码已重置为 password"
    echo "请在终端中输入 passwd 修改密码，或者在 系统-管理权 中修改"
    ehco "长期使用默认密码(弱密码)极易遭受远程指令攻击，后果严重"
    exit
}

while true; do
    menu
    read choice
    case $choice in
        1)
            setip
            ;;
        2)
            network_wizard
            ;;
        3)
            debug
            ;;
        4)
            catwrt_update
            ;;
        5)
            apply_repo
            ;;
        6)
            catnd
            ;;
        7)
            sysupgrade
            ;;
        8)
            enhancement_menu
            ;;
        0)
            echo "Exiting..."
            break
            ;;
        *)
            echo "Invalid choice, please try again"
            read -p "Press [Enter] key to continue..."
            ;;
    esac
done

echo "Done!"
