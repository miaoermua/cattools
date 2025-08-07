#!/bin/bash
# env
DEFAULT_IP="192.168.1.4"
RELEASE="/etc/catwrt_release"
BACKUP_FILE="/etc/catwrt_opkg_list_installed"
API_URL="https://api.miaoer.net/api/v2/snippets/catwrt/update"
BASE_URL="https://raw.miaoer.net/cattools/repo"

# sysupgrade env
AMD64_EFI_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_efi"
AMD64_BIOS_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_bios"
MT7621_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/mt7621/"
MT798X_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/mt798x/"

# Check ROOT & CatWrt/Lean's LEDE(QWRT)
if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this cattools, please use root user"
    exit 1
fi

if ! grep -qi -E "OpenWrt|QWRT" /etc/openwrt_release; then
    echo "Error: Your system is not supported by cattools!"
    exit 1
fi

# Update CatTools
update_cattools() {
    echo "Please wait for the cattools to be updated."
    local target_file="/usr/bin/cattools"
    local temp_file="/tmp/cattools/cattools.sh"
    local retries=3
    local success=false
    local urls=(
        "https://raw.miaoer.net/cattools/cattools.sh"
        "https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh"
    )

    mkdir -p /tmp/cattools

    while [ $retries -gt 0 ]; do
        for url in "${urls[@]}"; do
            curl --silent --connect-timeout 3 --max-time 5 -o "$temp_file" "$url"
            curl_exit_code=$?

            if [ $curl_exit_code -eq 0 ] && [ -s "$temp_file" ]; then
                success=true
                break 2
            fi
        done

        echo "Attempt $((4 - retries)) failed. Retrying..."
        retries=$((retries - 1))
    done

    if [ "$success" = false ]; then
        echo "Unable to download the latest version, continue to use the current offline version."
        echo ""
        rm -f "$temp_file"
        return
    fi

    mv "$temp_file" "$target_file"
    chmod +x "$target_file"
    echo "cattools updated successfully."
    echo ""
}

# Menu Function
menu() {
    echo ""
    echo "----------------------------------------------------------"
    echo "                         CatTools                         "
    echo "        https://www.miaoer.net/posts/blog/cattools        "
    echo "----------------------------------------------------------"
    echo "1. SetIP                                  -  设置 IP"
    echo "2. Network_Wizard                         -  网络向导"
    echo "3. Apply_repo                             -  软件源配置"
    echo "4. Diagnostics                            -  网络诊断"
    echo "5. Debug                                  -  抓取日志"
    echo "6. Catwrt_update                          -  检查更新"
    echo "7. Sysupgrade                             -  系统更新"
    echo "8. Restore                                -  恢复软件包"
    echo "9. Utilities(more)                        -  实用工具"
    echo "0. Exit                                   -  退出"
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
    echo "TG Guoup: t.me/miaoergroup  //  QQ Guoup: 669190476  // Blog: miaoer.net"
    exit 0
}

skip_update=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
    -h) help ;;
    -help) help ;;
    -u) skip_update=true ;;
    -update) skip_update=true ;;
    *)
        echo "Unknown parameter passed: $1"
        exit 1
        ;;
    esac
    shift
done

if [ "$skip_update" = false ]; then
    update_cattools
fi

# Setup
setip() {
    DEFAULT_IP="192.168.1.4"
    while true; do
        read -p "Please enter the IP Addr and press Enter /// 请输入 IP (默认为 $DEFAULT_IP): " input_ip
        if [ -z "$input_ip" ]; then
            input_ip=$DEFAULT_IP
        fi

        if echo "$input_ip" | grep -Eo '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' >/dev/null; then
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

configure_network_interfaces() {
        local interfaces="$1"
        bridge_ports=""

        for iface in $interfaces; do
            if [ "$iface" != "eth0" ]; then
                bridge_ports="$bridge_ports $iface"
            fi
        done

        uci set network.wan.ifname='eth0'
        uci set network.wan.proto='dhcp'
        uci set network.lan.type='bridge'
        uci set network.lan.ifname="$bridge_ports"
        uci set network.lan._orig_ifname="$bridge_ports"
        uci set network.lan._orig_bridge='true'
        uci set network.wan6._orig_bridge='false'
        uci set network.wan6._orig_ifname='eth1'
        uci set network.wan6.ifname='eth0'
        uci set network.wan6.reqaddress='try'
        uci set network.wan6.reqprefix='auto'

        echo "[Step10] Network interfaces configured: WAN (ETH0), LAN ($bridge_ports) /// 网口已配置: WAN (ETH0), LAN ($bridge_ports)"
}

# Network Wizard
network_wizard() {
    echo
    echo
    echo
    read -p "[Step1] Do you want Network Wizard? /// 是否使用网络向导？([Enter] 确认 / [0] 退出): " use_wizard
    if [ "$use_wizard" == "0" ]; then
        echo "网络向导已退出。"
        return
    fi

    interfaces=$(ls /sys/class/net | grep -E 'eth[0-9]+')
    iface_count=$(echo "$interfaces" | wc -w)

    if [ "$iface_count" -eq 1 ]; then
        echo
        echo "[Step2] Detected a single network interface /// 检测到单个网口"
        echo
        echo "Setup a Bypass Gateway            [Enter] "
        echo "Skip setup Bypass Gateway        [0]"
        read -p "是否进行旁路网关设置？([Enter] 确认 / [0] 跳过旁路设置)：" choice
        if [ "$choice" != "0" ]; then
            bypass_gateway
            return
        fi
    fi

    echo
    echo "[Step3] CatWrt default IP is 192.168.1.4 /// 默认 CatWrt IP 为 192.168.1.4"
    read -p "是否修改 IP 地址？([Enter] 保持默认 / [0] 自定义): " modify_ip
    if [ "$modify_ip" == "0" ]; then
        echo
        read -p "请输入 IP (默认为 $DEFAULT_IP): " input_ip
        if [[ -z $input_ip ]]; then
            input_ip=$DEFAULT_IP
        elif ! [[ $input_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "[ERROR] Invalid IP address"
            echo "[ERROR] 无效的 IP 地址。"
            return
        fi

        uci set network.lan.ipaddr=$input_ip
        echo "[INFO] IP 地址已设置为: $input_ip"
    else
        echo "[INFO] 保持默认 IP 地址：$DEFAULT_IP"
    fi

    echo
    echo "[Step4] IPv6 is enabled by default /// IPv6 默认是开启的"
    read -p "是否禁用 IPv6 网络？([Enter] 跳过 / [1] 禁用): " disable_ipv6
    if [ "$disable_ipv6" == "1" ]; then
        uci delete dhcp.lan.dhcpv6
        uci delete dhcp.lan.ra
        uci delete dhcp.lan.ra_management
        uci delete network.lan.ip6assign
        echo "[INFO] IPv6 已禁用"
    fi

    echo
    echo "[Step5] Default connection mode is DHCP /// 默认模式为 DHCP"
    read -p "是否进行 PPPoE 拨号？([Enter] 继续 DHCP /  [1] PPPoE 拨号): " use_pppoe
    if [ "$use_pppoe" == "1" ]; then
        echo "如不知道账号密码，可以寻求宽带师傅，必须要正确填写!"
        read -p "[PPPoE] 请输入宽带账号: " username
        read -s -p "[PPPoE] 请输入宽带密码: " password
        uci set network.wan.proto=pppoe
        uci set network.wan.username=$username
        uci set network.wan.password=$password
        echo "[INFO] PPPoE 拨号配置已完成"
    fi
    
    echo
    echo "[Step6] Use recommended DNS servers 223.6.6.6 119.29.29.99?"
    read -p " /// 使用推荐的 DNS 服务器 223.6.6.6 119.29.29.99 吗？([Enter] 确认 / [0] 跳过): " use_dns
    if [ "$use_dns" = "0" ]; then
        exit 0
    elif [ -z "$use_dns" ]; then
        uci set network.lan.dns="223.6.6.6 119.29.29.99"
    else
        if [[ $use_dns =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\s+([0-9]{1,3}\.){3}[0-9]{1,3})*$ ]]; then
            uci set network.lan.dns="$use_dns"
        else
            echo "[ERROR] Invalid DNS format /// 无效的 DNS 格式"
            exit 1
        fi
    fi
    
    echo
    echo "[Step7] Do you want to change the DHCP IP pool range? (default: 30-200)"
    read -p " /// 是否修改 IP 可用段？(默认: 30-200 按 [Enter] 确认 / [1] 自定义范围 ): " dhcp_choice
    if [ "$dhcp_choice" = "1" ]; then
        echo
        read -p "Enter the DHCP IP pool range (e.g., 40-210) /// 输入 DHCP IP 地址范围 (例如: 40-210): " dhcp_range
        if [[ $dhcp_range =~ ^([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
            dhcp_start=$(echo $dhcp_range | cut -d '-' -f 1)
            dhcp_limit=$(echo $dhcp_range | cut -d '-' -f 2)
            uci set dhcp.lan.start=$dhcp_start
            uci set dhcp.lan.limit=$dhcp_limit
        else
            echo
            echo "[ERROR] Invalid DHCP range format /// 无效的 DHCP 范围格式"
            exit 1
        fi
    else
        uci set dhcp.lan.start=30
        uci set dhcp.lan.limit=200
    fi
    
    echo
    echo "[Step8] Enable DHCP force /// 开启 DHCP 强制可以避免局域网收到 AP 吐地址的问题"
    read -p "是否开启强制 DHCP 模式？([Enter] 确认，按 [1] 跳过): " force_dhcp
    if [ "$force_dhcp" != "1" ]; then
        uci set dhcp.lan.force=1
        echo "[INFO] 强制 DHCP 模式已开启"
    fi
    
    echo
    echo "[Step9] Enable UPNP by default /// 默认开启 UPNP，可提升 BT/P2P 软件连接性，但客户端容易受到流氓软件滥用 P2P 网络导致上行带宽异常!"
    read -p "是否开启 UPNP？([Enter] 确认，按 [1] 跳过): " enable_upnp
    if [ "$enable_upnp" != "1" ]; then
        uci set upnpd.config.enabled=1
        echo "[INFO] UPNP 已开启"
    fi
    arch=$(grep "arch" /etc/catwrt_release | cut -d'=' -f2)

    # BIND Interfaces
    if [ "$arch" = "amd64" ] || [ "$arch" = "aarch64_generic" ]; then
        echo
        echo "[Step10] Configure network interfaces /// 配置网口"
        echo ""
        echo " Wan    LAN1    LAN2    LANX      ..."
        echo " eth0   eth1    eth2    ethX    ..."
        echo "      □    □    □    □      ..."
        echo ""
        echo "Press [Enter] to skip network configuration, press [1] to configure /// 按 [Enter] 跳过网口配置，按 [1] 确认配置: "
        read -p "" configure_network
        echo

        interfaces=$(ls /sys/class/net | grep -E 'eth[0-9]+')
        iface_count=$(echo "$interfaces" | wc -w)

        if [ "$iface_count" -eq 1 ]; then
            echo "[Step10] Detected a single network interface, no configuration needed /// 检测到单个网口，无需配置"
        elif [ "$iface_count" -eq 2 ]; then
            echo "[Step10] Detected two network interfaces, configuration not recommended /// 检测到两个网口，不推荐配置"
            echo "Press [1] to configure, press [Enter] to skip /// 按 [1] 配置，按 [Enter] 跳过"
            read -p "" continue_network

            if [ "$continue_network" != "1" ]; then
                echo "[Step10] Skipping network interface configuration /// 跳过网口配置"
            else
                echo "[Step10] Configuring network interfaces... /// 开始配置网口..."
                configure_network_interfaces "$interfaces"
            fi
        else
            echo "[Step10] Detected multiple network interfaces /// 检测到多个网口"
            echo "[Step10] Configuring network interfaces... /// 开始配置网口..."
            configure_network_interfaces "$interfaces"
        fi
    else
        echo "[Step10] System architecture $arch is not supported. No changes made. /// 系统架构 $arch 不支持该脚本，未进行任何更改"
    fi
    echo
    echo "[INFO] Ready to reboot CatWrt!"
    set -x
    uci commit
    /etc/init.d/network restart
    /etc/init.d/dnsmasq restart
    /etc/init.d/firewall restart
    /etc/init.d/miniupnpd restart
    reboot
    set +x
}

# BypassGateway
bypass_gateway() {
    # 输入主路由的 IP 地址
    while true; do
        echo
        echo "Please enter the IP address of the primary router (eg: 192.168.31.1):"
        read -p "[Step3] 请输入主路由的 IP 地址 (如: 192.168.31.1): " router_ip
        if [ -z "$router_ip" ]; then
            echo "[ERROR] 主路由 IP 地址不能为空，请重新输入。"
        elif ! echo "$router_ip" | grep -Eq '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.'; then
            echo "[ERROR] 输入的 IP 地址无效，请输入有效的 IP 地址"
        else
            break
        fi
    done

    subnet=$(echo "$router_ip" | cut -d. -f1-3)
    echo
    echo "[INFO] Scanning ${subnet}.4 to ${subnet}.10, looking for unoccupied local IPs..." 
    echo "[INFO] 正在扫描 ${subnet}.4 到 ${subnet}.10，查找未被占用的本机 IP..."
    
    for i in $(seq 4 10); do
        candidate_ip="${subnet}.${i}"
        if ping -c 1 -W 1 "$candidate_ip" >/dev/null 2>&1; then
            echo "[INFO] $candidate_ip is already in use, try the next one..."
            echo "[INFO] $candidate_ip 已被占用，继续尝试下一个..."
        else
            default_device_ip="$candidate_ip"
            echo "[INFO] Found available IP addr:"
            echo "[INFO] 找到可用的 IP 地址：$default_device_ip"
            break
        fi
    done

    if [ -z "$default_device_ip" ]; then
        echo
        echo "No available IP address found, please specify manually."
        echo "[ERROR] 没有找到可用的 IP 地址，请手动指定。"
        read -p "[Step4] 请输入本机 IP 地址：" device_ip
    else
        while true; do
            echo
            read -p "[Step4] 建议使用本机 IP 地址为 $default_device_ip，按回车确认或输入新的 IP 地址：" device_ip
            if [ -z "$device_ip" ]; then
                device_ip="$default_device_ip"
                break
            elif ! echo "$device_ip" | grep -Eq '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.'; then
                echo
                echo "[ERROR] 输入的 IP 地址无效，请输入有效的 IP 地址。"
            else
                break
            fi
        done
    fi
    echo "INFO    ========================"
    echo "Primary router IP addr：$router_ip"
    echo "Local IP(Bypass Gateway)：$device_ip"
    echo "主路由 IP 地址：$router_ip"
    echo "本机(旁路网关) IP 地址：$device_ip"
    
    echo
    echo "[Step5] Use recommended DNS servers 223.6.6.6 223.5.5.5?"
    read -p " /// 使用推荐的 DNS 服务器 223.6.6.6 223.5.5.5 吗？([Enter] 确认 / [0] 跳过): " use_dns
    if [ "$use_dns" = "0" ]; then
        exit 0
    elif [ -z "$use_dns" ]; then
        uci set network.lan.dns="223.6.6.6 223.5.5.5"
    else
        if [[ $use_dns =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\s+([0-9]{1,3}\.){3}[0-9]{1,3})*$ ]]; then
            uci set network.lan.dns="$use_dns"
        else
            echo "[ERROR] Invalid DNS format /// 无效的 DNS 格式"
            exit 1
        fi
    fi

    set -x
    # Configure the network
    uci set network.lan.ipaddr="$device_ip"
    uci set network.lan.gateway="$router_ip"
    uci set network.lan.proto='static'
    uci commit network

    # Disable IPv6 server for LAN port
    uci set dhcp.lan.dhcpv6='disabled'
    uci set dhcp.lan.ra='disabled'
    uci commit dhcp

    # Disable the DHCP service of the LAN port and delete related configurations
    uci set dhcp.lan.ignore='1'
    uci delete dhcp.lan.leasetime
    uci delete dhcp.lan.limit
    uci delete dhcp.lan.start
    uci commit dhcp

    lan_ip=$(uci get network.lan.ipaddr)
    echo
    echo "Bypass gateway configuration completed!"
    echo "local IP: $lan_ip"
    echo "旁路网关配置完成 IP: $lan_ip "

    # Restart related services to apply the changes
    /etc/init.d/network restart
    /etc/init.d/firewall restart
    /etc/init.d/dnsmasq restart
    set +x

    echo
    echo "[INFO] 如出现 Warning 是因为旁路防火墙是这样报错的，部分配置可以忽略不影响使用"
    echo
}

# Debug
debug() {
    if [ -f /www/logs.txt ]; then
        rm /www/logs.txt
    fi

    cat /etc/banner >>/www/logs.txt
    date >>/www/logs.txt

    echo "## RELEASE" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    cat /etc/catwrt_release >>/www/logs.txt

    echo "## STATUS" >>/www/logs.txt
    echo "=================" >>/www/logs.txt
    eval $UPTIME >>/www/logs.txt

    echo "## Memory Usage" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    free -h >>/www/logs.txt

    echo "## Disk Usage" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    df -h >>/www/logs.txt

    echo "## Application" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    opkg list_installed >>/www/logs.txt

    echo "## SYSLOG" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    logread >>/www/logs.txt

    echo "## DMESG" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    dmesg >>/www/logs.txt

    echo "## Plugins" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    cat /tmp/openclash.log >>/www/logs.txt
    cat /tmp/log/ssrplus.log >>/www/logs.txt
    cat /tmp/log/passwall.log >>/www/logs.txt
    cat /tmp/log/passwall2.log >>/www/logs.txt

    echo "## Task" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    top -b -n 1 >>/www/logs.txt

    echo "## Network Configuration" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    ifconfig -a >>/www/logs.txt

    echo "## UCI Network" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    uci show network >>/www/logs.txt

    echo "## Firewall" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    iptables -L -v -n >>/www/logs.txt
    ip6tables -L -v -n >>/www/logs.txt

    echo "## Routing Table" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    ip route >>/www/logs.txt
    ip -6 route >>/www/logs.txt

    lan_ip=$(uci get network.lan.ipaddr)

    echo
    echo "Finish!    ==========================================================================================="
    echo "请使用浏览器访问此地址下载 LOG 文件  http://$lan_ip/logs.txt"
    echo "日志已收集到 /www/logs.txt 如果你使用 PPPoE 拨号请手动将宽带账密删除，再使用以下链接上传 Github issues 附件!"
    echo
    echo "https://github.com/miaoermua/CatWrt/issues/new?assignees=&labels=bug&projects=&template=report.yaml"
    echo "尽可能使用 Github 提交你的问题不会操作再使用社交软件 TG Guoup: t.me/miaoergroup  //  QQ Guoup: 669190476"
    echo
    sleep 5
    exit
}

# catwrt_update
catwrt_update() {
source /etc/catwrt_release

api_data=$(curl -s $API_URL)

version_compare() {
    local v1_year=$(echo "$1" | cut -d'.' -f1 | sed 's/^v//')
    local v1_month=$(echo "$1" | cut -d'.' -f2)
    local v2_year=$(echo "$2" | cut -d'.' -f1 | sed 's/^v//')
    local v2_month=$(echo "$2" | cut -d'.' -f2)

    if [ "$v1_year" -gt "$v2_year" ]; then
        echo 1
    elif [ "$v1_year" -lt "$v2_year" ]; then
        echo -1
    else
        if [ "$v1_month" -gt "$v2_month" ]; then
            echo 1
        elif [ "$v1_month" -lt "$v2_month" ]; then
            echo -1
        else
            echo 0
        fi
    fi
}

check_update() {
        local current_version=$1
        local current_hash=$2
        local arch=$3
        local channel=$4

        echo
        echo "LOCAL  ================================================="
        echo "当前版本: $current_version"
        echo "当前架构: $arch"
        echo "当前通道: $channel"
        echo "========================================================"

        versions=$(echo "$api_data" | jq -r 'keys[]')

        latest_stable_version=""
        latest_beta_version=""
        stable_releases=""
        beta_releases=""
        stable_blogs=""
        beta_blogs=""

        for version in $versions; do
            version_data=$(echo "$api_data" | jq -r ".\"$version\".\"$arch\"")

            if [ "$version_data" != "null" ]; then
                api_channel=$(echo "$version_data" | jq -r ".channel")
                api_hash=$(echo "$version_data" | jq -r ".hash")
                api_latest=$(echo "$version_data" | jq -r ".latest")
                api_releases=$(echo "$version_data" | jq -r ".releases")
                api_blogs=$(echo "$version_data" | jq -r ".blogs")

                compare_result=$(version_compare "$version" "$current_version")

                if [ "$compare_result" -gt 0 ]; then
                    if [ "$channel" == "Beta" ]; then
                        if [ "$api_channel" == "Beta" ]; then
                            if [ -z "$latest_beta_version" ] || [ "$(version_compare "$version" "$latest_beta_version")" -gt 0 ]; then
                                latest_beta_version="$version"
                                beta_releases="$api_releases"
                                beta_blogs="$api_blogs"
                            fi
                        elif [ "$api_channel" == "Stable" ]; then
                            if [ -z "$latest_stable_version" ] || [ "$(version_compare "$version" "$latest_stable_version")" -gt 0 ]; then
                                latest_stable_version="$version"
                                stable_releases="$api_releases"
                                stable_blogs="$api_blogs"
                            fi
                        fi
                    elif [ "$channel" == "Stable" ] && [ "$api_channel" == "Stable" ]; then
                        if [ -z "$latest_stable_version" ] || [ "$(version_compare "$version" "$latest_stable_version")" -gt 0 ]; then
                            latest_stable_version="$version"
                            stable_releases="$api_releases"
                            stable_blogs="$api_blogs"
                        fi
                    fi
                fi
            fi
        done

        if [ -n "$latest_stable_version" ] || [ -n "$latest_beta_version" ]; then
            if [ -n "$latest_stable_version" ]; then
                echo
                echo "UPDATE  ================================================"
                echo "发现新版本: $current_version > $latest_stable_version (Stable)"
                echo "版本: $stable_releases"
                echo "博客: $stable_blogs"
                echo "========================================================"
                echo
            fi

            if [ -n "$latest_beta_version" ]; then
                echo
                echo "UPDATE  ================================================"
                echo "发现新版本: $current_version > $latest_beta_version (Beta)"
                echo "版本: $beta_releases"
                echo "博客: $beta_blogs"
                echo "========================================================"

            fi

            echo
            echo "INFO  =================================================="
            echo "              New CatWrt updates found!"
            echo "              Preview blog to learn more."
            if [ -n "$stable_blogs" ]; then
                echo "      $stable_blogs"
            elif [ -n "$beta_blogs" ]; then
                echo "      $beta_blogs"
            fi
            echo "========================================================"
            sleep 1
        else
            echo
            echo "INFO  ================================================="
            echo "          Your CatWrt is latest version!"
            echo "======================================================="
            sleep 1
        fi
    }

    current_version=$(grep 'version' /etc/catwrt_release | cut -d'=' -f2)
    current_hash=$(grep 'hash' /etc/catwrt_release | cut -d'=' -f2)
    arch=$(grep 'arch' /etc/catwrt_release | cut -d'=' -f2)
    channel=$(echo "$api_data" | jq -r ".\"$current_version\".\"$arch\".channel")

    check_update $current_version $current_hash $arch $channel
}

# Apply_repo

apply_repo() {
    command -v jq >/dev/null 2>&1 || {
        echo "[ERROR] 需要安装 jq，你的版本太老了!"
        exit 1
    }

    arch=$(grep -o 'arch=[^ ]*' "$RELEASE" | cut -d= -f2)
    version=$(grep -o 'version=[^ ]*' "$RELEASE" | cut -d= -f2)

    json=$(curl -fsSL "https://api.miaoer.net/api/v2/snippets/catwrt/repo-config")
    if [ -z "$json" ]; then
        echo "[ERROR] 无法获取软件源配置，请检查网络或稍后重试。"
        exit 1
    fi

    REPO_URL=$(echo "$json" | jq -r --arg a "$arch" --arg v "$version" '.[$a][$v].url')
    IS_BETA=$(echo "$json" | jq -r --arg a "$arch" --arg v "$version" '.[$a][$v].beta')

    if [ -z "$REPO_URL" ] || [ "$REPO_URL" == "null" ]; then
        echo "[ERROR] 未找到 $arch $version 的软件源配置，请反馈给维护者。"
        exit 1
    fi

    echo ""
    echo "INFO    ================================================================="
    echo "软件源纯属免费分享，但你可以使用免费的境外软件源托管，如果你需要更快的速度请使用主站。"
    echo "本人不对所有软件进行保证，我们没有提供第三方商业服务，使用风险需要自行承担。"
    echo "你需要同意 CatWrt 软件源用户协议，请确认是否继续。 (10 秒内按 [Ctrl]+[C] 取消操作)"

    if [ "$IS_BETA" = "true" ]; then
        echo "你目前使用的 BETA 版本，只能拉取临时镜像站软件源，请注意关注 CatWrt 的更新情况，避免软件源失效!"
        echo "============================================================================"
        echo "请选择要使用的软件源:"
        echo "1) netlify"
        echo "2) vercel (默认)"
        read -t 10 -p "Please enter your choice /// 请输入选择 (1-2): " choice
        choice=${choice:-2}

        case $choice in
            1) conf_file="netlify.conf" ;;
            2) conf_file="vercel.conf" ;;
            *) conf_file="vercel.conf" ;;
        esac
    else
        echo "============================================================================"
        echo "请选择要使用的软件源:"
        echo "1) miaoer.net   (主站)"
        echo "2) Github-Pages"
        echo "3) Cloudflare-Netlify"
        echo "4) Netlify              (默认)"

        if [[ "$REPO_URL" == *"/history/"* ]]; then
            read -t 10 -p "Please enter your choice /// 请输入选择 (1-4): " choice
            choice=${choice:-4}
        else
            echo "5) Cloudflare-Vercel"
            echo "6) Vercel             (默认)"
            read -t 10 -p "Please enter your choice /// 请输入选择 (1-6): " choice
            choice=${choice:-6}
        fi

        case $choice in
            1)
                echo "以赞助我们并获取支持代码，请访问链接: https://www.miaoer.net/sponsor"
                echo "我们将使用用户支持的费用用于继续维护 CatWrt 及博客"
                read -p "请输入支持代码: " sponsor_code
                if [ "$sponsor_code" != "cat666" ]; then
                    echo "[ERROR] 支持代码无效，返回菜单选择其他软件源。"
                    apply_repo
                    return
                fi
                conf_file="distfeeds.conf"
                ;;
            2) conf_file="github.conf" ;;
            3) conf_file="cfnetlify.conf" ;;
            4) conf_file="netlify.conf" ;;
            5) conf_file="cfvercel.conf" ;;
            6) conf_file="vercel.conf" ;;
            *) conf_file="netlify.conf" ;;
        esac
    fi

    CONF_PATH="$REPO_URL/$conf_file"
    if curl --output /dev/null --silent --head --fail "$CONF_PATH"; then
        echo "[INFO] 获取 $CONF_PATH"
    else
        echo "[ERROR] repo conf: $CONF_PATH 不存在，请反馈。"
        exit 1
    fi

    curl -sL "$CONF_PATH" -o /etc/opkg/distfeeds.conf

    [ -f /var/lock/opkg.lock ] && rm /var/lock/opkg.lock
    [ -f /var/opkg-lists/istore_compat ] && rm /var/opkg-lists/istore_compat

    opkg update

    echo "[INFO] 软件源配置已完成，可以使用 opkg install <pkg> 来安装插件/组件/内核模块！"
}

# catnd

catnd() {
    echo "$(date) - Starting CatWrt Network Diagnostics"
    echo

    # Ping & PPPoE
    ping -c 3 223.5.5.5 >/dev/null
    if [ $? -eq 0 ]; then
        echo "[Ping] Network connection succeeded!"
        echo
    else
        ping -c 3 119.29.29.99 >/dev/null
        if [ $? -eq 0 ]; then
            echo "[Ping] Network connection succeeded,But there may be problems!"
            echo
        else
            pppoe_config=$(grep 'pppoe' /etc/config/network)
            if [ ! -z "$pppoe_config" ]; then
                echo "[PPPoE] Please check if your PPPoE account and password are correct."
                echo
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
            echo
            exit 1
        fi
    done

    # Bad DNS
    echo "[DNS] DNS configuration looks good!"
    echo

    bad_dns="114.114.114.114 114.114.115.115 119.29.29.29"
    if [[ $dns_config =~ $bad_dns ]]; then
        echo "[DNS] DNS may be polluted or unreliable"
        echo
    fi

    # nslookup
    nslookup bilibili.com >/dev/null
    if [ $? -ne 0 ]; then
        nslookup www.miaoer.net >/dev/null
        if [ $? -eq 0 ]; then
            echo "[DNS] DNS resolution succeeded"
            echo
        else
            echo "[DNS] NS resolution failed for 'www.miaoer.net'"
            echo "[DNS] Your DNS server may have issues"
            echo
        fi
    fi

    # Public IP
    echo CatWrt IPv4 Addr: $(curl --silent --connect-timeout 5 4.ipw.cn)
    echo

    curl 6.ipw.cn --connect-timeout 5 >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[IPv6] IPv6 network connection timed out"
        echo
    else
        echo CatWrt IPv6 Addr: $(curl --silent 6.ipw.cn)
        echo
    fi

    # IPv6
    resp=$(curl --silent test.ipw.cn)

    if echo "$resp" | grep -q -E '240e|2408|2409|2401'; then
        echo "[IPv6] IPv6 access is preferred"
        echo
    else
        echo "[IPv6] IPv4 access is preferred"
        echo
    fi

    # Default IP
    ipaddr_config=$(grep '192.168.1.4' /etc/config/network)

    if [ -z "$ipaddr_config" ]; then
        echo "[Default-IP] address is not the catwrt default 192.168.1.4"
        echo "Please configure your network at 'https://www.miaoer.net/posts/network/quickstart-catwrt'"
        echo
    fi

    # Bypass Gateway
    wan_config=$(grep 'config interface' /etc/config/network | grep 'wan')

    if [ -z "$wan_config" ]; then
        echo "[Bypass Gateway] No config for 'wan' interface found in /etc/config/network"
        echo "Please check if your device is set as a Bypass Gateway"
        echo
    fi

    # Rotuer Mode(PPPoE)
    pass_config=$(grep 'password' /etc/config/network)
    user_config=$(grep 'username' /etc/config/network)
    pppoe_config=$(grep 'pppoe' /etc/config/network)

    if [ -n "$pass_config" ] && [ -n "$user_config" ] && [ -n "$pppoe_config" ]; then
        echo "[PPPoE] PPPoE Rotuer Mode"
        echo
    else
        echo "[PPPoE] DHCP protocol detected in WAN interface"
        echo "The device may not be in PPPoE Rotuer Mode"
        echo
    fi

    # IPv6 WAN6
    grep 'config interface' /etc/config/network | grep 'wan6' >/dev/null
    if [ $? -ne 0 ]; then
        echo "[wan6] Your IPv6 network may have issues"
        echo
    fi

    grep 'dhcpv6' /etc/config/network >/dev/null
    if [ $? -ne 0 ]; then
        echo "[wan6] Your IPv6 network may have issues"
        echo
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

    echo
    echo "$(date) - Network check completed!"
    echo "CatWrt Network Diagnostics by @miaoermua"
}

# Sysupgrade

sysupgrade() {
    arch=$(cat /etc/catwrt_release | grep "^arch=" | cut -d'=' -f2)
    board_name=$(cat /tmp/sysinfo/board_name)
    
    # 检查架构
    if [ "$arch" != "mt7621" ] && [ "$arch" != "amd64" ] && [ "$arch" != "mt798x" ]; then
        echo "[Error] 不支持的架构: $arch"
        exit 1
    fi

    if [ "$arch" = "mt7621" ]; then
        case "$board_name" in
            *"newifi-d2")
                base_fw_url="sysup_newifi-d2"
                ;;
            *"redmi-router-ac2100")
                base_fw_url="sysup_redmi-router-ac2100"
                ;;
            *"mi-router-ac2100")
                base_fw_url="sysup_mi-router-ac2100"
                ;;
            *)
                echo "[Error] 该设备不支持通过此 Cattools 进行系统升级，请反馈给我们以支持!"
                exit 1
                ;;
        esac
        firmware_url="$mt7621_sysup$base_fw_url"
    fi

    if [ "$arch" = "amd64" ]; then
        echo

    main_disk=""
    for dev in /sys/block/*; do
        dev_name=$(basename "$dev")
        case "$dev_name" in
            sd*|vd*|nvme*)
                main_disk="$dev_name"
                break
                ;;
        esac
    done

    if [ -z "$main_disk" ]; then
        echo "[Error] 未找到有效磁盘设备 (sd*, vd*, nvme*)"
        exit 1
    fi
    disk_path="/dev/$main_disk"
    disk_size=$(fdisk -l "$disk_path" 2>/dev/null | grep "Disk $disk_path:" | awk '{print $3}')
    tolerance=16
    allowed_size=800.28
    min_size=$(echo "$allowed_size - $tolerance" | bc -l)
    max_size=$(echo "$allowed_size + $tolerance" | bc -l)
    
    if [ -z "$disk_size" ]; then
        echo "[Error] 无法获取磁盘大小（$disk_path）。"
        exit 1
    fi

    if (( $(echo "$disk_size < $min_size" | bc -l) )) || (( $(echo "$disk_size > $max_size" | bc -l) )); then
        echo "[Error] 磁盘空间已被修改分区，无法继续升级。"
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
    fi

    if [ "$arch" = "mt798x" ]; then
        case "$board_name" in
            *"redmi-router-ax6000")
                base_fw_url="sysup_redmi-router-ax6000"
                ;;
            *"tl-xdr6088")
                base_fw_url="sysup_tl-xdr6088"
                ;;
            *"tl-xdr4288")
                base_fw_url="sysup_tl-xdr4288"
                ;;
            *"tl-xdr6086")
                base_fw_url="sysup_tl-xdr6086"
                ;;
            *)
                echo "[Error] 该设备不支持通过此 Cattools 进行系统升级，请反馈给我们以支持!"
                exit 1
                ;;
        esac
        firmware_url="$mt798x_sysup$base_fw_url"
    fi

    if [ -f /etc/catwrt_opkg_list_installed ]; then
        rm /etc/catwrt_opkg_list_installed
    fi

    catwrt_update

    catwrt_opkg_list_installed
    echo "[INFO] 已经生成备份软件包列表，方便你后续更新后恢复部分消失的插件和软件"

    echo ""
    echo "Warning   ================================================================="
    echo "即将升级系统，存在不可恢复风险请输入 ([1] 确认/[2] 取消)，15s 后将默认继续升级!"
    echo "该功能通过 OpenWrt sysupgrade 升级系统，不保证 100% 升级成功，请三思!"
    echo ""
    echo "+ 升级系统会导致启用软件源安装的所有软件被新固件覆盖"
    echo "+ ROOT 账户的密码可能被还原为默认密码: (password)"
    echo "+ 升级过程中会保留插件配置和预装插件以获得升级"
    echo "+ 会抹除 opkg 或手动方式安装的插件，可以通过后续在软件源中获取!"
    echo "+ 该更新同样会下载最新版本，应当更新前使用 Cattools 中的 catwrt_update 检查更新"
    echo "==========================================================================="
    read -t 30 -p "确认升级系统 ([1] 确认/[2] 取消)? " confirm_upgrade
    if [ -z "$confirm_upgrade" ] || [ "$confirm_upgrade" = "1" ]; then
        read -t 5 -p "[INFO] 是否需要加速下载？按 ([1] 加速 5s 默认/[2] 跳过): " use_accel
        if [ -z "$use_accel" ] || [ "$use_accel" != "2" ]; then
            firmware_url="${firmware_url}_ghproxy"
        fi
        
        curl "$firmware_url" | bash
    else
        echo "[INFO] 升级取消。"
    fi
}

# catwrt_opkg_list_installed
catwrt_opkg_list_installed() {
    PACKAGES=(
        "luci-app-adbyby-plus"
        "luci-i18n-adbyby-plus-zh-cn"
        "luci-app-adblock"
        "luci-i18n-adblock-zh-cn"
        "luci-app-airplay2"
        "luci-i18n-airplay2-zh-cn"
        "luci-app-design-config"
        "luci-i18n-design-config-zh-cn"
        "luci-app-argon-config"
        "luci-app-cifs-mount"
        "luci-app-diskman"
        "luci-i18n-diskman-zh-cn"
        "luci-app-ddns-go"
        "luci-i18n-ddns-go-zh-cn"
        "luci-app-frpc"
        "luci-i18n-frpc-zh-cn"
        "luci-app-frps"
        "luci-i18n-frps-zh-cn"
        "luci-app-ipsec-server"
        "luci-i18n-ipsec-server-zh-cn"
        "luci-app-ipsec-vpnd"
        "luci-i18n-ipsec-vpnd-zh-cn"
        "luci-app-mwan3"
        "luci-i18n-mwan3-zh-cn"
        "luci-app-mwan3helper"
        "luci-i18n-mwan3helper-zh-cn"
        "luci-app-n2n"
        "luci-i18n-n2n-zh-cn"
        "luci-app-nps"
        "luci-i18n-nps-zh-cn"
        "luci-app-openvpn-server"
        "luci-i18n-openvpn-server-zh-cn"
        "luci-app-openvpn"
        "luci-i18n-openvpn-zh-cn"
        "luci-app-oaf"
        "luci-i18n-oaf-zh-cn"
        "luci-app-netdata"
        "luci-i18n-netdata-zh-cn"
        "luci-app-pppoe-relay"
        "luci-i18n-pppoe-relay-zh-cn"
        "luci-app-qbittorrent"
        "luci-i18n-qbittorrent-zh-cn"
        "luci-app-qos"
        "luci-i18n-qos-zh-cn"
        "luci-app-samba4"
        "luci-i18n-samba4-zh-cn"
        "luci-app-smartdns"
        "luci-i18n-smartdns-zh-cn"
        "luci-app-socat"
        "luci-i18n-socat-zh-cn"
        "luci-app-sqm"
        "luci-i18n-sqm-zh-cn"
        "luci-app-transmission"
        "luci-i18n-transmission-zh-cn"
        "luci-app-ttyd"
        "luci-i18n-ttyd-zh-cn"
        "luci-app-udpxy"
        "luci-i18n-udpxy-zh-cn"
        "luci-app-uhttpd"
        "luci-i18n-uhttpd-zh-cn"
        "luci-app-unblockmusic"
        "luci-i18n-unblockmusic-zh-cn"
        "luci-app-uugamebooster"
        "luci-i18n-uugamebooster-zh-cn"
        "luci-app-wireguard"
        "luci-i18n-wireguard-zh-cn"
        "luci-app-xlnetacc"
        "luci-i18n-xlnetacc-zh-cn"
        "luci-app-zerotier"
        "luci-i18n-zerotier-zh-cn"
        "luci-app-dockerman"
        "luci-app-usb-printer"
        "luci-i18n-usb-printer-zh-cn"
        "luci-i18n-dockerman-zh-cn"
        "luci-app-docker"
        "luci-i18n-docker-zh-cn"
        "luci-app-ssr-plus"
        "luci-i18n-ssr-plus-zh-cn"
        "luci-app-passwall"
        "luci-i18n-passwall-zh-cn"
        "luci-app-passwall2"
        "luci-i18n-passwall2-zh-cn"
        "luci-app-openclash"
        "luci-app-poweroff"
        "luci-app-passwall2"
        "luci-i18n-passwall2-zh-cn"
        "luci-app-LingTiGameAcc"
        "luci-app-usb3disable"
        "luci-app-pushbot"
        "luci-app-store"
        "luci-app-serverchan"
        "luci-app-nezha-agent"
        "luci-theme-design"
        "luci-app-design-config"
        "luci-theme-argon"
        "luci-app-argon-config"
        "luci-app-eqos"
        "lcui-app-alist"
        "luci-i18n-alist-zh-cn"
        "lcui-app-ddnsto"
        "luci-i18n-ddnsto-zh-cn"
        "node"
        "node-npm"
        "homebox"
        "msd_lite"
        "screen"
        "apk"
        "adb"
        "python3"
        "python3-speedtest-cli"
        "python3-requests"
        "speedtest-go"
        "ua2f"
        "vim"
        "nano"
        "nginx"
        "ethtool"
        "tailscale"
        "igmpproxy"
        "openssh-client"
        "openssh-keygen"
        "openssh-server"
        "openssh-sftp-server"
        "kmod-usb2"
        "kmod-usb3"
        "kmod-usb-net-ipheth"
        "libimobiledevice-utils"
        "usbmuxd"
        "kmod-usb-net-rndis"
        "kmod-nls-base"
        "kmod-usb-core"
        "kmod-usb-net"
        "kmod-usb-net-cdc-ether"
        "kmod-fs-nfs"
        "kmod-fs-nfs-common"
        "kmod-fs-nfs-common-rpcsec"
        "kmod-fs-nfs-v4"
        "kmod-fs-nfsd"
        "amd64-microcode"
    )

    if ! grep -q -E "catwrt|raw.miaoer.net|raw-us.miaoer.net" /etc/opkg/distfeeds.conf  && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "[Error] 请先配置软件源"
        apply_repo
    fi

    backup_installed_packages() {
        echo "[INFO] 正在备份名单中已安装软件包列表..."
        >"$BACKUP_FILE"
        for package in "${PACKAGES[@]}"; do
            if opkg list_installed | grep -q "^$package "; then
                echo "$package" >>"$BACKUP_FILE"
            fi
        done

        if ! grep -Fxq "/etc/catwrt_opkg_list_installed" "/etc/sysupgrade.conf"; then
            echo "/etc/catwrt_opkg_list_installed" >> "/etc/sysupgrade.conf"
        fi

        echo "[INFO] 备份完成，现在升级也不怕啦~"
    }

    restore_installed_packages() {
        opkg list_installed | awk '{print \$1}' >/tmp/default_installed_packages
        if [ -f "$BACKUP_FILE" ]; then
            while IFS= read -r package; do
                if grep -q "^$package$" "$DEFAULT_PACKAGES_FILE"; then
                    echo "跳过固件默认包含的软件包: $package"
                    continue
                fi
                if ! opkg list_installed | grep -q "^$package "; then
                    echo "安装固件默认缺失的软件包: $package"
                    opkg install "$package"
                fi
            done <"$BACKUP_FILE"
            echo "[INFO] 安装完成"
        else
            echo "[Error] 未检测到备份文件!寄了!"
        fi
    }

    main() {
        if [ -f "$BACKUP_FILE" ]; then
            echo "Sponsor us    ======================================================"
            echo "你执行的下面命令如果使用的主站软件源将对服务器带宽带来挑战"
            echo "我们希望你在使用后继续支持我们，继续为您提供更好的服务"
            echo "如果不想支持我们也可以使用免费无服务器提供的镜像，请选择非主站"
            echo "不会对我们服务器造成流量激增，但访问速度受限于国际互联网"
            echo ""
            echo "https://www.miaoer.net/sponsor"
            echo ""
            echo "当然，你可以复制下链接在浏览器上挂起，待恢复软件包后再进行支付!"
            echo "===================================================================="

            sleep 3

            echo ""
            read -p "检测到备份文件，是否需要恢复软件包？ ([ENTER] 确认/[0] 取消):" choice
            case "$choice" in
            0)
                echo "[INFO] 你选择了不恢复，打算重新开始!如果你有需要请回来找我!"
                ;;
            *)
                restore_installed_packages
                ;;
            esac
        else
            backup_installed_packages
        fi

        rm -f /tmp/default_installed_packages
    }
    main
}

# Utilities MENU
utilities_menu() {
    echo ""
    echo "      从这里配置更多功能!"
    echo "============================="
    echo ""
    echo "1.    Mihomo 配置"
    echo "2.    Tailscale 配置"
    echo "3.    LeigodAcc 配置"
    echo "4.    TTYD 免密配置(危险)"
    echo "5.    导入 IPK 软件包"
    echo "6.    SSL/TLS 证书上传配置"
    echo "7.    重置 root 密码"
    echo "8.    重置系统"
    echo ""
    echo "0.    返回 Cattools 主菜单"
    echo
    read -p "请输入数字并回车(Please enter your choice): " choice
    case $choice in
    1) configure_luci_mihomo ;;
    2) configure_tailscale ;;
    3) configure_leigodacc ;;
    4) configure_ttyd ;;
    5) install_ipk ;;
    6) manual_deploy_uhttpd_ssl_cert ;;
    7) reset_root_password ;;
    8) openwrt_firstboot ;;
    0) menu ;;
    *) echo "[ERROR] 无效选项，请重试" && utilities_menu ;;
    esac
}

configure_luci_mihomo() {
    echo ""
    echo "Warning    =============================================================="
    echo ""
    echo "我站不提供服务器，该功能只是补全 Mihomo 的内核，仅此而已所有结果由用户自行承担!"
    echo "你需要阅读并同意以上协议并自行承担配置后的一切后果，如不同意请 [CTRL]+[C] 中断该功能"
    echo "========================================================================="
    sleep 2

    if [ ! -f "$RELEASE" ]; then
        echo "[ERROR] 找不到 RELEASE 文件: $RELEASE"
        exit 1
    fi

    . "$RELEASE"

    case "$arch" in
        "mt7621")
            arch="mipsle-hardfloat"
            ;;
        "amd64")
            arch="amd64"
            ;;
        "mt798x"|"rock64"|"rkarm64"|"mt7986")
            arch="arm64"
            ;;
        *)
            echo "[ERROR] 不支持的架构: $arch"
            exit 1
            ;;
    esac

    if ! opkg list_installed | grep -q luci-app-openclash; then
        echo "[INFO] luci-app-openclash 未安装，正在安装..."
        opkg update
        opkg install luci-app-openclash
    fi

    local core_name="clash_meta"
    local dest_dir="/etc/openclash/core"
    local temp_file
    temp_file=$(mktemp)
    local success=0
    local failed_urls=()

    local urls=(
        "https://raw.githubusercontent.com/vernesong/OpenClash/core/master/meta/clash-linux-${arch}.tar.gz"
        "https://cdn.jsdelivr.net/gh/vernesong/OpenClash@core/master/meta/clash-linux-${arch}.tar.gz"
        "https://fastly.jsdelivr.net/gh/vernesong/OpenClash@core/master/meta/clash-linux-${arch}.tar.gz"
        "https://gh-proxy.com/github.com/vernesong/OpenClash/raw/core/master/meta/clash-linux-${arch}.tar.gz"
        "https://ghfast.top/github.com/vernesong/OpenClash/raw/core/master/meta/clash-linux-${arch}.tar.gz"
    )

    echo ""
    echo "即将开始下载 Mihomo 内核（架构: $arch）..."
    echo "正在尝试下载 Mihomo 内核: $core_name ($arch)"

    for url in "${urls[@]}"; do
        echo "尝试下载: $url"
        if curl --silent --connect-timeout 5 --max-time 10 -L -o "$temp_file" "$url"; then
            if tar -tzf "$temp_file" &>/dev/null; then
                mkdir -p "$dest_dir"
                tar -xz -C "$dest_dir" -f "$temp_file"
                mv "$dest_dir/clash" "$dest_dir/$core_name"
                rm -f "$temp_file"
                echo "[SUCCESS] 下载成功: $url"
                success=1
                break
            else
                echo "[ERROR] 无效的压缩文件: $url"
                failed_urls+=("$url")
            fi
        else
            echo "[ERROR] 下载失败: $url"
            failed_urls+=("$url")
        fi
    done

    if [ $success -ne 1 ]; then
        rm -f "$temp_file"
        echo "[ERROR] 所有下载链接均失效，请检查网络或稍后再试。"
        exit 1
    fi

    echo "[INFO] Mihomo 内核下载完成"
}


configure_tailscale() {
    if ! grep -q -E "catwrt|raw.miaoer.net|raw-us.miaoer.net" /etc/opkg/distfeeds.conf  && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]\.[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "[ERROR] 请先配置 CatWrt 软件源"
        apply_repo
    fi

    if ! opkg list-installed | grep -q "tailscale "; then
        echo "[INFO] 正在安装 tailscale 和 tailscaled 软件包..."
        opkg update
        opkg install tailscale
        if [ $? -ne 0 ]; then
            echo "[ERROR] 安装 tailscale 失败，可能是你的设备当前版本并不支持 tailscale"
            menu
            return
        fi
    else
        echo "[INFO] tailscale 已安装"
    fi
    
    br_lan_ip=$(ip -o -f inet addr show br-lan | awk '{print $4}')
    if [ -z "$br_lan_ip" ]; then
        echo "[ERROR] 无法获取 br-lan 接口的子网。"
        menu
        return
    fi
    IFS='/' read -r ip mask <<< "$br_lan_ip"
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    subnet="$i1.$i2.$i3.0/$mask"

    echo "[INFO] 下载配置..."
    curl -fsSL https://raw.miaoer.net/cattools/configure/tailscale.sh -o /tmp/tailscale.sh
    if [ $? -ne 0 ]; then
        echo "[ERROR] 下载配置失败..."
        menu
        return
    fi

    sed -i "s|--advertise-routes=.*|--advertise-routes=$subnet --accept-routes --advertise-exit-node|" /tmp/tailscale.sh

    echo "[INFO] 开始配置 tailscale，请登录 tailscale 绑定设备"
    chmod +x /tmp/tailscale.sh && sh /tmp/tailscale.sh

    firewall_file="/etc/firewall.user"
    rules=("iptables -I FORWARD -i tailscale0 -j ACCEPT"
           "iptables -I FORWARD -o tailscale0 -j ACCEPT"
           "iptables -t nat -I POSTROUTING -o tailscale0 -j MASQUERADE")

    for rule in "${rules[@]}"; do
        if ! grep -q "^$rule$" $firewall_file; then
            echo $rule >>$firewall_file
        fi
    done

    rm /tmp/tailscale.sh
    lan_ip=$(uci get network.lan.ipaddr)

    echo "Tailscale 配置部分，剩下的交给你了~"
    echo "[INFO] 需要绑定 tailscale 接口: http://$lan_ip/cgi-bin/luci/admin/network/iface_add"
    echo "[INFO] CatTools - tailscale 配置博客: https://www.miaoer.net/posts/blog/cattools-step"
    sleep 5
}

configure_leigodacc() {
    if [ -d /usr/sbin/leigod ]; then
        echo "[INFO] 检测到已经安装 LeigodAcc，直接使用 LeigodAcc 管理器"
        sh -c "$(curl -fsSL https://raw.miaoer.net/openwrt-leigodacc-manager/leigod.sh)"
        return
    fi

    if [ -f /etc/catwrt_release ]; then
        if ! grep -q -E "catwrt|raw.miaoer.net|raw-us.miaoer.net" /etc/opkg/distfeeds.conf  && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
            echo "[ERROR] 请先配置 CatWrt 软件源"
            apply_repo
        fi
    fi
    
    if [ -f /var/lock/opkg.lock ]; then
        rm /var/lock/opkg.lock
    fi
    
    opkg update

    for pkg in libpcap iptables kmod-ipt-nat iptables-mod-tproxy ipset; do
        if ! opkg list_installed | grep -q "$pkg"; then
            echo "[INFO] 正在安装必备组件 $pkg"
            opkg install $pkg
        else
            echo "[INFO] $pkg 必备组件已安装，跳过"
        fi
    done

    for pkg in kmod-tun kmod-ipt-tproxy kmod-netem tc-full kmod-ipt-ipset conntrack; do
        if ! opkg list_installed | grep -q "$pkg"; then
            echo "[INFO] 尝试安装 $pkg"
            opkg install $pkg
        else
            echo "[INFO] $pkg 已安装，跳过"
        fi
    done

    echo "[INFO] 下面是雷神提供的脚本,打印内容偏长如遇到问题请提供输出内容(截图/文字)反馈到群里."
    
    sh -c "$(curl -fsSL http://119.3.40.126/router_plugin/plugin_install.sh)"

    if [ ! -d /usr/sbin/leigod ]; then
        echo "[ERROR] 检测到 LeigodAcc 未安装，有可能是设备存储空间已满!"
    else
        echo "[INFO] LeigodAcc 已成功安装"
    fi

    for pkg in kmod-tun kmod-ipt-tproxy kmod-netem tc-full kmod-ipt-ipset conntrack curl libpcap iptables kmod-ipt-nat iptables-mod-tproxy ipset; do
        if ! opkg list_installed | grep -q "$pkg"; then
            echo "[INFO] 缺少组件包: $pkg"
            echo "[INFO] 你可以通过管理器中的安装依赖性组件进行补充!"
        fi
    done

    sh -c "$(curl -fsSL https://raw.miaoer.net/openwrt-leigodacc-manager/leigod.sh)"
}

install_ipk() {
    echo
    echo "[INFO] 检测 /tmp/upload/ 目录中的 IPK 文件..."
    lan_ip=$(uci get network.lan.ipaddr)
    echo "[INFO] 文件上传访问链接: http://$lan_ip/cgi-bin/luci/admin/system/filetransfer"
    ipk_files=$(ls /tmp/upload/*.ipk 2>/dev/null)

    if [ -n "$ipk_files" ]; then
        echo "[INFO] 检测到以下 IPK 文件已上传到 /tmp/upload/:"
        echo "$ipk_files"
        echo
        echo "请选择操作: "
        echo "1. 立即安装"
        echo "2. 保留，稍后安装"
        echo "3. 移除文件"
        read -p "请输入选项 (1/2/3): " choice

        case $choice in
            1)
                echo "[INFO] 正在安装 IPK 文件..."
                install_ipk_files "$ipk_files"
                ;;
            2)
                echo "[INFO] 已选择稍后安装，请继续上传其他 IPK 文件"
                return
                ;;
            3)
                echo "[INFO] 移除 IPK 文件..."
                rm -f /tmp/upload/*.ipk
                echo "[INFO] 已移除所有 IPK 文件"
                install_ipk
                return
                ;;
            *)
                echo "[ERROR] 无效选项"
                return
                ;;
        esac
    else
        echo "[INFO] 你可以通过 IPK 文件/URL 导入 IPK 文件安装"
        read -p "请通过文件上传导入 IPK 文件，或多个 URL 在线下载(用英文逗号 ',' 分隔不能使用中文逗号'，'分割!): " input

        if [[ -z "$input" ]]; then
            echo "[INFO] 没有输入 URL，等待上传 IPK 文件..."
            sleep 5
            ipk_files=$(ls /tmp/upload/*.ipk 2>/dev/null)

            if [ -n "$ipk_files" ]; then
                echo "[INFO] 检测到本地文件: $ipk_files"
                install_ipk_manager "$ipk_files"
            else
                echo "[ERROR] 未检测到任何 IPK 文件，请重新尝试"
            fi
        else
            if [[ -f "$input" ]]; then
                echo "[INFO] 检测到本地文件: $input"
                install_ipk_manager "$input"
            else
                urls=$(echo "$input" | tr ',' ' ')
                echo "[INFO] 检测到多个 URL: $urls"
                echo

                for url in $urls; do
                    filename=$(basename "$url")

                    if [[ "$filename" == *kmod* ]]; then
                        echo "[Warn] 文件名包含 kmod 内核组件，如果不是 CatWrt 源下的可能会出现兼容性问题无法安装: $filename"
                    fi

                    echo "[INFO] 正在下载: $url"
                    wget -P /tmp/upload/ "$url"
                done

                ipk_files=$(ls /tmp/upload/*.ipk 2>/dev/null)
                if [ -n "$ipk_files" ]; then
                    install_ipk_manager "$ipk_files"
                else
                    echo "[ERROR] 无法下载任何 IPK 文件，请检查 URL 是否可以访问并下载"
                fi
            fi
        fi
    fi
}

install_ipk_manager() {
    files="$1"

    echo "[INFO] 安装前需要更新索引文件，获取在线软件源避免安装错误解决依赖问题"
    echo "1. 确认（执行 apply_repo 配置软件源并 opkg update）"
    echo "0. 尝试（仅 opkg update）"
    read -p "请输入选项 (1/0): " confirm_net

    if [ "$confirm_net" == "1" ]; then
        echo "[INFO] 正在配置软件源并更新软件包索引..."
        apply_repo
    elif [ "$confirm_net" == "0" ]; then
        echo "[INFO] 尝试仅更新软件包索引..."
        opkg update
    else
        echo "[ERROR] 无效选择"
        return
    fi

    for file in $files; do
        echo "[INFO] 安装 IPK 文件: $file"
        opkg install "$file" || echo "[ERROR] 安装 $file 时出错，请检查!"
    done
}


# TTYD (NOT SAFETY)
configure_ttyd() {
    if ! opkg list_installed | grep -q "luci-app-ttyd" || ! opkg list_installed | grep -q "ttyd"; then
        echo "[ERROR] 未安装 luci-app-ttyd 或 ttyd 软件包，请配置软件源并安装这些软件包"
        apply_repo
    fi



    echo ""
    echo "Warning    =============================================================="
    echo "此操作将修改 TTYD 的配置以自动登录 root 用户，而且不需要密码，仅适用于调试阶段。"
    echo "这存在被远程执行的安全风险!仅适用于方便未放行端口时的调试，使用后请务必回到此处配置禁用。"
    echo "你确定要继续吗？ ([1] 确认/[2] 取消)"
    read -r confirmation
    if [ "$confirmation" != "1" ]; then
        echo "操作取消"
        menu
        return
    fi

    echo ""
    echo "你阅读了此警告吗这非常主要!请务必使用此功能完成后将其禁用，以避免遭受远程执行命令!"
    echo "禁用只需要在 Cattools 里面再选一次 TTYD 配置就可以完成禁用，这是我们的承诺哦!"
    echo "你确定要继续吗？ ([1] 确认/[2] 取消)"
    read -r second_confirmation
    if [ "$second_confirmation" != "1" ]; then
        echo "[INFO] 操作取消"
        menu
        return
    fi

    if grep -q "option command '/bin/login -f root'" /etc/config/ttyd; then
        sed -i "s/option command '\/bin\/login -f root'/option command '\/bin\/login'/" /etc/config/ttyd
        /etc/init.d/ttyd restart
        echo ""
        echo "[INFO] TTYD 配置已还原为默认配置"
    else
        sed -i "s/option command '\/bin\/login'/option command '\/bin\/login -f root'/" /etc/config/ttyd
        /etc/init.d/ttyd restart
        echo ""
        echo "[INFO] TTYD 配置已修改为自动登录 root"
        lan_ip=$(uci get network.lan.ipaddr)
        echo "[INFO] TTYD 访问链接  http://$lan_ip:7681"
    fi

    menu
}

# Manual upload SSL/TLS
manual_deploy_uhttpd_ssl_cert() {
    if ! grep -q -E "catwrt|raw.miaoer.net|raw-us.miaoer.net" /etc/opkg/distfeeds.conf  && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]+\.[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "[ERROR] 请先配置 CatWrt 软件源"
        apply_repo
    fi

    if ! grep -q "option cert '/etc/uhttpd.crt'" /etc/config/uhttpd || ! grep -q "option key '/etc/uhttpd.key'" /etc/config/uhttpd; then
        echo "[ERROR] uhttpd 配置文件中的证书或密钥路径已被修改，无法继续执行!"
        echo "[ERROR] 请检查 /etc/config/uhttpd"
        menu
        return
    fi

    if ! grep -q "list listen_http '0.0.0.0:80'" /etc/config/uhttpd ||
        ! grep -q "list listen_http '\[::\]:80'" /etc/config/uhttpd ||
        ! grep -q "list listen_https '0.0.0.0:443'" /etc/config/uhttpd ||
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
    echo "INFO    ================================================================"
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
        echo "[ERROR] 检测到多个 zip 文件，请只上传一个 zip 文件"
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
    echo "Warning    =============================================================="
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

    echo "你还需要 'yes' 一次就开始 reset system"
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
    echo "Warning    =============================================================="
    echo "root 用户密码已重置为 password"
    echo "请在终端中输入 passwd 修改密码，或者在 系统-管理权 中修改"
    echo "长期使用默认密码(弱密码)极易遭受远程指令攻击，后果严重"
    exit
}

patch_banner_domains()
{
    if grep -q "Blog: miaoer\.xyz" "/etc/banner"; then
        echo "+ patch : miaoer.xyz > miaoer.net"
        sed -i 's/Blog: miaoer\.xyz/Blog: miaoer.net/g' "/etc/banner"
    fi
}


patch_catwrt_release() {
    if [ -f $RELEASE ]; then
        if ! grep -q "source=lean" $RELEASE; then
            if grep -q "version=v23.7" $RELEASE && grep -q "arch=amd64" $RELEASE; then
                echo "source=lean" >>$RELEASE
                echo "+ patch : release files x86_64 v23.7"
            elif grep -q "version=v23.8" $RELEASE && grep -q "arch=amd64" $RELEASE; then
                echo "source=lean" >>$RELEASE
                echo "+ patch : release files x86_64 v23.8"
            elif grep -q "version=v23.8" $RELEASE && grep -q "arch=mt798x" $RELEASE; then
                echo "source=lean" >>$RELEASE
                echo "+ patch : release files aarch64 v23.8"
            fi
        fi
    else
        if [ "$(uname -m)" == "mips" ] || [ "$(uname -m)" == "mipsel" ] && grep -q "R22.12.1" /etc/openwrt_release && grep -q "miaoer.xyz" /etc/banner; then
            echo "version=v22.12" >$RELEASE
            echo "arch=mt7621" >>$RELEASE
            echo "source=lean" >>$RELEASE
            echo "hash=a1682a48834efdc6c5e2c3c62921b3195d306c8c" >>$RELEASE
            echo "The patch file has been installed!"
        elif [ "$(uname -m)" == "aarch64" ] && grep -q "R22.12.1" /etc/openwrt_release && grep -q "miaoer.xyz" /etc/banner; then
            echo "version=v22.12" >$RELEASE
            echo "arch=rkarm" >>$RELEASE
            echo "source=lean" >>$RELEASE
            echo "hash=3fd4930e781e40e3f85e2c6c082d6fcdd544e9ce" >>$RELEASE
            echo "The patch file has been installed!"
        elif [ "$(uname -m)" == "x86_64" ] && grep -q "R23.2" /etc/openwrt_release && grep -q "miaoer.xyz" /etc/banner; then
            echo "version=v23.2" >$RELEASE
            echo "arch=amd64" >>$RELEASE
            echo "source=lean" >>$RELEASE
            echo "hash=0239fab82eb640b55d4f4050cbc227ffd22087f3" >>$RELEASE
            echo "The patch file has been installed!"
        elif [ "$(uname -m)" == "aarch64" ] && grep -q "R23.2.14" /etc/openwrt_release && grep -q "miaoer.xyz" /etc/banner && grep -q "mt7986a" /etc/banner; then
            echo "version=v23.2" >$RELEASE
            echo "arch=mt798x" >>$RELEASE
            echo "source=lean" >>$RELEASE
            echo "hash=5e4da39a20e95ff548c3eca1b8c3a2b76c4256d5" >>$RELEASE
            echo "The patch file has been installed!"
        elif [ "$(uname -m)" == "x86_64" ] && grep -q "R22.11.11" /etc/openwrt_release && grep -q "miaoer.xyz" /etc/banner; then
            echo "version=v22.12" >$RELEASE
            echo "arch=amd64" >>$RELEASE
            echo "source=lean" >>$RELEASE
            echo "hash=4d6877d960c5c3bdc01b8e47679d923b475bea82" >>$RELEASE
            echo "The patch file has been installed!"
        fi
    fi
}

patch_catwrt_release
patch_banner_domains

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
        apply_repo
        ;;
    4)
        catnd
        ;;
    5)
        debug
        ;;
    6)
        catwrt_update
        ;;
    7)
        sysupgrade
        ;;
    8)
        catwrt_opkg_list_installed
        ;;
    9)
        utilities_menu
        ;;
    0)
        echo "Exiting..."
        break
        ;;
    *)
        echo "Invalid choice, please try again /// 错误的数字请重试,[ENTER] 回车后重新输入"
        read -p "Press [Enter] key to continue..."
        ;;
    esac
done

echo "Done!"
