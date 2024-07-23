#!/bin/bash
# env
DEFAULT_IP="192.168.1.4"
RELEASE="/etc/catwrt_release"
BACKUP_FILE="/etc/catwrt_opkg_list_installed"
API_URL="https://api.miaoer.xyz/api/v2/snippets/catwrt/update"
BASE_URL="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo"
AMD64_EFI_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_efi"
AMD64_BIOS_SYSUP="https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_bios"

# Check ROOT & OpenWrt
if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root user"
    exit 1
fi

openwrt_release=$(cat /etc/openwrt_release)
if ! grep -q "OpenWrt" <<<"$openwrt_release"; then
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

# Network Wizard
network_wizard() {
    read -p "Do you want Network Wizard? /// 是否使用网络向导？([Enter] 确认 / [0] 退出): " use_wizard
    if [ "$use_wizard" == "0" ]; then
        echo "网络向导已退出。"
        return
    fi

    interfaces=$(ls /sys/class/net | grep -E 'eth[0-9]+')
    iface_count=$(echo "$interfaces" | wc -w)

    if [ "$iface_count" -eq 1 ]; then
        echo "Detected a single network interface /// 检测到单个网口"
        read -p "是否进行旁路网关设置？([Enter] 确认 / [0] 跳过旁路设置)：" choice
        if [ "$choice" != "0" ]; then
            bypass_gateway
            return
        fi
    fi

    echo "CatWrt default IP is 192.168.1.4 /// 默认 CatWrt IP 为 192.168.1.4"
    read -p "是否修改 IP 地址？([Enter] 保持默认 / [0] 自定义): " modify_ip
    if [ "$modify_ip" != "0" ]; then
        read -p "请输入 IP (默认为 $DEFAULT_IP): " input_ip
        if [[ -z $input_ip ]]; then
            input_ip=$DEFAULT_IP
        elif ! [[ $input_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "无效的 IP 地址。"
            return
        fi

        uci set network.lan.ipaddr=$input_ip
        echo "IP 地址已设置为 $input_ip"
    fi

    echo "IPv6 is enabled by default /// IPv6 默认是开启的"
    read -p "是否禁用 IPv6 网络？([Enter] 跳过 / [1] 禁用): " disable_ipv6
    if [ "$disable_ipv6" == "1" ]; then
        uci delete dhcp.lan.dhcpv6
        uci delete dhcp.lan.ra
        uci delete dhcp.lan.ra_management
        uci delete network.lan.ip6assign
        echo "IPv6 已禁用"
    fi

    echo "Default connection mode is DHCP /// 默认模式为 DHCP"
    read -p "是否进行 PPPoE 拨号？([Enter] 继续 DHCP /  [1] PPPoE 拨号): " use_pppoe
    if [ "$use_pppoe" == "1" ]; then
        read -p "请输入宽带账号: " username
        read -s -p "请输入宽带密码: " password
        uci set network.wan.proto=pppoe
        uci set network.wan.username=$username
        uci set network.wan.password=$password
        echo "PPPoE 拨号配置已完成"
    fi

    echo "Use recommended DNS servers 223.6.6.6 119.29.29.99?"
    read -p " /// 使用推荐的 DNS 服务器 223.6.6.6 119.29.29.99 吗？([Enter] 确认 / [0] 跳过): " use_dns
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

    echo "Do you want to change the DHCP IP pool range? (default: 30-200)"
    read -p " /// 是否修改 IP 可用段？(默认: 30-200 按 [Enter] 确认 / [1] 自定义范围 ): " dhcp_choice
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
    read -p "是否开启强制 DHCP 模式？([Enter] 确认，按 [1] 跳过): " force_dhcp
    if [ "$force_dhcp" != "1" ]; then
        uci set dhcp.lan.force=1
        echo "强制 DHCP 模式已开启"
    fi

    echo "Enable UPNP by default /// 默认开启 UPNP，可提升 BT/P2P 软件连接性，但客户端容易受到流氓软件滥用 P2P 网络导致上行带宽异常!"
    read -p "是否开启 UPNP？([Enter] 确认，按 [1] 跳过): " enable_upnp
    if [ "$enable_upnp" != "1" ]; then
        uci set upnpd.config.enabled=1
        echo "UPNP 已开启"
    fi
    arch=$(grep "arch" /etc/catwrt_release | cut -d'=' -f2)

    # 仅在 x86 和 aarch64_generic 架构上进行网口绑定
    if [ "$arch" = "amd64" ] || [ "$arch" = "aarch64_generic" ]; then
        echo "Configure network interfaces /// 配置网口"
        echo ""
        echo " Wan    LAN1    LANx  ..."
        echo " eth0   eth1    ethx  ..."
        echo " □       □       □    ..."
        echo ""
        echo "Press [Enter] to configure network interfaces, press [1] to skip"
        read -p " /// [Enter] 确认配置网口，按 [1] 跳过: " configure_network
        if [ "$configure_network" != "1" ]; then
            # 获取所有网口列表
            interfaces=$(ls /sys/class/net | grep -E 'eth[0-9]+')
            iface_count=$(echo "$interfaces" | wc -w)

            if [ "$iface_count" -eq 1 ]; then
                echo "Detected a single network interface, no configuration needed /// 检测到单个网口，无需配置"
            else
                echo "Detected multiple network interfaces /// 检测到多个网口"
                # 默认桥接网口为 eth1，检测其他可用网口并添加到桥接列表
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

                echo "Network interfaces configured: WAN (eth0), LAN ($bridge_ports) /// 网口已配置: WAN (eth0), LAN ($bridge_ports)"
            fi
        else
            echo "Skipping network interface configuration /// 跳过网口配置"
        fi
    else
        echo "System architecture $arch is not supported. No changes made. /// 系统架构 $arch 不支持该脚本。未进行任何更改。"
    fi

    uci commit
    /etc/init.d/network restart
    /etc/init.d/dnsmasq restart
    /etc/init.d/firewall restart
    /etc/init.d/miniupnpd restart
}

# BypassGateway
bypass_gateway() {
    # 输入主路由的 IP 地址
    while true; do
        read -p "请输入主路由的 IP 地址（例如 192.168.31.1）：" router_ip
        if [ -z "$router_ip" ]; then
            echo "主路由 IP 地址不能为空，请重新输入。"
        elif ! echo "$router_ip" | grep -Eq '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.'; then
            echo "输入的 IP 地址无效，请输入有效的 IP 地址"
        else
            break
        fi
    done

    # 提取子网地址和设置本机 IP 地址
    subnet=$(echo "$router_ip" | cut -d. -f1-3)
    default_device_ip="${subnet}.4"

    while true; do
        read -p "本机 IP 地址为 $default_device_ip 按回车键确认，或输入新的 IP 地址：" device_ip
        if [ -z "$device_ip" ]; then
            device_ip="$default_device_ip"
            break
        elif ! echo "$device_ip" | grep -Eq '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.'; then
            echo "输入的 IP 地址无效，请输入有效的 IP 地址。"
        else
            break
        fi
    done

    echo "主路由 IP 地址：$router_ip"
    echo "本机 IP 地址：$device_ip"

    # 配置网络
    uci set network.lan.ipaddr="$device_ip"
    uci set network.lan.gateway="$router_ip"
    uci set network.lan.proto='static'
    uci commit network

    # 禁用 LAN 口的 IPv6 服务器
    uci set dhcp.lan.dhcpv6='disabled'
    uci set dhcp.lan.ra='disabled'
    uci commit dhcp

    # 启用 MSS 钳制
    uci set firewall.@defaults[0].mss_clamping='1'

    # 启用 IP 伪装和 MTU fix
    # 找到 LAN 和 WAN 的 zone 配置节
    lan_zone=$(uci show firewall | grep "=zone" | grep -E 'name=.lan' | cut -d'.' -f2)
    wan_zone=$(uci show firewall | grep "=zone" | grep -E 'name=.wan' | cut -d'.' -f2)

    # 启用 LAN 区域的 IP 伪装和 MTU fix
    if [ -n "$lan_zone" ]; then
        uci set firewall.$lan_zone.masq='1'
        uci set firewall.$lan_zone.mtu_fix='1'
    else
        echo "未找到名称为 'lan' 的 zone 配置节"
        exit 1
    fi

    # 启用 WAN 区域的 IP 伪装和 MTU 修复
    if [ -n "$wan_zone" ]; then
        uci set firewall.$wan_zone.masq='1'
        uci set firewall.$wan_zone.mtu_fix='1'
    else
        echo "未找到名称为 'wan' 的 zone 配置节"
        exit 1
    fi

    uci commit firewall

    # 删除 WAN 口防火墙规则
    uci delete firewall.$wan_zone
    uci commit firewall

    # 关闭 LAN 口的 DHCP 服务并删除相关配置
    uci set dhcp.lan.ignore='1'
    uci delete dhcp.lan.leasetime
    uci delete dhcp.lan.limit
    uci delete dhcp.lan.start
    uci commit dhcp

    lan_ip=$(uci get network.lan.ipaddr)
    echo "旁路网关配置完成 $lan_ip "

    # 重启相关服务以应用更改
    /etc/init.d/network restart
    /etc/init.d/firewall restart
    /etc/init.d/dnsmasq restart

    echo ""
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
    echo ""

    echo "## STATUS" >>/www/logs.txt
    echo "=================" >>/www/logs.txt
    eval $UPTIME >>/www/logs.txt
    echo ""

    echo "## Memory Usage" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    free -h >>/www/logs.txt
    echo ""

    echo "## Disk Usage" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    df -h >>/www/logs.txt
    echo ""

    echo "## Application" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    opkg list_installed >>/www/logs.txt

    echo "## SYSLOG" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    logread >>/www/logs.txt
    echo ""

    echo "## DMESG" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    dmesg >>/www/logs.txt
    echo ""

    echo "## Plugins" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    cat /tmp/openclash.log >>/www/logs.txt
    cat /tmp/log/ssrplus.log >>/www/logs.txt
    cat /tmp/log/passwall.log >>/www/logs.txt
    cat /tmp/log/passwall2.log >>/www/logs.txt
    echo ""

    echo "## Task" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    top -b -n 1 >>/www/logs.txt
    echo ""

    echo "## Network Configuration" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    ifconfig -a >>/www/logs.txt
    echo ""

    echo "## UCI Network" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    uci show network >>/www/logs.txt
    echo ""

    echo "## Firewall" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    iptables -L -v -n >>/www/logs.txt
    ip6tables -L -v -n >>/www/logs.txt
    echo ""

    echo "## Routing Table" >>/www/logs.txt
    echo "==========" >>/www/logs.txt
    ip route >>/www/logs.txt
    ip -6 route >>/www/logs.txt
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
        else
            echo
            echo "INFO  ================================================="
            echo "          Your CatWrt is latest version!"
            echo "======================================================="
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
    arch=$(grep -o 'arch=[^ ]*' $RELEASE | cut -d= -f2)
    version=$(grep -o 'version=[^ ]*' $RELEASE | cut -d= -f2)

    case "$arch" in
    amd64)
        case "$version" in
        v22.12) REPO_URL="$BASE_URL/history/v22.12/amd64" ;;
        v23.2) REPO_URL="$BASE_URL/history/v23.2/amd64" ;;
        v23.8) REPO_URL="$BASE_URL/amd64" ;;
        v24.3) REPO_URL="$BASE_URL/pr/v24.3/amd64" ;;
        v24.8) REPO_URL="$BASE_URL/pr/v24.3/amd64" ;;
        *) echo "Unknown version" && exit 1 ;;
        esac
        ;;
    mt798x)
        case "$version" in
        v22.12) REPO_URL="$BASE_URL/history/v22.12/aarch64_cortex-a53" ;;
        v23.2) REPO_URL="$BASE_URL/history/v23.2/mt7986a" ;;
        v23.8) REPO_URL="$BASE_URL/mt798x" ;;
        v24.3) REPO_URL="$BASE_URL/pr/v24.3/mt798x" ;;
        *) echo "Unknown version" && exit 1 ;;
        esac
        ;;
    rkarm)
        case "$version" in
        v22.12) REPO_URL="$BASE_URL/rkarm" ;;
        v24.1) REPO_URL="$BASE_URL/pr/v24.1/rkarm" ;;
        *) echo "Unknown version" && exit 1 ;;
        esac
        ;;
    mt7621)
        case "$version" in
        v22.12) REPO_URL="$BASE_URL/mt7621" ;;
        *) echo "Unknown version" && exit 1 ;;
        esac
        ;;
    *) echo "Unknown arch" && exit 1 ;;
    esac

    echo ""
    echo "Warning:"
    echo "软件源纯属免费分享，赞助我们复制链接在浏览器打开，这对我们继续保持在线服务有很大影响。"
    echo "本人不对所有软件进行保证，我们没有第三方商业服务，风险需要自行承担。"
    echo "支持我们: https://www.miaoer.xyz/sponsor"
    echo "你需要同意 CatWrt 软件源用户协议,请确认是否继续 (10 秒内按 [Ctrl]+[C] 取消操作)"
    echo "=============================================================================="

    if { { [ "$arch" == "amd64" ] || [ "$arch" == "mt798x" ]; } && [ "$version" == "v24.3" ]; } || { [ "$arch" == "rkarm" ] && [ "$version" == "v24.1" ]; }; then
        echo "你目前使用的 BETA 版本，只能临时镜像站的软件源，请注意关注 CatWrt 的更新情况!"
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
        echo "请选择要使用的软件源:"
        echo "1) repo.miaoer.xyz (主站)"
        echo "2) cfnetlify"
        echo "3) netlify"
        echo "4) cfvercel"
        echo "5) vercel (默认)"

        read -t 10 -p "Please enter your choice /// 请输入选择 (1-5): " choice
        choice=${choice:-5}

        case $choice in
        1) conf_file="distfeeds.conf" ;;
        2) conf_file="cfnetlify.conf" ;;
        3) conf_file="netlify.conf" ;;
        4) conf_file="cfvercel.conf" ;;
        5) conf_file="vercel.conf" ;;
        *) conf_file="vercel.conf" ;;
        esac
    fi

    CONF_PATH="$REPO_URL/$conf_file"
    if curl --output /dev/null --silent --head --fail "$CONF_PATH"; then
        echo "使用 $CONF_PATH"
    else
        echo "源文件不存在: $CONF_PATH"
        exit 1
    fi

    curl -sL "$CONF_PATH" -o /etc/opkg/distfeeds.conf

    if [ -f /var/lock/opkg.lock ]; then
        rm /var/lock/opkg.lock
    fi

    # fack istore_compat
    if [ -f /var/opkg-lists/istore_compat ]; then
        rm /var/opkg-lists/istore_compat
    fi

    opkg update

    echo "完成"
}

# catnd

catnd() {
    echo "$(date) - Starting CatWrt Network Diagnostics"
    echo " "

    # Ping & PPPoE
    ping -c 3 223.5.5.5 >/dev/null
    if [ $? -eq 0 ]; then
        echo "[Ping] Network connection succeeded!"
        echo " "
    else
        ping -c 3 119.29.29.99 >/dev/null
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
    nslookup bilibili.com >/dev/null
    if [ $? -ne 0 ]; then
        nslookup www.miaoer.xyz >/dev/null
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
    echo CatWrt IPv4 Addr: $(curl --silent --connect-timeout 5 4.ipw.cn)
    echo " "

    curl 6.ipw.cn --connect-timeout 5 >/dev/null 2>&1
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
    grep 'config interface' /etc/config/network | grep 'wan6' >/dev/null
    if [ $? -ne 0 ]; then
        echo "[wan6] Your IPv6 network may have issues"
        echo " "
    fi

    grep 'dhcpv6' /etc/config/network >/dev/null
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
sysupgrade() {
    if [ "$(uname -m)" != "x86_64" ]; then
        echo "仅有 x86_64 可以使用脚本进行系统升级。"
        exit 1
    fi

    echo ""

    disk_size=$(fdisk -l /dev/sda | grep "Disk /dev/sda:" | awk '{print $3}')
    if (($(echo "$disk_size != 800.28" | bc -l))); then
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

    if [ -f /etc/catwrt_opkg_list_installed ]; then
        rm /etc/catwrt_opkg_list_installed
    fi

    catwrt_opkg_list_installed
    echo "已经生成备份软件包列表，方便你后续更新后恢复部分消失的插件和软件"

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
    )

    if ! grep -q -E "catwrt|repo.miaoer.xyz" /etc/opkg/distfeeds.conf && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "请先配置软件源"
        exit 1
    fi

    backup_installed_packages() {
        echo "名单中已安装软件包列表..."
        >"$BACKUP_FILE"
        for package in "${PACKAGES[@]}"; do
            if opkg list_installed | grep -q "^$package "; then
                echo "$package" >>"$BACKUP_FILE"
            fi
        done
        echo "备份完成"
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
            echo "安装完成"
        else
            echo "未检测到备份文件!寄了!"
        fi
    }

    main() {
        if [ -f "$BACKUP_FILE" ]; then
            echo "sponsor us"
            echo "========================================================================="
            echo "你执行的下面命令如果使用的主站软件源 repo.miaoer.xyz 将对服务器带宽产生新的挑战"
            echo "我们希望你在使用后继续支持我们，继续为您提供更好的服务"
            echo "如果不想支持我们也可以使用免费 serverless 提供的镜像服务选择非主站即可"
            echo "不会对我们服务器造成流量激增，但访问速度受限于国际互联网"
            echo ""
            echo "https://www.miaoer.xyz/sponsor"
            echo ""
            echo "你可以复制下链接在浏览器上打开，待恢复软件包后再进行支付!"

            sleep 3

            echo ""
            read -p "检测到备份文件，是否需要恢复软件包？([ENTER] 确认 / [0] 取消) " choice
            case "$choice" in
            0)
                echo "你选择了不恢复，打算重新开始!如果你有需要请回来找我!"
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
    echo "3.    TTYD 配置免密(危险)"
    echo "4.    SSL/TLS 证书上传配置"
    echo "5.    重置 root 密码"
    echo "6.    重置系统"
    echo ""
    echo "0.    返回 Cattools 主菜单"
    echo
    read -p "请输入数字并回车(Please enter your choice): " choice
    case $choice in
    1) configure_luci_mihomo ;;
    2) configure_tailscale ;;
    3) configure_ttyd ;;
    4) manual_deploy_uhttpd_ssl_cert ;;
    5) openwrt_firstboot ;;
    6) reset_root_password ;;
    0) menu ;;
    *) echo "无效选项，请重试" && utilities_menu ;;
    esac
}

configure_luci_mihomo() {
    if ! grep -q -E "catwrt|repo.miaoer.xyz" /etc/opkg/distfeeds.conf && ! ip a | grep -q -E "192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.1[6-9]\.[0-9]+\.[0-9]+|172\.2[0-9]+\.[0-9]+\.[0-9]+|172\.3[0-1]\.[0-9]+\.[0-9]+"; then
        echo "[ERROR] 请先配置软件源"
        exit 1
    fi

    arch=$(uname -m)
    case "$arch" in
    "x86_64")
        arch="amd64"
        ;;
    "aarch64")
        arch="arm64"
        ;;
    *)
        echo "[ERROR] 不支持的架构: $arch"
        exit 1
        ;;
    esac

    if ! opkg list_installed | grep -q luci-app-openclash; then
        opkg update
        opkg install luci-app-openclash
    fi

    download_mihomo_core() {
        local core_name="$1"
        shift
        local urls=("$@")
        local dest_dir="/etc/openclash/core"
        local temp_file=$(mktemp)
        local success=0
        local failed_urls=()

        for url in "${urls[@]}"; do
            echo "尝试下载: $url"
            if curl --silent --connect-timeout 5 --max-time 10 -o "$temp_file" "$url"; then
                if tar -tzf "$temp_file" &>/dev/null; then
                    tar -xz -C "$dest_dir" -f "$temp_file"
                    mv "$dest_dir/clash" "$dest_dir/$core_name"
                    rm -f "$temp_file"
                    echo "已成功下载: $url"
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
            echo "[ERROR] 所有下载链接均失败"
            exit 1
        fi
    }

    echo ""
    echo "Warning:"
    echo "========================================================================="
    echo "我站不提供服务器，该功能只是补全 Mihomo 的内核，仅此而已所有结果由用户自行承担!"
    echo "你需要阅读并同意以上协议并自行承担配置后的一切后果，如不同意请 [CTRL]+[C] 中断该功能"
    echo "========================================================================="

    sleep 2

    echo "请选择下载类型:"
    echo "1. 全部下载 (默认 3 秒自动执行)"
    echo "2. 仅下载 Mihomo 内核"
    echo "3. 仅下载原版内核"
    echo -n "输入选项 ([1]/[2]/[3]): "
    read -t 3 -p "" choice

    if [ -z "$choice" ]; then
        choice=1
    fi

    local clash_meta_urls=(
        "https://raw.githubusercontent.com/vernesong/OpenClash/core/master/meta/clash-linux-$arch.tar.gz"
        "https://cdn.jsdelivr.net/gh/vernesong/OpenClash@core/master/meta/clash-linux-$arch.tar.gz"
        "https://fastly.jsdelivr.net/gh/vernesong/OpenClash@core/master/meta/clash-linux-$arch.tar.gz"
    )

    local clash_urls=(
        "https://raw.githubusercontent.com/vernesong/OpenClash/core/master/dev/clash-linux-$arch.tar.gz"
        "https://cdn.jsdelivr.net/gh/vernesong/OpenClash@core/master/dev/clash-linux-$arch.tar.gz"
        "https://fastly.jsdelivr.net/gh/vernesong/OpenClash@core/master/dev/clash-linux-$arch.tar.gz"
    )

    case $choice in
    1)
        echo "正在更新 Mihomo 内核..."
        download_mihomo_core "clash_meta" "${clash_meta_urls[@]}"
        echo "正在更新原版内核..."
        download_mihomo_core "clash" "${clash_urls[@]}"
        ;;
    2)
        echo "正在更新 Mihomo 内核..."
        download_mihomo_core "clash_meta" "${clash_meta_urls[@]}"
        ;;
    3)
        echo "正在更新原版内核..."
        download_mihomo_core "clash" "${clash_urls[@]}"
        ;;
    *)
        echo "[ERROR] 无效选项"
        exit 1
        ;;
    esac

    echo "操作完成"
}

configure_tailscale() {
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
            echo $rule >>$firewall_file
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
configure_ttyd() {
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

patch_catwrt_release() {
    if [ -f $RELEASE ]; then
        if grep -q "version=v23.7" $RELEASE && grep -q "arch=amd64" $RELEASE && grep -q "source=lean" $RELEASE; then
            echo "Already patched for x86_64 v23.7"
        elif grep -q "version=v23.8" $RELEASE && grep -q "arch=amd64" $RELEASE && grep -q "source=lean" $RELEASE; then
            echo "Already patched for x86_64 v23.8"
        elif grep -q "version=v23.8" $RELEASE && grep -q "arch=mt798x" $RELEASE && grep -q "source=lean" $RELEASE; then
            echo "Already patched for aarch64 v23.8"
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
