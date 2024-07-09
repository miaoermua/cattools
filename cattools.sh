#!/bin/bash
# env
DEFAULT_IP="192.168.1.4"
RELEASE="/etc/catwrt_release"
AMD64_REPO="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/amd64/distfeeds.conf"
MT798X_REPO="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/mt798x/distfeeds.conf"
AMD64_EFI_SYSUP="https://github.com/miaoermua/CatWrt/releases/download/v23.8/CatWrt.v23.8.x86_64-squashfs-combined-efi.img.gz"
AMD64_BIOS_SYSUP="https://github.com/miaoermua/CatWrt/releases/download/v23.8/CatWrt.v23.8.x86_64-squashfs-combined.img.gz"

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
    echo: "Please wait for the script to be updated."
    local temp_file=$(mktemp)
    if curl --silent --connect-timeout 5 -o "$temp_file" https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh; then
        echo "cattools update downloaded from the first URL."
    elif curl --silent --connect-timeout 5 -o "$temp_file" https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/cattools.sh; then
        echo "cattools update downloaded from the second URL."
    else
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
    echo "1. SetIP                                    -  设置 IP"
    echo "2. network_wizard                           -  网络向导"
    echo "3. Debug                                    -  抓取日志"
    echo "4. catwrt_update                            -  检查更新"
    echo "5. use_repo                                 -  启用软件源"
    echo "6. diagnostics                              -  网络诊断"
    echo "7. sysupgrade                               -  系统更新"
    echo "0. Exit                                     -  退出"
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
    read -p "请输入 IP (默认为 $DEFAULT_IP): " input_ip
    if [ -z $input_ip ]; then
        input_ip=$DEFAULT_IP 
    fi

    uci set network.lan.ipaddr=$input_ip 
    uci commit network
    /etc/init.d/network restart
    
    echo "默认 IP 已设置为 $input_ip"
}

# Network Wizard
network_wizard() {
    read -p "Do you want Network Wizard? /// 是否使用网络向导？([Enter] 确认，按 [0] 退出): " use_wizard
    if [ "$use_wizard" == "0" ]; then
        echo "网络向导已退出。"
        return
    fi
    
    echo "CatWrt default IP is 192.168.1.4 /// 默认 CatWrt IP 为 192.168.1.4"
    read -p "是否修改 IP 地址？([Enter] 确认，按 [0] 跳过): " modify_ip
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
    read -p "是否禁用 IPv6 网络？([Enter] 确认，按 [1] 禁用，按 [0] 跳过): " disable_ipv6
    if [ "$disable_ipv6" == "1" ]; then
        uci delete dhcp.lan.dhcpv6 
        uci delete dhcp.lan.ra
        uci delete dhcp.lan.ra_management
        uci delete network.lan.ip6assign
        echo "IPv6 已禁用"
    fi
    
    echo "Default connection mode is DHCP /// 默认模式为 DHCP"
    read -p "是否进行 PPPoE 拨号？([Enter] 使用 DHCP，按 [1] 添加账号和密码，按 [0] 跳过): " use_pppoe
    if [ "$use_pppoe" == "1" ]; then
        read -p "请输入宽带账号: " username
        read -s -p "请输入宽带密码: " password
        uci set network.wan.proto=pppoe
        uci set network.wan.username=$username
        uci set network.wan.password=$password
        echo "PPPoE 拨号配置已完成"
    fi
    
    read -p "Use recommended DNS servers 223.6.6.6 119.29.29.99? /// 使用推荐的 DNS 服务器 223.6.6.6 119.29.29.99 吗？([Enter] 确认，按 [0] 跳过): " use_dns
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

    read -p "Do you want to change the DHCP IP pool range? (default: 30-200) /// 是否修改 IP 可用段？(默认: 30-200, 按 1 手动输入范围 [Enter] 确认): " dhcp_choice
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
        read -p "Press Enter to configure network interfaces, press 1 to skip /// [Enter] 确认配置网口，按 [1] 跳过: " configure_network
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
        echo "System architecture $arch is not supported by this script. No changes made. /// 系统架构 $arch 不支持该脚本。未进行任何更改。"
    fi
    
    uci commit
    /etc/init.d/network restart
    /etc/init.d/dnsmasq restart
    /etc/init.d/firewall restart
    /etc/init.d/miniupnpd restart
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
    ehco ""
    ehco "https://github.com/miaoermua/CatWrt/issues/new?assignees=&labels=&projects=&template=report.md&title="
    ehco "尽可能使用 Github 提交你的问题不会操作再使用社交软件 TG Guoup: t.me/miaoergroup  //  QQ Guoup: 669190476"
    ehco ""
    exit
}

# catwrt_update
catwrt_update() {

API_URL="https://api.miaoer.xyz/api/v2/snippets/catwrt/update"
VERSION_FILE="/etc/catwrt_release"

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
    if [ ! -f "$VERSION_FILE" ]; then
        local_error "version file"
    fi

    version_local=$(grep 'version' "$VERSION_FILE" | cut -d '=' -f 2)
    hash_local=$(grep 'hash' "$VERSION_FILE" | cut -d '=' -f 2)
    source_local=$(grep 'source' "$VERSION_FILE" | cut -d '=' -f 2)
    arch_local=$(grep 'arch' "$VERSION_FILE" | cut -d '=' -f 2)
}

contrast_version() {
    if [ "$version_remote" == "$version_local" ] && [ "$hash_remote" == "$hash_local" ]; then
        echo "================================"
        echo "Your CatWrt is up to date!"
        echo "================================"
    else
        echo "================================"
        echo "Your CatWrt is out of date, you should upgrade it!"
        echo "You can visit 'https://www.miaoer.xyz/posts/network/catwrt' to get more information!"
        echo "================================"
    fi
}

print_version() {
    echo "Local  Version : $version_local"
    echo "Remote Version : $version_remote"
    echo "Local  Hash    : $hash_local"
    echo "Remote Hash    : $hash_remote"
    echo "================================"
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
# Repo
use_repo() {
    # 删除现有的 istore_compat 文件
    if [ -f "/var/opkg-lists/istore_compat" ]; then
        rm /var/opkg-lists/istore_compat
    fi

    echo "=============================================================================="
    echo "Warning:"
    echo "软件源纯属免费分享，赞助我们复制链接在浏览器打开，这对我们继续保持在线服务有很大影响。"
    echo "本人不对所有软件进行保证，我们没有第三方商业服务，风险需要自行承担。"
    echo "支持我们: https://www.miaoer.xyz/sponsor"
    echo "你需要同意 CatWrt 软件源用户协议,请确认是否继续 (10 秒内按 [Ctrl]+[C] 取消操作)"
    echo "=============================================================================="
    
    for i in $(seq 10 -1 1); do
        echo -n "$i "
        sleep 1
    done
    
    arch=$(uname -m)
    
    model=$(grep "Model:" /etc/catwrt_release | cut -d ' ' -f2)

    download_success=false

    if [[ $model =~ "mt798x" ]]; then
        # mt798x
        curl --retry 2 --max-time 5 -o /etc/opkg/distfeeds.conf $MT798X_REPO && download_success=true
    
    elif [ "$arch" = "x86_64" ]; then
        # amd64
        curl --retry 2 --max-time 5 -o /etc/opkg/distfeeds.conf $AMD64_REPO && download_success=true
        
    else
        echo "不支持的机型: $model"
        return
    fi

    if [ "$download_success" = true ]; then
        if [ -f "/var/lock/opkg.lock" ]; then
            rm /var/lock/opkg.lock
        fi
    
        opkg update
    else
        echo "下载失败，无法更新软件源。"
    fi
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
sysupgrade() {
    if [ "$(uname -m)" != "x86_64" ]; then
        echo "仅有 x86_64 可以使用脚本进行系统升级。"
        exit 1
    fi

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
    echo "该功能未经过实践，不保证是否升级成功，请三思而后行！"
    echo "即将升级系统，存在风险请输入 (y/n) 确认，30 秒后默认退出脚本！"
    echo "升级系统会导致启用软件源安装的所有软件被新固件覆盖，ROOT 账户的密码可能被还原为默认密码 (password) 升级过程中会保留插件配置和预装插件获得升级。"
    read -t 30 -n 1 -p "所以你确认需要升级吗? " user_input
    if [ $? -ne 0 ] || [ "$user_input" != "y" ]; then
        echo -e "\n用户已取消升级!"
        exit 1
    fi

    echo -e "\n正在升级系统..."
    sysupgrade -v $firmware_url
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
            use_repo
            ;;
        6)
            catnd
            ;;
        7)
            sysupgrade
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
