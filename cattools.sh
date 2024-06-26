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
    echo "Please wait for the script to be updated."
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
    echo "1. SetIP                                   -  设置 IP"
    echo "2. network_wizard                          -  网络向导"
    echo "3. Debug                                   -  抓取日志"
    echo "4. catwrt_update                           -  检查更新"
    echo "5. use_repo                                -  启用软件源"
    echo "6. diagnostics                             -  网络诊断"
    echo "7. sysupgrade                              -  系统更新"
    echo "8. use_mirrors_repo                        -  选择软件源镜像"
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
            echo "无效的 IP 地址。"
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
    echo "网络配置已保存并应用，服务已重启，如遇到问题问题请手动重启！"
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
    echo "该功能通过 sysupgrade 进行升级系统，未经过可靠性实践，不保证 100% 升级成功，请三思而后行!"
    echo "即将升级系统，存在风险请输入 (y/n) 确认，30 秒后默认退出!"
    echo ""
    echo "+ 升级系统会导致启用软件源安装的所有软件被新固件覆盖"
    echo "+ ROOT 账户的密码可能被还原为默认密码 (password)"
    echo "+ 升级过程中会保留插件配置和预装插件以获得升级"
    echo "+ 会抹除 opkg 或手动方式安装的插件，可以通过后续在软件源中获取!"

    while true; do
        read -p "是否继续升级 (y/n)?" confirm_upgrade
        if [ "$confirm_upgrade" = "y" ]; then
            echo "正在进行系统升级..."
            # 执行系统升级命令
            sysupgrade -v /path/to/your/firmware.img
            echo "系统升级完成正在重启"
            break
        elif [ "$confirm_upgrade" = "n" ]; then
            echo "系统升级已取消。"
            break
        else
            echo "无效的输入，请输入 y 或 n。"
        fi
    done

}

# Use Mirrors repo and History repo
use_mirrors_repo() {
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
    get_url_prefix() {
        local version=$1
        local arch=$2
    
        case "$version" in
            v23.8)
                case "$arch" in
                    amd64)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/amd64/"
                        ;;
                    mt798x)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/mt798x/"
                        ;;
                    *)
                        echo "不支持的架构"
                        exit 1
                        ;;
                esac
                ;;
            v23.2)
                case "$arch" in
                    amd64)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/history/v23.2/amd64/"
                        ;;
                    mt798x)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/history/v23.2/mt7986a/"
                        ;;
                    *)
                        echo "不支持的架构"
                        exit 1
                        ;;
                esac
                ;;
            v22.12)
                case "$arch" in
                    amd64)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/history/v22.12/amd64/"
                        ;;
                    aarch64_generic)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/rkarm/"
                        ;;
                    aarch64_cortex-a53)
                        echo "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/history/v22.12/aarch64_cortex-a53/"
                        ;;
                    *)
                        echo "不支持的架构"
                        exit 1
                        ;;
                esac
                ;;
            *)
                echo "不支持的版本"
                exit 1
                ;;
        esac
    }
    
    OPENWRT_RELEASE_FILE="/etc/openwrt_release"
    
    if [ -f "$RELEASE" ]; then
        # Read release information
        . "$RELEASE"
    elif [ -f "$OPENWRT_RELEASE_FILE" ]; then
        if grep -q "R22.12.1" "$OPENWRT_RELEASE_FILE"; then
            version="v22.12"
            if grep -q "aarch64_cortex-a53" "$OPENWRT_RELEASE_FILE"; then
                arch="aarch64_cortex-a53"
            elif grep -q "aarch64_generic" "$OPENWRT_RELEASE_FILE"; then
                arch="aarch64_generic"
            fi
        else
            echo "$OPENWRT_RELEASE_FILE 不包含支持的版本信息"
            exit 1
        fi
    else
        echo "$RELEASE 和 $OPENWRT_RELEASE_FILE 文件都不存在或者设备不被 CatWrt LTS 支持!"
        exit 1
    fi
    
    if [ -z "$version" ] || [ -z "$arch" ]; then
        echo "缺少必要的版本或架构信息"
        exit 1
    fi
    
    url_prefix=$(get_url_prefix "$version" "$arch")
    
    # Display options
    echo "请选择源:"
    echo "1 主站"
    echo "2 cfnetlify"
    echo "3 netlify"
    echo "4 cfvercel"
    echo "5 vercel"
    
    read -p "请输入数字并回车(Please enter your choice):  " choice
    
    case "$choice" in
        1)
            conf_file="distfeeds.conf"
            ;;
        2)
            conf_file="cfnetlify.conf"
            ;;
        3)
            conf_file="netlify.conf"
            ;;
        4)
            conf_file="cfvercel.conf"
            ;;
        5)
            conf_file="vercel.conf"
            ;;
        *)
            echo "无效的选择"
            exit 1
            ;;
    esac
    
    # Download the selected configuration file and rename it to distfeeds.conf
    curl --connect-timeout 5 --retry 2 -o /etc/opkg/distfeeds.conf "${url_prefix}${conf_file}"

        if [ -f "/var/lock/opkg.lock" ]; then
            rm /var/lock/opkg.lock
        fi
    
        opkg update
    
    echo "源已切换到 ${url_prefix}${conf_file}"
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
        8)
            use_mirrors_repo
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
