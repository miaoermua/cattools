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


# Menu Function
show_menu() {
    echo "-------------------------"
    echo "        CatTools         "
    echo "-------------------------"
    echo "1. Debug"
    echo "2. catwrt_update"
    echo "0. Exit"
    echo "-------------------------"
    echo -n "Please enter your choice: "
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

    echo "## Application" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    opkg list_installed >> /www/logs.txt

    echo "## SYSLOG" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    logread >> /www/logs.txt

    echo "## DMESG" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    dmesg >> /www/logs.txt

    echo "## Plugins" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    cat /tmp/openclash.log >> /www/logs.txt
    cat /tmp/log/ssrplus.log >> /www/logs.txt
    cat /tmp/log/passwall.log >> /www/logs.txt
    cat /tmp/log/passwall2.log >> /www/logs.txt

    echo "## Task" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    top -b -n 1 >> /www/logs.txt

    echo "## Network Configuration" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    ifconfig -a >> /www/logs.txt

    echo "## UCI Network" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    uci show network >> /www/logs.txt

    echo "## Firewall" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    iptables -L -v -n >> /www/logs.txt
    ip6tables -L -v -n >> /www/logs.txt

    echo "## Routing Table" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    ip route >> /www/logs.txt
    ip -6 route >> /www/logs.txt

    echo "## Memory Usage" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    free -h >> /www/logs.txt

    echo "## Disk Usage" >> /www/logs.txt
    echo "==========" >> /www/logs.txt
    df -h >> /www/logs.txt

    lan_ip=$(uci get network.lan.ipaddr)

    echo "日志已收集到 /www/logs.txt"
    echo "使用浏览器访问下载 http://$lan_ip/logs.txt"
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
use_repo(){
    # fk is
    if [ -f "/var/opkg-lists/istore_compat" ]; then
        rm /var/opkg-lists/istore_compat
    fi

    echo "Warning:"
    echo "软件源纯属免费分享，赞助我们复制链接在浏览器打开，这对我们继续保持在线服务有很大影响。"
    echo "本人不对所有软件进行保证，我们没有第三方商业服务，风险需要自行承担。"
    echo "支持我们: https://www.miaoer.xyz/sponsor"
    echo "你需要同意 CatWrt 软件源用户协议,请确认是否继续 (y/n)"
    read -t 10 -p "您有 10 秒选择,输入 y 继续,其他退出:" confirm
    [ "$confirm" != y ] && return
    
    arch=$(uname -m)
    
    # Check ARCH release
    model=$(grep "Model:" $release | cut -d ' ' -f2)

    if [[ $model =~ "mt798x" ]]; then
        # mt798x  
		curl -o /etc/opkg/distfeeds.conf $MT798X_REPO
    
    elif [ "$arch" = "x86_64" ]; then
    	# amd64
        curl -o /etc/opkg/distfeeds.conf $AMD64_REPO
        
    else
        echo "不支持的机型: $model"
        return
    fi

    if [ -f "/var/lock/opkg.lock" ]; then
        rm /var/lock/opkg.lock
    fi
  
    opkg update
}

while true; do
    show_menu
    read choice
    case $choice in
        1)
            debug
            ;;
        2)
            catwrt_update
            ;;
        3)
            use_repo
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
