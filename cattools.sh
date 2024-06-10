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

# install
install_cattools() {
    local CATTOOLS_PATH="/usr/bin/cattools"
    local CATTOOLS_URLS=(
        "https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh"
        "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/cattools.sh"
    )

    if [ ! -f "$CATTOOLS_PATH" ]; then
        echo "cattools 未安装，正在安装..."

        for URL in "${CATTOOLS_URLS[@]}"; do
            curl -m 5 -s -o "$CATTOOLS_PATH" "$URL" && break
        done

        if [ ! -f "$CATTOOLS_PATH" ] || [ ! -s "$CATTOOLS_PATH" ]; then
            echo "cattools 下载失败，请检查网络连接。"
            exit 1
        fi

        chmod +x "$CATTOOLS_PATH"
        echo "cattools 安装成功。"
        echo ""
    fi
}

# HotUpdate
check_for_updates() {
    local UPDATE_URLS=(
        "https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh"
        "https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/cattools.sh"
    )

    local TEMP_FILE=$(mktemp)

    for URL in "${UPDATE_URLS[@]}"; do
        if curl -m 5 -s -o "$TEMP_FILE" "$URL"; then
            if [ -s "$TEMP_FILE" ]; then
                echo "更新已找到,替换当前脚本..."
                mv "$TEMP_FILE" "$0"
                chmod +x "$0"
                exec "$0" "$@"
            fi
        fi
    done

    rm -f "$TEMP_FILE"
    echo "没有找到更新，继续运行当前脚本..."
    echo ""
}

# Menu Function
show_menu() {
    echo "----------------------------------------------------------"
    echo "                         CatTools                         "
    echo "  https://www.miaoer.xyz/posts/network/catwrt-bash-script "
    echo "----------------------------------------------------------"
    echo "1. SetIP                                    -  设置 IP"
    echo "2. Debug                                    -  抓取日志"
    echo "3. catwrt_update                            -  检查更新"
    echo "4. use_repo                                 -  启用软件源"
    echo "0. Exit                                     -  退出"
    echo "----------------------------------------------------------"
    echo -n "请输入数字并回车(Please enter your choice): "
}

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
use_repo(){
    # fk is
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

    system_arch=$(uname -m)
    release="/etc/catwrt_release"
    

    if [ -f "$release" ]; then
        source "$release"
    else
        echo "Error: $release"
        return
    fi
    
    echo ""

    if [[ "$system_arch" == "x86_64" && "$arch" == "amd64" ]]; then
        echo "正在获取 x86_64 软件源..."
        curl -o /etc/opkg/distfeeds.conf $AMD64_REPO
    elif [[ "$system_arch" == "aarch64" && "$arch" == "mt798x" ]]; then
        echo "正在获取 mt798x 软件源..."
        curl -o /etc/opkg/distfeeds.conf $MT798X_REPO
    else
        echo "Unsupported System Arch: $system_arch or $arch ."
        return
    fi

    if [ -f "/var/lock/opkg.lock" ]; then
        rm /var/lock/opkg.lock
    fi

    echo "更新软件包列表..."
    opkg update
}

install_cattools

check_for_updates

while true; do
    show_menu
    read choice
    case $choice in
        1)
            setip
            ;;
        2)
            debug
            ;;
        3)
            catwrt_update
            ;;
        4)
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
