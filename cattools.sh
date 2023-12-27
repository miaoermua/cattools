#!/bin/bash
###
 # @Author: miaoermua
 # @Date: 2023-12-12 16:59:27
 # @LastEditors: miaoermua
 # @LastEditTime: 2023-12-27 15:42:39
 # @FilePath: \undefinedd:\Git\cattools\cattools.sh
### 

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


update(){
    if ! curl -fsSLo /root/cattools https://service.miaoer.xyz/cattools/cattools.sh; then
        echo "[main site]Unable to connect to update site! 无法连接更新站点!"

        if ! curl -fsSLo /root/cattools https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/mt798x/cattools.sh; then
            echo "[site 2]Unable to connect to update site! 无法连接更新仓库" 

           if ! curl -fsSLo /root/cattools https://raw.githubusercontent.com/miaoermua/service/main/cattools/cattools.sh; then
               echo "[site 3]Unable to connect to update site! 无法连接更新仓库" 
               echo "Unable to connect, please check the internet! 无法连接互联网,请联系作者!"
               return 
           fi
        fi
    fi

    exec $(readlink -f "$0")
}

setip(){
    read -p "请输入 IP(默认为 $DEFAULT_IP): " input_ip
    if [ -z $input_ip ]; then
        input_ip=$DEFAULT_IP 
    fi

    uci set network.lan.ipaddr=$input_ip 
    uci commit network
    /etc/init.d/network restart
    
    echo "默认 IP 已设置为 $input_ip"
}

catwrt_update(){
    /usr/bin/catwrt-update  
}

catwrt_network_diagnostics(){
    echo " "
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
    echo "$(date) - Network check completed"
    echo " "
}

use_repo(){
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

}

catwrt_sysupgrade(){
    
    # uname
    if [[ $(uname -m) =~ "x86_64" ]]; then
        echo "CatWrt ARCH: x86_64(AMD64)"
        
        # Check Disk space remaining
        size=$(fdisk -l /dev | grep "Disk /dev" | awk '{print $5}') 
        size=${size%\*}
        if [[ $size > 820 ]]; then
            echo "磁盘空间出现了更改！脚本退出！"
            exit
        fi
        
        # Check EFI remaining
        if [[ -b /dev/sda128 || -b /dev/vda128 ]]; then
            efi_part=true
        else
            efi_part=false
        fi
        
        # confirmation
        echo "即将升级系统，存在风险请你三思确认 (y/n) 30 秒后默认退出脚本！"
        read -t 30 confirm
        confirm=${confirm:-n}
        
        # upgrade
        if [[ $confirm =~ [Yy] ]]; then
            if [[ $efi_part == true ]]; then
                sysupgrade -v $AMD64_EFI_SYSUP
            else
                sysupgrade -v $AMD64_BIOS_SYSUP
            fi
        else
            echo "用户已取消升级!"
        fi
        
    else
        echo "仅有 x86_64 可以使用脚本进行系统升级。"
    fi
}

debug(){

        if [ -f /www/logs.txt ]; then
              rm /www/logs.txt
        fi
	
           cat /etc/banner >> /www/logs.txt
           echo "## RELEASE" >> /www/logs.txt
           cat /etc/catwrt_release >> /www/logs.txt
           echo "## SYSLOG" >> /www/logs.txt
           logread >> /www/logs.txt
           echo "## DMESG" >> /www/logs.txt
           dmesg >> /www/logs.txt

        lan_ip=$(uci get network.lan.ipaddr)
	
        echo "日志已收集到 /www/logs.txt" 
        echo "使用浏览器访问下载 http://$lan_ip/logs.txt"
	exit
}

bypass_gateway(){

        echo "没做完"
        exit
}

update

while :; do
    clear
    echo " "
    echo "                CatTools"
    echo "----------------------------------------"  
    echo "1.  Set IPv4 Addr          设置 IP"
    echo "2.  check update           检查系统更新"
    echo "3.  network diagnostics    网络诊断"
    echo "4.  use repo               使用软件源"
    echo "5.  sysupgrade             升级系统"
    echo "6.  debug                  日志收集"
    echo "7.  setup bypass gateway   旁路网关"
    echo "0.  Exit                   退出脚本"
    echo "----------------------------------------"  
    echo "请选择数字按下回车: "
    choice=""
    while [ -z $choice ]; do
      read choice
    done

    case $choice in
        1)
            setip
        ;;
        2) 
            catwrt_update
        ;;
        3)
            catwrt_network_diagnostics
        ;; 
        4)
            use_repo
        ;;
        5)
            catwrt_sysupgrade
        ;;
	6)
            debug
        ;;
	7)
            bypass_gateway
        ;;
        0)
            echo "Exit CatTools 退出脚本..."
            break
        ;;
        *)
            echo "无效的选择, 请重新输入"
        ;;
    esac

    sleep 1   
done

echo "结束!"
