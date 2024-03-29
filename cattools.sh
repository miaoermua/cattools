#!/bin/bash
###
 # @Author: miaoermua
 # @Date: 2023-12-12 16:59:27
 # @LastEditors: 喵二
 # @LastEditTime: 2024-01-13 17:45:49
 # @FilePath: \undefinedn:\Git\cattools\cattools.sh
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
        if [[ -b /dev/sda128 || -b /dev/vda128 || -b /dev/nvme0n1p128]]; then
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

        lan_ip=$(uci get network.lan.ipaddr)
	
        echo "日志已收集到 /www/logs.txt" 
        echo "使用浏览器访问下载 http://$lan_ip/logs.txt"
	exit
}

setup(){

read -p "Do you want toNetwork Setup? 是否使用网络向导? (Enter/1) " use_wizard
    if [ "$use_wizard" != 1 ]; then
      exit 0
    fi

echo "CatWrt default IP is 192.168.1.4. 默认 CatWrt IP 为 192.168.1.4"
read -p "Do you want to change IP address? 是否修改IP地址? (Enter/1) " change_ip
    if [ "$change_ip" = 1 ]; then
      read -p "Please input new IP: " new_ip
      uci set network.lan.ipaddr=$new_ip
    fi

echo "Recommended DNS: 223.6.6.6 119.29.29.99. 推荐使用的DNS: 223.6.6.6 119.29.29.99" 
read -p "Use recommended DNS servers? 使用推荐的DNS服务器? (Enter/1) " use_recommended_dns
    if [ "$use_recommended_dns" = 1 ]; then
      read -p "Please input DNS servers separated by space 请输入以空格分隔的DNS服务器: " dns_servers
      uci set network.lan.dns="$dns_servers"
    else
      uci set network.lan.dns="223.6.6.6 119.29.29.99"
    fi

echo "IPv6 is enabled by default. IPv6 默认是开启的"
read -p "Disable IPv6? 是否禁用IPv6? (Enter/1) " disable_ipv6
    if [ "$disable_ipv6" = 1 ]; then
      uci delete dhcp.lan.dhcpv6 
      uci delete dhcp.lan.ra
      uci delete dhcp.lan.ra_management
      uci delete network.lan.ip6assign
    fi

echo "Default connection mode is DHCP. 默认模式为 DHCP"
read -p "Use PPPoE dial up instead? 使用PPPoE拨号上网? (Enter/1) " use_pppoe
    if [ "$use_pppoe" = 1 ]; then
      read -p "Please input PPPoE username: " pppoe_user
      read -p "Please input PPPoE password: " pppoe_pass
      uci set network.wan.proto=pppoe
      uci set network.wan.username=$pppoe_user
      uci set network.wan.password=$pppoe_pass
    fi  

echo "Default client IP range: 30 to 200. 默认客户端 IP 段为 30 到 200"
read -p "Set custom client IP range instead? 设置自定义客户端IP段? (Enter/1)" custom_ip_range
    if [ "$custom_ip_range" = 1 ]; then
      read -p "Please input start IP: " dhcp_start
      read -p "Please input end IP: " dhcp_limit
      uci set dhcp.lan.start=$dhcp_start
      uci set dhcp.lan.limit=$dhcp_limit 
    fi
echo "WiFi 部分将等待完善!"

uci commit

/etc/init.d/network restart
/etc/init.d/dnsmasq restart
/etc/init.d/firewall restart

ping -c 2 bilibili.com > /dev/null

    if [ $? -eq 0 ]; then
      echo "Network connectivity OK!"  
    else
      lan_ip=$(uci get network.lan.ipaddr)
        echo "Network error, bilibili.com ping failed."
        echo "Please login to LuCI interface: http://$lan_ip to check settings."
    fi

echo "Network Wizard completed!"

bypass_gateway(){

        echo "没做完"
        exit
}

update

while true; do
  clear
  echo "                CatTools"
  echo "----------------------------------------"
  echo "1. Setup Network"
  echo "2. Set IP Address"  
  echo "3. Check Updates"
  echo "4. Network Diagnostics"
  echo "5. Use Custom Repo"
  echo "6. System Upgrade"
  echo "7. Collect Debug Logs" 
  echo "8. Setup Bypass Gateway"
  echo "0. Exit"
  echo "----------------------------------------"
  echo -n "Please enter your choice: "
  read choice

  case $choice in
    1)
      setup
      ;;
    2)
      setip
      ;;
    3)
      catwrt_update
      ;;
    4)
      catwrt_network_diagnostics
      ;;
    5)
      use_repo
      ;; 
    6)
      catwrt_sysupgrade
      ;;
    7)
      debug
      ;;
    8)
      bypass_gateway
      ;;
    0)
      echo "Exiting..."
      break
      ;;
    *)
      echo "Invalid choice, please try again"
      ;;
  esac

  sleep 1
done

echo "Done!"
