#!/bin/bash
###
 # @Author: miaoermua
 # @Date: 2023-12-12 16:59:27
 # @LastEditors: miaoermua
 # @LastEditTime: 2023-12-27 13:33:07
 # @FilePath: \undefinedd:\Git\cattools\cattools.sh
### 

default_ip="192.168.1.4"
release="/etc/catwrt_release"
amd64_repo="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/amd64/distfeeds.conf"
mt798x_repo="https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/mt798x/distfeeds.conf"
amd64_efi_boot_sysup="https://github.com/miaoermua/CatWrt/releases/download/v23.8/CatWrt.v23.8.x86_64-squashfs-combined-efi.img.gz"
amd64_bios_boot_sysup="https://github.com/miaoermua/CatWrt/releases/download/v23.8/CatWrt.v23.8.x86_64-squashfs-combined.img.gz"

# Check OpenWrt

if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root user"
    exit 1
fi

release=$(cat /etc/openwrt_release)

if [[ $release =~ "OpenWrt" ]]; then
  echo "$(date) - Starting CatWrt Network Diagnostics"  
else
  echo "Abnormal system environment..."
  echo " "
  exit 1
fi

update(){
    if ! curl -fsSL https://service.miaoer.xyz/cattools/cattools.sh -o $(readlink -f "$0"); then
        echo "无法连接更新站点"
        
        if ! curl -fsSL https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/repo/mt798x/cattools.sh -o $(readlink -f "$0"); then
            echo "无法连接更新仓库" 

           if ! curl -fsSL https://raw.githubusercontent.com/miaoermua/service/main/cattools/cattools.sh -o $(readlink -f "$0"); then
               echo "无法连接更新仓库" 
               echo "无法连接互联网,请联系作者."
               return 
           fi
        
    fi
    
    exec $(readlink -f "$0")
}

setip(){
    read -p "请输入 IP(默认为 $default_ip): " input_ip
    if [ -z $input_ip ]; then
        input_ip=$default_ip 
    fi

    uci set network.lan.ipaddr=$input_ip 
    uci commit network
    /etc/init.d/network restart
    
    echo "默认IP已设置为 $input_ip"
}

catwrt_update(){
    /usr/bin/catwrt-update  
}

catwrt_network_diagnostics(){
    /usr/bin/catnd
}

use_repo(){
    echo "你需要同意 CatWrt 软件源用户协议,请确认是否继续 (y/n)"
    read -t 10 -p "您有 10 秒选择,输入 y 继续,其他退出:" confirm
    [ "$confirm" != y ] && return
    
    arch=$(uname -m)
    
    # Check ARCH release
    model=$(grep "Model:" $release | cut -d ' ' -f2)

    if [[ $model =~ "mt798x" ]]; then
        # mt798x  
		curl -o /etc/opkg/distfeeds.conf $mt798x_repo 
    
    elif [ "$arch" = "x86_64" ]; then
    	# amd64
        curl -o /etc/opkg/distfeeds.conf $amd64_repo
        
    else
        echo "不支持的机型: $model"
        return
    fi

}

catwrt_sysupgrade(){
    
    # 检测架构
    if [[ $(uname -m) =~ "x86_64" ]]; then
        echo "CatWrt ARCH: x86_64(AMD64)"
        
        # 检测磁盘空间
        size=$(fdisk -l /dev | grep "Disk /dev" | awk '{print $5}') 
        size=${size%\*}
        if [[ $size > 820 ]]; then
            echo "磁盘空间超过限制,升级中止"
            exit
        fi
        
        # 检测EFI分区 
        if [[ -b /dev/sda128 || -b /dev/vda128 ]]; then
            efi_part=true
        else
            efi_part=false
        fi
        
        # 用户确认 
        echo "将升级系统,存在风险,请先确认(y/n), 30秒后默认n"
        read -t 30 confirm
        confirm=${confirm:-n}
        
        # 执行升级
        if [[ $confirm =~ [Yy] ]]; then
            if [[ $efi_part == true ]]; then
                sysupgrade -v $amd64_efi_boot_sysup
            else
                sysupgrade -v $amd64_bios_boot_sysup
            fi
        else
            echo "用户已取消升级"
        fi
        
    else
        echo "非 x86_64 架构,跳过升级"
    fi
}

debug(){

        if [ -f /www/logs.txt ]; then
              rm /www/logs.txt
        fi

           cat /etc/banner > /www/logs.txt
           cat /etc/catwrt_release > /www/logs.txt
           logread >> /www/logs.txt
           dmesg >> /www/logs.txt

        lan_ip=$(uci get network.lan.ipaddr)
	
        echo "系统日志已收集到 /www/logs.txt" 
        echo "访问下载 http://$lan_ip/logs.txt"
	exit
}

bypass_gateway(){

        echo "没做完"
        exit
}
	
update

while :; do
    clear
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
