#!/bin/sh

if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root user"
    exit 1
fi

disks=$(lsblk -dno NAME,SIZE | grep -E '^sd|^vd|^nvme')

disk_count=$(echo "$disks" | wc -l)

if [ "$disk_count" -eq 1 ]; then
    target_disk=$(echo "$disks" | awk '{print $1}')
    echo "检测到一个磁盘：/dev/$target_disk"
else
    echo "检测到多个磁盘，请选择目标磁盘："
    

    index=1
    echo "$disks" | while read -r disk; do
        echo "$index) $disk"
        index=$((index + 1))
    done

    read -p "请输入目标磁盘的数字编号： " disk_choice
    if ! echo "$disk_choice" | grep -qE '^[0-9]+$'; then
        echo "无效输入，必须为数字"
        exit 1
    fi

    target_disk=$(echo "$disks" | sed -n "${disk_choice}p" | awk '{print $1}')
    if [ -z "$target_disk" ]; then
        echo "无效的选择"
        exit 1
    fi

    echo "你选择的目标磁盘是：/dev/$target_disk"
fi

# 是否使用 ghproxy 加速
read -p "是否使用 ghproxy 加速下载固件? (y/n): " use_ghproxy
if [ "$use_ghproxy" = "y" ] || [ "$use_ghproxy" = "Y" ]; then
    echo "将使用 ghproxy 进行下载加速"
    GH_PROXY_PREFIX="https://mirror.ghproxy.com/"
else
    echo "不使用 ghproxy 加速"
    GH_PROXY_PREFIX=""
fi

# 选择是否 efi
efi_mode=0
if [ -d /sys/firmware/efi ]; then
    efi_mode=1
fi

# 添加 ghproxy
AMD64_EFI_SYSUP="${GH_PROXY_PREFIX}https://github.com/miaoermua/CatWrt/releases/download/v24.9/CatWrt.v24.9.amd64-ext4-combined-efi.img.gz"
AMD64_BIOS_SYSUP="${GH_PROXY_PREFIX}https://github.com/miaoermua/CatWrt/releases/download/v24.9/CatWrt.v24.9.amd64-ext4-combined.img.gz"

firmware_url=$([ "$efi_mode" -eq 1 ] && echo "$AMD64_EFI_SYSUP" || echo "$AMD64_BIOS_SYSUP")

# 下载固件
firmware_file="/tmp/catwrt_sysupgrade.img.gz"
wget --timeout=30 --tries=3 -O "$firmware_file" "$firmware_url"
if [ $? -ne 0 ] || [ ! -f "$firmware_file" ]; then
    echo "固件下载失败"
    exit 1
fi

echo "固件已下载到 $firmware_file。即将使用 dd 命令覆写 /dev/$target_disk。"
echo "此操作将永久删除所有数据，无法恢复。按回车键继续，或按 Ctrl+C 取消操作"
read -r

# 写入固件
dd if="$firmware_file" of="/dev/$target_disk" bs=4M status=progress

echo "固件更新完成。重启后使用 cattools 配置 CatWrt。"

echo "固件更新完成"
echo ""
echo "重启后可使用 cattools 命令配置 CatWrt，或者自行配置"
echo "IP: 192.168.1.4"
echo "密码: password"

reboot
