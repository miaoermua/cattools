#!/bin/sh

if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root user"
    exit 1
fi

if ! grep -q "OpenWrt" /etc/openwrt_release 2>/dev/null; then
    echo "Your system is not supported!"
    exit 1
fi

total_mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
if [ "$total_mem" -lt 1048576 ]; then
    echo "Error: At least 1G of total memory is required"
    exit 1
fi

root_disk=$(df / | awk 'NR==2 {print $2}')
if [ "$root_disk" -lt 1048576 ]; then
    echo "Error: At least 1G of total disk space is required"
    exit 1
fi

if ! grep -q "x86" /proc/cpuinfo; then
    echo "Error: This script only supports x86 devices"
    exit 1
fi

release_info=$(cat /etc/openwrt_release)
if echo "$release_info" | grep -qE "iStoreOS|QWRT|ImmortalWrt|LEDE"; then
    echo "Detected third-party firmware: $(echo "$release_info" | grep -E "iStoreOS|QWRT|ImmortalWrt|LEDE")"
fi

board_name=$(cat /tmp/sysinfo/board_name 2>/dev/null)
if [ -n "$board_name" ]; then
    echo "Board name: $board_name"
else
    echo "Board name information not found"
fi

efi_mode=0

if [ -d /sys/firmware/efi ]; then
  efi_mode=1
fi

is_efi_boot() {
    [ -e /dev/sda128 ] || [ -e /dev/vda128 ] || [ -e /dev/nvme0n1p128 ] || [ "$efi_mode" -eq 1 ]
}

AMD64_EFI_SYSUP="https://mirror.ghproxy.com/https://github.com/miaoermua/CatWrt/releases/download/v23.8/CatWrt.v23.8.x86_64-efi-squashfs-combined.img.gz"
AMD64_BIOS_SYSUP="https://mirror.ghproxy.com/https://github.com/miaoermua/CatWrt/releases/download/v23.8/CatWrt.v23.8.x86_64-bios-squashfs-combined.img.gz"

TIMEOUT=30
TRIES=3

download_firmware() {
    url=$1
    output=$2

    wget --timeout=$TIMEOUT --tries=$TRIES -O "$output" "$url"
    if [ $? -ne 0 ]; then
       echo "固件下载失败"
       exit 1
    fi
}

disk_count=$(lsblk -d | grep -c '^sd\|^vd\|^nvme')

if [ "$disk_count" -ne 1 ]; then
    echo "检测到多个磁盘，终止操作"
    exit 1
fi

if is_efi_boot; then
    firmware_url=$AMD64_EFI_SYSUP
else
    firmware_url=$AMD64_BIOS_SYSUP
fi

firmware_file="/tmp/catwrt_sysupgrade.img.gz"
download_firmware "$firmware_url" "$firmware_file"

if [ ! -f "$firmware_file" ]; then
    echo "固件下载失败，文件不存在"
    exit 1
fi

echo ""
echo "固件已下载到 $firmware_file。即将使用 dd 命令覆写整个磁盘 /dev/$target_disk。"
echo "此操作将永久删除所有数据，无法恢复"
echo "按回车键继续，或按 Ctrl+C 取消操作"
read -r

target_disk=$(lsblk -d | grep '^sd\|^vd\|^nvme' | awk '{print $1}')
dd if="$firmware_file" of="/dev/$target_disk" bs=4M status=progress

echo "固件更新完成"
echo ""
echo "重启后可使用 cattools 命令配置 CatWrt，或者自行配置"
echo "IP: 192.168.1.4"
echo "密码: password"

reboot
