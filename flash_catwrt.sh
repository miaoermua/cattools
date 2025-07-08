#!/bin/sh

if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root user"
    exit 1
fi

disks=$(lsblk -dno NAME,SIZE | grep -E '^sd|^vd|^nvme')

disk_count=$(echo "$disks" | wc -l)

if [ "$disk_count" -eq 1 ]; then
    target_disk=$(echo "$disks" | awk '{print $1}')
    echo "[INFO] 检测到一个磁盘：/dev/$target_disk"
else
    echo "[INFO] 检测到多个磁盘，请选择目标磁盘："
    

    index=1
    echo "$disks" | while read -r disk; do
        echo "$index) $disk"
        index=$((index + 1))
    done

    read -p "[INFO] 请输入目标磁盘的数字编号： " disk_choice
    if ! echo "$disk_choice" | grep -qE '^[0-9]+$'; then
        echo "[ERROR] 无效输入，必须为数字"
        exit 1
    fi

    target_disk=$(echo "$disks" | sed -n "${disk_choice}p" | awk '{print $1}')
    if [ -z "$target_disk" ]; then
        echo "[ERROR] 无效的选择"
        exit 1
    fi
    
    echo
    echo "[INFO] 你选择的目标磁盘是：/dev/$target_disk"
fi

# 下载源选择
echo "[INFO] 请选择固件下载源："
echo "1) GitHub（可选 ghproxy 加速）"
echo "2) 服务器直连（release.miaoer.net）"
read -p "[INFO] 输入选项 [1/2]: " source_choice

if [ "$source_choice" = "1" ]; then
    read -p "[INFO] 是否使用 ghproxy 加速下载固件? (y/n): " use_ghproxy
    if [ "$use_ghproxy" = "y" ] || [ "$use_ghproxy" = "Y" ]; then
        GH_PROXY_PREFIX="https://gh-proxy.com/"
        echo "[INFO] 将使用 gh-proxy.com 加速"
    else
        GH_PROXY_PREFIX=""
        echo "[INFO] 不使用加速"
    fi
    BASE_URL="${GH_PROXY_PREFIX}https://github.com/miaoermua/CatWrt/releases/download/v24.9/"
else
    BASE_URL="https://release.miaoer.net/CatWrt/v24.9/amd64/"
    echo "[INFO] 使用服务器直连"
fi

# 拼接文件名与完整 URL
if [ "$efi_mode" -eq 1 ]; then
    FILENAME="CatWrt.v24.9.amd64-squashfs-combined-efi.img.gz"
else
    FILENAME="CatWrt.v24.9.amd64-squashfs-combined.img.gz"
fi
firmware_url="${BASE_URL}${FILENAME}"

# 下载固件
firmware_file="/tmp/catwrt_sysupgrade.img.gz"
echo "[INFO] 开始下载固件：$firmware_url"
wget --timeout=30 --tries=3 -O "$firmware_file" "$firmware_url"
if [ $? -ne 0 ] || [ ! -f "$firmware_file" ]; then
    echo "[ERROR] 固件下载失败"
    exit 1
fi

# 解压固件
echo "[INFO] 解压固件..."
gunzip -f "$firmware_file"
firmware_file="/tmp/catwrt_sysupgrade.img"

if [ ! -f "$firmware_file" ]; then
    echo "[ERROR] 固件解压失败"
    exit 1
fi

echo "[INFO] 固件已解压到 $firmware_file 即将使用 dd 命令覆写 /dev/$target_disk"
echo "[INFO] 此操作将永久删除所有数据，无法恢复。按 [ENTER] 回车键继续，或按 [Ctrl]+[C] 终止操作"
read -r

# 写入固件
dd if="$firmware_file" of="/dev/$target_disk" bs=4M


echo "Successful!"
echo
echo "固件覆写成功，重启后使用 cattools 配置 CatWrt"
echo
echo "重启后可使用 cattools 命令配置 CatWrt，或者自行配置"
echo "默认 IP: 192.168.1.4"
echo "默认密码: password"
echo
reboot
