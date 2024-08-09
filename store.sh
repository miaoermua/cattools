#!/bin/bash

# 远程 JSON 文件的 URL
REMOTE_JSON_URL="https://api.miaoer.xyz/api/v2/snippets/catstore/amd64_packages"

# 获取包的标签
get_tag() {
    package=\$1
    if [[ "${package}" == luci-app-* ]]; then
        echo "[luci]"
    elif [[ "${package}" == kmod-* ]]; then
        echo "[kmod]"
    elif [[ "${package}" == luci-theme-* ]]; then
        echo "[theme]"
    else
        echo "[bin]"
    fi
}

# 显示菜单并处理用户输入
show_menu() {
    local page=\$1
    local start=$((page * 25))
    local end=$((start + 24))
    echo "请选择要操作的插件（第 $((page + 1)) 页）："
    echo "序号  包名                                 标签       操作"
    echo "-----------------------------------------------------------"
    for i in $(seq $start $end); do
        if [ $i -ge ${#PACKAGES[@]} ]; then
            break
        fi
        package=${PACKAGES[$i]}
        tag=$(get_tag "${package}")
        status=$(opkg list_installed | grep -c "^${package}")
        action=""
        if [ $status -eq 0 ]; then
            action="安装"
        else
            action="卸载"
        fi
        printf "%-5s %-35s %-10s %s\n" "$((i+1))" "${package}" "${tag}" "${action}"
    done
    echo "p. 上一页"
    echo "n. 下一页"
    echo "0. 退出"
}

# 安装或卸载包
manage_package() {
    package=\$1
    status=$(opkg list_installed | grep -c "^${package}")
    if [ $status -eq 0 ]; then
        echo "安装 ${package}..."
        opkg update
        opkg install ${package}
        # 检查是否有对应的中文包，并安装
        lang_package="${package//luci-app-/luci-i18n-}-zh-cn"
        if opkg list | grep -q "^${lang_package}"; then
            opkg install ${lang_package}
        fi
    else
        echo "卸载 ${package}..."
        opkg remove ${package}
        # 检查是否有对应的中文包，并卸载
        lang_package="${package//luci-app-/luci-i18n-}-zh-cn"
        if opkg list_installed | grep -q "^${lang_package}"; then
            opkg remove ${lang_package}
        fi
    fi
}

# 主程序
main() {
    # 从远程 JSON 文件获取包列表
    response=$(curl -s "$REMOTE_JSON_URL")
    if [ $? -ne 0 ]; then
        echo "无法从远程服务器获取数据。"
        exit 1
    fi

    PACKAGES=($(echo "$response" | jq -r '.packages[]'))

    if [ ${#PACKAGES[@]} -eq 0 ]; then
        echo "没有找到包列表。"
        exit 1
    fi

    page=0
    while true; do
        show_menu $page
        read -p "输入序号选择或输入应用包名: " choice
        if [ "$choice" == "0" ]; then
            echo "退出插件商店"
            break
        elif [ "$choice" == "p" ]; then
            if [ $page -gt 0 ]; then
                page=$((page - 1))
            else
                echo "已经是第一页"
            fi
        elif [ "$choice" == "n" ]; then
            if [ $((page * 25 + 25)) -lt ${#PACKAGES[@]} ]; then
                page=$((page + 1))
            else
                echo "已经是最后一页"
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -gt 0 ] && [ "$choice" -le ${#PACKAGES[@]} ]; then
            manage_package "${PACKAGES[$((choice - 1))]}"
        elif [[ " ${PACKAGES[@]} " =~ " ${choice} " ]]; then
            manage_package "$choice"
        else
            echo "无效的选项，请重新选择"
        fi
    done
}

main
