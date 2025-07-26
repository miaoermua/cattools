#!/bin/bash
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

# installed
install_cattools() {
set -
    if [ ! -f /usr/bin/cattools ]; then
        echo "cattools not found, installing..."
        if curl --silent --connect-timeout 5 -o /usr/bin/cattools https://raw.miaoer.net/cattools/cattools.sh; then
            echo "cattools installed successfully from the first URL."
        elif curl --silent --connect-timeout 5 -o /usr/bin/cattools https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh; then
            echo "cattools installed successfully from the second URL."
        else
            echo "Failed to download cattools from both URLs."
            exit 1
        fi
        chmod +x /usr/bin/cattools
    fi
    echo "cattools is installed successfully!"
    echo "please type ‘cattools’ or ‘/usr/bin/cattools’ to run it."
set +
}

install_cattools
