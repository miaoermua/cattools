/* src/constants.rs */

// Common package list (203 packages from bash script)
pub const COMMON_PACKAGES: &[&str] = &[
    // Network tools
    "luci-app-ssr-plus",
    "luci-app-passwall",
    "luci-app-passwall2",
    "luci-app-openclash",
    "luci-app-zerotier",
    "luci-app-wireguard",
    "luci-app-tailscale",
    "luci-app-frpc",
    "luci-app-frps",
    "luci-app-nps",
    "luci-app-n2n",
    "luci-app-shadowsocks-libev",
    "luci-app-v2ray",
    "luci-app-xray",
    "luci-app-trojan",
    "luci-app-clash",
    "shadowsocks-libev-ss-local",
    "shadowsocks-libev-ss-redir",
    "shadowsocks-libev-ss-tunnel",
    "v2ray-core",
    "xray-core",
    // System tools
    "luci-app-ttyd",
    "luci-app-dockerman",
    "luci-app-samba4",
    "luci-app-usb-printer",
    "luci-app-diskman",
    "luci-app-netdata",
    "luci-app-statistics",
    "luci-app-uhttpd",
    "luci-app-upnp",
    "luci-app-wol",
    "luci-app-nlbwmon",
    "luci-app-adblock",
    "ttyd",
    "docker",
    "dockerd",
    "docker-compose",
    "samba4-server",
    "samba4-client",
    // Download tools
    "luci-app-qbittorrent",
    "luci-app-transmission",
    "luci-app-aria2",
    "qbittorrent",
    "transmission-daemon",
    "transmission-web",
    "aria2",
    // Game accelerators
    "luci-app-uugamebooster",
    "luci-app-xlnetacc",
    "luci-app-LingTiGameAcc",
    "luci-app-natter",
    // Themes
    "luci-theme-design",
    "luci-theme-argon",
    "luci-theme-bootstrap",
    "luci-theme-material",
    "luci-app-design-config",
    "luci-app-argon-config",
    // Programming environments
    "python3",
    "python3-pip",
    "node",
    "npm",
    "vim",
    "nano",
    "git",
    "git-http",
    "curl",
    "wget",
    "rsync",
    "screen",
    "tmux",
    // Network utilities
    "iperf3",
    "tcpdump",
    "nmap",
    "mtr",
    "socat",
    "netcat",
    "bind-dig",
    "bind-host",
    "openssh-sftp-server",
    // System utilities
    "htop",
    "iotop",
    "lsof",
    "strace",
    "procps-ng-ps",
    "coreutils",
    "coreutils-nohup",
    "bash",
    "zsh",
    // File system
    "e2fsprogs",
    "ntfs-3g",
    "exfat-utils",
    "f2fs-tools",
    "btrfs-progs",
    // Compression
    "gzip",
    "bzip2",
    "xz",
    "zip",
    "unzip",
    "p7zip",
    "tar",
    // Database
    "mariadb-server",
    "mariadb-client",
    "postgresql",
    "redis",
    "sqlite3-cli",
    // Web servers
    "nginx",
    "nginx-ssl",
    "apache",
    "lighttpd",
    "php8",
    "php8-cgi",
    "php8-fastcgi",
    "php8-fpm",
    "php8-mod-curl",
    "php8-mod-gd",
    "php8-mod-json",
    "php8-mod-mbstring",
    "php8-mod-mysqli",
    "php8-mod-pdo",
    "php8-mod-pdo-mysql",
    "php8-mod-session",
    "php8-mod-xml",
    "php8-mod-zip",
    // VPN
    "openvpn-openssl",
    "openvpn-easy-rsa",
    "strongswan",
    "xl2tpd",
    "pptpd",
    "softethervpn",
    // DNS
    "dnsmasq-full",
    "bind-server",
    "unbound",
    "smartdns",
    // Firewall
    "iptables",
    "ip6tables",
    "ipset",
    "conntrack",
    // Monitoring
    "collectd",
    "snmpd",
    "vnstat",
    // Additional
    "kmod-usb-storage",
    "kmod-usb-ohci",
    "kmod-usb-uhci",
    "kmod-usb2",
    "kmod-usb3",
    "kmod-fs-ext4",
    "kmod-fs-ntfs",
    "kmod-fs-exfat",
    "kmod-fs-vfat",
    "block-mount",
    "blkid",
    "swap-utils",
    "fdisk",
    "gdisk",
    "parted",
    "lsblk",
    "smartmontools",
];

// API URLs
pub const API_UPDATE_URL: &str = "https://api.miaoer.net/api/v2/snippets/catwrt/update";
#[allow(dead_code)]
pub const API_REPO_CONFIG_URL: &str = "https://api.miaoer.net/api/v2/snippets/catwrt/repo-config";
#[allow(dead_code)]
pub const BASE_REPO_URL: &str = "https://raw.miaoer.net/cattools/repo";

// Sysupgrade URLs
pub const SYSUP_AMD64_URL: &str =
    "https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/amd64/sysup_efi";
pub const SYSUP_MT7621_URL: &str =
    "https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/mt7621/sysup";
pub const SYSUP_MT798X_URL: &str =
    "https://raw.githubusercontent.com/miaoermua/cattools/main/sysupgrade/mt798x/sysup";

// Default values
pub const DEFAULT_IP: &str = "192.168.1.4";
#[allow(dead_code)]
pub const RELEASE_FILE: &str = "/etc/catwrt_release";
pub const BACKUP_FILE: &str = "/etc/catwrt_opkg_list_installed";

// Mirror options
pub const MIRROR_OPTIONS: &[&str] = &[
    "miaoer.net (主站)",
    "Github-Pages",
    "Cloudflare-Netlify",
    "Netlify (默认)",
    "Cloudflare-Vercel",
    "Vercel",
];

pub const BETA_MIRROR_OPTIONS: &[&str] = &["netlify", "vercel (默认)"];
