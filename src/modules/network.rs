/* src/modules/network.rs */

use crate::config::Config;
use crate::constants::DEFAULT_IP;
use crate::error::Result;
use crate::uci::Uci;
use crate::utils::system::{restart_service, run_command};
use crate::utils::validation::validate_ip;
use dialoguer::{Confirm, Input};

/// Set IP address
pub fn set_ip_address(config: &Config) -> Result<()> {
    println!("\n设置 IP 地址");

    let ip: String = Input::new()
        .with_prompt(format!("请输入 IP (默认为 {})", config.default_ip))
        .default(config.default_ip.clone())
        .interact_text()?;

    // Validate IP
    validate_ip(&ip)?;

    // Set IP using UCI
    let uci = Uci::new();
    uci.set("network.lan.ipaddr", &ip)?;
    uci.commit("network")?;

    // Restart network service
    restart_service("network")?;

    println!("✓ IP 已设置为: {}", ip);
    Ok(())
}

/// Configure bypass gateway
pub fn configure_bypass_gateway() -> Result<()> {
    println!("\n旁路网关配置");

    // Get primary router IP
    let router_ip: String = loop {
        let ip: String = Input::new()
            .with_prompt("请输入主路由的 IP 地址 (如: 192.168.31.1)")
            .interact_text()?;

        if ip.is_empty() {
            println!("[ERROR] 主路由 IP 地址不能为空，请重新输入。");
            continue;
        }

        if !ip.starts_with("10.") && !ip.starts_with("172.") && !ip.starts_with("192.168.") {
            println!("[ERROR] 输入的 IP 地址无效，请输入有效的 IP 地址");
            continue;
        }

        break ip;
    };

    // Extract subnet
    let parts: Vec<&str> = router_ip.split('.').collect();
    let subnet = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    // Scan for available IP
    println!(
        "[INFO] 正在扫描 {}.4 到 {}.10，查找未被占用的本机 IP...",
        subnet, subnet
    );

    let mut default_device_ip = String::new();
    for i in 4..=10 {
        let candidate_ip = format!("{}.{}", subnet, i);
        print!("[INFO] 检测 {}... ", candidate_ip);

        // Try ping
        let result = run_command("ping", &["-c", "1", "-W", "1", &candidate_ip]);
        if result.is_err() {
            // IP is available
            default_device_ip = candidate_ip.clone();
            println!("可用!");
            println!("[INFO] 找到可用的 IP 地址：{}", default_device_ip);
            break;
        } else {
            println!("已占用");
        }
    }

    // Get device IP
    let device_ip: String = if default_device_ip.is_empty() {
        println!("\n[ERROR] 没有找到可用的 IP 地址，请手动指定。");
        Input::new()
            .with_prompt("请输入本机 IP 地址")
            .interact_text()?
    } else {
        Input::new()
            .with_prompt(format!(
                "建议使用本机 IP 地址为 {}，按回车确认或输入新的 IP 地址",
                default_device_ip
            ))
            .default(default_device_ip)
            .interact_text()?
    };

    println!("\n=============================");
    println!("主路由 IP 地址：{}", router_ip);
    println!("本机(旁路网关) IP 地址：{}", device_ip);
    println!("=============================\n");

    // DNS configuration
    let dns = if Confirm::new()
        .with_prompt("使用推荐的 DNS 服务器 223.6.6.6 223.5.5.5?")
        .default(true)
        .interact()?
    {
        "223.6.6.6 223.5.5.5".to_string()
    } else {
        Input::new()
            .with_prompt("请输入 DNS 服务器（空格分隔）")
            .interact_text()?
    };

    // Configure network
    let uci = Uci::new();
    uci.set("network.lan.ipaddr", &device_ip)?;
    uci.set("network.lan.gateway", &router_ip)?;
    uci.set("network.lan.proto", "static")?;
    uci.set("network.lan.dns", &dns)?;
    uci.commit("network")?;

    // Disable IPv6
    uci.set("dhcp.lan.dhcpv6", "disabled")?;
    uci.set("dhcp.lan.ra", "disabled")?;
    uci.commit("dhcp")?;

    // Disable DHCP
    uci.set("dhcp.lan.ignore", "1")?;
    let _ = uci.delete("dhcp.lan.leasetime");
    let _ = uci.delete("dhcp.lan.limit");
    let _ = uci.delete("dhcp.lan.start");
    uci.commit("dhcp")?;

    println!("✓ 旁路网关配置完成！");
    println!("  本机 IP: {}", device_ip);

    // Restart services
    restart_service("network")?;
    restart_service("firewall")?;
    restart_service("dnsmasq")?;

    println!("\n[INFO] 如出现 Warning 是因为旁路防火墙是这样报错的，部分配置可以忽略不影响使用");
    Ok(())
}

/// Network wizard (main network configuration function)
pub fn network_wizard() -> Result<()> {
    println!("\n\n网络向导");

    if !Confirm::new()
        .with_prompt("是否使用网络向导？")
        .default(true)
        .interact()?
    {
        println!("网络向导已退出。");
        return Ok(());
    }

    let uci = Uci::new();

    // Step 1: Detect network interfaces
    let interfaces_output = run_command("ls", &["/sys/class/net"])?;
    let interfaces: Vec<&str> = interfaces_output
        .lines()
        .filter(|line| line.starts_with("eth"))
        .collect();
    let iface_count = interfaces.len();

    if iface_count == 1 {
        println!("\n[Step2] 检测到单个网口");
        if Confirm::new()
            .with_prompt("是否进行旁路网关设置？")
            .default(true)
            .interact()?
        {
            configure_bypass_gateway()?;
            return Ok(());
        }
    }

    // Step 3: IP configuration
    println!("\n[Step3] CatWrt 默认 IP 为 192.168.1.4");
    let input_ip = if Confirm::new()
        .with_prompt("是否修改 IP 地址？")
        .default(false)
        .interact()?
    {
        let ip: String = Input::new()
            .with_prompt("请输入 IP")
            .default(DEFAULT_IP.to_string())
            .interact_text()?;
        validate_ip(&ip)?;
        uci.set("network.lan.ipaddr", &ip)?;
        println!("[INFO] IP 地址已设置为: {}", ip);
        ip
    } else {
        println!("[INFO] 保持默认 IP 地址：{}", DEFAULT_IP);
        DEFAULT_IP.to_string()
    };

    // Step 4: IPv6
    println!("\n[Step4] IPv6 默认是开启的");
    if Confirm::new()
        .with_prompt("是否禁用 IPv6 网络？")
        .default(false)
        .interact()?
    {
        let _ = uci.delete("dhcp.lan.dhcpv6");
        let _ = uci.delete("dhcp.lan.ra");
        let _ = uci.delete("dhcp.lan.ra_management");
        let _ = uci.delete("network.lan.ip6assign");
        println!("[INFO] IPv6 已禁用");
    }

    // Step 5: PPPoE configuration
    println!("\n[Step5] 默认模式为 DHCP");
    if Confirm::new()
        .with_prompt("是否进行 PPPoE 拨号？")
        .default(false)
        .interact()?
    {
        println!("如不知道账号密码，可以寻求宽带师傅，必须要正确填写!");
        let username: String = Input::new()
            .with_prompt("[PPPoE] 请输入宽带账号")
            .interact_text()?;
        let password: String = dialoguer::Password::new()
            .with_prompt("[PPPoE] 请输入宽带密码")
            .interact()?;

        uci.set("network.wan.proto", "pppoe")?;
        uci.set("network.wan.username", &username)?;
        uci.set("network.wan.password", &password)?;
        println!("[INFO] PPPoE 拨号配置已完成");
    }

    // Step 6: DNS
    println!("\n[Step6] DNS 配置");
    let dns = if Confirm::new()
        .with_prompt("使用推荐的 DNS 服务器 223.6.6.6 119.29.29.99?")
        .default(true)
        .interact()?
    {
        "223.6.6.6 119.29.29.99".to_string()
    } else {
        Input::new()
            .with_prompt("请输入 DNS 服务器（空格分隔）")
            .interact_text()?
    };
    uci.set("network.lan.dns", &dns)?;

    // Step 7: DHCP IP pool
    println!("\n[Step7] DHCP IP 池配置 (默认: 30-200)");
    if Confirm::new()
        .with_prompt("是否修改 IP 可用段？")
        .default(false)
        .interact()?
    {
        let dhcp_range: String = Input::new()
            .with_prompt("输入 DHCP IP 地址范围 (例如: 40-210)")
            .interact_text()?;

        let parts: Vec<&str> = dhcp_range.split('-').collect();
        if parts.len() == 2 {
            uci.set("dhcp.lan.start", parts[0])?;
            uci.set("dhcp.lan.limit", parts[1])?;
        }
    } else {
        uci.set("dhcp.lan.start", "30")?;
        uci.set("dhcp.lan.limit", "200")?;
    }

    // Step 8: Force DHCP
    println!("\n[Step8] 强制 DHCP 模式");
    if Confirm::new()
        .with_prompt("是否开启强制 DHCP 模式？")
        .default(true)
        .interact()?
    {
        uci.set("dhcp.lan.force", "1")?;
        println!("[INFO] 强制 DHCP 模式已开启");
    }

    // Step 9: UPnP
    println!("\n[Step9] UPnP 配置");
    if Confirm::new()
        .with_prompt("是否开启 UPNP？")
        .default(true)
        .interact()?
    {
        uci.set("upnpd.config.enabled", "1")?;
        println!("[INFO] UPNP 已开启");
    }

    // Step 10: Network interfaces (for amd64/aarch64)
    let arch_result = std::fs::read_to_string("/etc/catwrt_release");
    if let Ok(content) = arch_result {
        if content.contains("arch=amd64") || content.contains("arch=aarch64_generic") {
            println!("\n[Step10] 配置网口");
            if iface_count > 2
                && Confirm::new()
                    .with_prompt("是否配置网口？(eth0=WAN, 其他=LAN)")
                    .default(false)
                    .interact()?
            {
                configure_network_interfaces()?;
            }
        }
    }

    println!("\n[INFO] 准备重启网络服务...");
    uci.commit("network")?;
    uci.commit("dhcp")?;
    uci.commit("firewall")?;

    restart_service("network")?;
    restart_service("dnsmasq")?;
    restart_service("firewall")?;
    let _ = restart_service("miniupnpd");

    println!("✓ 网络配置完成！");
    println!("  本机 IP: {}", input_ip);

    Ok(())
}

/// Configure network interfaces
pub fn configure_network_interfaces() -> Result<()> {
    let interfaces_output = run_command("ls", &["/sys/class/net"])?;
    let interfaces: Vec<&str> = interfaces_output
        .lines()
        .filter(|line| line.starts_with("eth"))
        .collect();

    let mut bridge_ports = Vec::new();
    for iface in &interfaces {
        if *iface != "eth0" {
            bridge_ports.push(*iface);
        }
    }

    let uci = Uci::new();
    uci.set("network.wan.ifname", "eth0")?;
    uci.set("network.wan.proto", "dhcp")?;
    uci.set("network.lan.type", "bridge")?;
    uci.set("network.lan.ifname", &bridge_ports.join(" "))?;
    uci.set("network.lan._orig_ifname", &bridge_ports.join(" "))?;
    uci.set("network.lan._orig_bridge", "true")?;
    uci.set("network.wan6._orig_bridge", "false")?;
    uci.set("network.wan6._orig_ifname", "eth1")?;
    uci.set("network.wan6.ifname", "eth0")?;
    uci.set("network.wan6.reqaddress", "try")?;
    uci.set("network.wan6.reqprefix", "auto")?;

    println!(
        "[Step10] 网口已配置: WAN (ETH0), LAN ({})",
        bridge_ports.join(" ")
    );
    Ok(())
}
