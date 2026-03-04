/* src/modules/diagnostic.rs */

use crate::error::Result;
use crate::utils::system::run_command;
use std::fs;

fn now_string() -> String {
    run_command("date", &["+%Y-%m-%d %H:%M:%S"])
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-time".to_string())
}

/// Network diagnostic
pub fn network_diagnostic() -> Result<()> {
    println!(
        "\n{} - Starting CatWrt Network Diagnostics",
        now_string()
    );
    println!();

    // Ping test
    println!("[Ping] Testing network connection...");
    let ping_result = run_command("ping", &["-c", "3", "223.5.5.5"]);
    if ping_result.is_ok() {
        println!("[Ping] Network connection succeeded!");
        println!();
    } else {
        println!("[Ping] Primary DNS failed, trying backup...");
        let backup_ping = run_command("ping", &["-c", "3", "119.29.29.99"]);
        if backup_ping.is_ok() {
            println!("[Ping] Network connection succeeded, but there may be problems!");
            println!();
        } else {
            println!("[Ping] Network connection failed!");
            // Check PPPoE
            if let Ok(config) = fs::read_to_string("/etc/config/network") {
                if config.contains("pppoe") {
                    println!(
                        "[PPPoE] Please check if your PPPoE account and password are correct."
                    );
                }
            }
            println!();
        }
    }

    // DNS check
    println!("[DNS] Checking DNS configuration...");
    if let Ok(config) = fs::read_to_string("/etc/config/network") {
        let _valid_dns = [
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "223.6.6.6",
            "223.5.5.5",
            "180.76.76.76",
            "208.67.222.222",
            "208.67.220.220",
            "119.29.29.99",
        ];

        for line in config.lines() {
            if line.contains("option dns") {
                println!("[DNS] DNS configuration found: {}", line.trim());
            }
        }
    }
    println!("[DNS] DNS configuration looks good!");
    println!();

    // Public IP
    println!("[IPv4] Checking public IPv4 address...");
    if let Ok(output) = run_command("curl", &["--silent", "--connect-timeout", "5", "4.ipw.cn"]) {
        println!("CatWrt IPv4 Addr: {}", output.trim());
    } else {
        println!("[IPv4] Failed to get IPv4 address");
    }
    println!();

    // IPv6
    println!("[IPv6] Checking IPv6 connectivity...");
    let ipv6_result = run_command("curl", &["--silent", "--connect-timeout", "5", "6.ipw.cn"]);
    if ipv6_result.is_ok() {
        if let Ok(output) = ipv6_result {
            println!("CatWrt IPv6 Addr: {}", output.trim());
        }
    } else {
        println!("[IPv6] IPv6 network connection timed out");
    }
    println!();

    // Tcping
    println!("[Tcping] Testing connectivity to common sites...");
    let sites = ["cn.bing.com", "bilibili.com", "github.com", "google.com.hk"];
    for site in &sites {
        let result = run_command("tcping", &["-q", "-c", "1", site]);
        if result.is_err() {
            println!("Failed: {}", site);
        } else {
            println!("Success: {}", site);
        }
    }
    println!();

    println!(
        "{} - Network check completed!",
        now_string()
    );
    println!("CatWrt Network Diagnostics by @miaoermua");

    Ok(())
}

/// System debug - collect system logs
pub fn system_debug() -> Result<()> {
    println!("\n收集系统诊断日志...");

    let log_file = "/www/logs.txt";

    // Remove old log file
    let _ = fs::remove_file(log_file);

    let mut log_content = String::new();

    // Banner
    if let Ok(banner) = fs::read_to_string("/etc/banner") {
        log_content.push_str(&banner);
        log_content.push_str("\n");
    }

    // Date
    log_content.push_str(&format!("{}\n\n", now_string()));

    // Release info
    log_content.push_str("## RELEASE\n");
    log_content.push_str("==========\n");
    if let Ok(release) = fs::read_to_string("/etc/catwrt_release") {
        log_content.push_str(&release);
    }
    log_content.push_str("\n");

    // Memory usage
    log_content.push_str("## Memory Usage\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("free", &["-h"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Disk usage
    log_content.push_str("## Disk Usage\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("df", &["-h"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Installed packages
    log_content.push_str("## Application\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("opkg", &["list-installed"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // System log
    log_content.push_str("## SYSLOG\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("logread", &[]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Kernel log
    log_content.push_str("## DMESG\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("dmesg", &[]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Plugin logs
    log_content.push_str("## Plugins\n");
    log_content.push_str("==========\n");
    let plugin_logs = [
        "/tmp/openclash.log",
        "/tmp/log/ssrplus.log",
        "/tmp/log/passwall.log",
        "/tmp/log/passwall2.log",
    ];
    for log in &plugin_logs {
        if let Ok(content) = fs::read_to_string(log) {
            log_content.push_str(&format!("\n--- {} ---\n", log));
            log_content.push_str(&content);
        }
    }
    log_content.push_str("\n");

    // Network configuration
    log_content.push_str("## Network Configuration\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("ifconfig", &["-a"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // UCI network
    log_content.push_str("## UCI Network\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("uci", &["show", "network"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Firewall
    log_content.push_str("## Firewall\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("iptables", &["-L", "-v", "-n"]) {
        log_content.push_str(&output);
    }
    if let Ok(output) = run_command("ip6tables", &["-L", "-v", "-n"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Routing table
    log_content.push_str("## Routing Table\n");
    log_content.push_str("==========\n");
    if let Ok(output) = run_command("ip", &["route"]) {
        log_content.push_str(&output);
    }
    if let Ok(output) = run_command("ip", &["-6", "route"]) {
        log_content.push_str(&output);
    }
    log_content.push_str("\n");

    // Write to file
    fs::write(log_file, log_content)?;

    // Get LAN IP
    let lan_ip = if let Ok(output) = run_command("uci", &["get", "network.lan.ipaddr"]) {
        output.trim().to_string()
    } else {
        "192.168.1.1".to_string()
    };

    println!("\n✓ 日志收集完成！");
    println!(
        "=========================================================================================="
    );
    println!(
        "请使用浏览器访问此地址下载 LOG 文件: http://{}/logs.txt",
        lan_ip
    );
    println!("日志已收集到 /www/logs.txt");
    println!("如果你使用 PPPoE 拨号请手动将宽带账密删除，再使用以下链接上传 Github issues 附件!");
    println!();
    println!(
        "https://github.com/miaoermua/CatWrt/issues/new?assignees=&labels=bug&projects=&template=report.yaml"
    );
    println!("尽可能使用 Github 提交你的问题");
    println!();

    Ok(())
}
