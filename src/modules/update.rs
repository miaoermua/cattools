/* src/modules/update.rs */

use crate::api::update::fetch_update_info;
use crate::constants::{SYSUP_AMD64_URL, SYSUP_MT798X_URL, SYSUP_MT7621_URL};
use crate::error::Result;
use crate::utils::system::{download_text, run_command};
use crate::utils::validation::compare_version;
use dialoguer::{Confirm, Select};
use std::fs;

/// Check for system updates
pub fn check_update() -> Result<()> {
    println!("\n检查更新...");

    // Read release file
    let release_content = fs::read_to_string("/etc/catwrt_release")
        .unwrap_or_else(|_| "arch=amd64\nversion=v25.8".to_string());

    let current_version = release_content
        .lines()
        .find(|line| line.starts_with("version="))
        .and_then(|line| line.split('=').nth(1))
        .unwrap_or("v25.8");

    println!("当前版本: {}", current_version);

    // Fetch update info from API
    let update_info = fetch_update_info()?;

    println!("\n最新版本: {}", update_info.version);
    println!("更新时间: {}", update_info.date);

    // Compare versions
    let comparison = compare_version(current_version, &update_info.version)?;

    if comparison >= 0 {
        println!("\n✓ 您的系统已是最新版本！");
    } else {
        println!("\n发现新版本可用！");
        println!("\n更新内容:");
        for change in &update_info.changes {
            println!("  - {}", change);
        }

        if Confirm::new()
            .with_prompt("是否现在更新？")
            .default(false)
            .interact()?
        {
            system_upgrade()?;
        }
    }

    Ok(())
}

/// System upgrade
pub fn system_upgrade() -> Result<()> {
    println!("\n系统升级");

    // Read release file
    let release_content = fs::read_to_string("/etc/catwrt_release")
        .unwrap_or_else(|_| "arch=amd64\nversion=v25.8".to_string());

    let arch = release_content
        .lines()
        .find(|line| line.starts_with("arch="))
        .and_then(|line| line.split('=').nth(1))
        .unwrap_or("amd64");

    println!("当前架构: {}", arch);

    // Determine sysupgrade script URL
    let sysup_url = match arch {
        "amd64" => {
            // For amd64, need to check EFI vs BIOS
            println!("\n检测启动模式...");

            let options = ["EFI", "BIOS/Legacy"];
            let selection = Select::new()
                .with_prompt("请选择您的启动模式")
                .items(&options)
                .default(0)
                .interact()?;

            if selection == 0 {
                SYSUP_AMD64_URL
            } else {
                println!("[ERROR] BIOS/Legacy 模式暂不支持自动升级");
                println!("请手动下载固件并使用 sysupgrade 命令升级");
                return Ok(());
            }
        }
        "mt7621" => SYSUP_MT7621_URL,
        "mt798x" => SYSUP_MT798X_URL,
        _ => {
            println!("[ERROR] 不支持的架构: {}", arch);
            return Ok(());
        }
    };

    println!("\n警告: 系统升级将会重启设备！");
    println!("请确保已保存所有重要数据和配置。");

    if !Confirm::new()
        .with_prompt("确认继续升级？")
        .default(false)
        .interact()?
    {
        println!("已取消升级");
        return Ok(());
    }

    // Download sysupgrade script
    println!("\n下载升级脚本...");
    let script_content = download_text(sysup_url)?;

    let script_path = "/tmp/sysupgrade.sh";
    fs::write(script_path, script_content)?;

    // Make executable
    run_command("chmod", &["+x", script_path])?;

    // Execute upgrade script
    println!("\n开始升级...");
    println!("升级过程中请勿断电或重启设备！");

    run_command("sh", &[script_path])?;

    println!("\n✓ 升级完成！设备将自动重启...");

    Ok(())
}
