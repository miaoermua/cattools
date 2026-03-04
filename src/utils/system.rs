/* src/utils/system.rs */

use crate::error::{CatoolsError, Result};
use std::process::Command;

pub fn check_root() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| CatoolsError::CommandError(format!("Failed to check user ID: {}", e)))?;

    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if uid != "0" {
        return Err(CatoolsError::CommandError(
            "This tool requires root privileges. Please run with sudo or as root.".to_string(),
        ));
    }

    Ok(())
}

pub fn check_openwrt() -> Result<()> {
    if !std::path::Path::new("/etc/openwrt_release").exists() {
        return Err(CatoolsError::CommandError(
            "This tool is designed for OpenWrt/CatWrt systems.".to_string(),
        ));
    }
    Ok(())
}

pub fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| CatoolsError::CommandError(format!("Failed to execute {}: {}", cmd, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CatoolsError::CommandError(format!(
            "Command {} failed: {}",
            cmd, stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn run_shell(command: &str) -> Result<String> {
    run_command("sh", &["-c", command])
}

pub fn download_text(url: &str) -> Result<String> {
    run_command("uclient-fetch", &["-qO-", url])
        .or_else(|_| run_command("wget", &["-qO-", url]))
        .or_else(|_| run_command("curl", &["-fsSL", url]))
        .map_err(|e| CatoolsError::ApiError(format!("下载失败: {}", e)))
}

pub fn download_to_file(url: &str, path: &str) -> Result<()> {
    run_command("uclient-fetch", &["-qO", path, url])
        .or_else(|_| run_command("wget", &["-qO", path, url]))
        .or_else(|_| run_command("curl", &["-fsSL", "-o", path, url]))
        .map_err(|e| CatoolsError::ApiError(format!("下载失败: {}", e)))?;
    Ok(())
}

pub fn url_exists(url: &str) -> bool {
    if run_command("curl", &["--output", "/dev/null", "--silent", "--head", "--fail", url]).is_ok() {
        return true;
    }

    if run_command("wget", &["--spider", "-q", url]).is_ok() {
        return true;
    }

    if run_command("uclient-fetch", &["--spider", "-q", url]).is_ok() {
        return true;
    }

    false
}

pub fn restart_service(service: &str) -> Result<()> {
    run_command("/etc/init.d", &[service, "restart"])?;
    Ok(())
}

pub fn patch_banner_domains() -> Result<()> {
    let banner_path = "/etc/banner";
    if let Ok(content) = std::fs::read_to_string(banner_path) {
        let new_content = content.replace("miaoer.xyz", "miaoer.net");
        std::fs::write(banner_path, new_content)?;
    }
    Ok(())
}

pub fn patch_catwrt_release() -> Result<()> {
    let release_path = "/etc/catwrt_release";
    if !std::path::Path::new(release_path).exists() {
        // Generate default release file
        let content = "CATWRT_RELEASE=\"v25.8\"\nCATWRT_ARCH=\"unknown\"\n";
        std::fs::write(release_path, content)?;
    }
    Ok(())
}
