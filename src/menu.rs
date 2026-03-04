/* src/menu.rs */

use crate::error::Result;
use dialoguer::Select;

#[derive(Debug, Clone)]
pub enum MenuOption {
    SetIp,
    NetworkWizard,
    ApplyRepo,
    NetworkDiagnostic,
    SystemDebug,
    CheckUpdate,
    SystemUpgrade,
    PackageBackup,
    UtilitiesMenu,
    Exit,
}

#[derive(Debug, Clone)]
pub enum UtilitiesMenuOption {
    ConfigureMihomo,
    ConfigureTailscale,
    ConfigureLeigod,
    ConfigureTtyd,
    InstallIpk,
    DeploySslCert,
    ResetPassword,
    SystemReset,
    Back,
}

pub struct Menu;

impl Menu {
    pub fn show() -> Result<MenuOption> {
        let options = vec![
            "设置 IP 地址",
            "网络向导",
            "软件源配置",
            "网络诊断",
            "系统诊断",
            "检查更新",
            "系统升级",
            "软件包备份/恢复",
            "实用工具",
            "退出",
        ];

        let selection = Select::new()
            .with_prompt("CatWrt 配置工具 - 请选择功能")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|e| {
                crate::error::CatoolsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                ))
            })?;

        Ok(match selection {
            0 => MenuOption::SetIp,
            1 => MenuOption::NetworkWizard,
            2 => MenuOption::ApplyRepo,
            3 => MenuOption::NetworkDiagnostic,
            4 => MenuOption::SystemDebug,
            5 => MenuOption::CheckUpdate,
            6 => MenuOption::SystemUpgrade,
            7 => MenuOption::PackageBackup,
            8 => MenuOption::UtilitiesMenu,
            9 => MenuOption::Exit,
            _ => MenuOption::Exit,
        })
    }

    pub fn show_utilities() -> Result<UtilitiesMenuOption> {
        let options = vec![
            "Mihomo 内核安装",
            "Tailscale 配置",
            "雷神加速器配置",
            "TTYD 免密登录",
            "IPK 安装",
            "SSL 证书部署",
            "重置 root 密码",
            "系统重置",
            "返回主菜单",
        ];

        let selection = Select::new()
            .with_prompt("实用工具 - 请选择功能")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|e| {
                crate::error::CatoolsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                ))
            })?;

        Ok(match selection {
            0 => UtilitiesMenuOption::ConfigureMihomo,
            1 => UtilitiesMenuOption::ConfigureTailscale,
            2 => UtilitiesMenuOption::ConfigureLeigod,
            3 => UtilitiesMenuOption::ConfigureTtyd,
            4 => UtilitiesMenuOption::InstallIpk,
            5 => UtilitiesMenuOption::DeploySslCert,
            6 => UtilitiesMenuOption::ResetPassword,
            7 => UtilitiesMenuOption::SystemReset,
            8 => UtilitiesMenuOption::Back,
            _ => UtilitiesMenuOption::Back,
        })
    }
}
