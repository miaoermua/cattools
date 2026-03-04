/* src/config.rs */

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub mirror_priority: Vec<String>,
    pub default_ip: String,
    pub beta_channel: bool,
    pub language: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mirror_priority: vec![
                "netlify".to_string(),
                "github".to_string(),
                "miaoer".to_string(),
            ],
            default_ip: "192.168.1.4".to_string(),
            beta_channel: false,
            language: "zh_CN".to_string(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_file()?;
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            Ok(toml::from_str(&content).unwrap_or_default())
        } else {
            Ok(Self::default())
        }
    }

    #[allow(dead_code)]
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_file()?;
        let content = toml::to_string_pretty(self).unwrap();
        std::fs::write(&config_path, content)?;
        Ok(())
    }

    pub fn config_dir() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .ok_or_else(|| {
                crate::error::CatoolsError::ConfigError("Cannot find config directory".to_string())
            })?
            .join("catools");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn config_file() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }
}
