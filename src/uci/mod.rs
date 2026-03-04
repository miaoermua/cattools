/* src/uci/mod.rs */

pub mod dhcp;
pub mod firewall;
pub mod network;
pub mod system;

use crate::error::Result;
use crate::utils::system::run_command;

pub struct Uci;

impl Uci {
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn get(&self, path: &str) -> Result<String> {
        let output = run_command("uci", &["get", path])?;
        Ok(output.trim().to_string())
    }

    pub fn set(&self, path: &str, value: &str) -> Result<()> {
        run_command("uci", &["set", &format!("{}={}", path, value)])?;
        Ok(())
    }

    pub fn delete(&self, path: &str) -> Result<()> {
        run_command("uci", &["delete", path])?;
        Ok(())
    }

    pub fn commit(&self, config: &str) -> Result<()> {
        run_command("uci", &["commit", config])?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn add_list(&self, path: &str, value: &str) -> Result<()> {
        run_command("uci", &["add_list", &format!("{}={}", path, value)])?;
        Ok(())
    }
}

impl Default for Uci {
    fn default() -> Self {
        Self::new()
    }
}
