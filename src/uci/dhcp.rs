/* src/uci/dhcp.rs */

#![allow(dead_code)]

use crate::error::Result;
use crate::uci::Uci;

pub fn set_dns(_uci: &Uci, _dns: &[&str]) -> Result<()> {
    // TODO: implement DNS configuration
    Ok(())
}

pub fn configure_dhcp_pool(_uci: &Uci, _start: u8, _limit: u8) -> Result<()> {
    // TODO: implement DHCP pool configuration
    Ok(())
}

pub fn enable_dhcp(_uci: &Uci, _enable: bool) -> Result<()> {
    // TODO: implement DHCP enable/disable
    Ok(())
}

pub fn set_dhcp_force(_uci: &Uci, _force: bool) -> Result<()> {
    // TODO: implement DHCP force mode
    Ok(())
}
