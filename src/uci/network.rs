/* src/uci/network.rs */

#![allow(dead_code)]

use crate::error::Result;
use crate::uci::Uci;

pub fn set_ip_address(uci: &Uci, ip: &str) -> Result<()> {
    uci.set("network.lan.ipaddr", ip)?;
    uci.commit("network")?;
    Ok(())
}

pub fn set_gateway(uci: &Uci, gateway: &str) -> Result<()> {
    uci.set("network.lan.gateway", gateway)?;
    Ok(())
}

pub fn set_netmask(uci: &Uci, mask: &str) -> Result<()> {
    uci.set("network.lan.netmask", mask)?;
    Ok(())
}

pub fn enable_ipv6(_uci: &Uci, _enable: bool) -> Result<()> {
    // TODO: implement IPv6 configuration
    Ok(())
}

pub fn configure_pppoe(uci: &Uci, username: &str, password: &str) -> Result<()> {
    uci.set("network.wan.proto", "pppoe")?;
    uci.set("network.wan.username", username)?;
    uci.set("network.wan.password", password)?;
    Ok(())
}

pub fn set_wan_interface(_uci: &Uci, _iface: &str) -> Result<()> {
    // TODO: implement WAN interface configuration
    Ok(())
}

pub fn bridge_interfaces(_uci: &Uci, _interfaces: &[&str]) -> Result<()> {
    // TODO: implement bridge configuration
    Ok(())
}
