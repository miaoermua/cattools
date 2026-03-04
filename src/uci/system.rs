/* src/uci/system.rs */

#![allow(dead_code)]

use crate::error::Result;
use crate::uci::Uci;

pub fn get_hostname(uci: &Uci) -> Result<String> {
    uci.get("system.@system[0].hostname")
}

pub fn set_hostname(uci: &Uci, name: &str) -> Result<()> {
    uci.set("system.@system[0].hostname", name)?;
    uci.commit("system")?;
    Ok(())
}
