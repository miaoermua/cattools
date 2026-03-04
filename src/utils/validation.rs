/* src/utils/validation.rs */

use crate::error::{CatoolsError, Result};

pub fn validate_ip(ip: &str) -> Result<()> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return Err(CatoolsError::ValidationError(format!(
            "Invalid IP format: {}",
            ip
        )));
    }

    for octet in &parts {
        if octet.is_empty() || octet.len() > 3 {
            return Err(CatoolsError::ValidationError("Invalid IP octet".to_string()));
        }
    }

    for octet in parts.iter().take(3) {
        octet
            .parse::<u8>()
            .map_err(|_| CatoolsError::ValidationError("Invalid IP octet".to_string()))?;
    }

    let pd = parts[3]
        .parse::<u8>()
        .map_err(|_| CatoolsError::ValidationError("Invalid IP octet".to_string()))?;

    if !(1..=254).contains(&pd) {
        return Err(CatoolsError::ValidationError(
            "Last octet must be 1-254".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_version(ver: &str) -> Result<()> {
    let Some(rest) = ver.strip_prefix('v') else {
        return Err(CatoolsError::ValidationError(format!(
            "Invalid version format: {}",
            ver
        )));
    };

    let Some((year, month)) = rest.split_once('.') else {
        return Err(CatoolsError::ValidationError(format!(
            "Invalid version format: {}",
            ver
        )));
    };

    let year_ok = year.len() == 2 && year.bytes().all(|c| c.is_ascii_digit());
    let month_ok = !month.is_empty() && month.len() <= 2 && month.bytes().all(|c| c.is_ascii_digit());
    let month_no_leading_zero = month.len() == 1 || !month.starts_with('0');

    if !(year_ok && month_ok && month_no_leading_zero) {
        return Err(CatoolsError::ValidationError(format!(
            "Invalid version format: {}",
            ver
        )));
    }

    Ok(())
}

pub fn parse_version(ver: &str) -> Result<(u32, u32)> {
    validate_version(ver)?;

    let rest = ver
        .strip_prefix('v')
        .ok_or_else(|| CatoolsError::ValidationError("Cannot parse version".to_string()))?;

    let (year_str, month_str) = rest
        .split_once('.')
        .ok_or_else(|| CatoolsError::ValidationError("Cannot parse version".to_string()))?;

    let year: u32 = year_str
        .parse()
        .map_err(|_| CatoolsError::ValidationError("Cannot parse version".to_string()))?;
    let month: u32 = month_str
        .parse()
        .map_err(|_| CatoolsError::ValidationError("Cannot parse version".to_string()))?;

    Ok((year, month))
}

pub fn compare_version(v1: &str, v2: &str) -> Result<i8> {
    let (y1, m1) = parse_version(v1)?;
    let (y2, m2) = parse_version(v2)?;

    if y1 > y2 || (y1 == y2 && m1 > m2) {
        Ok(1)
    } else if y1 < y2 || (y1 == y2 && m1 < m2) {
        Ok(-1)
    } else {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.254").is_ok());
        assert!(validate_ip("256.1.1.1").is_err());
        assert!(validate_ip("192.168.1").is_err());
    }

    #[test]
    fn test_version_compare() {
        assert!(validate_version("v25.08").is_err());
        assert_eq!(compare_version("v25.8", "v24.12").unwrap(), 1);
        assert_eq!(compare_version("v24.12", "v25.8").unwrap(), -1);
        assert_eq!(compare_version("v25.8", "v25.8").unwrap(), 0);
    }
}
