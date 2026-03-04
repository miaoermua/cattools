/* src/api/repo.rs */

use crate::constants::API_REPO_CONFIG_URL;
use crate::error::Result;
use crate::utils::system::download_text;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RepoSource {
    pub url: String,
    #[serde(default)]
    pub beta: bool,
}

pub fn fetch_repo_source(arch: &str, version: &str) -> Result<Option<RepoSource>> {
    let body = download_text(API_REPO_CONFIG_URL)?;
    let root: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| crate::error::CatoolsError::ApiError(format!("解析软件源配置失败: {}", e)))?;

    let Some(entry) = root.get(arch).and_then(|node| node.get(version)) else {
        return Ok(None);
    };

    let source: RepoSource = serde_json::from_value(entry.clone())
        .map_err(|e| crate::error::CatoolsError::ApiError(format!("解析软件源配置失败: {}", e)))?;

    Ok(Some(source))
}
