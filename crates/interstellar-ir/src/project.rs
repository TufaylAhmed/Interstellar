//! On-disk project persistence for Interstellar.

use crate::PolicyDocument;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("project not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProject {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub document: PolicyDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectListItem {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub vendor: String,
    pub rules: usize,
    pub addresses: usize,
}

pub fn default_projects_dir() -> PathBuf {
    if let Ok(p) = std::env::var("INTERSTELLAR_HOME") {
        return PathBuf::from(p).join("projects");
    }
    dirs_next_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".interstellar")
        .join("projects")
}

fn dirs_next_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

pub fn ensure_dir(dir: &Path) -> Result<(), ProjectError> {
    fs::create_dir_all(dir)?;
    Ok(())
}

pub fn save_project(
    dir: &Path,
    name: impl Into<String>,
    document: PolicyDocument,
    id: Option<String>,
    notes: Option<String>,
) -> Result<StoredProject, ProjectError> {
    ensure_dir(dir)?;
    let now = Utc::now();
    let id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let path = dir.join(format!("{id}.json"));
    let created_at = if path.exists() {
        load_project(dir, &id)?.created_at
    } else {
        now
    };
    let stored = StoredProject {
        id: id.clone(),
        name: name.into(),
        created_at,
        updated_at: now,
        document,
        notes,
    };
    fs::write(&path, serde_json::to_string_pretty(&stored)?)?;
    Ok(stored)
}

pub fn load_project(dir: &Path, id: &str) -> Result<StoredProject, ProjectError> {
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(ProjectError::NotFound(id.into()));
    }
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn delete_project(dir: &Path, id: &str) -> Result<(), ProjectError> {
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(ProjectError::NotFound(id.into()));
    }
    fs::remove_file(path)?;
    Ok(())
}

pub fn list_projects(dir: &Path) -> Result<Vec<ProjectListItem>, ProjectError> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut items = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let Ok(p) = serde_json::from_str::<StoredProject>(&text) else {
            continue;
        };
        let s = p.document.summary();
        items.push(ProjectListItem {
            id: p.id,
            name: p.name,
            created_at: p.created_at,
            updated_at: p.updated_at,
            vendor: s.vendor.as_str().into(),
            rules: s.security_rules,
            addresses: s.addresses,
        });
    }
    items.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(items)
}
