//! On-disk project persistence for Interstellar workspaces.

use crate::{DocumentSummary, PolicyDocument};
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

/// One imported vendor config that contributed to the project document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    pub id: String,
    pub filename: String,
    pub vendor: String,
    pub imported_at: DateTime<Utc>,
    #[serde(default)]
    pub summary: Option<DocumentSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProject {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub document: PolicyDocument,
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
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
    pub sources: usize,
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

pub fn create_empty_project(
    dir: &Path,
    name: impl Into<String>,
    notes: Option<String>,
) -> Result<StoredProject, ProjectError> {
    let now = Utc::now();
    let stored = StoredProject {
        id: Uuid::new_v4().to_string(),
        name: name.into(),
        created_at: now,
        updated_at: now,
        document: PolicyDocument::default(),
        sources: vec![],
        notes,
    };
    write_project(dir, &stored)?;
    Ok(stored)
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
    let (created_at, sources) = if let Ok(existing) = load_project(dir, &id) {
        (existing.created_at, existing.sources)
    } else {
        (now, vec![])
    };
    let stored = StoredProject {
        id: id.clone(),
        name: name.into(),
        created_at,
        updated_at: now,
        document,
        sources,
        notes,
    };
    write_project(dir, &stored)?;
    Ok(stored)
}

pub fn write_project(dir: &Path, project: &StoredProject) -> Result<(), ProjectError> {
    ensure_dir(dir)?;
    let path = dir.join(format!("{}.json", project.id));
    fs::write(&path, serde_json::to_string_pretty(project)?)?;
    Ok(())
}

pub fn update_project(dir: &Path, mut project: StoredProject) -> Result<StoredProject, ProjectError> {
    project.updated_at = Utc::now();
    write_project(dir, &project)?;
    Ok(project)
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
            sources: p.sources.len(),
        });
    }
    items.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(items)
}

/// Merge `incoming` into the project document and record the source file.
pub fn import_into_project(
    project: &mut StoredProject,
    filename: impl Into<String>,
    mut incoming: PolicyDocument,
) -> SourceConfig {
    let filename = filename.into();
    let summary = incoming.summary();
    let source = SourceConfig {
        id: Uuid::new_v4().to_string(),
        filename,
        vendor: summary.vendor.as_str().into(),
        imported_at: Utc::now(),
        summary: Some(summary),
    };
    // Prefer project vendor once set; otherwise take first import vendor.
    if project.document.vendor == crate::Vendor::Unknown {
        project.document.vendor = incoming.vendor;
    }
    // Avoid carrying duplicate source_name into merged doc noise
    incoming.source_name = Some(source.filename.clone());
    project.document.merge(incoming);
    project.sources.push(source.clone());
    project.updated_at = Utc::now();
    source
}
