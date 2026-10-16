//! Expedition-style workspace API: projects, import/merge, edit, export.

use axum::extract::{Multipart, Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use interstellar_analyze::{analyze, report_markdown, AnalysisReport};
use interstellar_emit::{
    apply_zone_map, dedup_objects, emit_panos_xml, emit_set_commands, parse_zone_map,
    validate_document,
};
use interstellar_ir::project::{
    create_empty_project, delete_project, import_into_project, list_projects, load_project,
    update_project, write_project, ProjectListItem, SourceConfig, StoredProject,
};
use interstellar_ir::{PolicyDocument, ValidationReport};
use interstellar_parse::{parse_text, parse_vendor_str};
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState};

#[derive(Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameProjectRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct SaveDocumentRequest {
    pub document: PolicyDocument,
}

#[derive(Serialize)]
pub struct WorkspaceProjectView {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub notes: Option<String>,
    pub sources: Vec<SourceConfig>,
    pub summary: interstellar_ir::DocumentSummary,
    pub document: PolicyDocument,
    pub validation: ValidationReport,
    pub analysis: AnalysisReport,
    pub report_markdown: String,
}

#[derive(Serialize)]
pub struct ImportResult {
    pub source: SourceConfig,
    pub project: WorkspaceProjectView,
}

fn view(p: StoredProject) -> WorkspaceProjectView {
    let validation = validate_document(&p.document);
    let analysis = analyze(&p.document);
    let report_markdown = report_markdown(&p.document, &analysis);
    let summary = p.document.summary();
    WorkspaceProjectView {
        id: p.id,
        name: p.name,
        created_at: p.created_at,
        updated_at: p.updated_at,
        notes: p.notes,
        sources: p.sources,
        summary,
        document: p.document,
        validation,
        analysis,
        report_markdown,
    }
}

pub async fn ws_list(State(state): State<AppState>) -> Result<Json<Vec<ProjectListItem>>, ApiError> {
    list_projects(&state.projects_dir)
        .map(Json)
        .map_err(|e| ApiError::bad(e.to_string()))
}

pub async fn ws_create(
    State(state): State<AppState>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<Json<WorkspaceProjectView>, ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad("project name required"));
    }
    let p = create_empty_project(&state.projects_dir, name, req.notes)
        .map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(view(p)))
}

pub async fn ws_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WorkspaceProjectView>, ApiError> {
    let p = load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    Ok(Json(view(p)))
}

pub async fn ws_rename(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RenameProjectRequest>,
) -> Result<Json<WorkspaceProjectView>, ApiError> {
    let mut p =
        load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad("project name required"));
    }
    p.name = name.to_string();
    let p = update_project(&state.projects_dir, p).map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(view(p)))
}

pub async fn ws_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    delete_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    Ok(Json(serde_json::json!({ "deleted": id })))
}

pub async fn ws_save_document(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SaveDocumentRequest>,
) -> Result<Json<WorkspaceProjectView>, ApiError> {
    let mut p =
        load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    p.document = req.document;
    let p = update_project(&state.projects_dir, p).map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(view(p)))
}

pub async fn ws_import_multipart(
    State(state): State<AppState>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<ImportResult>, ApiError> {
    let mut content = None;
    let mut filename = None;
    let mut vendor = None;
    let mut zone_map = None;
    let mut dedup = false;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                filename = field
                    .file_name()
                    .map(|s| s.to_string())
                    .or(filename);
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad(e.to_string()))?;
                content = Some(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|e| ApiError::bad(format!("file not utf-8: {e}")))?,
                );
            }
            "vendor" => {
                vendor = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| ApiError::bad(e.to_string()))?,
                );
            }
            "filename" => {
                filename = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| ApiError::bad(e.to_string()))?,
                );
            }
            "zone_map" => {
                zone_map = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| ApiError::bad(e.to_string()))?,
                );
            }
            "dedup" => {
                let t = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad(e.to_string()))?;
                dedup = t == "1" || t.eq_ignore_ascii_case("true");
            }
            _ => {}
        }
    }
    let content = content.ok_or_else(|| ApiError::bad("missing file"))?;
    let filename = filename.unwrap_or_else(|| "import.conf".into());
    ws_import_inner(state, id, filename, content, vendor, zone_map, dedup).await
}

#[derive(Deserialize)]
pub struct ImportJsonRequest {
    pub content: String,
    pub filename: Option<String>,
    pub vendor: Option<String>,
    pub zone_map: Option<String>,
    pub dedup: Option<bool>,
}

pub async fn ws_import_json(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ImportJsonRequest>,
) -> Result<Json<ImportResult>, ApiError> {
    ws_import_inner(
        state,
        id,
        req.filename.unwrap_or_else(|| "import.conf".into()),
        req.content,
        req.vendor,
        req.zone_map,
        req.dedup.unwrap_or(false),
    )
    .await
}

async fn ws_import_inner(
    state: AppState,
    id: String,
    filename: String,
    content: String,
    vendor: Option<String>,
    zone_map: Option<String>,
    dedup: bool,
) -> Result<Json<ImportResult>, ApiError> {
    let mut project =
        load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    let forced = match &vendor {
        Some(v) => parse_vendor_str(v).map_err(|e| ApiError::bad(e.to_string()))?,
        None => None,
    };
    let mut doc = parse_text(&content, forced).map_err(|e| ApiError::bad(e.to_string()))?;
    if let Some(zm) = zone_map {
        apply_zone_map(&mut doc, &parse_zone_map(&zm));
    }
    if dedup {
        let _ = dedup_objects(&mut doc);
    }
    let source = import_into_project(&mut project, filename, doc);
    if dedup {
        let _ = dedup_objects(&mut project.document);
    }
    write_project(&state.projects_dir, &project).map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(ImportResult {
        source,
        project: view(project),
    }))
}

pub async fn ws_dedup(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WorkspaceProjectView>, ApiError> {
    let mut p =
        load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    let _ = dedup_objects(&mut p.document);
    let p = update_project(&state.projects_dir, p).map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(view(p)))
}

pub async fn ws_export_xml(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let p = load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        emit_panos_xml(&p.document),
    )
        .into_response())
}

pub async fn ws_export_set(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let p = load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        emit_set_commands(&p.document),
    )
        .into_response())
}

pub async fn ws_export_ir(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let p = load_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    let body = serde_json::to_string_pretty(&p.document).map_err(|e| ApiError::bad(e.to_string()))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}
