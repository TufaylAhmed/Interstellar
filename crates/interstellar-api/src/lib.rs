//! Local HTTP API + static UI for Interstellar.

mod workspace;

use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use interstellar_analyze::{analyze, diff_documents, report_html, report_markdown, AnalysisReport};
use interstellar_emit::{
    apply_zone_map, dedup_objects, emit_panos_xml, emit_set_commands, parse_zone_map,
    validate_document,
};
use interstellar_ir::project::{
    delete_project, list_projects as list_disk_projects, load_project, save_project, ProjectListItem,
    StoredProject,
};
use interstellar_ir::{DocumentSummary, PolicyDocument, ValidationReport};
use interstellar_parse::{parse_text, parse_vendor_str};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    projects: Arc<Mutex<HashMap<String, Project>>>,
    projects_dir: PathBuf,
}

#[derive(Clone, Serialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub summary: DocumentSummary,
    #[serde(skip)]
    pub document: PolicyDocument,
    pub validation: ValidationReport,
    pub analysis: AnalysisReport,
}

#[derive(Deserialize)]
pub struct ConvertRequest {
    pub vendor: Option<String>,
    pub content: String,
    pub name: Option<String>,
    pub zone_map: Option<String>,
    pub dedup: Option<bool>,
    pub persist: Option<bool>,
}

#[derive(Serialize)]
pub struct ConvertResponse {
    pub project: ProjectMeta,
    pub xml: String,
    pub set_commands: String,
    pub validation: ValidationReport,
    pub analysis: AnalysisReport,
    pub ir: PolicyDocument,
    pub report_markdown: String,
}

#[derive(Serialize, Clone)]
pub struct ProjectMeta {
    pub id: String,
    pub name: String,
    pub summary: DocumentSummary,
}

#[derive(Deserialize)]
pub struct DiffRequest {
    pub left: String,
    pub right: String,
    pub left_vendor: Option<String>,
    pub right_vendor: Option<String>,
    pub left_name: Option<String>,
    pub right_name: Option<String>,
}

pub async fn serve(
    addr: SocketAddr,
    static_dir: PathBuf,
    projects_dir: PathBuf,
    open_browser: bool,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&projects_dir)?;
    let state = AppState {
        projects: Arc::new(Mutex::new(HashMap::new())),
        projects_dir,
    };

    let app = Router::new()
        .route(
            "/api/health",
            get(|| async {
                Json(serde_json::json!({
                    "ok": true,
                    "service": "interstellar",
                    "version": env!("CARGO_PKG_VERSION")
                }))
            }),
        )
        .route("/api/convert", post(convert_handler))
        .route("/api/upload", post(upload_handler))
        .route("/api/diff", post(diff_handler))
        .route("/api/projects", get(list_memory_projects))
        .route("/api/projects/{id}", get(get_project))
        .route("/api/projects/{id}/xml", get(get_project_xml))
        .route("/api/projects/{id}/set", get(get_project_set))
        .route("/api/projects/{id}/report", get(get_project_report))
        .route("/api/disk/projects", get(disk_list))
        .route("/api/disk/projects", post(disk_save_from_memory))
        .route("/api/disk/projects/{id}", get(disk_show))
        .route("/api/disk/projects/{id}", delete(disk_delete))
        // Expedition-style workspace (disk-backed)
        .route("/api/workspace/projects", get(workspace::ws_list).post(workspace::ws_create))
        .route(
            "/api/workspace/projects/{id}",
            get(workspace::ws_get)
                .delete(workspace::ws_delete)
                .patch(workspace::ws_rename),
        )
        .route(
            "/api/workspace/projects/{id}/document",
            put(workspace::ws_save_document),
        )
        .route(
            "/api/workspace/projects/{id}/import",
            post(workspace::ws_import_multipart),
        )
        .route(
            "/api/workspace/projects/{id}/import-json",
            post(workspace::ws_import_json),
        )
        .route(
            "/api/workspace/projects/{id}/dedup",
            post(workspace::ws_dedup),
        )
        .route(
            "/api/workspace/projects/{id}/export/xml",
            get(workspace::ws_export_xml),
        )
        .route(
            "/api/workspace/projects/{id}/export/set",
            get(workspace::ws_export_set),
        )
        .route(
            "/api/workspace/projects/{id}/export/ir",
            get(workspace::ws_export_ir),
        )
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr().unwrap_or(addr);
    let url = browser_url(bound);
    tracing::info!("interstellar UI/API listening on {url}");

    if open_browser {
        match open_in_browser(&url) {
            Ok(()) => tracing::info!("opened browser at {url}"),
            Err(e) => tracing::warn!("could not open browser automatically: {e} (open {url} manually)"),
        }
    } else {
        tracing::info!("open {url} in your browser (--no-open was set)");
    }

    axum::serve(listener, app).await?;
    Ok(())
}

/// Prefer localhost in the browser when bound to unspecified (0.0.0.0 / ::).
fn browser_url(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
        std::net::IpAddr::V6(v6) if v6.is_unspecified() => "127.0.0.1".to_string(),
        ip => ip.to_string(),
    };
    format!("http://{host}:{}", addr.port())
}

fn open_in_browser(url: &str) -> std::io::Result<()> {
    use std::process::Command;

    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).spawn()?.wait()?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        // `start` is a cmd builtin; empty title arg avoids swallowing the URL.
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()?
            .wait()?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open").arg(url).spawn()?.wait()?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
    {
        let _ = url;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no browser open command for this OS",
        ))
    }
}

async fn convert_handler(
    State(state): State<AppState>,
    Json(req): Json<ConvertRequest>,
) -> Result<Json<ConvertResponse>, ApiError> {
    let vendor = match &req.vendor {
        Some(v) => parse_vendor_str(v).map_err(|e| ApiError::bad(e.to_string()))?,
        None => None,
    };
    let mut doc = parse_text(&req.content, vendor).map_err(|e| ApiError::bad(e.to_string()))?;
    if doc.source_name.is_none() {
        doc.source_name = req.name.clone().or_else(|| Some("upload".into()));
    }
    if let Some(zm) = &req.zone_map {
        apply_zone_map(&mut doc, &parse_zone_map(zm));
    }
    if req.dedup.unwrap_or(false) {
        let _ = dedup_objects(&mut doc);
    }
    let name = req.name.clone().unwrap_or_else(|| "project".into());
    let built = build_project(doc, name.clone());
    let xml = emit_panos_xml(&built.document);
    let set_commands = emit_set_commands(&built.document);
    let report_markdown = report_markdown(&built.document, &built.analysis);

    if req.persist.unwrap_or(false) {
        save_project(
            &state.projects_dir,
            name,
            built.document.clone(),
            Some(built.id.clone()),
            None,
        )
        .map_err(|e| ApiError::bad(e.to_string()))?;
    }

    let response = ConvertResponse {
        project: ProjectMeta {
            id: built.id.clone(),
            name: built.name.clone(),
            summary: built.summary.clone(),
        },
        xml,
        set_commands,
        validation: built.validation.clone(),
        analysis: built.analysis.clone(),
        ir: built.document.clone(),
        report_markdown,
    };
    state
        .projects
        .lock()
        .unwrap()
        .insert(built.id.clone(), built);
    Ok(Json(response))
}

async fn upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<ConvertResponse>, ApiError> {
    let mut content = None;
    let mut vendor = None;
    let mut name = None;
    let mut zone_map = None;
    let mut dedup = None;
    let mut persist = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad(e.to_string()))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                name = field.file_name().map(|s| s.to_string()).or(name);
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
            "name" => {
                name = Some(
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
                dedup = Some(t == "1" || t.eq_ignore_ascii_case("true"));
            }
            "persist" => {
                let t = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad(e.to_string()))?;
                persist = Some(t == "1" || t.eq_ignore_ascii_case("true"));
            }
            _ => {}
        }
    }
    let content = content.ok_or_else(|| ApiError::bad("missing file field"))?;
    convert_handler(
        State(state),
        Json(ConvertRequest {
            vendor,
            content,
            name,
            zone_map,
            dedup,
            persist,
        }),
    )
    .await
}

async fn diff_handler(Json(req): Json<DiffRequest>) -> Result<Json<serde_json::Value>, ApiError> {
    let lv = match &req.left_vendor {
        Some(v) => parse_vendor_str(v).map_err(|e| ApiError::bad(e.to_string()))?,
        None => None,
    };
    let rv = match &req.right_vendor {
        Some(v) => parse_vendor_str(v).map_err(|e| ApiError::bad(e.to_string()))?,
        None => None,
    };
    let left = parse_text(&req.left, lv).map_err(|e| ApiError::bad(e.to_string()))?;
    let right = parse_text(&req.right, rv).map_err(|e| ApiError::bad(e.to_string()))?;
    let report = diff_documents(
        &left,
        &right,
        req.left_name.unwrap_or_else(|| "left".into()),
        req.right_name.unwrap_or_else(|| "right".into()),
    );
    Ok(Json(serde_json::to_value(report).unwrap()))
}

async fn list_memory_projects(State(state): State<AppState>) -> Json<Vec<ProjectMeta>> {
    let guard = state.projects.lock().unwrap();
    let list = guard
        .values()
        .map(|p| ProjectMeta {
            id: p.id.clone(),
            name: p.name.clone(),
            summary: p.summary.clone(),
        })
        .collect();
    Json(list)
}

async fn get_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let guard = state.projects.lock().unwrap();
    let p = guard
        .get(&id)
        .ok_or_else(|| ApiError::not_found("project not found"))?;
    Ok(Json(serde_json::json!({
        "id": p.id,
        "name": p.name,
        "summary": p.summary,
        "validation": p.validation,
        "analysis": p.analysis,
        "ir": p.document,
    })))
}

async fn get_project_xml(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let guard = state.projects.lock().unwrap();
    let p = guard
        .get(&id)
        .ok_or_else(|| ApiError::not_found("project not found"))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        emit_panos_xml(&p.document),
    )
        .into_response())
}

async fn get_project_set(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let guard = state.projects.lock().unwrap();
    let p = guard
        .get(&id)
        .ok_or_else(|| ApiError::not_found("project not found"))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        emit_set_commands(&p.document),
    )
        .into_response())
}

async fn get_project_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let guard = state.projects.lock().unwrap();
    let p = guard
        .get(&id)
        .ok_or_else(|| ApiError::not_found("project not found"))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        report_html(&p.document, &p.analysis),
    )
        .into_response())
}

#[derive(Deserialize)]
struct DiskSaveRequest {
    pub id: String,
    pub name: Option<String>,
}

async fn disk_list(State(state): State<AppState>) -> Result<Json<Vec<ProjectListItem>>, ApiError> {
    list_disk_projects(&state.projects_dir)
        .map(Json)
        .map_err(|e| ApiError::bad(e.to_string()))
}

async fn disk_show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<StoredProject>, ApiError> {
    load_project(&state.projects_dir, &id)
        .map(Json)
        .map_err(|e| ApiError::not_found(e.to_string()))
}

async fn disk_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    delete_project(&state.projects_dir, &id).map_err(|e| ApiError::not_found(e.to_string()))?;
    Ok(Json(serde_json::json!({"deleted": id})))
}

async fn disk_save_from_memory(
    State(state): State<AppState>,
    Json(req): Json<DiskSaveRequest>,
) -> Result<Json<StoredProject>, ApiError> {
    let (name, doc) = {
        let guard = state.projects.lock().unwrap();
        let p = guard
            .get(&req.id)
            .ok_or_else(|| ApiError::not_found("memory project not found"))?;
        (
            req.name.clone().unwrap_or_else(|| p.name.clone()),
            p.document.clone(),
        )
    };
    save_project(&state.projects_dir, name, doc, Some(req.id), None)
        .map(Json)
        .map_err(|e| ApiError::bad(e.to_string()))
}

fn build_project(doc: PolicyDocument, name: String) -> Project {
    let validation = validate_document(&doc);
    let analysis = analyze(&doc);
    let summary = doc.summary();
    Project {
        id: Uuid::new_v4().to_string(),
        name,
        summary,
        document: doc,
        validation,
        analysis,
    }
}

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(crate) fn bad(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    pub(crate) fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({"error": self.message}));
        (self.status, body).into_response()
    }
}
