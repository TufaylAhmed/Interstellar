//! Local HTTP API + static UI for interstellar.

use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use interstellar_analyze::{analyze, AnalysisReport};
use interstellar_emit::{emit_panos_xml, emit_set_commands, validate_document};
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
}

#[derive(Serialize)]
pub struct ConvertResponse {
    pub project: ProjectMeta,
    pub xml: String,
    pub set_commands: String,
    pub validation: ValidationReport,
    pub analysis: AnalysisReport,
    pub ir: PolicyDocument,
}

#[derive(Serialize, Clone)]
pub struct ProjectMeta {
    pub id: String,
    pub name: String,
    pub summary: DocumentSummary,
}

pub async fn serve(addr: SocketAddr, static_dir: PathBuf) -> anyhow::Result<()> {
    let state = AppState {
        projects: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/api/health", get(|| async { Json(serde_json::json!({"ok": true, "service": "interstellar"})) }))
        .route("/api/convert", post(convert_handler))
        .route("/api/projects", get(list_projects))
        .route("/api/projects/{id}", get(get_project))
        .route("/api/projects/{id}/xml", get(get_project_xml))
        .route("/api/projects/{id}/set", get(get_project_set))
        .route("/api/upload", post(upload_handler))
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("interstellar UI/API listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
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
    let built = build_project(doc, req.name.unwrap_or_else(|| "project".into()));
    let xml = emit_panos_xml(&built.document);
    let set_commands = emit_set_commands(&built.document);
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
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad(e.to_string()))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                name = field.file_name().map(|s| s.to_string());
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
        }),
    )
    .await
}

async fn list_projects(State(state): State<AppState>) -> Json<Vec<ProjectMeta>> {
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
    fn bad(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
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
