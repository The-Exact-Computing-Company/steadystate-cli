// backend/src/routes/sessions.rs

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, delete},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    jwt::CustomClaims,
    models::{Session, SessionInfo, SessionRequest, SessionState},
    state::AppState,
    compute::ComputeProvider, // <--- THIS WAS MISSING and is required!
};

/// Router for the /sessions endpoints.
/// Note: We explicitly define the state type here to match main.rs expectations.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_session))
        .route("/:id", get(get_session_status))
        .route("/:id", delete(terminate_session))
}

/// The main async task that performs the long-running provisioning.
async fn run_provisioning(
    app_state: Arc<AppState>,
    session_id: String,
    request: SessionRequest,
) {
    // 1. Retrieve the provider ID for this session
    let provider_id = if let Some(session) = app_state.sessions.get(&session_id) {
        session.compute_provider.clone()
    } else {
        return; // Session was deleted before we started?
    };

    // 2. Get the actual provider implementation
    let provider = if let Some(p) = app_state.compute_providers.get(&provider_id) {
        p.clone()
    } else {
        tracing::error!("Provider '{}' not found for session {}", provider_id, session_id);
        return;
    };

    // 3. Do the work (Clone the session state mutably for the provider)
    // We need to access the DashMap entry to modify it.
    let result = if let Some(mut session_entry) = app_state.sessions.get_mut(&session_id) {
        // We pass the mutable reference to the session inside the DashMap entry
        provider.start_session(&mut session_entry, &request).await
    } else {
        return; // Session disappeared
    };

    // 4. Handle failure by updating the state
    if let Err(e) = result {
        tracing::error!("Provisioning failed for session {}: {:#}", session_id, e);
        if let Some(mut session) = app_state.sessions.get_mut(&session_id) {
            session.state = SessionState::Failed;
            session.error_message = Some(format!("{:#}", e));
            session.updated_at = std::time::SystemTime::now();
        }
    }
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    claims: CustomClaims,
    Json(request): Json<SessionRequest>,
) -> (StatusCode, Json<SessionInfo>) {
    let session_id = Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now();

    let session = Session {
        id: session_id.clone(),
        state: SessionState::Provisioning,
        repo_url: request.repo_url.clone(),
        branch: request.branch.clone(),
        environment: request.environment.clone(),
        endpoint: None,
        compute_provider: state.default_compute_provider.clone(),
        creator_login: claims.sub,
        created_at: now,
        updated_at: now,
        error_message: None,
    };

    let session_info = SessionInfo::from(&session);
    
    // Persist the initial session state
    state.sessions.insert(session_id.clone(), session);

    // Spawn the background task to do the actual work.
    tokio::spawn(run_provisioning(state, session_id, request));

    (StatusCode::ACCEPTED, Json(session_info))
}

async fn get_session_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, StatusCode> {
    match state.sessions.get(&id) {
        Some(session) => Ok(Json(SessionInfo::from(&*session))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn terminate_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    if let Some(mut session) = state.sessions.get_mut(&id) {
        // Mark as terminating
        session.state = SessionState::Terminating;
        
        // Get the provider to clean up resources
        if let Some(provider) = state.compute_providers.get(&session.compute_provider) {
            let provider = provider.clone();
            let session_clone = session.clone();
            
            // Spawn termination in background
            tokio::spawn(async move {
                if let Err(e) = provider.terminate_session(&session_clone).await {
                    tracing::error!("Failed to terminate session {}: {:#}", id, e);
                }
            });
        }
        
        StatusCode::ACCEPTED
    } else {
        StatusCode::NOT_FOUND
    }
}
