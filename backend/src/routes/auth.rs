// backend/src/routes/auth.rs

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
// ... (other use statements)
use crate::state::AppState;


// --- CHANGE IS HERE ---
// The router should not have a state generic.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/device", post(device_start))
        .route("/poll", post(poll))
        .route("/refresh", post(refresh))
        .route("/revoke", post(revoke))
        .route("/me", get(me))
}

// ... (rest of the file is unchanged)
