// backend/src/jwt.rs

use std::collections::HashSet;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Clone)]
pub struct JwtKeys {
    key: HS256Key,
    issuer: String,
    ttl_duration: Duration,
}

/// The custom claims specific to the SteadyState application.
/// `jwt-simple` will handle standard claims like `iss` (issuer) and `exp` (expiration) separately.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomClaims {
    /// The subject of the token (the user's login name).
    pub sub: String,
    /// The authentication provider used (e.g., "github").
    pub provider: String,
}

impl JwtKeys {
    pub fn new(secret: &str, issuer: &str, ttl_secs: u64) -> Self {
        Self {
            key: HS256Key::from_bytes(secret.as_bytes()),
            issuer: issuer.into(),
            ttl_duration: Duration::from_secs(ttl_secs),
        }
    }

    /// Creates and signs a new JWT.
    pub fn sign(&self, login: &str, provider: &str) -> Result<String> {
        let custom_claims = CustomClaims {
            sub: login.to_string(),
            provider: provider.to_string(),
        };

        // Use the library's `Claims` builder to wrap our custom data and set standard claims.
        let claims = Claims::with_custom_claims(custom_claims, self.ttl_duration)
            .with_issuer(self.issuer.clone())
            .with_subject(login.to_string());

        self.key.authenticate(claims).map_err(|e| anyhow!("Failed to sign JWT: {}", e))
    }

    /// Verifies a token and returns the custom claims if valid.
    pub fn verify(&self, token: &str) -> Result<CustomClaims> {
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(self.issuer.clone());

        let options = VerificationOptions {
            allowed_issuers: Some(allowed_issuers),
            ..Default::default()
        };

        // Tell `verify_token` to expect our `CustomClaims` struct in the payload.
        let claims = self.key
            .verify_token::<CustomClaims>(token, Some(options))
            .map_err(|e| anyhow!("Invalid or expired JWT: {}", e))?;
        
        Ok(claims.custom)
    }
}

// --- AXUM EXTRACTOR FOR CUSTOM CLAIMS ---

#[async_trait]
impl FromRequestParts<Arc<AppState>> for CustomClaims {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Get the Authorization header.
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header".into())
            })?;

        // Check for "Bearer " prefix and get the token.
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (StatusCode::BAD_REQUEST, "Invalid token type; expected Bearer".into())
            })?;

        // Verify the token and extract the custom claims.
        state
            .jwt
            .verify(token)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
    }
}
