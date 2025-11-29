use reqwest::Client;
use std::collections::HashSet;
use anyhow::{Result, anyhow, Context};

#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub user: String,
    pub key: String,
}

#[derive(Debug)]
pub struct SshKeyManager {
    http_client: Client,
}

impl SshKeyManager {
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
        }
    }
    
    /// Fetch SSH keys for a GitHub user
    pub async fn fetch_github_keys(&self, username: &str) -> Result<Vec<String>> {
        let url = format!("https://github.com/{}.keys", username);
        
        let response = self.http_client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .context("Failed to fetch GitHub keys")?;
            
        if !response.status().is_success() {
            return Err(anyhow!("GitHub returned {}", response.status()));
        }
        
        let body = response.text().await?;
        let keys: Vec<String> = body
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
            
        Ok(keys)
    }
    
    /// Build authorized_keys entries for multiple users
    pub async fn build_authorized_keys(
        &self,
        creator: Option<&str>,
        allowed_users: Option<&[String]>,
        github_token: Option<&str>,
    ) -> Vec<AuthorizedKey> {
        let mut seen_keys = HashSet::new();
        let mut result = Vec::new();
        
        // Collect all usernames
        let mut usernames: Vec<String> = Vec::new();
        
        if let Some(creator) = creator {
            usernames.push(creator.to_string());
        }
        
        if let Some(users) = allowed_users {
            usernames.extend(users.iter().cloned());
        }
        
        // Fetch keys for each user
        for username in usernames {
            match self.fetch_github_keys(&username).await {
                Ok(keys) => {
                    for key in keys {
                        if seen_keys.insert(key.clone()) {
                            result.push(AuthorizedKey {
                                user: username.clone(),
                                key,
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch keys for {}: {}", username, e);
                }
            }
        }
        
        // Optionally fetch collaborators from GitHub API if token is provided
        if let Some(token) = github_token {
             // Logic to fetch collaborators would go here.
             // For now, we'll skip implementing the full collaborator fetching logic 
             // as it requires more complex API interactions (pagination, etc.)
             // which can be migrated from local_provider.rs later or implemented here.
             // The guide stubbed this out, so we will too for now.
             tracing::debug!("GitHub token provided, but collaborator fetching not yet fully implemented in SshKeyManager");
        }
        
        result
    }
    
    /// Generate authorized_keys file content
    pub fn generate_authorized_keys_file(
        &self,
        keys: &[AuthorizedKey],
        command_template: Option<&str>,
    ) -> String {
        let mut content = String::new();
        
        for ak in keys {
            if let Some(template) = command_template {
                let command = template.replace("{user}", &ak.user);
                content.push_str(&format!("command=\"{}\" {}\n", command, ak.key));
            } else {
                content.push_str(&format!("{}\n", ak.key));
            }
        }
        
        content
    }
}
