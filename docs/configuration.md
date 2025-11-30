# NAME

**steadystate configuration** - environment variables and settings

# DESCRIPTION

SteadyState is configured primarily through environment variables. This page documents all available configuration options for both the CLI and backend server.

# CLI CONFIGURATION

## STEADYSTATE_BACKEND_URL

URL of the SteadyState backend server.

```
export STEADYSTATE_BACKEND_URL="http://localhost:3000"
```

**Default:** `http://localhost:3000`

## STEADYSTATE_USERNAME

Override the username for sync operations. Primarily used internally by the session wrapper.

```
export STEADYSTATE_USERNAME="brodrigues"
```

**Default:** Derived from authenticated session or system `$USER`

## STEADYSTATE_DEBUG_MERGE

Enable verbose merge debugging output.

```
export STEADYSTATE_DEBUG_MERGE=1
```

When set, the merge engine will log detailed information about each file being merged, including tree sizes and merge decisions.

**Default:** Unset (disabled)

## STEADYSTATE_CONFIG_DIR

Override the directory where SteadyState stores configuration and session files.

```
export STEADYSTATE_CONFIG_DIR="/path/to/config"
```

**Default:** `~/.config/steadystate` (Linux), `~/Library/Application Support/steadystate` (macOS)

# BACKEND CONFIGURATION

## Required Variables

### GITHUB_CLIENT_ID

GitHub OAuth application client ID.

```
export GITHUB_CLIENT_ID="Iv1.abc123..."
```

Obtain this from your GitHub OAuth App settings.

### GITHUB_CLIENT_SECRET

GitHub OAuth application client secret.

```
export GITHUB_CLIENT_SECRET="secret123..."
```

**Security:** Keep this value secret. Do not commit to version control.

### JWT_SECRET

Secret key for signing JWT tokens.

```
export JWT_SECRET="$(openssl rand -base64 32)"
```

Generate a random 32+ byte string. All backend instances must share the same secret.

**Security:** Keep this value secret. Rotate periodically.

## Optional Variables

### STEADYSTATE_PORT

Port for the backend HTTP server.

```
export STEADYSTATE_PORT=3000
```

**Default:** `3000`

### STEADYSTATE_EXTERNAL_HOST

Public hostname or IP address for SSH connections.

```
export STEADYSTATE_EXTERNAL_HOST="192.168.1.100"
export STEADYSTATE_EXTERNAL_HOST="steadystate.example.com"
```

**Default:** Auto-detected local IP address

This is included in magic links and must be reachable by collaborators.

### STEADYSTATE_SSH_USER

System user for SSH session connections.

```
export STEADYSTATE_SSH_USER="steadystate"
```

**Default:** `steadystate`

This user must exist on the system and have appropriate permissions.

### RUST_LOG

Control logging verbosity.

```
export RUST_LOG=info
export RUST_LOG=steadystate=debug
export RUST_LOG=steadystate::compute=trace
```

**Default:** `info`

# SESSION ENVIRONMENT

Inside a collaboration session, the following variables are set automatically:

| Variable | Description |
|----------|-------------|
| `REPO_ROOT` | Path to session root directory |
| `SESSION_ID` | Unique session identifier |
| `STEADYSTATE_USERNAME` | GitHub username of connected user |
| `USER_WORKSPACE` | Path to user's worktree |
| `CANONICAL_REPO` | Path to canonical repository |
| `REPO_NAME` | Name of the repository (used by dashboard) |

# FILES

## ~/.config/steadystate/session.json

Stores the current authentication session:

```json
{
  "login": "username",
  "jwt": "eyJ...",
  "jwt_exp": 1699999999
}
```

**Permissions:** `0600` (user read/write only)

## ~/.config/steadystate/refresh_token

Stores the refresh token for automatic re-authentication.

**Permissions:** `0600`

## /tmp/steadystate-*-known_hosts

Temporary SSH known_hosts files created for session connections. Automatically cleaned up.

# SYSTEMD CONFIGURATION

Example systemd service file for the backend:

```ini
[Unit]
Description=SteadyState Backend
After=network.target

[Service]
Type=simple
User=steadystate
Group=steadystate
WorkingDirectory=/opt/steadystate
ExecStart=/opt/steadystate/steadystate-backend
Restart=always
RestartSec=5

Environment=GITHUB_CLIENT_ID=Iv1.abc123
Environment=GITHUB_CLIENT_SECRET=secret123
Environment=JWT_SECRET=your-secret-here
Environment=STEADYSTATE_PORT=3000
Environment=STEADYSTATE_EXTERNAL_HOST=your-server.com
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

# NIXOS CONFIGURATION

Example NixOS module:

```nix
{ config, pkgs, ... }:

{
  users.users.steadystate = {
    isNormalUser = true;
    home = "/home/steadystate";
    shell = pkgs.bash;
  };

  systemd.services.steadystate = {
    description = "SteadyState Backend";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    
    environment = {
      GITHUB_CLIENT_ID = "Iv1.abc123";
      STEADYSTATE_PORT = "3000";
      STEADYSTATE_EXTERNAL_HOST = "your-server.com";
      RUST_LOG = "info";
    };
    
    serviceConfig = {
      Type = "simple";
      User = "steadystate";
      ExecStart = "${pkgs.steadystate}/bin/steadystate-backend";
      Restart = "always";
      RestartSec = 5;
      
      # Load secrets from file
      EnvironmentFile = "/run/secrets/steadystate";
    };
  };

  networking.firewall.allowedTCPPorts = [ 3000 ];
  networking.firewall.allowedTCPPortRanges = [
    { from = 2000; to = 3000; }  # SSH sessions
  ];
}
```

# SEE ALSO

**steadystate**(1), **systemd.service**(5)
