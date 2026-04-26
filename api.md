
PumpkinAuth API

PumpkinAuth provides a lightweight API that allows other plugins to check the
authentication status of players. Use this to prevent unauthenticated players
from interacting with your plugin's systems (e.g., economy, shops, or clans).

API Methods

1. is_registered

Checks if a player has an account in the local database.

`pub fn is_registered(uuid: &str) -> bool`

  - Returns: true if the player has a set password, false otherwise.

2. is_logged_in

Checks if the player has successfully authenticated in the current session.

`pub fn is_logged_in(uuid: &str) -> bool`

  - Returns: true if the player is logged in and can move/chat, false if they
    are still at the login screen.
  - Recommendation: Use this check before allowing any sensitive actions in your
    plugin.

3. is_banned

Checks if the player is currently under a temporary lockout (ban) due to too
many failed login attempts.

`pub fn is_banned(uuid: &str) -> bool`

  - Returns: true if the player is restricted from logging in.
  - Persistence: Bans are saved to auth_database.json and persist across server
    restarts.

