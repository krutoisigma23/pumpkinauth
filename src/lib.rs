use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use pumpkin_plugin_api::{
    Context, Plugin, PluginMetadata, Server,
    command::{Command, CommandError, CommandNode, CommandSender, ConsumedArgs},
    command_wit::{Arg, ArgumentType, StringType},
    commands::CommandHandler,
    events::{
        EventData, EventHandler, EventPriority, 
        PlayerChatEvent, PlayerJoinEvent, PlayerLeaveEvent, PlayerMoveEvent, PlayerLoginEvent,
        BlockBreakEvent, BlockPlaceEvent, BlockCanBuildEvent
    },
    permission::{Permission, PermissionDefault},
    text::{NamedColor, TextComponent},
};
use sha2::{Sha256, Digest};
use tracing::{error, info};

// --- GLOBAL STATE ---

pub static AUTH_STATE: OnceLock<AuthState> = OnceLock::new();

pub struct AuthState {
    // Database: Player UUID -> Hashed password
    pub database: Arc<Mutex<HashMap<String, String>>>,
    // Sessions: UUIDs of currently logged in players
    pub logged_in: Arc<Mutex<HashSet<String>>>,
    
    pub login_attempts: Arc<Mutex<HashMap<String, u8>>>,
    pub temp_bans: Arc<Mutex<HashMap<String, u64>>>,
    
    pub data_path: PathBuf,
}

impl AuthState {
    pub fn init(context: &Context) {
        let mut path = PathBuf::from(context.get_data_folder());
        path.push("auth_database.json");

        let database = Self::load_db(&path);

        let state = AuthState {
            database: Arc::new(Mutex::new(database)),
            logged_in: Arc::new(Mutex::new(HashSet::new())),
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            temp_bans: Arc::new(Mutex::new(HashMap::new())),
            data_path: path,
        };

        AUTH_STATE.set(state).ok();
    }

    fn load_db(path: &Path) -> HashMap<String, String> {
        match File::open(path) {
            Ok(mut file) => {
                let mut data = String::new();
                if file.read_to_string(&mut data).is_ok() {
                    if let Ok(db) = serde_json::from_str(&data) {
                        return db;
                    }
                }
                HashMap::new()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                error!("Failed to read auth database: {}", e);
                HashMap::new()
            }
        }
    }

    pub fn save_db(&self) {
        let db = self.database.lock().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*db) {
            if let Ok(mut file) = File::create(&self.data_path) {
                let _ = file.write_all(json.as_bytes());
            } else {
                error!("Failed to create database file!");
            }
        }
    }

    pub fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"PumpkinSuperSecretSalt_"); 
        hasher.update(password.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn is_registered(&self, uuid: &str) -> bool {
        self.database.lock().unwrap().contains_key(uuid)
    }

    pub fn is_logged_in(&self, uuid: &str) -> bool {
        self.logged_in.lock().unwrap().contains(uuid)
    }


    pub fn unix_now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    pub fn get_ban_time_left(&self, uuid: &str) -> Option<u64> {
        let bans = self.temp_bans.lock().unwrap();
        if let Some(&expire_time) = bans.get(uuid) {
            let now = Self::unix_now();
            if now < expire_time {
                return Some(expire_time - now);
            }
        }
        None
    }

    pub fn add_failed_attempt(&self, uuid: &str) -> u8 {
        let mut attempts = self.login_attempts.lock().unwrap();
        let count = attempts.entry(uuid.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    pub fn reset_attempts(&self, uuid: &str) {
        self.login_attempts.lock().unwrap().remove(uuid);
    }

    pub fn temp_ban(&self, uuid: &str, duration_secs: u64) {
        let expire = Self::unix_now() + duration_secs;
        self.temp_bans.lock().unwrap().insert(uuid.to_string(), expire);
    }
}

// --- EVENT HANDLERS ---

struct LoginHandler;
impl EventHandler<PlayerLoginEvent> for LoginHandler {
    fn handle(&self, _server: Server, mut event: EventData<PlayerLoginEvent>) -> EventData<PlayerLoginEvent> {
        let state = AUTH_STATE.get().unwrap();
        let uuid = event.player.get_id();

        if let Some(left) = state.get_ban_time_left(&uuid) {
            let msg = TextComponent::text(&format!("You are temporarily banned! Wait {} seconds.", left));
            msg.color_named(NamedColor::Red);
            event.kick_message = msg;
        }
        event
    }
}

struct JoinHandler;
impl EventHandler<PlayerJoinEvent> for JoinHandler {
    fn handle(&self, _server: Server, event: EventData<PlayerJoinEvent>) -> EventData<PlayerJoinEvent> {
        let state = AUTH_STATE.get().unwrap();
        let uuid = event.player.get_id();

        let msg = TextComponent::text("");
        
        if state.is_registered(&uuid) {
            let info = TextComponent::text("Welcome back! Please login: ");
            info.color_named(NamedColor::Yellow);
            
            let cmd = TextComponent::text("/login <password>");
            cmd.color_named(NamedColor::Red);
            cmd.bold(true);
            
            msg.add_child(info);
            msg.add_child(cmd);
        } else {
            let info = TextComponent::text("Welcome! Please register: ");
            info.color_named(NamedColor::Yellow);
            
            let cmd = TextComponent::text("/register <password> <confirm_password>");
            cmd.color_named(NamedColor::Red);
            cmd.bold(true);
            
            msg.add_child(info);
            msg.add_child(cmd);
        }

        event.player.send_system_message(msg, false);
        event
    }
}

struct LeaveHandler;
impl EventHandler<PlayerLeaveEvent> for LeaveHandler {
    fn handle(&self, _server: Server, event: EventData<PlayerLeaveEvent>) -> EventData<PlayerLeaveEvent> {
        let state = AUTH_STATE.get().unwrap();
        let uuid = event.player.get_id();
        state.logged_in.lock().unwrap().remove(&uuid);
        event
    }
}

struct ChatHandler;
impl EventHandler<PlayerChatEvent> for ChatHandler {
    fn handle(&self, _server: Server, mut event: EventData<PlayerChatEvent>) -> EventData<PlayerChatEvent> {
        let state = AUTH_STATE.get().unwrap();
        if !state.is_logged_in(&event.player.get_id()) {
            event.cancelled = true;
            let warning = TextComponent::text("You cannot chat before logging in!");
            warning.color_named(NamedColor::Red);
            event.player.send_system_message(warning, false);
        }
        event
    }
}

struct MoveHandler;
impl EventHandler<PlayerMoveEvent> for MoveHandler {
    fn handle(&self, _server: Server, mut event: EventData<PlayerMoveEvent>) -> EventData<PlayerMoveEvent> {
        let state = AUTH_STATE.get().unwrap();
        if !state.is_logged_in(&event.player.get_id()) {
            event.cancelled = true;
        }
        event
    }
}

struct BlockBreakHandler;
impl EventHandler<BlockBreakEvent> for BlockBreakHandler {
    fn handle(&self, _server: Server, mut event: EventData<BlockBreakEvent>) -> EventData<BlockBreakEvent> {
        let state = AUTH_STATE.get().unwrap();
        
        // В документации сказано "contains the player (if any)", поэтому используем Option
        if let Some(player) = &event.player {
            let uuid = player.get_id();
            if !state.is_logged_in(&uuid) {
                event.cancelled = true;
            }
        }
        event
    }
}

struct BlockPlaceHandler;
impl EventHandler<BlockPlaceEvent> for BlockPlaceHandler {
    fn handle(&self, _server: Server, mut event: EventData<BlockPlaceEvent>) -> EventData<BlockPlaceEvent> {
        let state = AUTH_STATE.get().unwrap();
        if !state.is_logged_in(&event.player.get_id()) {
            event.cancelled = true;
        }
        event
    }
}

struct BlockCanBuildHandler;
impl EventHandler<BlockCanBuildEvent> for BlockCanBuildHandler {
    fn handle(&self, _server: Server, mut event: EventData<BlockCanBuildEvent>) -> EventData<BlockCanBuildEvent> {
        let state = AUTH_STATE.get().unwrap();
        if !state.is_logged_in(&event.player.get_id()) {
            event.cancelled = true;
        }
        event
    }
}

// --- COMMANDS ---

struct RegisterExecutor;
impl CommandHandler for RegisterExecutor {
    fn handle(&self, sender: CommandSender, _server: Server, args: ConsumedArgs) -> pumpkin_plugin_api::Result<i32, CommandError> {
        let Some(player) = sender.as_player() else { return Ok(0); };
        let uuid = player.get_id();
        let state = AUTH_STATE.get().unwrap();

        // Проверяем бан
        if let Some(left) = state.get_ban_time_left(&uuid) {
            let msg = TextComponent::text(&format!("You are banned! Please wait {} seconds.", left));
            msg.color_named(NamedColor::Red);
            sender.send_message(msg);
            return Ok(0);
        }

        if state.is_registered(&uuid) {
            let msg = TextComponent::text("You are already registered! Use /login.");
            msg.color_named(NamedColor::Red);
            sender.send_message(msg);
            return Ok(0);
        }

        let Arg::Simple(pass1) = args.get_value("password") else { return Ok(0); };
        let Arg::Simple(pass2) = args.get_value("confirm") else { return Ok(0); };

        if pass1 != pass2 {
            let msg = TextComponent::text("Passwords do not match!");
            msg.color_named(NamedColor::Red);
            sender.send_message(msg);
            return Ok(0);
        }

        let hashed = AuthState::hash_password(pass1.as_str());
        state.database.lock().unwrap().insert(uuid.clone(), hashed);
        state.save_db();
        
        state.logged_in.lock().unwrap().insert(uuid);

        let msg = TextComponent::text("Registration successful! Have fun.");
        msg.color_named(NamedColor::Green);
        sender.send_message(msg);

        Ok(1)
    }
}

struct LoginExecutor;
impl CommandHandler for LoginExecutor {
    fn handle(&self, sender: CommandSender, _server: Server, args: ConsumedArgs) -> pumpkin_plugin_api::Result<i32, CommandError> {
        let Some(player) = sender.as_player() else { return Ok(0); };
        let uuid = player.get_id();
        let state = AUTH_STATE.get().unwrap();

        if let Some(left) = state.get_ban_time_left(&uuid) {
            let msg = TextComponent::text(&format!("You are banned! Please wait {} seconds.", left));
            msg.color_named(NamedColor::Red);
            sender.send_message(msg);
            return Ok(0);
        }

        if !state.is_registered(&uuid) {
            let msg = TextComponent::text("You are not registered! Use /register.");
            msg.color_named(NamedColor::Red);
            sender.send_message(msg);
            return Ok(0);
        }

        if state.is_logged_in(&uuid) {
            let msg = TextComponent::text("You are already logged in!");
            msg.color_named(NamedColor::Yellow);
            sender.send_message(msg);
            return Ok(0);
        }

        let Arg::Simple(password) = args.get_value("password") else { return Ok(0); };
        let input_hash = AuthState::hash_password(password.as_str());

        let db = state.database.lock().unwrap();
        if let Some(saved_hash) = db.get(&uuid) {
            if saved_hash == &input_hash {
                // Правильный пароль
                state.logged_in.lock().unwrap().insert(uuid.clone());
                state.reset_attempts(&uuid); // Сбрасываем попытки
                
                let msg = TextComponent::text("Login successful! Have fun.");
                msg.color_named(NamedColor::Green);
                sender.send_message(msg);
            } else {
                // Неправильный пароль
                let attempts = state.add_failed_attempt(&uuid);
                
                if attempts >= 3 {
                    state.temp_ban(&uuid, 300); // Бан на 5 минут (300 сек)
                    state.reset_attempts(&uuid); // Сбрасываем счетчик, бан уже выдан
                    
                    let msg = TextComponent::text("You have been banned for 5 minutes due to too many failed attempts!");
                    msg.color_named(NamedColor::DarkRed);
                    sender.send_message(msg);
                } else {
                    let msg = TextComponent::text(&format!("Incorrect password! Attempts left: {}", 3 - attempts));
                    msg.color_named(NamedColor::Red);
                    sender.send_message(msg);
                }
            }
        }

        Ok(1)
    }
}

// --- PLUGIN INITIALIZATION ---

struct AuthPlugin;

impl Plugin for AuthPlugin {
    fn new() -> Self {
        AuthPlugin
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "PumpkinAuth".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authors: vec!["Assistant".into()],
            description: "Authentication system with limits and blocks protection.".into(),
            dependencies: vec![],
        }
    }

    fn on_load(&mut self, context: Context) -> pumpkin_plugin_api::Result<()> {
        info!("Loading PumpkinAuth...");

        AuthState::init(&context);

        context.register_event_handler(LoginHandler, EventPriority::Highest, true)?;
        context.register_event_handler(JoinHandler, EventPriority::Highest, true)?;
        context.register_event_handler(LeaveHandler, EventPriority::Highest, true)?;
        context.register_event_handler(ChatHandler, EventPriority::Highest, true)?;
        context.register_event_handler(MoveHandler, EventPriority::Highest, true)?;
        
        context.register_event_handler(BlockBreakHandler, EventPriority::Highest, true)?;
        context.register_event_handler(BlockPlaceHandler, EventPriority::Highest, true)?;
        context.register_event_handler(BlockCanBuildHandler, EventPriority::Highest, true)?;

        let perm_auth = Permission {
            node: "PumpkinAuth:command.auth".into(),
            description: "Allows the use of auth commands".into(),
            default: PermissionDefault::Allow,
            children: vec![],
        };
        context.register_permission(&perm_auth)?;

        let cmd_register = Command::new(&["register".to_string(), "reg".to_string()], "Register an account");
        let pwd_node = CommandNode::argument("password", &ArgumentType::String(StringType::SingleWord));
        pwd_node.then(CommandNode::argument("confirm", &ArgumentType::String(StringType::SingleWord)).execute(RegisterExecutor));
        cmd_register.then(pwd_node);
        context.register_command(cmd_register, "PumpkinAuth:command.auth");

        let cmd_login = Command::new(&["login".to_string(), "l".to_string()], "Login to your account");
        cmd_login.then(CommandNode::argument("password", &ArgumentType::String(StringType::SingleWord)).execute(LoginExecutor));
        context.register_command(cmd_login, "PumpkinAuth:command.auth");

        info!("PumpkinAuth successfully loaded!");
        Ok(())
    }

    fn on_unload(&mut self, _context: Context) -> pumpkin_plugin_api::Result<()> {
        if let Some(state) = AUTH_STATE.get() {
            state.save_db();
        }
        info!("PumpkinAuth unloaded.");
        Ok(())
    }
}

pumpkin_plugin_api::register_plugin!(AuthPlugin);