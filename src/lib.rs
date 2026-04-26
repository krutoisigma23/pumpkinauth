use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use pumpkin_plugin_api::{
    Context, Plugin, PluginMetadata, Server,
    command::{Command, CommandError, CommandNode, CommandSender, ConsumedArgs},
    command_wit::{Arg, ArgumentType, StringType},
    commands::CommandHandler,
    // Добавили PlayerMoveEvent в импорты:
    events::{EventData, EventHandler, EventPriority, PlayerChatEvent, PlayerJoinEvent, PlayerLeaveEvent, PlayerMoveEvent},
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

    // Password hashing (SHA-256 + simple static salt)
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
}

// --- EVENT HANDLERS ---

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
        
        // Remove player from logged in list on disconnect
        state.logged_in.lock().unwrap().remove(&uuid);
        event
    }
}

struct ChatHandler;
impl EventHandler<PlayerChatEvent> for ChatHandler {
    fn handle(&self, _server: Server, mut event: EventData<PlayerChatEvent>) -> EventData<PlayerChatEvent> {
        let state = AUTH_STATE.get().unwrap();
        let uuid = event.player.get_id();

        // If player is not logged in - block chat
        if !state.is_logged_in(&uuid) {
            event.cancelled = true; // Cancel message

            let warning = TextComponent::text("You cannot chat before logging in!");
            warning.color_named(NamedColor::Red);
            event.player.send_system_message(warning, false);
        }

        event
    }
}

// НОВЫЙ ОБРАБОТЧИК: Заморозка передвижения
struct MoveHandler;
impl EventHandler<PlayerMoveEvent> for MoveHandler {
    fn handle(&self, _server: Server, mut event: EventData<PlayerMoveEvent>) -> EventData<PlayerMoveEvent> {
        let state = AUTH_STATE.get().unwrap();
        let uuid = event.player.get_id();

        // Если игрок не авторизован - отменяем его шаги (замораживаем на месте)
        if !state.is_logged_in(&uuid) {
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

        // Hash and save
        let hashed = AuthState::hash_password(pass1.as_str());
        state.database.lock().unwrap().insert(uuid.clone(), hashed);
        state.save_db();
        
        // Automatically login after registration
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
                // Correct password
                state.logged_in.lock().unwrap().insert(uuid);
                
                let msg = TextComponent::text("Login successful! Have fun.");
                msg.color_named(NamedColor::Green);
                sender.send_message(msg);
            } else {
                let msg = TextComponent::text("Incorrect password!");
                msg.color_named(NamedColor::DarkRed);
                sender.send_message(msg);
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
            description: "Basic registration and authentication system with freeze.".into(),
            dependencies: vec![],
        }
    }

    fn on_load(&mut self, context: Context) -> pumpkin_plugin_api::Result<()> {
        info!("Loading PumpkinAuth...");

        // Init database and state
        AuthState::init(&context);

        // Register event handlers
        context.register_event_handler(JoinHandler, EventPriority::Highest, true)?;
        context.register_event_handler(LeaveHandler, EventPriority::Highest, true)?;
        context.register_event_handler(ChatHandler, EventPriority::Highest, true)?;
        
        // Регистрируем наш новый обработчик передвижения с высшим приоритетом:
        context.register_event_handler(MoveHandler, EventPriority::Highest, true)?;

        let perm_auth = Permission {
            node: "PumpkinAuth:command.auth".into(),
            description: "Allows the use of auth commands".into(),
            default: PermissionDefault::Allow,
            children: vec![],
        };
        context.register_permission(&perm_auth)?;

        // Register /register command
        let cmd_register = Command::new(&["register".to_string(), "reg".to_string()], "Register an account");
        let pwd_node = CommandNode::argument("password", &ArgumentType::String(StringType::SingleWord));
        pwd_node.then(CommandNode::argument("confirm", &ArgumentType::String(StringType::SingleWord)).execute(RegisterExecutor));
        cmd_register.then(pwd_node);
        context.register_command(cmd_register, "PumpkinAuth:command.auth");

        // Register /login command
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