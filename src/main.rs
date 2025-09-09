use std::time::Duration;
use tracing::{Level, debug, error, info, instrument, span, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::Registry;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::prelude::*;
use tracing_tree::HierarchicalLayer;

use once_cell::sync::Lazy;
use std::sync::Mutex;
use tracing_appender::non_blocking::WorkerGuard;

// Keep the guard alive for the whole program
static FILE_GUARD: Lazy<Mutex<Option<WorkerGuard>>> = Lazy::new(|| Mutex::new(None));

// --------------------- Init Tracing ---------------------
fn init_tracing() {
    // File appender: minute rotation (for quick testing)
    let file_appender: RollingFileAppender = tracing_appender::rolling::minutely("logs", "app.log");
    let (non_blocking_file, guard) = tracing_appender::non_blocking(file_appender);

    // Store guard globally so it isn't dropped
    *FILE_GUARD.lock().unwrap() = Some(guard);

    // Console logs with hierarchical tree view
    let console_layer = HierarchicalLayer::new(2)
        .with_targets(false)
        .with_writer(std::io::stdout);

    // File logs: structured, timestamped
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking_file)
        .with_ansi(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_timer(ChronoLocal::rfc_3339());

    // Combine console + file layers
    let subscriber = Registry::default().with(console_layer).with(file_layer);

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");
}
// --------------------- App Logic ---------------------

#[instrument(name = "user_registration", skip(password))]
async fn register_user(user_id: u64, email: &str, password: &str) -> Result<(), String> {
    info!(user_id, email, "Starting user registration");

    validate_email(email).await?;
    let _hashed_password = hash_password(password).await?;
    save_user_to_db(user_id, email).await?;

    info!(user_id, "User registration completed successfully");
    Ok(())
}

#[instrument(skip(email))]
async fn validate_email(email: &str) -> Result<(), String> {
    debug!("Validating email format");

    if !email.contains('@') {
        error!(email, "Invalid email format");
        return Err("Invalid email format".into());
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    info!("Email validation passed");
    Ok(())
}

#[instrument]
async fn hash_password(password: &str) -> Result<String, String> {
    debug!(length = password.len(), "Starting password hashing");

    tokio::time::sleep(Duration::from_millis(100)).await;

    if password.len() < 8 {
        warn!("Password length below recommended minimum");
    }

    info!("Password hashing completed");
    Ok("hashed_password_placeholder".to_string())
}

#[instrument(fields(user_id, email))]
async fn save_user_to_db(user_id: u64, email: &str) -> Result<(), String> {
    let db_span = span!(
        Level::INFO,
        "db_operation",
        table = "users",
        operation = "insert"
    );
    let _enter = db_span.enter();

    debug!("Connecting to database");
    tokio::time::sleep(Duration::from_millis(30)).await;

    info!("Executing INSERT query");
    tokio::time::sleep(Duration::from_millis(80)).await;

    info!("User saved to database successfully");
    Ok(())
}

#[instrument]
async fn process_multiple_users() {
    info!("Processing batch of users");

    let users = vec![
        (1, "alice@example.com", "password123"),
        (2, "bob@example.com", "securepass"),
        (3, "charlie@example.com", "weakpw"),
    ];

    for (user_id, email, password) in users {
        if let Err(e) = register_user(user_id, email, password).await {
            error!(user_id, "Failed to register user: {}", e);
        }
    }

    info!("Batch processing completed");
}

#[instrument]
async fn api_request_handler(request_id: String, endpoint: &str) {
    let start_time = std::time::Instant::now();

    info!(
        request.id = %request_id,
        request.endpoint = endpoint,
        request.method = "POST",
        "Handling API request"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;

    info!(
        request.id = %request_id,
        request.duration_ms = start_time.elapsed().as_millis(),
        request.status = 200,
        "Request completed"
    );
}

#[instrument]
async fn error_prone_function() -> Result<String, Box<dyn std::error::Error>> {
    debug!("Starting potentially failing operation");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
    error!("Operation failed: {}", err);
    Err(Box::new(err))
}

// --------------------- Main ---------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let app_span = span!(Level::INFO, "application_startup", version = "1.0.0");
    let _enter = app_span.enter();

    info!("Application started");

    register_user(1, "john@example.com", "mypassword123").await?;
    process_multiple_users().await;

    api_request_handler("req-001".into(), "/api/users").await;
    api_request_handler("req-002".into(), "/api/posts").await;

    if let Err(e) = error_prone_function().await {
        error!("Error occurred in error_prone_function: {}", e);
    }

    info!("Application shutting down");
    Ok(())
}
