// VaultMaid entry point: initializes tracing and launches the Iced application.
//
// This file exists solely to wire together the cross-cutting concerns (logging,
// error handling) before handing control to the UI layer. It deliberately avoids
// any business logic — that belongs in `app.rs` and its submodules.
//
// Tracing is initialized here rather than in `app.rs` because the application
// struct may be constructed multiple times during hot-reload scenarios, and we
// want a single subscriber for the entire process lifetime.

mod app;
mod message;
mod state;

fn main() -> iced::Result {
    tracing_subscriber::fmt::init();
    tracing::info!("VaultMaid starting");
    app::run()
}
