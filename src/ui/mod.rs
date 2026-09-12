//! UI module root.
//!
//! This file exists to organize the view layer into per-screen modules.
//! Each submodule renders one screen and emits messages; no business
//! logic lives here. The `app.rs` module owns the update function and
//! dispatches to these views based on `State::screen`.

pub mod login;
pub mod set_pin;
pub mod unlock;
