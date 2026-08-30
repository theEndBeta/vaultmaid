//! First-launch PIN setup form.
//!
//! This view exists to collect a new PIN from the user on first launch.
//! It enforces a minimum length (4 digits) and requires confirmation to
//! prevent typos from locking the user out immediately. The strength
//! hint is a simple length check; more sophisticated entropy estimation
//! is out of scope because the PIN is local-only and not transmitted.
//!
//! This module does not hash the PIN or write it to config. It emits
//! `Message::PinSet(Pin)` when the user confirms a valid PIN; the
//! update function in `app.rs` handles hashing and persistence.

use iced::widget::{button, column, container, text, text_input};
use iced::{Alignment, Element, Length};

use crate::message::Message;

fn error_text(message: &str) -> Element<'_, Message> {
    text(message)
        .size(14)
        .color(iced::Color::from_rgb(0.8, 0.2, 0.2))
        .into()
}

/// Coarse length-based strength label.
///
/// Entropy estimation is deliberately skipped: the PIN only protects the
/// local cache, so a human-readable hint is enough to nudge toward a
/// longer PIN without implying server-grade security.
fn strength_hint(len: usize) -> &'static str {
    match len {
        0..=3 => "Too short — at least 4 characters",
        4..=7 => "Weak",
        8..=11 => "Fair",
        _ => "Strong",
    }
}

/// Render the PIN setup form.
///
/// `pin` and `confirm` are the current field values from State. `error`
/// is an optional message (e.g., "PINs do not match") shown below the
/// form. The form is disabled until both fields are at least 4 characters
/// and match.
pub fn view<'a>(pin: &'a str, confirm: &'a str, error: Option<&'a str>) -> Element<'a, Message> {
    let pin_input = text_input("Enter PIN (min 4 digits)", pin)
        .on_input(Message::PinInput)
        .padding(10)
        .size(16);

    let confirm_input = text_input("Confirm PIN", confirm)
        .on_input(Message::PinConfirmInput)
        .padding(10)
        .size(16);

    let valid = pin.len() >= 4 && pin == confirm;
    let submit_button = button("Set PIN")
        .on_press_maybe(if valid {
            Some(Message::PinSet(crate::pin::Pin::new(pin)))
        } else {
            None
        })
        .padding(10);

    let mut content = column![
        text("Set a PIN to protect your vault cache").size(24),
        text("This PIN unlocks your vault when the app restarts or after idle. It is not sent to the server.").size(14),
        pin_input,
        text(strength_hint(pin.len())).size(14),
        confirm_input,
    ]
    .spacing(10)
    .align_x(Alignment::Center);

    if let Some(err) = error {
        content = content.push(error_text(err));
    }

    content = content.push(submit_button);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}
