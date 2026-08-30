//! PIN unlock form.
//!
//! This view exists to collect the PIN when the app starts or after idle
//! lock. It shows an error message if the PIN does not match the stored
//! verifier. The unlock flow is: user enters PIN → `Message::PinSubmitted`
//! → update function verifies against `config.pin_verifier` → on success,
//! decrypt cache and transition to `Screen::Main`; on failure, show error.
//!
//! This module does not verify the PIN or decrypt the cache. It only
//! renders the form and emits messages.

use iced::widget::{button, column, container, text, text_input};
use iced::{Alignment, Element, Length};

use crate::message::Message;

/// Render the PIN unlock form.
///
/// `pin` is the current field value from State. `error` is an optional
/// message (e.g., "Incorrect PIN") shown below the form. The submit
/// button is disabled until the field is non-empty.
pub fn view<'a>(pin: &'a str, error: Option<&'a str>) -> Element<'a, Message> {
    let pin_input = text_input("Enter PIN", pin)
        .on_input(Message::PinInput)
        .padding(10)
        .size(16);

    let submit_button = button("Unlock")
        .on_press_maybe(if !pin.is_empty() {
            Some(Message::PinSubmitted(crate::pin::Pin::new(pin)))
        } else {
            None
        })
        .padding(10);

    let mut content = column![text("Unlock your vault").size(24), pin_input,]
        .spacing(10)
        .align_x(Alignment::Center);

    if let Some(err) = error {
        content = content.push(
            text(err)
                .size(14)
                .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
        );
    }

    content = content.push(submit_button);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}
