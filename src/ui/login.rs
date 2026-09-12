//! Login, device-code, and two-factor views.
//!
//! These views exist to drive the device-authorization sign-in flow: enter
//! a server URL, start the flow, approve a short code in a browser, and
//! supply a second factor when the server asks. Login and 2FA live in one
//! file because they are stages of the same interaction and share the same
//! error/busy presentation.
//!
//! The module renders only; it never talks to the network. Buttons emit
//! messages (`StartDeviceCode`, `PollDeviceCode`, `TwoFactorSubmitted`,
//! `OpenVerificationUri`) that the update function turns into commands.

use iced::widget::{button, column, container, text, text_input};
use iced::{Alignment, Element, Length};

use crate::api::auth::DeviceCode;
use crate::message::Message;

fn error_text(message: &str) -> Element<'_, Message> {
    text(message)
        .size(14)
        .color(iced::Color::from_rgb(0.8, 0.2, 0.2))
        .into()
}

/// Render the login screen, including the device-code waiting state.
///
/// `server_url` is bound to the persisted config value; `device_code` is
/// `Some` once the server has issued a code to approve. `busy` disables
/// the start button while a request is in flight so the user cannot
/// launch overlapping flows.
pub fn view<'a>(
    server_url: &'a str,
    device_code: Option<&'a DeviceCode>,
    busy: bool,
    error: Option<&'a str>,
) -> Element<'a, Message> {
    let server_input = text_input("Server URL", server_url)
        .on_input(Message::ServerUrlChanged)
        .padding(10)
        .size(16);

    let mut content = column![
        text("VaultMaid").size(28),
        text("Organize your Bitwarden vault across folders and collections").size(14),
        server_input,
    ]
    .spacing(10)
    .align_x(Alignment::Center);

    if let Some(code) = device_code {
        content = content.push(text("Enter this code in your browser:").size(16));
        content = content.push(text(&code.user_code).size(32));
        content = content.push(
            button("Open browser")
                .on_press(Message::OpenVerificationUri(code.verification_uri.clone()))
                .padding(10),
        );
        content = content.push(text("Waiting for approval…").size(14));
    } else {
        content = content.push(
            button("Log in with device")
                .on_press_maybe(if busy {
                    None
                } else {
                    Some(Message::StartDeviceCode)
                })
                .padding(10),
        );
        if busy {
            content = content.push(text("Contacting server…").size(14));
        }
    }

    if let Some(error) = error {
        content = content.push(error_text(error));
    }

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}

/// Render the two-factor prompt.
///
/// Displayed when the token endpoint reports that a second factor is
/// required; the code is resubmitted with the next poll.
pub fn two_factor_view<'a>(
    code: &'a str,
    busy: bool,
    error: Option<&'a str>,
) -> Element<'a, Message> {
    let code_input = text_input("Authentication code", code)
        .on_input(Message::TwoFactorInput)
        .padding(10)
        .size(16);

    let submit = button("Verify")
        .on_press_maybe(if code.is_empty() || busy {
            None
        } else {
            Some(Message::TwoFactorSubmitted)
        })
        .padding(10);

    let mut content = column![
        text("Two-factor authentication").size(24),
        text("Enter the code from your authenticator app or email.").size(14),
        code_input,
    ]
    .spacing(10)
    .align_x(Alignment::Center);

    if busy {
        content = content.push(text("Verifying…").size(14));
    }
    if let Some(error) = error {
        content = content.push(error_text(error));
    }
    content = content.push(submit);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}
