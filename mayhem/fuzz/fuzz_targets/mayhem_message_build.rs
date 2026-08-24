#![no_main]
// mayhem_message_build -- drives lettre's message-construction/encoding pipeline
// (MessageBuilder -> Message::formatted()) with untrusted header values and body bytes. This is
// lettre's other real attack surface: an application that lets a user supply their own display
// name / subject / message body and then serializes the result with lettre before handing it to
// an SMTP transport. Exercises the RFC2047 word-encoder, the automatic body
// 7bit/quoted-printable/base64 Content-Transfer-Encoding selection (src/message/body.rs), and the
// final EmailWriter line-folding serializer -- none of which is covered by
// mayhem_mailbox_parse (which only exercises the *parsers*, not the builder/encoder path).
//
// Input framing: the raw fuzzer bytes are split on NUL (0x00) into up to five fields --
// from, to, subject, message-id, body -- so a human-readable seed file doubles as a realistic
// example message. from/to must be valid Mailbox strings (parsed with Mailbox::from_str) or the
// input is discarded; subject/message-id/body are used as-is (including adversarial UTF-8 and
// control characters) since real callers cannot pre-validate free-text header/body content.
use std::str::FromStr;

use lettre::message::{Mailbox, Message, header::ContentType};
use libfuzzer_sys::fuzz_target;

const MAX_FIELD: usize = 1 << 14;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(5, |&b| b == 0);
    let from_bytes = parts.next().unwrap_or(&[]);
    let to_bytes = parts.next().unwrap_or(&[]);
    let subject_bytes = parts.next().unwrap_or(&[]);
    let message_id_bytes = parts.next().unwrap_or(&[]);
    let body_bytes = parts.next().unwrap_or(&[]);

    if subject_bytes.len() > MAX_FIELD
        || message_id_bytes.len() > MAX_FIELD
        || body_bytes.len() > MAX_FIELD
    {
        return; // keep runs fast; nothing new is learned from megabyte-scale fields
    }

    let Ok(from_str) = std::str::from_utf8(from_bytes) else {
        return;
    };
    let Ok(to_str) = std::str::from_utf8(to_bytes) else {
        return;
    };
    let Ok(from) = Mailbox::from_str(from_str) else {
        return;
    };
    let Ok(to) = Mailbox::from_str(to_str) else {
        return;
    };

    let subject = String::from_utf8_lossy(subject_bytes).into_owned();
    let message_id = String::from_utf8_lossy(message_id_bytes).into_owned();

    let mut builder = Message::builder()
        .from(from.clone())
        .to(to.clone())
        .subject(subject);

    if !message_id.is_empty() {
        builder = builder.message_id(Some(message_id));
    }

    let result = builder
        .header(ContentType::TEXT_PLAIN)
        .body(body_bytes.to_vec());

    let Ok(message) = result else {
        // A body-encoding failure is a legitimate outcome for some inputs; nothing to assert.
        return;
    };

    let formatted = message.formatted();

    // A successfully built message must always serialize to a non-empty byte stream containing
    // the RFC5322 header/body CRLFCRLF separator -- a neutered/no-op builder would violate this.
    assert!(
        !formatted.is_empty(),
        "formatted() returned empty output for a built Message"
    );
    assert!(
        formatted.windows(4).any(|w| w == b"\r\n\r\n"),
        "formatted() output is missing the header/body CRLFCRLF separator"
    );

    // The From/To mailbox addresses are never RFC2047-encoded (only a display name can be) and
    // so must survive serialization byte-for-byte.
    // (Address impls both AsRef<str> and AsRef<OsStr>, so disambiguate explicitly.)
    let from_email: &str = AsRef::<str>::as_ref(&from.email);
    let to_email: &str = AsRef::<str>::as_ref(&to.email);
    let haystack = String::from_utf8_lossy(&formatted);
    assert!(
        haystack.contains(from_email),
        "formatted() output lost the From address {from_email:?}"
    );
    assert!(
        haystack.contains(to_email),
        "formatted() output lost the To address {to_email:?}"
    );
});
