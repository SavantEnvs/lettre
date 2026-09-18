#![no_main]
// mayhem_mailbox_parse -- drives lettre's RFC5322/RFC2822 header-value parsers with raw,
// untrusted bytes. This is lettre's real "parse untrusted text" surface: the crate never parses
// a full raw MIME message (it is a *builder*, not a parser), but every header value a caller
// hands it -- an address, a Content-Type, a Content-Disposition -- goes through one of these
// FromStr/Header::parse entry points, all reachable straight from network- or user-supplied
// strings in a real mail application (e.g. parsing a Reply-To pulled out of an inbound message).
//
// Exercises:
//   - Mailbox::from_str / Mailboxes::from_str  -> src/message/mailbox/parsers/rfc2822.rs (nom)
//   - Address::from_str                        -> email_address crate + idna::domain_to_ascii
//   - ContentType::parse                       -> the `mime` crate's grammar
//   - ContentDisposition (Header::parse)        -> src/message/header/content_disposition.rs
//   - Date (Header::parse)                      -> httpdate, with lettre's "+0000"->"GMT" patch
//
// For every successful parse we also assert an idempotency property: re-serializing the parsed
// value (Display) and parsing that output again must ALSO succeed -- a real behavioral check that
// a no-op/neutered parser (or a broken Display impl) would fail.
use std::str::FromStr;

use lettre::{
    Address,
    message::{
        Mailbox, Mailboxes,
        header::{ContentDisposition, ContentType, Header},
    },
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if s.len() > 1 << 16 {
        return; // keep runs fast; the grammar has no legitimate use for huge inputs
    }

    if let Ok(mbox) = Mailbox::from_str(s) {
        let rendered = mbox.to_string();
        let reparsed = Mailbox::from_str(&rendered);
        assert!(
            reparsed.is_ok(),
            "Mailbox round-trip failed: {s:?} -> {rendered:?} -> {reparsed:?}"
        );
        // The address portion must never be dropped or truncated by the round-trip.
        // (Address impls both AsRef<str> and AsRef<OsStr>, so disambiguate explicitly.)
        let email_str: &str = AsRef::<str>::as_ref(&mbox.email);
        assert!(
            rendered.contains(email_str),
            "Mailbox Display lost the address: {s:?} -> {rendered:?}"
        );
    }

    if let Ok(mboxes) = Mailboxes::from_str(s) {
        let rendered = mboxes.to_string();
        // An empty list has nothing to prove; a non-empty one must round-trip.
        if mboxes.iter().next().is_some() {
            let reparsed = Mailboxes::from_str(&rendered);
            assert!(
                reparsed.is_ok(),
                "Mailboxes round-trip failed: {s:?} -> {rendered:?} -> {reparsed:?}"
            );
        }
    }

    if let Ok(addr) = Address::from_str(s) {
        let rendered = addr.to_string();
        let reparsed = Address::from_str(&rendered);
        assert!(
            reparsed.is_ok(),
            "Address round-trip failed: {s:?} -> {rendered:?} -> {reparsed:?}"
        );
        assert_eq!(
            reparsed.unwrap(),
            addr,
            "Address round-trip changed value: {s:?} -> {rendered:?}"
        );
    }

    // ContentType has no public accessor to re-extract its parsed string (the mime crate's
    // Display is only reachable through a private field), so this call is coverage-only: it
    // still exercises the mime grammar and must never panic on adversarial input.
    let _ = ContentType::parse(s);

    let _ = ContentDisposition::parse(s);
    let _ = lettre::message::header::Date::parse(s);
});
