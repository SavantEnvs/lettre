//! client-buggy-mhh-run-30 — the backport reproducer for the mayhemheroes `client` target
//! (run 30: https://app.mayhem.security/mayhemheroes/lettre/client/30).
//!
//! The original harness (mayhem/client/src/main.rs on the fuzzed fork commit 8814933) is a plain
//! binary that builds one fixed email and hands it to an `SmtpTransport` pointed at
//! tcp://127.0.0.1:25, with Mayhem's NETWORK fuzzer playing the remote SMTP server and the fuzzed
//! bytes being the server's *responses*. The untrusted input is therefore the server's byte
//! stream, and the code under test is lettre's SMTP-client response parser
//! (src/transport/smtp/{response,extension}.rs, reached through SmtpConnection::connect/ehlo).
//!
//! v2 environments do not run Mayhem's network mode, so the same input surface is reproduced with
//! a loopback socket inside the process: bind an ephemeral 127.0.0.1 listener, write the test
//! case's bytes to the socket as soon as the client connects, then close the write half. The
//! client sees exactly the byte stream the fuzzer used to send over the wire. Everything else —
//! the fixed email, `builder_dangerous`, the single `send()` — is the original harness verbatim.
//!
//! The test case is a FILE (`cmd: /mayhem/client-buggy-mhh-run-30 @@`), which is how the backport
//! replays the original run's crashers. This is deliberately NOT a libFuzzer target: libFuzzer's
//! deadly-signal handler prints a symbolized stack trace, and Mayhem then groups every crash with
//! that same trace into ONE defect, while the original run — a plain binary whose only output is
//! the Rust panic line — got one defect per crashing input. Keeping the original's crash form
//! keeps the backport's defect accounting comparable to the run it reproduces.
//!
//! Harness errors (a file that cannot be read, a socket that cannot be bound) exit with code 2
//! WITHOUT panicking, so the only panic this binary can produce comes from lettre itself. A lettre
//! panic unwinds out of main and exits 101 — the original harness's exact termination, and the one
//! whose crash report carries no backtrace (see mayhem/client-repro/Cargo.toml).

use std::env;
use std::fs;
use std::io::Write;
use std::net::{Shutdown, TcpListener};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use lettre::{Message, SmtpTransport, Transport};

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: client-buggy-mhh-run-30 <file: the SMTP server's response bytes>");
        return ExitCode::from(2);
    };
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind a loopback listener: {e}");
            return ExitCode::from(2);
        }
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("cannot read the listener address: {e}");
            return ExitCode::from(2);
        }
    };

    // The fake SMTP server: one connection, the test case's bytes, then EOF.
    let server = thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = sock.write_all(&data);
            let _ = sock.flush();
            let _ = sock.shutdown(Shutdown::Write);
        }
    });

    // The original harness's email, unchanged: only the server's responses are the input.
    let email = Message::builder()
        .from("NoBody <nobody@domain.tld>".parse().unwrap())
        .reply_to("Yuin <yuin@domain.tld>".parse().unwrap())
        .to("Hei <hei@domain.tld>".parse().unwrap())
        .subject("Happy new year")
        .body(String::from("Be happy!"))
        .unwrap();

    let sender = SmtpTransport::builder_dangerous(addr.ip().to_string())
        .port(addr.port())
        // The original dialed a real port with no timeout; a replay must not hang on a test case
        // that leaves the client waiting, so the connection is bounded.
        .timeout(Some(Duration::from_millis(500)))
        .build();

    let _result = sender.send(&email);

    let _ = server.join();
    ExitCode::SUCCESS
}
