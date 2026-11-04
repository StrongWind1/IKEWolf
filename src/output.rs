//! Terminal output helpers -- status lines, colored prefixes, section headers.
//!
//! Convention: `[*]` info, `[+]` success, `[!]` warning,
//! `[-]` error, with `colored` for ANSI coloring.
//!
//! Status lines (`status_*`) go to stderr so they don't mix with data
//! output (JSON, hash lines). Section headers and result data go to stdout.

use colored::Colorize;

/// Print an informational status line to stderr: `[*] msg`.
pub(crate) fn status_info(msg: &str) {
    eprintln!("{} {msg}", "[*]".bold().blue());
}

/// Print a success status line to stderr: `[+] msg`.
pub(crate) fn status_ok(msg: &str) {
    eprintln!("{} {msg}", "[+]".bold().green());
}

/// Print a warning status line to stderr: `[!] msg`.
pub(crate) fn status_warn(msg: &str) {
    eprintln!("{} {msg}", "[!]".bold().yellow());
}

/// Print an error status line to stderr: `[-] msg`.
#[expect(dead_code, reason = "used by future subcommands (psk, enum-groups)")]
pub(crate) fn status_err(msg: &str) {
    eprintln!("{} {msg}", "[-]".bold().red());
}

/// Print a section header to stdout (result data, not status).
pub(crate) fn section_header(title: &str) {
    println!("{}", title.bold().underline());
}

/// Apply the `--no-color` flag globally.
/// The `colored` crate also honours the `NO_COLOR` env var automatically.
pub(crate) fn apply_no_color(no_color: bool) {
    if no_color {
        colored::control::set_override(false);
    }
}
