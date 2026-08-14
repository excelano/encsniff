//! Detect common non-UTF-8 text encodings from byte-perfect signatures.
//!
//! `encsniff` inspects the head of a file or byte slice and reports whether
//! the caller should proceed (clean UTF-8/ASCII), silently skip a UTF-8 BOM,
//! or warn the user about a non-UTF-8 encoding with a copy-pasteable `iconv`
//! hint. It detects only patterns with byte-perfect signatures — no
//! heuristics, no language models, no byte-frequency analysis.
//!
//! ```
//! use encsniff::{sniff_file, Action};
//!
//! # fn run(path: &str) -> std::io::Result<()> {
//! let s = sniff_file(path)?;
//! match s.action {
//!     Action::UseAsIs => { /* proceed */ }
//!     Action::StripBom => { /* skip s.bom_len bytes */ }
//!     Action::Warn => {
//!         eprintln!("warning: file appears to be {} encoded.", s.encoding.unwrap());
//!         if let Some(hint) = &s.hint {
//!             eprintln!("hint: {}", hint);
//!         }
//!     }
//!     Action::WarnUnknown => {
//!         eprintln!("warning: file is not valid UTF-8, and its encoding could not be named.");
//!         if let Some(hint) = &s.hint {
//!             eprintln!("hint: {}", hint);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// What the caller should do with the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Input looks like UTF-8 or ASCII; proceed unchanged.
    UseAsIs,
    /// Input is UTF-8 with a leading BOM; skip [`Sniff::bom_len`] bytes.
    StripBom,
    /// Input is a non-UTF-8 encoding the user should know about.
    Warn,
    /// Input is provably not UTF-8, but which encoding it is could not be
    /// determined. [`Sniff::encoding`] is `None` — nothing was proven about
    /// the identity, only about what it is not.
    ///
    /// Naming a single-byte encoding would be a guess, and this crate does not
    /// guess. Saying the bytes are not UTF-8 is not a guess: UTF-8 is a
    /// decidable grammar and [`std::str::from_utf8`] decides it exactly.
    WarnUnknown,
}

/// The detected encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Utf7,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Encoding::Utf8Bom => "UTF-8 with BOM",
            Encoding::Utf16Le => "UTF-16 little-endian",
            Encoding::Utf16Be => "UTF-16 big-endian",
            Encoding::Utf7 => "UTF-7",
        };
        f.write_str(s)
    }
}

/// The result of a detection pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniff {
    pub action: Action,
    pub encoding: Option<Encoding>,
    pub bom_len: usize,
    /// Copy-pasteable iconv command. Set by [`sniff_file`] on either warning
    /// action; `None` from [`sniff_bytes`] because no path is available.
    pub hint: Option<String>,
}

impl Sniff {
    /// Whether this result is something the user should be told about.
    ///
    /// Prefer this to comparing against [`Action::Warn`]: every consumer in
    /// the fleet wrote `action != Action::Warn` to mean "nothing to report",
    /// which silently swallowed [`Action::WarnUnknown`] when it was added.
    /// A predicate absorbs the next verdict too.
    pub fn is_warning(&self) -> bool {
        matches!(self.action, Action::Warn | Action::WarnUnknown)
    }
}

/// How far into the input we look for the UTF-7 escape marker. 4 KiB
/// comfortably covers CSV header rows, JSON object starts, and short docs.
const SCAN_WINDOW: usize = 4096;

/// UTF-7 escape for the double-quote character — the canonical user-facing
/// tell of UTF-7 in Scoutbook and Excel exports.
const UTF7_MARKER: &[u8] = b"+ACI-";

/// Inspect the head of `b` and return the detected action.
///
/// The `hint` field is left empty; callers with a path should use
/// [`sniff_file`], or compose a hint with [`iconv_command`].
pub fn sniff_bytes(b: &[u8]) -> Sniff {
    if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Sniff {
            action: Action::StripBom,
            encoding: Some(Encoding::Utf8Bom),
            bom_len: 3,
            hint: None,
        };
    }
    if b.starts_with(&[0xFF, 0xFE]) {
        return Sniff {
            action: Action::Warn,
            encoding: Some(Encoding::Utf16Le),
            bom_len: 0,
            hint: None,
        };
    }
    if b.starts_with(&[0xFE, 0xFF]) {
        return Sniff {
            action: Action::Warn,
            encoding: Some(Encoding::Utf16Be),
            bom_len: 0,
            hint: None,
        };
    }
    let window = if b.len() > SCAN_WINDOW {
        &b[..SCAN_WINDOW]
    } else {
        b
    };
    if find_subslice(window, UTF7_MARKER).is_some() {
        return Sniff {
            action: Action::Warn,
            encoding: Some(Encoding::Utf7),
            bom_len: 0,
            hint: None,
        };
    }
    if window_has_invalid_utf8(window) {
        return Sniff {
            action: Action::WarnUnknown,
            encoding: None,
            bom_len: 0,
            hint: None,
        };
    }
    Sniff {
        action: Action::UseAsIs,
        encoding: None,
        bom_len: 0,
        hint: None,
    }
}

/// Whether `window` contains a genuinely invalid UTF-8 byte, as opposed to a
/// multi-byte sequence cut in half by the end of the scan window.
///
/// The distinction is the whole difficulty. `SCAN_WINDOW` is a fixed 4 KiB, so
/// a character straddling byte 4096 arrives here truncated, and a file that is
/// perfectly good UTF-8 would be reported as broken. `Utf8Error::error_len`
/// draws exactly the line needed: `None` means the input ended mid-sequence,
/// `Some(_)` means a byte that cannot appear where it did.
fn window_has_invalid_utf8(window: &[u8]) -> bool {
    match std::str::from_utf8(window) {
        Ok(_) => false,
        Err(e) => e.error_len().is_some(),
    }
}

/// Open `path`, sniff the head, and return the result with `hint` set to a
/// copy-pasteable `iconv` command when `action == Warn`.
pub fn sniff_file<P: AsRef<Path>>(path: P) -> io::Result<Sniff> {
    let path = path.as_ref();
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; SCAN_WINDOW];
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    buf.truncate(filled);
    let mut s = sniff_bytes(&buf);
    match s.action {
        Action::Warn => {
            if let Some(enc) = s.encoding {
                s.hint = iconv_command(enc, path);
            }
        }
        Action::WarnUnknown => s.hint = Some(iconv_guess_command(path)),
        Action::UseAsIs | Action::StripBom => {}
    }
    Ok(s)
}

/// Compose an `iconv` command that converts `path` from `enc` to UTF-8,
/// writing to a sibling file with `.utf8` inserted before the extension.
/// Returns `None` for encodings that need no conversion (only `Utf8Bom`).
pub fn iconv_command(enc: Encoding, path: &Path) -> Option<String> {
    let from = iconv_from_name(enc)?;
    let dst = utf8_sibling_path(path);
    Some(format!(
        "iconv -f {} -t UTF-8 {} > {}",
        from,
        path.display(),
        dst.display()
    ))
}

/// Compose a *suggested* conversion for a file that is provably not UTF-8 but
/// whose encoding could not be named.
///
/// Deliberately worded as something to try rather than as a claim. Every other
/// hint this crate produces follows a byte-perfect signature and can assert
/// what the file is; this one follows only the absence of valid UTF-8, and the
/// two candidates it names are the common cases, not a detection.
pub fn iconv_guess_command(path: &Path) -> String {
    let dst = utf8_sibling_path(path);
    format!(
        "if this is a legacy export, try: iconv -f WINDOWS-1252 -t UTF-8 {} > {} (or -f LATIN1)",
        path.display(),
        dst.display()
    )
}

fn iconv_from_name(enc: Encoding) -> Option<&'static str> {
    match enc {
        Encoding::Utf7 => Some("UTF-7"),
        Encoding::Utf16Le => Some("UTF-16LE"),
        Encoding::Utf16Be => Some("UTF-16BE"),
        Encoding::Utf8Bom => None,
    }
}

fn utf8_sibling_path(path: &Path) -> PathBuf {
    match path.extension() {
        Some(ext) => {
            let mut new_ext = OsString::from("utf8.");
            new_ext.push(ext);
            path.with_extension(new_ext)
        }
        None => path.with_extension("utf8"),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn s(action: Action, encoding: Option<Encoding>, bom_len: usize) -> Sniff {
        Sniff {
            action,
            encoding,
            bom_len,
            hint: None,
        }
    }

    #[test]
    fn sniff_bytes_clean_ascii() {
        assert_eq!(
            sniff_bytes(b"memberid,prefix,firstname\n101,Mr,David\n"),
            s(Action::UseAsIs, None, 0)
        );
    }

    #[test]
    fn sniff_bytes_clean_utf8_with_non_ascii() {
        assert_eq!(
            sniff_bytes("name,city\nDavid,München\n".as_bytes()),
            s(Action::UseAsIs, None, 0)
        );
    }

    #[test]
    fn sniff_bytes_latin1_is_not_use_as_is() {
        // "café" in Latin-1: 0xE9 is a lone continuation-less lead byte in
        // UTF-8 terms, so the bytes are decidably not UTF-8.
        let input = b"name,city\nDavid,caf\xE9\n";
        assert_eq!(
            sniff_bytes(input),
            s(Action::WarnUnknown, None, 0),
            "a CP1252/Latin-1 export must not assert it is usable as-is"
        );
    }

    #[test]
    fn sniff_bytes_flags_an_invalid_byte_at_the_very_end() {
        // 0xFF can never appear in UTF-8 at all, so there is no truncation
        // story that excuses it, even as the last byte.
        assert_eq!(sniff_bytes(b"ok,\xFF"), s(Action::WarnUnknown, None, 0));
    }

    #[test]
    fn sniff_bytes_does_not_flag_a_character_cut_by_the_scan_window() {
        // The trap the whole check has to survive: a 3-byte character starting
        // at 4094 leaves two of its bytes inside the window and one outside.
        // The file is perfectly good UTF-8; only our view of it is truncated.
        let mut input = vec![b'a'; SCAN_WINDOW - 2];
        input.extend_from_slice("€".as_bytes()); // E2 82 AC
        assert_eq!(input.len(), SCAN_WINDOW + 1);
        assert_eq!(
            sniff_bytes(&input),
            s(Action::UseAsIs, None, 0),
            "a character straddling the window boundary is not a broken file"
        );
    }

    #[test]
    fn sniff_bytes_does_not_flag_a_truncated_character_at_end_of_input() {
        // Same case reached by a short file rather than by the window: the
        // input simply stops mid-character.
        let euro = "€".as_bytes();
        assert_eq!(sniff_bytes(&euro[..2]), s(Action::UseAsIs, None, 0));
    }

    #[test]
    fn sniff_bytes_flags_an_overlong_encoding() {
        // C0 80 is a two-byte encoding of NUL — well-formed in shape, illegal
        // in UTF-8. error_len() reports Some, so it is a real error and not a
        // truncation.
        assert_eq!(sniff_bytes(b"a\xC0\x80b"), s(Action::WarnUnknown, None, 0));
    }

    #[test]
    fn sniff_bytes_does_not_flag_a_lone_high_byte_at_end_of_input() {
        // Looks like a bug and is not. 0xE9 is a legal lead byte for a 3-byte
        // sequence, so as the final byte of the input it is indistinguishable
        // from a character the window cut in half — and the rule is that
        // truncation is never flagged. Real Latin-1 files are unaffected: 4 KiB
        // of legacy text puts high bytes in front of ASCII repeatedly, and each
        // of those is a genuine error. Only a file ending exactly on one is
        // quiet, which is the price of never crying wolf on a good file.
        assert_eq!(sniff_bytes(b"caf\xE9"), s(Action::UseAsIs, None, 0));
        assert_eq!(sniff_bytes(b"caf\xE9\n"), s(Action::WarnUnknown, None, 0));
    }

    #[test]
    fn warn_unknown_is_a_warning() {
        assert!(sniff_bytes(b"caf\xE9\n").is_warning());
        assert!(sniff_bytes(&[0xFF, 0xFE]).is_warning());
        assert!(!sniff_bytes(b"plain ascii").is_warning());
        assert!(!sniff_bytes(&[0xEF, 0xBB, 0xBF]).is_warning());
    }

    #[test]
    fn sniff_file_hints_at_conversion_for_an_unnameable_encoding() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("l1.csv");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"name\ncaf\xE9\n").unwrap();
        drop(f);

        let got = sniff_file(&path).unwrap();
        assert_eq!(got.action, Action::WarnUnknown);
        assert_eq!(got.encoding, None);
        let hint = got.hint.expect("an unnameable encoding still earns a hint");
        assert!(hint.contains("WINDOWS-1252"), "hint was: {hint}");
        assert!(hint.contains("LATIN1"), "hint was: {hint}");
        assert!(hint.contains("l1.utf8.csv"), "hint was: {hint}");
        // Worded as a suggestion, because unlike every other hint here it does
        // not follow from a signature.
        assert!(hint.starts_with("if this is"), "hint was: {hint}");
    }

    #[test]
    fn sniff_bytes_empty() {
        assert_eq!(sniff_bytes(b""), s(Action::UseAsIs, None, 0));
    }

    #[test]
    fn sniff_bytes_utf8_bom() {
        let mut input = vec![0xEF, 0xBB, 0xBF];
        input.extend_from_slice(b"memberid,prefix\n");
        assert_eq!(
            sniff_bytes(&input),
            s(Action::StripBom, Some(Encoding::Utf8Bom), 3)
        );
    }

    #[test]
    fn sniff_bytes_utf16_le_bom() {
        assert_eq!(
            sniff_bytes(&[0xFF, 0xFE, b'a', 0x00, b'b', 0x00]),
            s(Action::Warn, Some(Encoding::Utf16Le), 0)
        );
    }

    #[test]
    fn sniff_bytes_utf16_be_bom() {
        assert_eq!(
            sniff_bytes(&[0xFE, 0xFF, 0x00, b'a', 0x00, b'b']),
            s(Action::Warn, Some(Encoding::Utf16Be), 0)
        );
    }

    #[test]
    fn sniff_bytes_utf7_marker() {
        assert_eq!(
            sniff_bytes(b"+ACI-memberid+ACI-,+ACI-prefix+ACI-\n"),
            s(Action::Warn, Some(Encoding::Utf7), 0)
        );
    }

    #[test]
    fn sniff_bytes_utf7_marker_deep_in_window() {
        let mut input = vec![b'a'; 3000];
        input.extend_from_slice(b"+ACI-x+ACI-");
        assert_eq!(
            sniff_bytes(&input),
            s(Action::Warn, Some(Encoding::Utf7), 0)
        );
    }

    #[test]
    fn sniff_bytes_utf7_marker_past_window_not_detected() {
        let mut input = vec![b'a'; SCAN_WINDOW];
        input.extend_from_slice(b"+ACI-x+ACI-");
        assert_eq!(sniff_bytes(&input), s(Action::UseAsIs, None, 0));
    }

    #[test]
    fn sniff_bytes_short_fragment_could_be_bom_prefix() {
        assert_eq!(sniff_bytes(&[0xEF]), s(Action::UseAsIs, None, 0));
    }

    fn write_temp(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.path().join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    #[test]
    fn sniff_file_utf7_csv_hint_matches() {
        let dir = TempDir::new().unwrap();
        let p = write_temp(
            &dir,
            "Roster_Report.csv",
            b"+ACI-memberid+ACI-,+ACI-prefix+ACI-\n101,Mr\n",
        );
        let got = sniff_file(&p).unwrap();
        assert_eq!(got.action, Action::Warn);
        assert_eq!(got.encoding, Some(Encoding::Utf7));
        let want = format!(
            "iconv -f UTF-7 -t UTF-8 {} > {}",
            p.display(),
            dir.path().join("Roster_Report.utf8.csv").display()
        );
        assert_eq!(got.hint.as_deref(), Some(want.as_str()));
    }

    #[test]
    fn sniff_file_utf8_bom_strip_no_hint() {
        let dir = TempDir::new().unwrap();
        let mut input = vec![0xEF, 0xBB, 0xBF];
        input.extend_from_slice(b"a,b\n1,2\n");
        let p = write_temp(&dir, "excel.csv", &input);
        let got = sniff_file(&p).unwrap();
        assert_eq!(got.action, Action::StripBom);
        assert_eq!(got.bom_len, 3);
        assert!(got.hint.is_none());
    }

    #[test]
    fn sniff_file_utf16_le_hint_suggests_utf16le() {
        let dir = TempDir::new().unwrap();
        let p = write_temp(&dir, "wide.csv", &[0xFF, 0xFE, b'a', 0x00]);
        let got = sniff_file(&p).unwrap();
        assert_eq!(got.action, Action::Warn);
        assert_eq!(got.encoding, Some(Encoding::Utf16Le));
        assert!(got.hint.unwrap().contains("UTF-16LE"));
    }

    #[test]
    fn sniff_file_clean_utf8_no_action() {
        let dir = TempDir::new().unwrap();
        let p = write_temp(&dir, "clean.csv", b"a,b\n1,2\n");
        let got = sniff_file(&p).unwrap();
        assert_eq!(got.action, Action::UseAsIs);
    }

    #[test]
    fn sniff_file_missing_file_returns_error() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("nope.csv");
        assert!(sniff_file(&p).is_err());
    }

    #[test]
    fn sniff_file_tiny_file() {
        let dir = TempDir::new().unwrap();
        let p = write_temp(&dir, "tiny.csv", b"a");
        let got = sniff_file(&p).unwrap();
        assert_eq!(got.action, Action::UseAsIs);
    }

    #[test]
    fn utf8_sibling_path_cases() {
        let cases = [
            ("Roster.csv", "Roster.utf8.csv"),
            ("/tmp/data.txt", "/tmp/data.utf8.txt"),
            ("noext", "noext.utf8"),
            ("a.b.csv", "a.b.utf8.csv"),
        ];
        for (input, want) in cases {
            let got = utf8_sibling_path(Path::new(input));
            assert_eq!(got, PathBuf::from(want), "input={input}");
        }
    }

    #[test]
    fn encoding_display() {
        assert_eq!(Encoding::Utf7.to_string(), "UTF-7");
        assert_eq!(Encoding::Utf16Le.to_string(), "UTF-16 little-endian");
        assert_eq!(Encoding::Utf16Be.to_string(), "UTF-16 big-endian");
        assert_eq!(Encoding::Utf8Bom.to_string(), "UTF-8 with BOM");
    }
}
