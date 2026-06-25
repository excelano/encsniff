# encsniff

A small Rust crate for sniffing common non-UTF-8 text encodings at the head of a file or byte slice. It detects only patterns with byte-perfect signatures — no heuristics. It returns an action (use as is, strip BOM, or warn) and a copy-pasteable `iconv` hint when conversion is needed.

Companion to [`encsniff-go`](https://github.com/excelano/encsniff-go).

## Install

```toml
[dependencies]
encsniff = "0.1"
```

## Usage

```rust
use encsniff::{sniff_file, Action};

let s = sniff_file("Roster_Report.csv")?;
match s.action {
    Action::UseAsIs => { /* proceed */ }
    Action::StripBom => { /* skip s.bom_len bytes silently */ }
    Action::Warn => {
        eprintln!("warning: file appears to be {} encoded.", s.encoding.unwrap());
        if let Some(hint) = &s.hint {
            eprintln!("hint: {}", hint);
        }
    }
}
# Ok::<(), std::io::Error>(())
```

`sniff_bytes(&[u8]) -> Sniff` is the in-memory version.

## What it detects

| Pattern | Action | Why |
| --- | --- | --- |
| `EF BB BF` at offset 0 | StripBom | UTF-8 BOM from "Save as CSV UTF-8". Skip the 3 bytes; the file is otherwise clean. |
| `FF FE` at offset 0 | Warn | UTF-16 little-endian. Hint suggests `iconv -f UTF-16LE -t UTF-8`. |
| `FE FF` at offset 0 | Warn | UTF-16 big-endian. Hint suggests `iconv -f UTF-16BE -t UTF-8`. |
| `+ACI-` in first 4KB | Warn | UTF-7 escape for `"` (common in Scoutbook and some Microsoft exports). Hint suggests `iconv -f UTF-7 -t UTF-8`. |
| Anything else | UseAsIs | Assume UTF-8/ASCII; no guessing. |

## What it does not do

No heuristic encoding detection. CP1252 vs Latin-1, language-based detection, byte-frequency analysis are all out of scope. If you need that, reach for `uchardet`.

## License

MIT. Author: David M. Anderson. Built with AI assistance (Claude, Anthropic).
