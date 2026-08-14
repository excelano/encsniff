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
| Window is not valid UTF-8 | WarnUnknown | The bytes are decidably not UTF-8, but which encoding they are is not knowable from a signature. `encoding` is empty. Hint *suggests* trying `iconv -f WINDOWS-1252` or `-f LATIN1`. |
| Anything else | UseAsIs | Assume UTF-8/ASCII; no guessing. |

`WarnUnknown` is not an exception to the no-guessing rule. Naming a single-byte
encoding would be a guess; saying the bytes are not UTF-8 is not, because UTF-8
is a decidable grammar. The verdict is "definitely not UTF-8, and I cannot tell
you which encoding it is" — and the hint that comes with it is worded as
something to try rather than as a claim about the file.

The scan window is 4 KB, so a character straddling its end arrives truncated.
Truncation is never reported as invalid: only a byte that could not appear where
it did counts. The cost of that rule is one quiet case — a file ending on a lone
lead byte reads as clean, because it is indistinguishable from a character cut
in half. Real legacy exports put high bytes in front of ASCII repeatedly, so
they are flagged on the first such pair.

A clean sniff still proves nothing about the rest of the file. This has always
been a head-of-file check, so callers still need a decent error on the read path
and should not treat `UseAsIs` as a guarantee.

## What it does not do

No heuristic encoding detection. CP1252 vs Latin-1, language-based detection, byte-frequency analysis are all out of scope. If you need that, reach for `uchardet`.

## License

MIT. Author: David M. Anderson. Built with AI assistance (Claude, Anthropic).
