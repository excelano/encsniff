# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories at https://github.com/excelano/encsniff/security/advisories/new. If you would rather not use GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest 0.x release receives security fixes. Older versions are not supported.

## What encsniff can access

encsniff is a library, not a service. `sniff_bytes` inspects a byte slice you pass it and never touches the filesystem or network. `sniff_file` opens the path you give it, reads only the head of the file to check for a known signature and to test whether those bytes are valid UTF-8, and closes it. It does no writes, makes no network calls, runs no subprocesses, and stores nothing. It detects only byte-perfect signatures (UTF-8 BOM, UTF-16 LE/BE, the UTF-7 escape) and UTF-8 validity — there is no heuristic parsing of file contents and no execution of anything the file contains.

The `hint` field composes an `iconv` command as a string for the caller to display. It is never run, and nothing in this crate executes a shell.

## What encsniff stores

Nothing. No telemetry, no analytics, no caching, no remote logging. The only output is the returned `Sniff` value and, for `sniff_file`, a single read against the path you supplied.
