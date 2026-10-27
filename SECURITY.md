# Security policy

lately reads sensitive evidence (logs, crash reports, persistence items) and is meant to help people judge whether something on their Mac is wrong. Any of these is a security issue:

- it changes, deletes or starts anything on the system, or writes a file other than its baseline and files the user explicitly saves;
- personal data (user, host or real names, paths, serial numbers, addresses) survives redaction in `--json`, `--md` or the export;
- the baseline stores something readable (a name, path or URL) instead of salted hashes;
- a rule hides, or rates too low, evidence that something malicious happened (for example a detection that never reaches the timeline);
- crafted log text, plist or report content makes lately misbehave.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Include the lately version, macOS version and chip, and steps to reproduce. Replace real names and paths with placeholders. You can expect an acknowledgement within a week.

## Supported versions

Only the latest release receives fixes.
