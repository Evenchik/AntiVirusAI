# Security policy

## Scope

ArmorAV performs local static analysis. It does not execute scanned files, submit them to cloud services, or provide kernel-level real-time protection. Do not use it as the sole control for high-risk environments.

## Reporting a vulnerability

Do **not** publish exploit details, private keys, personal data or live malware samples in a public issue. Use GitHub's private security advisory/reporting facility for this repository, with:

- affected version and operating system;
- minimal safe reproduction steps;
- expected and observed behaviour;
- impact assessment.

## Operational guidance

- Keep reports, allowlists, scan cache and quarantine outside source control.
- Treat quarantine as sensitive local data. Its encryption key is stored in the same per-user application-data area in order to support offline restore; protect that account and back up the data directory together.
- Validate detections before using the destructive `--quarantine` option.
- Use the latest release and run the smoke tests after modifying detection rules.
