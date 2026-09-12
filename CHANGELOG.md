# Changelog

## 4.2.1 — Startup and security hardening

- `Start ArmorAV.cmd` now offers `1` CLI and `2` Browser Console, validates the locally built version and rebuilds a stale selected executable.
- Browser Console binds to a dynamically assigned `127.0.0.1` port, writes its active URL only after Kestrel starts, and records startup failures in `%LOCALAPPDATA%\ArmorAV\armorav-web.log`.
- A random in-memory session token protects all local data, scan, restore, report and shutdown APIs; security headers prevent embedding and cross-origin use.
- Cache entries require an exact SHA-256 content match and engine-version match; cache writes are atomic and path-safe.
- ZIP analysis streams signatures under a decompression budget and keeps only an 8 MB entry prefix in memory; OLE/VBA parsers validate container fields and cap entries, streams and decompression attempts.
- Quarantine item IDs and metadata are validated, AES-GCM binds restore-relevant metadata, restore cannot overwrite a newly created destination, and plaintext quarantine size is capped at 64 MB.
- Fixed the Downloads/AppData executable-location heuristic and neutralized spreadsheet formulas in CSV output.
- Added smoke coverage for cache timestamp spoofing and quarantine metadata tampering.

## 4.2.0 — Browser Console

- Avalonia Desktop-интерфейс заменён на локальную Browser Console без сторонних UI-пакетов.
- `ArmorAV.Web.exe` открывает браузер автоматически и слушает только `127.0.0.1`.
- Добавлены проводник файловой системы, очередь проверки, прогресс состояния, таблица результатов, подробности срабатываний, экран карантина и экспорт всех форматов отчётов.
- `Start ArmorAV.cmd` собирает и запускает Browser Console двойным щелчком.
- Добавлены сигнатуры для загрузчиков, LOLBins, persistence, credential theft, exfiltration, lateral movement и defense evasion.
- Добавлены эвристики исполняемых lure-файлов, файлов из user-writable каталогов, цепочек download-and-execute, encoded execution и native interop.
- Добавлены ATT&CK-связи для execution и lateral movement.

## 4.0.0 — ArmorAV

- Переименование SentrAV в **ArmorAV**.
- Исходники вынесены из ZIP в обычную solution-структуру .NET 8.
- Добавлены общий `ArmorAV.Core`, CLI-проект `armorav` и кроссплатформенный Desktop-интерфейс Avalonia.
- Добавлен прикладной API `ArmorAVService`, общий для GUI и CLI-сценариев.
- Карантин переведён на AES-256-GCM с аутентификацией, атомарными записями и дополнительной проверкой хэша перед удалением оригинала.
- Кэш и карантин по умолчанию хранятся в пользовательской папке данных, а не в каталоге приложения.
- Scanner не следует reparse points даже если они переданы как исходный путь; исключено слишком широкое сравнение путей карантина.
- `--help` возвращает код 0, проверяются границы числовых параметров, `--fail-fast` теперь работает, добавлен `--data-dir`.
- Добавлены dependency-free smoke-тесты для EICAR, benign sample, ZIP traversal и quarantine round trip.
- Удалён из поставки PFX-артефакт, находившийся в исходном ZIP.
