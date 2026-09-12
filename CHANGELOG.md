# Changelog

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
