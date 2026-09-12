# ArmorAV

**ArmorAV** — локальный статический анализатор вредоносных файлов для .NET 8. Он не отправляет проверяемые данные в интернет и предоставляет два интерфейса, которые используют одно и то же ядро:

1. **CLI** — для терминала, скриптов и CI.
2. **ArmorAV Desktop** — кроссплатформенное нативное окно на Avalonia для Windows, Linux и macOS.

> ArmorAV — эвристический и сигнатурный scanner, а не замена полнофункциональному антивирусу с real-time protection. Любое срабатывание следует проверять перед удалением файлов.

## Что умеет ядро

- Потоковые сигнатуры Aho–Corasick, байтовые паттерны и составные правила.
- Хэши MD5/SHA-1/SHA-256, fuzzy fingerprint, imphash и Rich Header для PE.
- Эвристики для PE, .NET metadata, LNK, ZIP/вложенных ZIP, ISO, PDF, RTF, OLE/VBA, OOXML и почтовых контейнеров.
- Деобфускация Base64, PowerShell `EncodedCommand`, XOR, hex, конкатенаций и других распространённых приёмов.
- Проверки path traversal, двойных расширений, RTL-override, archive bombs, ссылок/reparse points и ограничения на глубину/размеры.
- Классификация `Clean`, `Suspicious`, `Confirmed`, ATT&CK-техники, JSON/HTML/CSV/SARIF-отчёты.
- Локальный allowlist и кэш (кэш включается только по явному запросу).

## Быстрый старт

Нужен **.NET SDK 8**. Скрипт устанавливает его только для текущего пользователя, без `sudo`:

```bash
chmod +x scripts/*.sh
./scripts/install-dotnet.sh
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$DOTNET_ROOT:$PATH"
./scripts/build.sh
```

Для Desktop-интерфейса при первом `restore` загрузятся пакеты Avalonia 11.2.3 из NuGet.

### CLI

```bash
# Справка
./scripts/run-cli.sh --help

# Сканирование папки и отчёты
./scripts/run-cli.sh ./samples --html armorav-report.html --sarif armorav-report.sarif --stats

# Проверить файл, включить безопасный кэш
./scripts/run-cli.sh suspicious-file.ps1 --cache --json report.json

# Карантин только подтверждённых угроз
./scripts/run-cli.sh ./incoming --quarantine

# Просмотр и восстановление карантина
./scripts/run-cli.sh --list-quarantine
./scripts/run-cli.sh --restore <id>
```

Коды завершения: `0` — чисто, `1` — есть подозрительные файлы, `2` — есть подтверждённые угрозы, `3` — ошибка запуска или параметров.

Полезные параметры:

```text
--data-dir <directory>   расположение кэша и карантина
--allowlist <file>       по одному MD5/SHA-1/SHA-256 на строку
--max-depth N            предел рекурсии (по умолчанию 10)
--max-nested-depth N     глубина вложенных ZIP (по умолчанию 5)
--max-decompressed N     лимит распаковки в байтах
--max-entries N          лимит файлов в ZIP
--max-file-size N        пропускать файлы крупнее N байт
--threads N              число рабочих потоков
--fail-fast              не начинать новые проверки после Confirmed
--verbose / --quiet / --no-color
```

### Desktop

```bash
./scripts/run-desktop.sh
```

В приложении выберите файл или папку, при необходимости включите карантин, нажмите **«Сканировать»** и сохраните JSON/HTML-отчёт. Приложение запускает анализ в фоне, поэтому окно не блокируется.

## Данные и безопасность

- Кэш и карантин по умолчанию хранятся в пользовательской папке данных ОС (`.../ArmorAV`), а не рядом с установленным приложением.
- В quarantine попадают только результаты `Confirmed` и только после включения `--quarantine`/опции в GUI. Без неё показан только dry-run.
- Новые объекты карантина используют **AES-256-GCM**: данные аутентифицированы, зашифрованы и записываются атомарно. Перед удалением оригинала ArmorAV повторно проверяет SHA-256, чтобы не удалить файл, заменённый во время анализа.
- Восстановление откажется перезаписывать существующий файл и проверит аутентификацию с SHA-256.
- В проект не включены сертификаты, ключи, кэш, карантин или готовые вредоносные бинарные файлы.

## Структура

```text
src/ArmorAV.Core       общее ядро статического анализа
src/ArmorAV.Cli        консольная точка входа (armorav)
src/ArmorAV.Desktop    GUI Avalonia
tests/ArmorAV.SmokeTests  smoke-тесты без тестового фреймворка
scripts/               установка SDK, сборка и запуск
```

## Сборка релизов

```bash
dotnet publish src/ArmorAV.Cli/ArmorAV.Cli.csproj -c Release -r win-x64 --self-contained true
dotnet publish src/ArmorAV.Desktop/ArmorAV.Desktop.csproj -c Release -r win-x64 --self-contained true
```

Замените `win-x64` на нужный RID, например `linux-x64`, `linux-arm64` или `osx-arm64`.
