# ArmorAV

**ArmorAV** — локальный статический анализатор файлов для .NET 8. В продукте два интерфейса, работающие с общим ядром:

- **Browser Console** — основной графический интерфейс в браузере.
- **CLI** — режим для терминала, автоматизации и CI.

Browser Console запускается только на `127.0.0.1` и открывает браузер автоматически. Проверяемые файлы не отправляются в интернет.

> ArmorAV использует сигнатуры, структурный анализ и эвристики. Это не замена системному антивирусу с real-time protection. Проверяйте срабатывания до удаления файлов.

## Запуск в Windows без команд

1. Установите .NET 8 SDK, если его ещё нет: <https://dotnet.microsoft.com/download/dotnet/8.0>.
2. Дважды щёлкните `Start ArmorAV.cmd` в корне папки проекта.
3. При первом запуске файл соберёт локальное приложение и автоматически откроет Browser Console.
4. В дальнейшем этот же файл сразу запускает ArmorAV.

После первой сборки самостоятельный исполняемый файл расположен здесь:

```text
artifacts\win-x64\web\ArmorAV.Web.exe
```

Его можно запускать двойным щелчком или закрепить на панели задач. При запуске он сам открывает браузер с интерфейсом ArmorAV.

## Возможности Browser Console

- Панель состояния и метрики последней проверки.
- Локальный проводник: выбор папки или файла без ручного ввода пути.
- Профили глубины, потоков, локальный кэш и карантин для `Confirmed` угроз.
- Результаты с баллами, типом, хэшем, ATT&CK-техниками и детальными срабатываниями.
- Просмотр объектов карантина и безопасное восстановление.
- Скачивание отчётов JSON, HTML, CSV или SARIF 2.1.

## Возможности ядра

- Более 230 потоковых сигнатур, байтовые паттерны и составные правила.
- Хэши MD5/SHA-1/SHA-256, fuzzy fingerprint, imphash и Rich Header для PE.
- Анализ PE, .NET metadata, LNK, ZIP/вложенных ZIP, ISO, PDF, RTF, OLE/VBA, OOXML и почтовых контейнеров.
- Деобфускация Base64, `EncodedCommand`, XOR, hex, конкатенаций и распространённых PowerShell-приёмов.
- Дополнительные цепочки для download-and-execute, encoded execution, native interop/injection, LOLBins, persistence, credential theft и exfiltration.
- Защита от archive bombs, path traversal, double extensions, RTL-override и reparse points.
- AES-256-GCM карантин с аутентификацией, атомарной записью и повторной проверкой SHA-256 перед удалением оригинала.

## CLI

Показать справку:

```powershell
dotnet run --project .\src\ArmorAV.Cli\ArmorAV.Cli.csproj -- --help
```

Проверить папку и создать HTML-отчёт:

```powershell
dotnet run --project .\src\ArmorAV.Cli\ArmorAV.Cli.csproj -- "$HOME\Downloads" --html report.html --stats
```

Параметры:

```text
--json <file>             JSON-отчёт
--html <file>             HTML-отчёт
--csv <file>              CSV-отчёт
--sarif <file>            SARIF 2.1-отчёт
--quarantine              карантинировать Confirmed результаты
--cache                   включить локальный кэш
--data-dir <directory>    путь к кэшу и карантину
--allowlist <file>        по одному MD5/SHA-1/SHA-256 на строку
--max-depth N             предел рекурсии
--max-nested-depth N      предел вложенных ZIP
--max-decompressed N      лимит распаковки в байтах
--max-entries N           лимит записей в ZIP
--max-file-size N         пропускать крупные файлы
--threads N               рабочие потоки
--fail-fast               не начинать новые проверки после Confirmed
--verbose --quiet --no-color
```

Коды завершения: `0` — чисто, `1` — найдено подозрительное, `2` — найдено подтверждённое, `3` — ошибка запуска.

## Сборка

```powershell
dotnet restore .\ArmorAV.sln
dotnet build .\ArmorAV.sln --configuration Release --no-restore
dotnet run --project .\tests\ArmorAV.SmokeTests\ArmorAV.SmokeTests.csproj --configuration Release --no-build
```

Для Windows EXE:

```powershell
dotnet publish .\src\ArmorAV.Cli\ArmorAV.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\artifacts\win-x64\cli
dotnet publish .\src\ArmorAV.Web\ArmorAV.Web.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\artifacts\win-x64\web
```

## Структура

```text
src/ArmorAV.Core          ядро анализа
src/ArmorAV.Cli           CLI
src/ArmorAV.Web           локальный browser interface
tests/ArmorAV.SmokeTests  dependency-free smoke-тесты
Start ArmorAV.cmd          запуск Browser Console двойным щелчком в Windows
```
