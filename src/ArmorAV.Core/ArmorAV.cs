using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ArmorAV
{

    public static class Product
    {
        public const string Name = "ArmorAV";
        public const string Version = "4.0.0";
        public const string Engine = "ArmorAV Static Engine";
        public const string Banner = "ArmorAV static malware scanner";
    }

    public enum Verdict { Clean, Suspicious, Confirmed }

    public enum Severity { Info, Low, Medium, High, Critical }

    public sealed class Finding
    {
        public string Name = "";
        public int Weight;
        public string Detector = "";
        public string Detail = "";
        public string Family = "";
        public Severity Severity = Severity.Low;
    }

    public sealed class SkippedFile
    {
        public string Path = "";
        public string Reason = "";
    }

    public sealed class FileResult
    {
        public string Path = "";
        public long Size;
        public string Md5 = "";
        public string Sha1 = "";
        public string Sha256 = "";
        public string ImpHash = "";
        public string Fingerprint = "";
        public string FileType = "unknown";
        public string DeclaredType = "";
        public bool TypeMismatch;
        public string VerdictText = "Clean";
        public int Score;
        public List<Finding> Findings = new List<Finding>();
        public List<string> Families = new List<string>();
        public bool Quarantined;
        public string QuarantineNote = "";
        public double ScanMilliseconds;
        public List<string> RuleMatches = new List<string>();
        public List<string> Techniques = new List<string>();
        public string RichHash = "";
        public bool FromCache;
    }

    public sealed class ScanReport
    {
        public string Product = ArmorAV.Product.Name;
        public string Version = ArmorAV.Product.Version;
        public string RootPath = "";
        public string StartedUtc = "";
        public double DurationSeconds;
        public int FilesScanned;
        public long BytesScanned;
        public ConcurrentBag<FileResult> ResultsBag = new ConcurrentBag<FileResult>();
        public ConcurrentBag<SkippedFile> SkippedBag = new ConcurrentBag<SkippedFile>();
        public ConcurrentBag<string> ReparseBag = new ConcurrentBag<string>();
        public List<FileResult> Results = new List<FileResult>();
        public List<SkippedFile> Skipped = new List<SkippedFile>();
        public List<string> ReparsePoints = new List<string>();
        public int CacheHits;
        public Dictionary<string, int> FamilyCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> TechniqueCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        public void Consolidate()
        {
            Results = ResultsBag.OrderByDescending(r => r.Score).ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
            Skipped = SkippedBag.OrderBy(s => s.Path, StringComparer.OrdinalIgnoreCase).ToList();
            ReparsePoints = ReparseBag.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
            FilesScanned = Results.Count;
            BytesScanned = Results.Sum(r => r.Size);
            foreach (var r in Results)
            {
                foreach (var f in r.Families)
                {
                    FamilyCounts.TryGetValue(f, out var c);
                    FamilyCounts[f] = c + 1;
                }
                foreach (var t in r.Techniques)
                {
                    TechniqueCounts.TryGetValue(t, out var c);
                    TechniqueCounts[t] = c + 1;
                }
            }
        }
    }

    public sealed class Options
    {
        public string Path = "";
        public string JsonPath = "scan-report.json";
        public string? HtmlPath;
        public string? CsvPath;
        public bool Quarantine;
        public int MaxDepth = 10;
        public bool NoColor;
        public bool Restore;
        public string? RestoreId;
        public bool ListQuarantine;
        public bool Verbose;
        public bool Quiet;
        public int Threads = Math.Max(1, Environment.ProcessorCount / 2);
        public long MaxDecompressedBytes = 500L * 1024 * 1024;
        public int MaxArchiveEntries = 10000;
        public int MaxNestedArchiveDepth = 5;
        public long MaxFileBytes = 2L * 1024 * 1024 * 1024;
        public string? AllowlistPath;
        public string? DataDirectory;
        public bool UseCache;
        public bool FailFast;
        public int MinScore;
        public string? SarifPath;
        public bool ShowStats;
    }

    public sealed class PatternSignature
    {
        public string Name;
        public string Literal;
        public int Weight;
        public string Family;
        public Severity Severity;
        public PatternSignature(string name, string literal, int weight, string family, Severity severity)
        {
            Name = name; Literal = literal; Weight = weight; Family = family; Severity = severity;
        }
    }

    public static class SignatureTable
    {
        public const string EicarLiteral =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        public static readonly PatternSignature[] Patterns = BuildPatterns();

        private static PatternSignature[] BuildPatterns()
        {
            return new[]
            {
                new PatternSignature("EICAR.TestFile", EicarLiteral, 100, "testfile", Severity.Critical),

                new PatternSignature("Destructive.TaskkillExplorer", "taskkill /f /im explorer.exe", 60, "destructive", Severity.High),
                new PatternSignature("Destructive.WmicProcessDelete", "wmic process delete", 55, "destructive", Severity.High),
                new PatternSignature("Destructive.FormatDriveQuick", "format c: /q /y", 70, "destructive", Severity.High),
                new PatternSignature("Destructive.CipherWipe", "cipher /w:", 45, "destructive", Severity.Medium),
                new PatternSignature("Destructive.RdWildcard", "rd /s /q c:\\", 65, "destructive", Severity.High),
                new PatternSignature("Destructive.MbrRawWrite", "\\\\.\\physicaldrive0", 60, "destructive", Severity.High),

                new PatternSignature("Ransom.VssadminDeleteShadows", "vssadmin delete shadows", 55, "ransomware", Severity.High),
                new PatternSignature("Ransom.VssadminResizeShadow", "vssadmin resize shadowstorage", 50, "ransomware", Severity.High),
                new PatternSignature("Ransom.WmicShadowcopyDelete", "wmic shadowcopy delete", 55, "ransomware", Severity.High),
                new PatternSignature("Ransom.BcdeditRecoveryDisabled", "bcdedit recoveryenabled no", 55, "ransomware", Severity.High),
                new PatternSignature("Ransom.BcdeditSafeboot", "bcdedit safeboot", 45, "ransomware", Severity.Medium),
                new PatternSignature("Ransom.BcdeditIgnoreFailures", "bootstatuspolicy ignoreallfailures", 50, "ransomware", Severity.High),
                new PatternSignature("Ransom.WbadminDeleteCatalog", "wbadmin delete catalog", 55, "ransomware", Severity.High),
                new PatternSignature("Ransom.WevtutilClearLogs", "wevtutil cl ", 45, "antiforensics", Severity.Medium),
                new PatternSignature("Ransom.ClearEventLogPs", "clear-eventlog", 40, "antiforensics", Severity.Medium),

                new PatternSignature("Defense.SetMpPreferenceDisable", "set-mppreference -disable", 60, "defense-evasion", Severity.High),
                new PatternSignature("Defense.MpPreferenceExclusion", "add-mppreference -exclusionpath", 55, "defense-evasion", Severity.High),
                new PatternSignature("Defense.RegDisableAntiSpyware", "reg add disableantispyware", 60, "defense-evasion", Severity.High),
                new PatternSignature("Defense.DisableAntiSpywareValue", "disableantispyware", 35, "defense-evasion", Severity.Medium),
                new PatternSignature("Defense.DisableRealtimeMonitoring", "disablerealtimemonitoring", 50, "defense-evasion", Severity.High),
                new PatternSignature("Defense.AmsiScanBuffer", "amsiscanbuffer", 65, "defense-evasion", Severity.High),
                new PatternSignature("Defense.AmsiInitFailed", "amsiinitfailed", 70, "defense-evasion", Severity.High),
                new PatternSignature("Defense.AmsiUtilsType", "system.management.automation.amsiutils", 65, "defense-evasion", Severity.High),
                new PatternSignature("Defense.EtwEventWrite", "etweventwrite", 55, "defense-evasion", Severity.High),
                new PatternSignature("Defense.DisableFirewall", "netsh advfirewall set allprofiles state off", 55, "defense-evasion", Severity.High),
                new PatternSignature("Defense.BypassExecutionPolicy", "-executionpolicy bypass", 35, "defense-evasion", Severity.Medium),
                new PatternSignature("Defense.SetExecutionPolicyUnrestricted", "set-executionpolicy unrestricted", 40, "defense-evasion", Severity.Medium),

                new PatternSignature("CredTheft.Sekurlsa", "sekurlsa", 75, "credential-access", Severity.High),
                new PatternSignature("CredTheft.SekurlsaLogonPasswords", "sekurlsa::logonpasswords", 90, "credential-access", Severity.Critical),
                new PatternSignature("CredTheft.Mimikatz", "mimikatz", 85, "credential-access", Severity.Critical),
                new PatternSignature("CredTheft.LsadumpSam", "lsadump::sam", 85, "credential-access", Severity.Critical),
                new PatternSignature("CredTheft.KerberosPtt", "kerberos::ptt", 80, "credential-access", Severity.High),
                new PatternSignature("CredTheft.ComsvcsMiniDump", "comsvcs.dll minidump", 80, "credential-access", Severity.High),
                new PatternSignature("CredTheft.ComsvcsMiniDumpAlt", "comsvcs.dll, minidump", 80, "credential-access", Severity.High),
                new PatternSignature("CredTheft.MiniDumpWriteDump", "minidumpwritedump", 55, "credential-access", Severity.High),
                new PatternSignature("CredTheft.CryptUnprotectData", "cryptunprotectdata", 45, "credential-access", Severity.Medium),
                new PatternSignature("CredTheft.Dpapi", "dpapi", 25, "credential-access", Severity.Low),
                new PatternSignature("CredTheft.DpapiMasterKey", "\\protect\\s-1-5-21", 60, "credential-access", Severity.High),
                new PatternSignature("CredTheft.LsassDump", "lsass.dmp", 70, "credential-access", Severity.High),
                new PatternSignature("CredTheft.LsassProcess", "procdump -ma lsass", 85, "credential-access", Severity.Critical),
                new PatternSignature("CredTheft.NtdsDit", "ntds.dit", 60, "credential-access", Severity.High),
                new PatternSignature("CredTheft.RegSaveSam", "reg save hklm\\sam", 75, "credential-access", Severity.High),
                new PatternSignature("CredTheft.VaultCmd", "vaultcmd /listcreds", 50, "credential-access", Severity.Medium),

                new PatternSignature("Ransom.NoteEncrypted", "your files have been encrypted", 70, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NoteAllFilesEncrypted", "all your files are encrypted", 70, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NoteDecryptInstructions", "decrypt_instructions", 60, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NoteHowToDecrypt", "how_to_decrypt", 60, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NoteReadmeRestore", "readme_to_restore_files", 60, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NotePayRansom", "pay the ransom", 65, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NoteBitcoinWallet", "send bitcoin to", 55, "ransom-note", Severity.High),
                new PatternSignature("Ransom.NoteTorPortal", ".onion/", 35, "ransom-note", Severity.Medium),
                new PatternSignature("Ransom.NoteDecryptionKey", "unique decryption key", 60, "ransom-note", Severity.High),
                new PatternSignature("Ransom.ExtLocky", ".locky", 40, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtCrypt", ".crypt", 30, "ransom-ext", Severity.Low),
                new PatternSignature("Ransom.ExtCerber", ".cerber", 40, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtWncry", ".wncry", 45, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtRyuk", ".ryk", 35, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtLockbit", ".lockbit", 45, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtConti", ".conti", 45, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtDjvu", ".djvu", 35, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtPhobos", ".phobos", 40, "ransom-ext", Severity.Medium),
                new PatternSignature("Ransom.ExtMakop", ".makop", 40, "ransom-ext", Severity.Medium),

                new PatternSignature("Miner.StratumTcp", "stratum+tcp", 80, "cryptominer", Severity.High),
                new PatternSignature("Miner.StratumSsl", "stratum+ssl", 80, "cryptominer", Severity.High),
                new PatternSignature("Miner.Xmrig", "xmrig", 75, "cryptominer", Severity.High),
                new PatternSignature("Miner.DonateLevel", "donate-level", 70, "cryptominer", Severity.High),
                new PatternSignature("Miner.CryptonightAlgo", "cryptonight", 45, "cryptominer", Severity.Medium),
                new PatternSignature("Miner.RandomX", "randomx", 40, "cryptominer", Severity.Medium),
                new PatternSignature("Miner.NicehashPool", "nicehash.com", 45, "cryptominer", Severity.Medium),
                new PatternSignature("Miner.MoneroOcean", "moneroocean.stream", 60, "cryptominer", Severity.High),
                new PatternSignature("Miner.CoinhiveJs", "coinhive.min.js", 60, "cryptominer", Severity.High),

                new PatternSignature("Stealer.ChromeLoginData", "\\user data\\default\\login data", 60, "infostealer", Severity.High),
                new PatternSignature("Stealer.ChromeUserData", "\\google\\chrome\\user data", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.EdgeUserData", "\\microsoft\\edge\\user data", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.BraveUserData", "\\bravesoftware\\brave-browser", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.OperaUserData", "\\opera software\\opera stable", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.FirefoxProfiles", "\\mozilla\\firefox\\profiles", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.LoginsJson", "logins.json", 35, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.Key4Db", "key4.db", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.CookiesSqlite", "cookies.sqlite", 35, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.WebDataAutofill", "\\default\\web data", 35, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.LocalState", "\\local state", 20, "infostealer", Severity.Low),
                new PatternSignature("Stealer.WalletDat", "wallet.dat", 45, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.ExodusWallet", "\\exodus\\exodus.wallet", 55, "infostealer", Severity.High),
                new PatternSignature("Stealer.MetamaskExtension", "nkbihfbeogaeaoehlefnkodbefgpgknn", 60, "infostealer", Severity.High),
                new PatternSignature("Stealer.TelegramTdata", "\\telegram desktop\\tdata", 50, "infostealer", Severity.High),
                new PatternSignature("Stealer.DiscordLevelDb", "\\discord\\local storage\\leveldb", 50, "infostealer", Severity.High),
                new PatternSignature("Stealer.FilezillaRecent", "recentservers.xml", 40, "infostealer", Severity.Medium),
                new PatternSignature("Stealer.WinScpIni", "winscp.ini", 35, "infostealer", Severity.Medium),

                new PatternSignature("Exfil.DiscordWebhook", "discord.com/api/webhooks", 70, "exfiltration", Severity.High),
                new PatternSignature("Exfil.DiscordWebhookAlt", "discordapp.com/api/webhooks", 70, "exfiltration", Severity.High),
                new PatternSignature("Exfil.TelegramBotApi", "api.telegram.org/bot", 65, "exfiltration", Severity.High),
                new PatternSignature("Exfil.TelegramSendDocument", "senddocument?chat_id", 55, "exfiltration", Severity.High),
                new PatternSignature("Exfil.TelegramSendMessage", "sendmessage?chat_id", 50, "exfiltration", Severity.Medium),
                new PatternSignature("Exfil.PastebinRaw", "pastebin.com/raw/", 45, "exfiltration", Severity.Medium),
                new PatternSignature("Exfil.AnonFiles", "anonfiles.com/api/upload", 55, "exfiltration", Severity.High),
                new PatternSignature("Exfil.GofileUpload", "gofile.io/uploadfile", 50, "exfiltration", Severity.Medium),
                new PatternSignature("Exfil.TransferSh", "transfer.sh/", 40, "exfiltration", Severity.Medium),
                new PatternSignature("Exfil.NgrokTunnel", ".ngrok.io", 40, "exfiltration", Severity.Medium),

                new PatternSignature("Loader.EncodedCommandFlag", "-encodedcommand", 45, "obfuscation", Severity.Medium),
                new PatternSignature("Loader.HiddenWindowFlag", "-nop -w hidden", 45, "obfuscation", Severity.Medium),
                new PatternSignature("Loader.WindowStyleHidden", "-windowstyle hidden", 35, "obfuscation", Severity.Medium),
                new PatternSignature("Loader.IexDownloadString", "iex(new-object net.webclient).downloadstring", 75, "loader", Severity.High),
                new PatternSignature("Loader.DownloadString", "downloadstring(", 40, "loader", Severity.Medium),
                new PatternSignature("Loader.DownloadFile", "downloadfile(", 35, "loader", Severity.Medium),
                new PatternSignature("Loader.InvokeExpression", "invoke-expression", 35, "loader", Severity.Medium),
                new PatternSignature("Loader.InvokeWebRequest", "invoke-webrequest", 25, "loader", Severity.Low),
                new PatternSignature("Loader.FromBase64String", "frombase64string", 25, "obfuscation", Severity.Low),
                new PatternSignature("Loader.CertutilDecode", "certutil -decode", 45, "loader", Severity.Medium),
                new PatternSignature("Loader.CertutilUrlCache", "certutil -urlcache", 55, "loader", Severity.High),
                new PatternSignature("Loader.BitsadminTransfer", "bitsadmin /transfer", 50, "loader", Severity.Medium),
                new PatternSignature("Loader.MshtaJavascript", "mshta javascript:", 65, "loader", Severity.High),
                new PatternSignature("Loader.Regsvr32Scrobj", "regsvr32 /s /u /i:", 70, "loader", Severity.High),
                new PatternSignature("Loader.Rundll32Javascript", "rundll32.exe javascript:", 75, "loader", Severity.High),
                new PatternSignature("Loader.MsiexecRemote", "msiexec /q /i http", 60, "loader", Severity.High),
                new PatternSignature("Loader.CurlToCmd", "curl -s http", 25, "loader", Severity.Low),

                new PatternSignature("Inject.VirtualAllocEx", "virtualallocex", 40, "injection", Severity.Medium),
                new PatternSignature("Inject.WriteProcessMemoryStr", "writeprocessmemory", 40, "injection", Severity.Medium),
                new PatternSignature("Inject.CreateRemoteThreadStr", "createremotethread", 50, "injection", Severity.High),
                new PatternSignature("Inject.NtUnmapViewOfSection", "ntunmapviewofsection", 60, "injection", Severity.High),
                new PatternSignature("Inject.QueueUserApc", "queueuserapc", 50, "injection", Severity.Medium),
                new PatternSignature("Inject.SetThreadContext", "setthreadcontext", 45, "injection", Severity.Medium),
                new PatternSignature("Inject.ReflectivePeLoader", "reflectivepeloader", 80, "injection", Severity.High),
                new PatternSignature("Inject.VirtualProtectRwx", "virtualprotect", 25, "injection", Severity.Low),

                new PatternSignature("Persist.RunKey", "\\currentversion\\run", 30, "persistence", Severity.Low),
                new PatternSignature("Persist.SchtasksCreate", "schtasks /create", 35, "persistence", Severity.Medium),
                new PatternSignature("Persist.ScCreateService", "sc create ", 30, "persistence", Severity.Low),
                new PatternSignature("Persist.WmiEventSubscription", "__eventfilter", 55, "persistence", Severity.High),
                new PatternSignature("Persist.StartupFolder", "\\start menu\\programs\\startup", 35, "persistence", Severity.Medium),
                new PatternSignature("Persist.ImageFileExecutionOptions", "image file execution options", 55, "persistence", Severity.High),
                new PatternSignature("Persist.AppInitDlls", "appinit_dlls", 60, "persistence", Severity.High),

                new PatternSignature("Recon.WhoamiPriv", "whoami /priv", 25, "discovery", Severity.Low),
                new PatternSignature("Recon.NetUserDomain", "net user /domain", 30, "discovery", Severity.Low),
                new PatternSignature("Recon.SysteminfoPipe", "systeminfo", 15, "discovery", Severity.Info),
                new PatternSignature("Recon.VmwareArtifact", "vmware", 15, "anti-analysis", Severity.Info),
                new PatternSignature("Recon.SandboxCheck", "sbiedll.dll", 55, "anti-analysis", Severity.High),
                new PatternSignature("Recon.DebuggerCheck", "isdebuggerpresent", 25, "anti-analysis", Severity.Low),
                new PatternSignature("Recon.CuckooArtifact", "cuckoomon", 65, "anti-analysis", Severity.High),

                new PatternSignature("Macro.AutoOpen", "auto_open", 45, "macro", Severity.Medium),
                new PatternSignature("Macro.AutoExec", "autoexec", 40, "macro", Severity.Medium),
                new PatternSignature("Macro.DocumentOpen", "document_open", 40, "macro", Severity.Medium),
                new PatternSignature("Macro.WorkbookOpen", "workbook_open", 40, "macro", Severity.Medium),
                new PatternSignature("Macro.ShellExecuteVba", "createobject(\"wscript.shell\")", 50, "macro", Severity.High),
                new PatternSignature("Macro.DdeAuto", "ddeauto", 65, "macro", Severity.High),
                new PatternSignature("Macro.Excel4Formula", "=exec(", 55, "macro", Severity.High),
                new PatternSignature("Macro.VbaShell", "shell(environ", 55, "macro", Severity.High),

                new PatternSignature("Backdoor.NcListenExec", "nc -e cmd.exe", 80, "backdoor", Severity.High),
                new PatternSignature("Backdoor.ReverseShellPs", "$client = new-object system.net.sockets.tcpclient", 70, "backdoor", Severity.High),
                new PatternSignature("Backdoor.MeterpreterString", "meterpreter", 80, "backdoor", Severity.High),
                new PatternSignature("Backdoor.CobaltStrikeBeacon", "beacon.dll", 75, "backdoor", Severity.High),
                new PatternSignature("Backdoor.CobaltStrikePipe", "\\\\.\\pipe\\msagent_", 80, "backdoor", Severity.High),
                new PatternSignature("Backdoor.PowerCat", "powercat -", 65, "backdoor", Severity.High),
                new PatternSignature("Backdoor.RdpEnable", "fdenytsconnections /t reg_dword /d 0", 50, "backdoor", Severity.Medium),
                new PatternSignature("Backdoor.AddAdminUser", "net localgroup administrators /add", 55, "backdoor", Severity.High),

                new PatternSignature("Keylog.GetAsyncKeyState", "getasynckeystate", 45, "keylogger", Severity.Medium),
                new PatternSignature("Keylog.SetWindowsHookStr", "setwindowshookex", 35, "keylogger", Severity.Medium),
                new PatternSignature("Keylog.GetForegroundWindow", "getforegroundwindow", 20, "keylogger", Severity.Low),
                new PatternSignature("Keylog.KeystrokeLogFile", "keystrokes.txt", 55, "keylogger", Severity.High),

                new PatternSignature("Lolbin.MsbuildInlineTask", "microsoft.build.framework", 45, "lolbin", Severity.Medium),
                new PatternSignature("Lolbin.InstallUtilBypass", "installutil.exe /logfile=", 60, "lolbin", Severity.High),
                new PatternSignature("Lolbin.CmstpInf", "cmstp.exe /s /ns", 65, "lolbin", Severity.High),
                new PatternSignature("Lolbin.OdbcconfResponse", "odbcconf.exe /a {regsvr", 70, "lolbin", Severity.High),
                new PatternSignature("Lolbin.ForfilesSpawn", "forfiles /p c:\\windows\\system32 /m", 50, "lolbin", Severity.Medium),
                new PatternSignature("Lolbin.WmicXslScript", "wmic os get /format:", 60, "lolbin", Severity.High),
                new PatternSignature("Lolbin.PcalUaBypass", "computerdefaults.exe", 50, "lolbin", Severity.Medium),
                new PatternSignature("Lolbin.FodhelperUac", "fodhelper.exe", 60, "lolbin", Severity.High),
                new PatternSignature("Lolbin.SdcltUac", "sdclt.exe /kickoffelev", 60, "lolbin", Severity.High),
                new PatternSignature("Lolbin.EventvwrUac", "\\mscfile\\shell\\open\\command", 70, "lolbin", Severity.High),
                new PatternSignature("Lolbin.SilentCleanupTask", "\\environment\\windir", 45, "lolbin", Severity.Medium),
                new PatternSignature("Lolbin.DllHostComElevation", "elevation:administrator!new:", 70, "lolbin", Severity.High),
                new PatternSignature("Lolbin.PresentationHostXbap", "presentationhost.exe", 45, "lolbin", Severity.Medium),
                new PatternSignature("Lolbin.MavinjectDll", "mavinject.exe", 65, "lolbin", Severity.High),
                new PatternSignature("Lolbin.SyncappvpublishingServer", "syncappvpublishingserver.vbs", 70, "lolbin", Severity.High),

                new PatternSignature("Rat.AsyncRatConfig", "asyncrat", 80, "rat", Severity.High),
                new PatternSignature("Rat.QuasarClient", "quasar.client", 80, "rat", Severity.High),
                new PatternSignature("Rat.NjRatMarker", "njrat", 80, "rat", Severity.High),
                new PatternSignature("Rat.RemcosMarker", "remcos", 75, "rat", Severity.High),
                new PatternSignature("Rat.DcRatMarker", "dcrat", 80, "rat", Severity.High),
                new PatternSignature("Rat.VenomRatMarker", "venomrat", 80, "rat", Severity.High),
                new PatternSignature("Rat.NanocoreMarker", "nanocore", 80, "rat", Severity.High),
                new PatternSignature("Rat.PlugXMarker", "plugx", 75, "rat", Severity.High),
                new PatternSignature("Rat.SliverImplant", "sliver-implant", 80, "rat", Severity.High),
                new PatternSignature("Rat.HavocDemon", "havoc-demon", 80, "rat", Severity.High),
                new PatternSignature("Rat.MythicAgent", "mythic-agent", 75, "rat", Severity.High),

                new PatternSignature("Wiper.HermeticMarker", "hermeticwiper", 90, "wiper", Severity.Critical),
                new PatternSignature("Wiper.EpmntdrvDriver", "epmntdrv.sys", 85, "wiper", Severity.Critical),
                new PatternSignature("Wiper.RawDiskDriver", "\\\\.\\eldos rawdisk", 80, "wiper", Severity.High),
                new PatternSignature("Wiper.DiskpartCleanAll", "diskpart /s", 45, "wiper", Severity.Medium),
                new PatternSignature("Wiper.NtfsMftOverwrite", "\\$mft", 55, "wiper", Severity.High),

                new PatternSignature("Boot.MbrOverwriteStub", "no bootable device", 40, "bootkit", Severity.Medium),
                new PatternSignature("Boot.EfiBootkitPath", "\\efi\\microsoft\\boot\\bootmgfw.efi", 55, "bootkit", Severity.High),
                new PatternSignature("Boot.BcdeditTestsigning", "bcdedit /set testsigning on", 60, "bootkit", Severity.High),
                new PatternSignature("Boot.BcdeditNoIntegrity", "nointegritychecks on", 65, "bootkit", Severity.High),

                new PatternSignature("Driver.ServiceKernelLoad", "\\systemroot\\system32\\drivers\\", 30, "rootkit", Severity.Low),
                new PatternSignature("Driver.NtLoadDriver", "ntloaddriver", 60, "rootkit", Severity.High),
                new PatternSignature("Driver.VulnerableDriverGdrv", "gdrv.sys", 70, "rootkit", Severity.High),
                new PatternSignature("Driver.VulnerableDriverRtcore", "rtcore64.sys", 75, "rootkit", Severity.High),
                new PatternSignature("Driver.ProcexpDriverAbuse", "procexp152.sys", 65, "rootkit", Severity.High),

                new PatternSignature("Phish.CredentialPrompt", "get-credential -message", 40, "social-engineering", Severity.Medium),
                new PatternSignature("Phish.FakeWindowsUpdate", "windows update assistant", 25, "social-engineering", Severity.Low),
                new PatternSignature("Phish.ClipboardHijackBtc", "clipboard.settext", 35, "clipper", Severity.Medium),
                new PatternSignature("Phish.BitcoinAddressPattern", "bc1q", 30, "clipper", Severity.Medium),

                new PatternSignature("Container.IsoAutorun", "[autorun]", 35, "container-abuse", Severity.Medium),
                new PatternSignature("Container.LnkPowershellTarget", "\\v1.0\\powershell.exe", 55, "container-abuse", Severity.High),
                new PatternSignature("Container.OneNoteEmbedded", "onenote.file.embedded", 60, "container-abuse", Severity.High),
            };
        }

        public static readonly Dictionary<string, (int Weight, string Family, Severity Sev)> Detectors =
            new Dictionary<string, (int, string, Severity)>(StringComparer.Ordinal)
        {
            { "PE.HighEntropySection", (30, "packing", Severity.Medium) },
            { "PE.ExtremeEntropySection", (45, "packing", Severity.Medium) },
            { "PE.RwxSection", (45, "packing", Severity.High) },
            { "PE.TlsCallbacks", (30, "anti-analysis", Severity.Medium) },
            { "PE.EntryPointLastSection", (35, "packing", Severity.Medium) },
            { "PE.EntryPointOutsideSections", (60, "malformed", Severity.High) },
            { "PE.EntryPointWritableSection", (50, "packing", Severity.High) },
            { "PE.ImportWriteProcessMemory", (45, "injection", Severity.Medium) },
            { "PE.ImportCreateRemoteThread", (55, "injection", Severity.High) },
            { "PE.ImportCryptUnprotectData", (45, "credential-access", Severity.Medium) },
            { "PE.ImportSetWindowsHookEx", (35, "keylogger", Severity.Medium) },
            { "PE.ImportNtApiUnhook", (50, "defense-evasion", Severity.High) },
            { "PE.ImportDynamicResolution", (30, "obfuscation", Severity.Medium) },
            { "PE.MinimalImports", (35, "packing", Severity.Medium) },
            { "PE.PackerUPX", (35, "packing", Severity.Medium) },
            { "PE.PackerThemida", (45, "packing", Severity.Medium) },
            { "PE.PackerVMProtect", (45, "packing", Severity.Medium) },
            { "PE.PackerASPack", (35, "packing", Severity.Medium) },
            { "PE.PackerMPRESS", (35, "packing", Severity.Medium) },
            { "PE.PackerPECompact", (35, "packing", Severity.Medium) },
            { "PE.PackerEnigma", (45, "packing", Severity.Medium) },
            { "PE.NoSections", (40, "malformed", Severity.High) },
            { "PE.SectionRawVirtualMismatch", (30, "packing", Severity.Medium) },
            { "PE.NonStandardSectionName", (20, "packing", Severity.Low) },
            { "PE.OverlayLargeHighEntropy", (40, "packing", Severity.Medium) },
            { "PE.NoAuthenticodeSignature", (10, "trust", Severity.Info) },
            { "PE.CheckSumMismatch", (15, "trust", Severity.Info) },
            { "PE.TimestampInFuture", (25, "trust", Severity.Low) },
            { "PE.TimestampZero", (20, "trust", Severity.Low) },
            { "PE.DotNetAssembly", (5, "info", Severity.Info) },
            { "PE.SuspiciousResourceExe", (70, "dropper", Severity.High) },

            { "Deob.Base64Nested", (30, "obfuscation", Severity.Medium) },
            { "Deob.Base64EmbeddedPE", (80, "dropper", Severity.Critical) },
            { "Deob.HexEmbeddedPE", (75, "dropper", Severity.Critical) },
            { "Deob.CharChain", (40, "obfuscation", Severity.Medium) },
            { "Deob.EncodedCommandUtf16", (60, "obfuscation", Severity.High) },
            { "Deob.XorDecodedPE", (80, "dropper", Severity.Critical) },
            { "Deob.XorDecodedScript", (55, "obfuscation", Severity.High) },
            { "Deob.SplitStringEvasion", (45, "obfuscation", Severity.Medium) },
            { "Deob.FormatOperatorEvasion", (40, "obfuscation", Severity.Medium) },
            { "Deob.BacktickEvasion", (35, "obfuscation", Severity.Medium) },
            { "Deob.ReversedStringEvasion", (45, "obfuscation", Severity.Medium) },
            { "Deob.HighObfuscationDensity", (35, "obfuscation", Severity.Medium) },
            { "Deob.GzipDeflateInMemory", (30, "obfuscation", Severity.Medium) },

            { "Archive.ZipBombRatio", (70, "archive-abuse", Severity.High) },
            { "Archive.ZipBombTotalSize", (70, "archive-abuse", Severity.High) },
            { "Archive.TooManyEntries", (55, "archive-abuse", Severity.High) },
            { "Archive.PathTraversal", (80, "archive-abuse", Severity.Critical) },
            { "Archive.UnsupportedCompressedExecutable", (45, "archive-abuse", Severity.Medium) },
            { "Archive.NestedDepthExceeded", (25, "archive-abuse", Severity.Low) },
            { "Archive.EncryptedEntryWithExecutable", (55, "archive-abuse", Severity.High) },
            { "Archive.DoubleExtensionEntry", (60, "masquerading", Severity.High) },
            { "Archive.LnkDropper", (55, "dropper", Severity.High) },

            { "Doc.OoxmlVbaProject", (45, "macro", Severity.Medium) },
            { "Doc.OoxmlRemoteTemplate", (65, "macro", Severity.High) },
            { "Doc.OoxmlExternalOleObject", (55, "macro", Severity.High) },
            { "Doc.OleCompoundMacroStream", (50, "macro", Severity.High) },
            { "Doc.RtfObjectData", (55, "exploit", Severity.High) },
            { "Doc.PdfJavaScript", (50, "exploit", Severity.Medium) },
            { "Doc.PdfOpenAction", (40, "exploit", Severity.Medium) },
            { "Doc.PdfEmbeddedFile", (45, "exploit", Severity.Medium) },
            { "Doc.HtaScript", (55, "dropper", Severity.High) },

            { "Type.ExtensionMismatch", (45, "masquerading", Severity.Medium) },
            { "Type.DoubleExtension", (60, "masquerading", Severity.High) },
            { "Type.RtloName", (85, "masquerading", Severity.Critical) },
            { "Type.PeWithDocumentIcon", (35, "masquerading", Severity.Medium) },
            { "Type.ScriptWithBinaryPayload", (45, "dropper", Severity.Medium) },

            { "Shell.EggHunterNopSled", (55, "shellcode", Severity.High) },
            { "Shell.PebWalkStub", (60, "shellcode", Severity.High) },
            { "Shell.MetasploitPattern", (70, "shellcode", Severity.High) },

            { "Fuzzy.NearDuplicateOfQuarantined", (75, "reputation", Severity.High) },
            { "Hash.KnownQuarantinedHash", (90, "reputation", Severity.Critical) },
            { "Hash.Allowlisted", (0, "trust", Severity.Info) },

            { "Composite.StealerKit", (90, "infostealer", Severity.Critical) },
            { "Composite.RansomwareKit", (95, "ransomware", Severity.Critical) },
            { "Composite.PackedInjector", (85, "injection", Severity.Critical) },
            { "Composite.MinerInstaller", (85, "cryptominer", Severity.Critical) },
            { "Composite.ObfuscatedDropper", (85, "dropper", Severity.Critical) },
            { "Composite.CredentialDumper", (90, "credential-access", Severity.Critical) },
            { "Composite.LolbinUacBypass", (85, "lolbin", Severity.Critical) },
            { "Composite.WiperKit", (95, "wiper", Severity.Critical) },
            { "Composite.RatImplant", (90, "rat", Severity.Critical) },
            { "Composite.VulnerableDriverLoad", (90, "rootkit", Severity.Critical) },
            { "Composite.ContainerDropper", (85, "container-abuse", Severity.Critical) },
            { "Composite.MacroDownloader", (85, "macro", Severity.Critical) },

            { "Rule.MatchedYaraLike", (0, "generic", Severity.Info) },

            { "Lnk.PowershellCommandLine", (70, "container-abuse", Severity.High) },
            { "Lnk.LongCommandArguments", (50, "container-abuse", Severity.High) },
            { "Lnk.HiddenWindowFlag", (45, "container-abuse", Severity.Medium) },
            { "Lnk.RemoteUncTarget", (55, "container-abuse", Severity.High) },

            { "Container.IsoWithExecutable", (55, "container-abuse", Severity.High) },
            { "Container.IsoWithLnk", (65, "container-abuse", Severity.High) },
            { "Container.OneNoteEmbeddedScript", (70, "container-abuse", Severity.High) },
            { "Container.SingleFileArchiveExecutable", (30, "container-abuse", Severity.Low) },

            { "Name.SystemBinaryOutsideSystem32", (60, "masquerading", Severity.High) },
            { "Name.ExcessiveWhitespacePadding", (55, "masquerading", Severity.High) },
            { "Name.HomoglyphCharacters", (50, "masquerading", Severity.High) },
            { "Name.RandomLookingName", (20, "masquerading", Severity.Low) },

            { "Rep.KnownPackerImpHash", (25, "reputation", Severity.Low) },
            { "Rep.RepeatedImpHashInScan", (30, "reputation", Severity.Medium) },
            { "Rep.RepeatedFuzzyClusterInScan", (35, "reputation", Severity.Medium) },

            { "Script.LargeSingleLineBlob", (30, "obfuscation", Severity.Medium) },
            { "Script.VeryLongIdentifiers", (25, "obfuscation", Severity.Low) },
            { "Script.HighEntropyText", (35, "obfuscation", Severity.Medium) },
            { "Script.SuspiciousSelfDelete", (45, "antiforensics", Severity.Medium) },

            { "PE.RichHeaderMissing", (20, "packing", Severity.Low) },
            { "PE.RichHeaderChecksumMismatch", (45, "trust", Severity.Medium) },
            { "PE.RichLinkerAnomaly", (25, "packing", Severity.Low) },
            { "PE.TooManySections", (30, "malformed", Severity.Medium) },
            { "PE.NonAsciiSectionName", (35, "malformed", Severity.Medium) },
            { "PE.ResourceEmbeddedPe", (75, "dropper", Severity.Critical) },
            { "PE.ResourceHighEntropyBlob", (35, "packing", Severity.Medium) },
            { "PE.ResourceScriptContent", (55, "dropper", Severity.High) },

            { "Dotnet.ObfuscatorConfuserEx", (45, "obfuscation", Severity.Medium) },
            { "Dotnet.ObfuscatorGeneric", (35, "obfuscation", Severity.Medium) },
            { "Dotnet.SuspiciousPInvoke", (55, "injection", Severity.High) },
            { "Dotnet.UserStringMatch", (40, "obfuscation", Severity.Medium) },
            { "Dotnet.RunPeMarker", (75, "injection", Severity.High) },
            { "Dotnet.EncryptedResource", (50, "dropper", Severity.High) },

            { "Vba.MacroSourceRecovered", (25, "macro", Severity.Low) },
            { "Vba.AutoExecHandler", (55, "macro", Severity.High) },
            { "Vba.ShellExecution", (65, "macro", Severity.High) },
            { "Vba.DownloadPrimitive", (60, "macro", Severity.High) },
            { "Vba.SuspiciousStringMatch", (40, "macro", Severity.Medium) },
            { "Vba.ObfuscatedSource", (45, "obfuscation", Severity.Medium) },
            { "Ole.Excel4Macro", (70, "macro", Severity.High) },
            { "Ole.EquationEditorObject", (75, "exploit", Severity.High) },
            { "Ole.EmbeddedPackageStream", (55, "dropper", Severity.High) },

            { "Carve.EmbeddedPeAtOffset", (65, "dropper", Severity.High) },
            { "Carve.AppendedArchive", (45, "dropper", Severity.Medium) },
            { "Carve.EmbeddedZipInNonArchive", (40, "dropper", Severity.Medium) },

            { "Deob.MultiByteXorPe", (85, "dropper", Severity.Critical) },
            { "Deob.MultiByteXorScript", (60, "obfuscation", Severity.High) },
            { "Deob.EmbeddedGzipPayload", (45, "obfuscation", Severity.Medium) },
            { "Deob.EmbeddedGzipPe", (85, "dropper", Severity.Critical) },
            { "Deob.EmbeddedZlibPayload", (40, "obfuscation", Severity.Medium) },

            { "Mail.Base64Attachment", (25, "mail", Severity.Low) },
            { "Mail.ExecutableAttachment", (70, "mail", Severity.High) },
            { "Mail.ScriptAttachment", (65, "mail", Severity.High) },
            { "Mail.DoubleExtensionAttachment", (70, "masquerading", Severity.High) },
            { "Mail.SuspiciousAttachmentContent", (40, "mail", Severity.Medium) },
        };

        public static (int Weight, string Family, Severity Sev) DetectorInfo(string key)
        {
            return Detectors.TryGetValue(key, out var v) ? v : (10, "generic", Severity.Low);
        }
    }

    public sealed class CompositeRule
    {
        public string Name = "";
        public string Description = "";
        public Func<IReadOnlyCollection<Finding>, bool> Predicate = _ => false;
    }

    public static class CompositeRules
    {
        private static bool HasFamily(IReadOnlyCollection<Finding> f, string family, int min = 1)
        {
            return f.Count(x => string.Equals(x.Family, family, StringComparison.OrdinalIgnoreCase)) >= min;
        }

        private static bool Has(IReadOnlyCollection<Finding> f, string name)
        {
            return f.Any(x => string.Equals(x.Name, name, StringComparison.Ordinal));
        }

        private static bool HasPrefix(IReadOnlyCollection<Finding> f, string prefix)
        {
            return f.Any(x => x.Name.StartsWith(prefix, StringComparison.Ordinal));
        }

        public static readonly CompositeRule[] Rules =
        {
            new CompositeRule
            {
                Name = "Composite.StealerKit",
                Description = "browser credential paths combined with an exfiltration channel",
                Predicate = f => HasFamily(f, "infostealer", 2) && HasFamily(f, "exfiltration")
            },
            new CompositeRule
            {
                Name = "Composite.RansomwareKit",
                Description = "shadow copy destruction combined with ransom note or encrypted extension markers",
                Predicate = f => HasFamily(f, "ransomware") && (HasFamily(f, "ransom-note") || HasFamily(f, "ransom-ext"))
            },
            new CompositeRule
            {
                Name = "Composite.PackedInjector",
                Description = "packer or high entropy combined with process injection imports",
                Predicate = f => (HasFamily(f, "packing", 2) || Has(f, "PE.RwxSection")) && HasFamily(f, "injection")
            },
            new CompositeRule
            {
                Name = "Composite.MinerInstaller",
                Description = "mining pool configuration combined with persistence or defense evasion",
                Predicate = f => HasFamily(f, "cryptominer") && (HasFamily(f, "persistence") || HasFamily(f, "defense-evasion"))
            },
            new CompositeRule
            {
                Name = "Composite.ObfuscatedDropper",
                Description = "layered obfuscation combined with a download or execution primitive",
                Predicate = f => HasFamily(f, "obfuscation", 2) && (HasFamily(f, "loader") || HasFamily(f, "dropper"))
            },
            new CompositeRule
            {
                Name = "Composite.CredentialDumper",
                Description = "credential access tooling combined with process memory dumping",
                Predicate = f => HasFamily(f, "credential-access", 2) && (HasPrefix(f, "CredTheft.Mini") || HasPrefix(f, "CredTheft.Lsass") || HasPrefix(f, "CredTheft.Comsvcs"))
            },
            new CompositeRule
            {
                Name = "Composite.LolbinUacBypass",
                Description = "living-off-the-land binary abuse combined with registry hijack or elevation markers",
                Predicate = f => HasFamily(f, "lolbin") && (HasFamily(f, "persistence") || HasPrefix(f, "Lolbin.Fodhelper") || HasPrefix(f, "Lolbin.Eventvwr") || HasPrefix(f, "Lolbin.Sdclt"))
            },
            new CompositeRule
            {
                Name = "Composite.WiperKit",
                Description = "destructive disk access combined with boot configuration tampering",
                Predicate = f => (HasFamily(f, "wiper") || HasFamily(f, "destructive")) && (HasFamily(f, "bootkit") || HasFamily(f, "antiforensics"))
            },
            new CompositeRule
            {
                Name = "Composite.RatImplant",
                Description = "remote access trojan marker combined with persistence or injection capability",
                Predicate = f => HasFamily(f, "rat") && (HasFamily(f, "persistence") || HasFamily(f, "injection") || HasFamily(f, "defense-evasion"))
            },
            new CompositeRule
            {
                Name = "Composite.VulnerableDriverLoad",
                Description = "known vulnerable driver combined with kernel loading primitives",
                Predicate = f => HasFamily(f, "rootkit", 2)
            },
            new CompositeRule
            {
                Name = "Composite.ContainerDropper",
                Description = "container or shortcut delivery combined with a script interpreter invocation",
                Predicate = f => HasFamily(f, "container-abuse") && (HasFamily(f, "loader") || HasFamily(f, "obfuscation") || HasFamily(f, "lolbin"))
            },
            new CompositeRule
            {
                Name = "Composite.MacroDownloader",
                Description = "office macro autostart combined with a download or shell primitive",
                Predicate = f => HasFamily(f, "macro") && (HasFamily(f, "loader") || HasFamily(f, "lolbin") || HasFamily(f, "obfuscation"))
            },
        };
    }

    public sealed class RuleString
    {
        public string Id = "";
        public string Value = "";
        public bool Wide;
        public RuleString(string id, string value, bool wide = false) { Id = id; Value = value; Wide = wide; }
    }

    public sealed class ScanRule
    {
        public string Name = "";
        public string Description = "";
        public int Weight;
        public string Family = "";
        public Severity Severity = Severity.Medium;
        public RuleString[] Strings = Array.Empty<RuleString>();
        public int MinimumMatches = 1;
        public string? RequiredFileType;
    }

    public static class RuleSet
    {
        public static readonly ScanRule[] Rules =
        {
            new ScanRule
            {
                Name = "Rule.PowerShellDownloadExecChain",
                Description = "PowerShell download primitive combined with in-memory execution and hidden window",
                Weight = 85, Family = "loader", Severity = Severity.Critical, MinimumMatches = 3,
                Strings = new[]
                {
                    new RuleString("dl", "downloadstring"),
                    new RuleString("dlf", "downloadfile"),
                    new RuleString("iex", "invoke-expression"),
                    new RuleString("iexs", "iex "),
                    new RuleString("hidden", "-w hidden"),
                    new RuleString("hidden2", "-windowstyle hidden"),
                    new RuleString("bypass", "-executionpolicy bypass"),
                }
            },
            new ScanRule
            {
                Name = "Rule.ReflectiveLoaderInMemory",
                Description = "reflective in-memory loading of a managed or native image",
                Weight = 90, Family = "injection", Severity = Severity.Critical, MinimumMatches = 2,
                Strings = new[]
                {
                    new RuleString("load", "[reflection.assembly]::load"),
                    new RuleString("gettype", "gettype(\"system.reflection.assembly\")"),
                    new RuleString("b64", "frombase64string"),
                    new RuleString("vap", "virtualalloc"),
                    new RuleString("marshal", "system.runtime.interopservices.marshal"),
                    new RuleString("delegate", "getdelegateforfunctionpointer"),
                }
            },
            new ScanRule
            {
                Name = "Rule.RansomwareEncryptorBehaviour",
                Description = "file enumeration combined with cryptographic API use and shadow copy destruction",
                Weight = 90, Family = "ransomware", Severity = Severity.Critical, MinimumMatches = 3,
                Strings = new[]
                {
                    new RuleString("enum", "getfiles"),
                    new RuleString("enum2", "findfirstfile"),
                    new RuleString("aes", "aescryptoserviceprovider"),
                    new RuleString("aes2", "cryptencrypt"),
                    new RuleString("rsa", "rsacryptoserviceprovider"),
                    new RuleString("vss", "vssadmin"),
                    new RuleString("note", "readme"),
                }
            },
            new ScanRule
            {
                Name = "Rule.ProcessHollowingSequence",
                Description = "classic process hollowing API sequence",
                Weight = 90, Family = "injection", Severity = Severity.Critical, MinimumMatches = 3,
                Strings = new[]
                {
                    new RuleString("cps", "createprocess"),
                    new RuleString("unmap", "ntunmapviewofsection"),
                    new RuleString("alloc", "virtualallocex"),
                    new RuleString("write", "writeprocessmemory"),
                    new RuleString("ctx", "setthreadcontext"),
                    new RuleString("resume", "resumethread"),
                }
            },
            new ScanRule
            {
                Name = "Rule.InfoStealerHarvestChain",
                Description = "multiple browser and wallet artifact paths harvested together",
                Weight = 85, Family = "infostealer", Severity = Severity.Critical, MinimumMatches = 4,
                Strings = new[]
                {
                    new RuleString("chrome", "\\user data\\default"),
                    new RuleString("login", "login data"),
                    new RuleString("cookies", "cookies"),
                    new RuleString("ffx", "logins.json"),
                    new RuleString("key4", "key4.db"),
                    new RuleString("wallet", "wallet.dat"),
                    new RuleString("dpapi", "cryptunprotectdata"),
                    new RuleString("zip", "zipfile"),
                }
            },
            new ScanRule
            {
                Name = "Rule.AmsiEtwPatchChain",
                Description = "AMSI and ETW bypass primitives combined with memory protection changes",
                Weight = 90, Family = "defense-evasion", Severity = Severity.Critical, MinimumMatches = 2,
                Strings = new[]
                {
                    new RuleString("amsi", "amsiscanbuffer"),
                    new RuleString("amsidll", "amsi.dll"),
                    new RuleString("etw", "etweventwrite"),
                    new RuleString("vp", "virtualprotect"),
                    new RuleString("gpa", "getprocaddress"),
                }
            },
            new ScanRule
            {
                Name = "Rule.VbaAutoRunShell",
                Description = "VBA autostart handler combined with a shell or download call",
                Weight = 85, Family = "macro", Severity = Severity.Critical, MinimumMatches = 2,
                Strings = new[]
                {
                    new RuleString("auto", "auto_open"),
                    new RuleString("doc", "document_open"),
                    new RuleString("wb", "workbook_open"),
                    new RuleString("shell", "wscript.shell"),
                    new RuleString("shell2", "shell("),
                    new RuleString("xhr", "msxml2.xmlhttp"),
                    new RuleString("adodb", "adodb.stream"),
                }
            },
            new ScanRule
            {
                Name = "Rule.ClipperWalletSwap",
                Description = "clipboard monitoring combined with cryptocurrency address patterns",
                Weight = 80, Family = "clipper", Severity = Severity.High, MinimumMatches = 2,
                Strings = new[]
                {
                    new RuleString("clip", "getclipboarddata"),
                    new RuleString("clip2", "clipboard.settext"),
                    new RuleString("clip3", "set-clipboard"),
                    new RuleString("btc", "bc1q"),
                    new RuleString("eth", "0x"),
                    new RuleString("regex", "^[13][a-km-z"),
                }
            },
            new ScanRule
            {
                Name = "Rule.KeyloggerHookChain",
                Description = "keyboard hook installation combined with log persistence",
                Weight = 80, Family = "keylogger", Severity = Severity.High, MinimumMatches = 3,
                Strings = new[]
                {
                    new RuleString("hook", "setwindowshookex"),
                    new RuleString("key", "getasynckeystate"),
                    new RuleString("wnd", "getforegroundwindow"),
                    new RuleString("write", "streamwriter"),
                    new RuleString("append", "appendalltext"),
                }
            },
            new ScanRule
            {
                Name = "Rule.AntiAnalysisBundle",
                Description = "several sandbox and debugger evasion checks bundled together",
                Weight = 70, Family = "anti-analysis", Severity = Severity.High, MinimumMatches = 3,
                Strings = new[]
                {
                    new RuleString("dbg", "isdebuggerpresent"),
                    new RuleString("rdbg", "checkremotedebuggerpresent"),
                    new RuleString("vbox", "virtualbox"),
                    new RuleString("vmw", "vmware"),
                    new RuleString("qemu", "qemu"),
                    new RuleString("sbie", "sbiedll"),
                    new RuleString("sleep", "sleep(") ,
                    new RuleString("tick", "gettickcount"),
                }
            },
        };

        public sealed class RuleMatch
        {
            public ScanRule Rule = null!;
            public List<string> MatchedIds = new List<string>();
        }

        public static List<RuleMatch> Evaluate(string lowerText, string fileType)
        {
            var results = new List<RuleMatch>();
            if (lowerText.Length == 0) return results;
            foreach (var rule in Rules)
            {
                if (rule.RequiredFileType != null && !string.Equals(rule.RequiredFileType, fileType, StringComparison.OrdinalIgnoreCase)) continue;
                var matched = new List<string>();
                foreach (var rs in rule.Strings)
                    if (lowerText.IndexOf(rs.Value, StringComparison.Ordinal) >= 0) matched.Add(rs.Id);
                if (matched.Count >= rule.MinimumMatches)
                    results.Add(new RuleMatch { Rule = rule, MatchedIds = matched });
            }
            return results;
        }
    }

    public static class LnkAnalyzer
    {
        public static List<DeobHit> Analyze(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            if (count < 0x4C) return hits;
            uint flags = (uint)(data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24));
            bool hasArguments = (flags & 0x20) != 0;
            uint showCommand = count > 60 ? (uint)(data[60] | (data[61] << 8) | (data[62] << 16) | (data[63] << 24)) : 1;

            var ascii = Encoding.ASCII.GetString(data, 0, Math.Min(count, 1 << 18));
            var unicode = Encoding.Unicode.GetString(data, 0, Math.Min(count, 1 << 18) & ~1);
            var combined = (ascii + "\n" + unicode).ToLowerInvariant();

            string[] interpreters = { "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "curl.exe" };
            foreach (var i in interpreters)
            {
                if (combined.IndexOf(i, StringComparison.Ordinal) >= 0)
                {
                    hits.Add(new DeobHit("Lnk.PowershellCommandLine", $"shortcut target invokes {i}"));
                    break;
                }
            }
            if (showCommand == 7 || combined.IndexOf("-w hidden", StringComparison.Ordinal) >= 0 || combined.IndexOf("windowstyle hidden", StringComparison.Ordinal) >= 0)
                hits.Add(new DeobHit("Lnk.HiddenWindowFlag", "shortcut runs minimized or with a hidden window"));
            if (hasArguments && count > 2048)
                hits.Add(new DeobHit("Lnk.LongCommandArguments", $"shortcut carries an unusually large argument block ({count} bytes)"));
            if (combined.IndexOf("\\\\", StringComparison.Ordinal) >= 0 && (combined.IndexOf("http", StringComparison.Ordinal) >= 0 || combined.IndexOf(".onion", StringComparison.Ordinal) >= 0))
                hits.Add(new DeobHit("Lnk.RemoteUncTarget", "shortcut references a remote UNC or web target"));
            return hits;
        }
    }

    public static class ContainerAnalyzer
    {
        public static bool LooksLikeIso(byte[] head, long fileLength)
        {
            if (fileLength < 0x8006) return false;
            return head.Length > 0x8006 &&
                   head[0x8001] == 0x43 && head[0x8002] == 0x44 && head[0x8003] == 0x30 &&
                   head[0x8004] == 0x30 && head[0x8005] == 0x31;
        }

        public static List<DeobHit> AnalyzeIso(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            var text = Encoding.ASCII.GetString(data, 0, Math.Min(count, 8 << 20)).ToUpperInvariant();
            bool hasExe = text.Contains(".EXE", StringComparison.Ordinal) || text.Contains(".DLL", StringComparison.Ordinal) || text.Contains(".SCR", StringComparison.Ordinal);
            bool hasLnk = text.Contains(".LNK", StringComparison.Ordinal);
            if (hasLnk) hits.Add(new DeobHit("Container.IsoWithLnk", "disc image contains a shortcut file, a common phishing delivery pattern"));
            else if (hasExe) hits.Add(new DeobHit("Container.IsoWithExecutable", "disc image contains an executable payload"));
            return hits;
        }

        public static List<DeobHit> AnalyzeOneNote(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            if (count < 16) return hits;
            byte[] guid = { 0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D };
            if (PatternEngine.IndexOf(data, Math.Min(count, 1 << 16), guid) < 0) return hits;
            var text = Encoding.ASCII.GetString(data, 0, Math.Min(count, 8 << 20)).ToLowerInvariant();
            string[] markers = { ".hta", ".vbs", ".js", ".cmd", ".bat", ".ps1", ".wsf" };
            foreach (var m in markers)
            {
                if (text.IndexOf(m, StringComparison.Ordinal) >= 0)
                {
                    hits.Add(new DeobHit("Container.OneNoteEmbeddedScript", $"OneNote section embeds a '{m}' attachment"));
                    break;
                }
            }
            return hits;
        }
    }

    public static class NameAnalyzer
    {
        private static readonly string[] SystemBinaries =
        {
            "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
            "explorer.exe", "taskhostw.exe", "spoolsv.exe", "dwm.exe", "conhost.exe", "wininit.exe"
        };

        public static List<DeobHit> Analyze(string fullPath)
        {
            var hits = new List<DeobHit>();
            var name = Path.GetFileName(fullPath);
            var lowerName = name.ToLowerInvariant();
            var lowerPath = fullPath.Replace('/', '\\').ToLowerInvariant();

            if (SystemBinaries.Contains(lowerName) &&
                !lowerPath.Contains("\\windows\\system32\\", StringComparison.Ordinal) &&
                !lowerPath.Contains("\\windows\\syswow64\\", StringComparison.Ordinal) &&
                !lowerPath.Contains("\\windows\\winsxs\\", StringComparison.Ordinal))
                hits.Add(new DeobHit("Name.SystemBinaryOutsideSystem32", $"system binary name '{name}' located outside the expected Windows directories"));

            int runLength = 0;
            foreach (char c in name)
            {
                if (c == ' ' || c == '\u00A0') { runLength++; if (runLength >= 12) break; }
                else runLength = 0;
            }
            if (runLength >= 12)
                hits.Add(new DeobHit("Name.ExcessiveWhitespacePadding", "file name pads the real extension out of view with whitespace"));

            foreach (char c in name)
            {
                if (c > 0x7F && (c >= 0x0400 && c <= 0x04FF))
                {
                    bool mostlyAscii = name.Count(ch => ch < 0x80) > name.Length / 2;
                    if (mostlyAscii)
                    {
                        hits.Add(new DeobHit("Name.HomoglyphCharacters", "file name mixes Latin characters with Cyrillic homoglyphs"));
                        break;
                    }
                }
            }

            var stem = Path.GetFileNameWithoutExtension(lowerName);
            if (stem.Length >= 12 && stem.All(c => char.IsLetterOrDigit(c)))
            {
                int digits = stem.Count(char.IsDigit);
                int letters = stem.Length - digits;
                if (digits > 0 && letters > 0 && Util.Entropy(Encoding.ASCII.GetBytes(stem), 0, stem.Length) > 3.6)
                    hits.Add(new DeobHit("Name.RandomLookingName", $"file stem '{stem}' looks machine-generated"));
            }
            return hits;
        }
    }

    public static class ScriptAnalyzer
    {
        public static List<DeobHit> Analyze(string text, string lowerText)
        {
            var hits = new List<DeobHit>();
            if (text.Length < 256) return hits;

            int longestLine = 0, current = 0;
            foreach (char c in text)
            {
                if (c == '\n') { if (current > longestLine) longestLine = current; current = 0; }
                else current++;
            }
            if (current > longestLine) longestLine = current;
            if (longestLine > 4000)
                hits.Add(new DeobHit("Script.LargeSingleLineBlob", $"single logical line of {longestLine} characters"));

            int longIdentifiers = 0;
            var sb = new StringBuilder();
            foreach (char c in text)
            {
                if (char.IsLetterOrDigit(c) || c == '_' || c == '$') sb.Append(c);
                else { if (sb.Length > 40) longIdentifiers++; sb.Clear(); }
            }
            if (longIdentifiers >= 5)
                hits.Add(new DeobHit("Script.VeryLongIdentifiers", $"{longIdentifiers} identifiers longer than 40 characters"));

            var bytes = Encoding.ASCII.GetBytes(text.Substring(0, Math.Min(text.Length, 200000)));
            double e = Util.Entropy(bytes, 0, bytes.Length);
            if (e > 5.4)
                hits.Add(new DeobHit("Script.HighEntropyText", $"text entropy {e:F2} is unusually high for source code"));

            if ((lowerText.Contains("del \"%~f0\"", StringComparison.Ordinal) ||
                 lowerText.Contains("remove-item $myinvocation", StringComparison.Ordinal) ||
                 lowerText.Contains("deletefile(wscript.scriptfullname", StringComparison.Ordinal)))
                hits.Add(new DeobHit("Script.SuspiciousSelfDelete", "script deletes itself after execution"));

            return hits;
        }
    }

    public static class Obf
    {
        private const byte Key = 0x5A;

        public static string D(string encoded)
        {
            var bytes = new byte[encoded.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = Hex(encoded[i * 2]);
                int lo = Hex(encoded[i * 2 + 1]);
                bytes[i] = (byte)(((hi << 4) | lo) ^ Key);
            }
            return Encoding.ASCII.GetString(bytes);
        }

        public static byte[] B(string encoded)
        {
            var bytes = new byte[encoded.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = Hex(encoded[i * 2]);
                int lo = Hex(encoded[i * 2 + 1]);
                bytes[i] = (byte)(((hi << 4) | lo) ^ Key);
            }
            return bytes;
        }

        public static string J(params string[] parts)
        {
            return string.Concat(parts);
        }

        private static int Hex(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        }

        public static string Encode(string plain)
        {
            var sb = new StringBuilder(plain.Length * 2);
            foreach (var b in Encoding.ASCII.GetBytes(plain)) sb.Append(((byte)(b ^ Key)).ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
    }

    public enum TrustLevel { Untrusted, Neutral, SystemPath, Signed, SignedSystem, Allowlisted }

    public sealed class TrustContext
    {
        public TrustLevel Level = TrustLevel.Neutral;
        public bool HasAuthenticode;
        public bool InSystemDirectory;
        public bool InProgramFiles;
        public bool InUserWritableSystemPath;
        public string Rationale = "";

        public double StructuralMultiplier()
        {
            switch (Level)
            {
                case TrustLevel.Allowlisted: return 0.0;
                case TrustLevel.SignedSystem: return 0.1;
                case TrustLevel.Signed: return 0.25;
                case TrustLevel.SystemPath: return 0.5;
                default: return 1.0;
            }
        }

        public double BehaviouralMultiplier()
        {
            switch (Level)
            {
                case TrustLevel.Allowlisted: return 0.0;
                case TrustLevel.SignedSystem: return 0.6;
                case TrustLevel.Signed: return 0.85;
                default: return 1.0;
            }
        }
    }

    public static class TrustEvaluator
    {
        private static readonly string[] SystemRoots = BuildSystemRoots();
        private static readonly string[] ProgramRoots = BuildProgramRoots();

        private static string[] BuildSystemRoots()
        {
            var list = new List<string>();
            try
            {
                var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrEmpty(win)) list.Add(Normalize(win));
            }
            catch (Exception) { }
            return list.ToArray();
        }

        private static string[] BuildProgramRoots()
        {
            var list = new List<string>();
            try
            {
                var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!string.IsNullOrEmpty(pf)) list.Add(Normalize(pf));
                var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                if (!string.IsNullOrEmpty(pf86)) list.Add(Normalize(pf86));
            }
            catch (Exception) { }
            return list.ToArray();
        }

        private static string Normalize(string path)
        {
            var p = path.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
            return p + "\\";
        }

        private static readonly string[] UserWritableInsideSystem =
        { "\\temp\\", "\\tracing\\", "\\tasks\\", "\\debug\\wia\\", "\\registration\\crmlog\\", "\\system32\\spool\\drivers\\color\\", "\\syswow64\\tasks\\" };

        public static TrustContext Evaluate(string fullPath, bool hasAuthenticode, bool allowlisted)
        {
            var ctx = new TrustContext { HasAuthenticode = hasAuthenticode };
            if (allowlisted)
            {
                ctx.Level = TrustLevel.Allowlisted;
                ctx.Rationale = "hash present in the operator allowlist";
                return ctx;
            }

            string lower;
            try { lower = Path.GetFullPath(fullPath).Replace('/', '\\').ToLowerInvariant(); }
            catch (Exception) { lower = fullPath.ToLowerInvariant(); }

            foreach (var root in SystemRoots)
                if (lower.StartsWith(root, StringComparison.Ordinal)) { ctx.InSystemDirectory = true; break; }
            foreach (var root in ProgramRoots)
                if (lower.StartsWith(root, StringComparison.Ordinal)) { ctx.InProgramFiles = true; break; }

            if (ctx.InSystemDirectory)
                foreach (var w in UserWritableInsideSystem)
                    if (lower.Contains(w, StringComparison.Ordinal)) { ctx.InUserWritableSystemPath = true; break; }

            bool protectedLocation = (ctx.InSystemDirectory || ctx.InProgramFiles) && !ctx.InUserWritableSystemPath;

            if (hasAuthenticode && protectedLocation)
            {
                ctx.Level = TrustLevel.SignedSystem;
                ctx.Rationale = "Authenticode certificate present and file resides in a protected system location";
            }
            else if (hasAuthenticode)
            {
                ctx.Level = TrustLevel.Signed;
                ctx.Rationale = "Authenticode certificate directory present";
            }
            else if (protectedLocation)
            {
                ctx.Level = TrustLevel.SystemPath;
                ctx.Rationale = "file resides in a protected system location without a signature";
            }
            else if (ctx.InUserWritableSystemPath)
            {
                ctx.Level = TrustLevel.Untrusted;
                ctx.Rationale = "file sits in a user-writable directory inside a system root";
            }
            else
            {
                ctx.Level = TrustLevel.Neutral;
                ctx.Rationale = "ordinary user-space location";
            }
            return ctx;
        }
    }

    public enum EvidenceClass { Structural, Contextual, Behavioural, Definitive }

    public static class EvidencePolicy
    {
        private static readonly System.Collections.Generic.HashSet<string> StructuralFamilies =
            new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "packing", "trust", "malformed", "info", "reputation" };

        private static readonly System.Collections.Generic.HashSet<string> DefinitiveNames =
            new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal)
        { "EICAR.TestFile", "Hash.KnownQuarantinedHash" };

        private static readonly string[] StructuralPrefixes =
        { "PE.HighEntropySection", "PE.ExtremeEntropySection", "PE.Packer", "PE.NonStandardSectionName",
          "PE.MinimalImports", "PE.CheckSumMismatch", "PE.TimestampZero", "PE.NoAuthenticodeSignature",
          "PE.RichHeaderMissing", "PE.TooManySections", "PE.SectionRawVirtualMismatch", "PE.OverlayLargeHighEntropy",
          "PE.DotNetAssembly", "Script.HighEntropyText", "Name.RandomLookingName", "Byte.MzDosStubOverwritten",
          "Container.SingleFileArchiveExecutable", "PE.ResourceHighEntropyBlob", "Deob.HighObfuscationDensity" };

        private static readonly string[] BehaviouralPrefixes =
        { "Composite.", "Rule.", "Deob.", "Vba.", "Mail.", "Lnk.", "Carve.", "Ole." };

        public static EvidenceClass Classify(Finding f)
        {
            if (DefinitiveNames.Contains(f.Name)) return EvidenceClass.Definitive;
            foreach (var p in StructuralPrefixes)
                if (f.Name.StartsWith(p, StringComparison.Ordinal)) return EvidenceClass.Structural;
            if (StructuralFamilies.Contains(f.Family) && f.Weight < 60) return EvidenceClass.Structural;
            foreach (var p in BehaviouralPrefixes)
                if (f.Name.StartsWith(p, StringComparison.Ordinal)) return EvidenceClass.Behavioural;
            return EvidenceClass.Contextual;
        }

        public static int Adjust(Finding f, TrustContext trust)
        {
            var cls = Classify(f);
            if (cls == EvidenceClass.Definitive) return f.Weight;
            double m = cls == EvidenceClass.Structural ? trust.StructuralMultiplier() : trust.BehaviouralMultiplier();
            if (m >= 1.0) return f.Weight;
            int adjusted = (int)Math.Round(f.Weight * m);
            return adjusted < 0 ? 0 : adjusted;
        }
    }

    public static class Normalizer
    {
        public static string Collapse(string lowerText, int cap)
        {
            int n = Math.Min(lowerText.Length, cap);
            var sb = new StringBuilder(n);
            for (int i = 0; i < n; i++)
            {
                char c = lowerText[i];
                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.Append(c);
            }
            return sb.ToString();
        }

        public static string StripQuotesAndTicks(string text, int cap)
        {
            int n = Math.Min(text.Length, cap);
            var sb = new StringBuilder(n);
            for (int i = 0; i < n; i++)
            {
                char c = text[i];
                if (c == '`' || c == '^' || c == '"' || c == '\'' || c == '+') continue;
                sb.Append(c);
            }
            return sb.ToString().ToLowerInvariant();
        }
    }

    public sealed class CollapsedRule
    {
        public string Name = "";
        public string Description = "";
        public int Weight;
        public string Family = "";
        public Severity Severity = Severity.High;
        public string[] Required = Array.Empty<string>();
        public string[] AnyOf = Array.Empty<string>();
    }

    public static class CollapsedRuleSet
    {
        public static readonly CollapsedRule[] Rules =
        {
            new CollapsedRule
            {
                Name = "Collapsed.StealerKillChain",
                Description = "credential targets and an exfiltration channel survive full string normalization",
                Weight = 90, Family = "infostealer", Severity = Severity.Critical,
                Required = new[] { "loginsjson|cryptunprotectdata|oscrypt|walletdat|key4db|logindata" },
                AnyOf = new[] { "apitelegramorgbot", "discordcomapiwebhooks", "discordappcomapiwebhooks", "webhooksite", "anonfilescom", "gofileio" }
            },
            new CollapsedRule
            {
                Name = "Collapsed.PowerShellTcpStager",
                Description = "PowerShell TCP client type name reassembled from fragmented literals",
                Weight = 85, Family = "backdoor", Severity = Severity.Critical,
                Required = new[] { "systemnetsocketstcpclient" }
            },
            new CollapsedRule
            {
                Name = "Collapsed.ShadowCopyDestruction",
                Description = "shadow copy deletion command reassembled after removing separators",
                Weight = 80, Family = "ransomware", Severity = Severity.Critical,
                Required = new[] { "vssadmindeleteshadows|wmicshadowcopydelete|win32shadowcopydelete" }
            },
            new CollapsedRule
            {
                Name = "Collapsed.CredentialDumpModule",
                Description = "credential dumping module name reassembled after removing separators",
                Weight = 90, Family = "credential-access", Severity = Severity.Critical,
                Required = new[] { "sekurlsalogonpasswords|lsadumpsam|lsadumpdcsync|kerberosptt" }
            },
            new CollapsedRule
            {
                Name = "Collapsed.AmsiBypass",
                Description = "AMSI bypass identifier reassembled after removing separators",
                Weight = 80, Family = "defense-evasion", Severity = Severity.Critical,
                Required = new[] { "amsiinitfailed|amsiscanbuffer|amsiutils" }
            },
            new CollapsedRule
            {
                Name = "Collapsed.DefenderTamper",
                Description = "Defender tampering command reassembled after removing separators",
                Weight = 75, Family = "defense-evasion", Severity = Severity.High,
                Required = new[] { "setmppreferencedisable|addmppreferenceexclusionpath|disableantispyware|disablerealtimemonitoring" }
            },
            new CollapsedRule
            {
                Name = "Collapsed.MinerPool",
                Description = "mining pool URL reassembled after removing separators",
                Weight = 80, Family = "cryptominer", Severity = Severity.Critical,
                Required = new[] { "stratumtcp|stratumssl|donatelevel" }
            },
        };

        public static List<(CollapsedRule Rule, string Matched)> Evaluate(string collapsed, string rawLower)
        {
            var hits = new List<(CollapsedRule, string)>();
            if (collapsed.Length < 8) return hits;
            foreach (var rule in Rules)
            {
                string matchedToken = "";
                bool ok = true;
                foreach (var group in rule.Required)
                {
                    bool groupHit = false;
                    foreach (var alt in group.Split('|'))
                    {
                        if (alt.Length == 0) continue;
                        if (collapsed.IndexOf(alt, StringComparison.Ordinal) >= 0)
                        {
                            groupHit = true;
                            if (matchedToken.Length == 0) matchedToken = alt;
                            break;
                        }
                    }
                    if (!groupHit) { ok = false; break; }
                }
                if (!ok) continue;
                if (rule.AnyOf.Length > 0)
                {
                    bool anyHit = false;
                    foreach (var alt in rule.AnyOf)
                        if (collapsed.IndexOf(alt, StringComparison.Ordinal) >= 0) { anyHit = true; matchedToken += "+" + alt; break; }
                    if (!anyHit) continue;
                }
                bool visibleInRaw = matchedToken.Length > 0 && rawLower.IndexOf(matchedToken, StringComparison.Ordinal) >= 0;
                hits.Add((rule, visibleInRaw ? matchedToken + " (also visible unmodified)" : matchedToken + " (only visible after normalization)"));
            }
            return hits;
        }
    }

    public static class AttackMap
    {
        private static readonly Dictionary<string, string[]> Techniques = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "ransomware", new[] { "T1486", "T1490" } },
            { "ransom-note", new[] { "T1486" } },
            { "ransom-ext", new[] { "T1486" } },
            { "credential-access", new[] { "T1003", "T1555" } },
            { "defense-evasion", new[] { "T1562.001", "T1562.006" } },
            { "injection", new[] { "T1055" } },
            { "shellcode", new[] { "T1055.002" } },
            { "persistence", new[] { "T1547.001", "T1053.005" } },
            { "infostealer", new[] { "T1555.003", "T1539" } },
            { "exfiltration", new[] { "T1567.002" } },
            { "cryptominer", new[] { "T1496" } },
            { "lolbin", new[] { "T1218", "T1548.002" } },
            { "macro", new[] { "T1204.002", "T1059.005" } },
            { "obfuscation", new[] { "T1027" } },
            { "packing", new[] { "T1027.002" } },
            { "loader", new[] { "T1105", "T1059.001" } },
            { "dropper", new[] { "T1105" } },
            { "keylogger", new[] { "T1056.001" } },
            { "rat", new[] { "T1219", "T1071.001" } },
            { "backdoor", new[] { "T1071.001" } },
            { "wiper", new[] { "T1485", "T1561.002" } },
            { "destructive", new[] { "T1485" } },
            { "bootkit", new[] { "T1542.003" } },
            { "rootkit", new[] { "T1014", "T1068" } },
            { "discovery", new[] { "T1082", "T1033" } },
            { "anti-analysis", new[] { "T1497" } },
            { "antiforensics", new[] { "T1070.001" } },
            { "archive-abuse", new[] { "T1027.002" } },
            { "masquerading", new[] { "T1036.005" } },
            { "container-abuse", new[] { "T1204.002" } },
            { "clipper", new[] { "T1565.002" } },
            { "social-engineering", new[] { "T1566.001" } },
            { "exploit", new[] { "T1203" } },
            { "mail", new[] { "T1566.001" } },
        };

        public static string[] For(string family)
        {
            return Techniques.TryGetValue(family, out var t) ? t : Array.Empty<string>();
        }

        public static List<string> Collect(IEnumerable<string> families)
        {
            var set = new System.Collections.Generic.SortedSet<string>(StringComparer.Ordinal);
            foreach (var f in families) foreach (var t in For(f)) set.Add(t);
            return set.ToList();
        }
    }

    public sealed class BytePattern
    {
        public string Name = "";
        public string Description = "";
        public int Weight;
        public string Family = "";
        public Severity Severity = Severity.Medium;
        public short[] Mask = Array.Empty<short>();

        public static short[] Compile(string spec)
        {
            var parts = spec.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            var mask = new short[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                var token = parts[i];
                if (token.Length != 2) { mask[i] = -1; continue; }
                bool hiWild = token[0] == '?';
                bool loWild = token[1] == '?';
                if (hiWild && loWild) { mask[i] = -1; continue; }
                if (loWild)
                {
                    int hi = HexDigit(token[0]);
                    mask[i] = hi < 0 ? (short)-1 : (short)(-2 - hi);
                    continue;
                }
                if (hiWild) { mask[i] = -1; continue; }
                int h = HexDigit(token[0]);
                int l = HexDigit(token[1]);
                mask[i] = (h < 0 || l < 0) ? (short)-1 : (short)((h << 4) | l);
            }
            return mask;
        }

        private static int HexDigit(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }

    public static class BytePatternEngine
    {
        public static readonly BytePattern[] Patterns = Build();

        private static BytePattern Make(string name, string spec, int weight, string family, Severity sev, string desc)
        {
            return new BytePattern { Name = name, Mask = BytePattern.Compile(spec), Weight = weight, Family = family, Severity = sev, Description = desc };
        }

        private static BytePattern[] Build()
        {
            return new[]
            {
                Make("Byte.MsfShikataGaNai", "D9 74 24 F4 5? 29 C9 B1", 80, "shellcode", Severity.Critical,
                    "Metasploit shikata_ga_nai polymorphic decoder stub"),
                Make("Byte.MsfFnstenvGetPc", "D9 EE D9 74 24 F4 5? ", 70, "shellcode", Severity.High,
                    "fnstenv GetPC shellcode stub"),
                Make("Byte.CallPopGetPc", "E8 00 00 00 00 5?", 45, "shellcode", Severity.Medium,
                    "call/pop GetPC shellcode idiom"),
                Make("Byte.PebLdrWalk64", "65 48 8B 04 25 60 00 00 00 48 8B 4? 18", 70, "shellcode", Severity.High,
                    "x64 PEB to LDR module list walk"),
                Make("Byte.HashApiRor13", "C1 CF 0D 01 C7", 65, "shellcode", Severity.High,
                    "ROR13 API hashing loop used by position independent loaders"),
                Make("Byte.HeavensGateFar", "EA ?? ?? ?? ?? 33 00", 75, "shellcode", Severity.High,
                    "Heaven's Gate far jump into 64-bit mode from WOW64"),
                Make("Byte.SyscallStubDirect", "4C 8B D1 B8 ?? ?? 00 00 0F 05", 60, "defense-evasion", Severity.High,
                    "direct syscall stub bypassing userland hooks"),
                Make("Byte.IndirectSyscallJmp", "4C 8B D1 B8 ?? ?? 00 00 49 89 CA FF 25", 70, "defense-evasion", Severity.High,
                    "indirect syscall trampoline"),
                Make("Byte.UpxUnpackerStub", "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57", 40, "packing", Severity.Medium,
                    "UPX unpacking stub prologue"),
                Make("Byte.AspackStub", "60 E8 03 00 00 00 E9 EB", 40, "packing", Severity.Medium,
                    "ASPack decompression stub"),
                Make("Byte.FsuGetPcCld", "FC 60 8B 6C 24 24 8B 45 3C", 65, "shellcode", Severity.High,
                    "cld/pusha PE header parsing shellcode"),
                Make("Byte.Rc4KsaLoop", "8A ?? ?? 02 ?? 88 ?? ?? 8A ?? ?? 02", 35, "obfuscation", Severity.Medium,
                    "RC4 key scheduling loop shape"),
                Make("Byte.AmsiPatchBytes", "B8 57 00 07 80 C3", 85, "defense-evasion", Severity.Critical,
                    "AmsiScanBuffer patch returning E_INVALIDARG"),
                Make("Byte.EtwPatchRet", "C3 00 00 00 00 00 00 00 4C 8B DC", 55, "defense-evasion", Severity.High,
                    "EtwEventWrite prologue patched with an immediate return"),
                Make("Byte.MzDosStubOverwritten", "4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00", 30, "packing", Severity.Low,
                    "PE with a stripped DOS stub, typical of generated or packed images"),
            };
        }

        public static List<BytePattern> Scan(byte[] data, int count)
        {
            var found = new List<BytePattern>();
            foreach (var p in Patterns)
            {
                if (Matches(data, count, p.Mask)) found.Add(p);
            }
            return found;
        }

        private static bool Unit(short m, byte b)
        {
            if (m == -1) return true;
            if (m < -1) return (b >> 4) == (-2 - m);
            return b == (byte)m;
        }

        private static bool Matches(byte[] data, int count, short[] mask)
        {
            int n = mask.Length;
            if (n == 0 || count < n) return false;
            int limit = count - n;
            for (int i = 0; i <= limit; i++)
            {
                int k = 0;
                while (k < n)
                {
                    if (!Unit(mask[k], data[i + k])) break;
                    k++;
                }
                if (k == n) return true;
            }
            return false;
        }
    }

    public static class RichHeaderParser
    {
        public static void Populate(byte[] data, PeImage pe)
        {
            try
            {
                int limit = Math.Min(data.Length, 0x400);
                int richPos = -1;
                for (int i = 0x80; i + 8 <= limit; i += 4)
                {
                    if (data[i] == 0x52 && data[i + 1] == 0x69 && data[i + 2] == 0x63 && data[i + 3] == 0x68)
                    {
                        richPos = i;
                        break;
                    }
                }
                if (richPos < 0)
                {
                    for (int i = 0x40; i + 8 <= limit; i += 4)
                    {
                        if (data[i] == 0x52 && data[i + 1] == 0x69 && data[i + 2] == 0x63 && data[i + 3] == 0x68)
                        {
                            richPos = i;
                            break;
                        }
                    }
                }
                if (richPos < 0 || richPos + 8 > data.Length) return;

                uint key = (uint)(data[richPos + 4] | (data[richPos + 5] << 8) | (data[richPos + 6] << 16) | (data[richPos + 7] << 24));
                int start = -1;
                for (int i = richPos - 4; i >= 0x40; i -= 4)
                {
                    uint v = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));
                    if ((v ^ key) == 0x536E6144u) { start = i; break; }
                }
                if (start < 0) return;

                pe.HasRichHeader = true;
                var decoded = new List<byte>();
                int entries = 0;
                for (int i = start + 16; i + 8 <= richPos; i += 8)
                {
                    uint compid = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) ^ key;
                    uint cnt = (uint)(data[i + 4] | (data[i + 5] << 8) | (data[i + 6] << 16) | (data[i + 7] << 24)) ^ key;
                    decoded.Add((byte)(compid & 0xFF));
                    decoded.Add((byte)((compid >> 8) & 0xFF));
                    decoded.Add((byte)((compid >> 16) & 0xFF));
                    decoded.Add((byte)((compid >> 24) & 0xFF));
                    decoded.Add((byte)(cnt & 0xFF));
                    decoded.Add((byte)((cnt >> 8) & 0xFF));
                    decoded.Add((byte)((cnt >> 16) & 0xFF));
                    decoded.Add((byte)((cnt >> 24) & 0xFF));
                    entries++;
                }
                pe.RichEntryCount = entries;
                if (decoded.Count > 0) pe.RichHash = Util.ToHex(MD5.HashData(decoded.ToArray()));

                uint sum = 0;
                for (int i = 0; i < start; i++)
                {
                    if (i >= 0x3C && i < 0x40) continue;
                    byte b = data[i];
                    sum += (uint)((b << (i % 32)) | (b >> (32 - (i % 32))));
                }
                sum += (uint)start;
                pe.RichChecksumPlausible = true;
            }
            catch (Exception)
            {
            }
        }
    }

    public sealed class DotNetInfo
    {
        public bool Parsed;
        public string RuntimeVersion = "";
        public List<string> UserStrings = new List<string>();
        public List<string> Names = new List<string>();
        public bool HasStrongName;
    }

    public static class DotNetParser
    {
        private static ushort U16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
        private static uint U32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

        public static DotNetInfo Parse(byte[] data, PeImage pe)
        {
            var info = new DotNetInfo();
            if (!pe.IsDotNet || pe.ComDescriptorRva == 0) return info;
            int cli = PeParser.RvaToOffset(pe, pe.ComDescriptorRva);
            if (cli < 0 || cli + 72 > data.Length) return info;

            uint metaRva = U32(data, cli + 8);
            uint metaSize = U32(data, cli + 12);
            uint snRva = U32(data, cli + 32);
            info.HasStrongName = snRva != 0;
            int meta = PeParser.RvaToOffset(pe, metaRva);
            if (meta < 0 || meta + 20 > data.Length) return info;
            if (U32(data, meta) != 0x424A5342u) return info;

            uint verLen = U32(data, meta + 12);
            if (verLen > 256 || meta + 16 + verLen + 4 > data.Length) return info;
            info.RuntimeVersion = Encoding.ASCII.GetString(data, meta + 16, (int)verLen).TrimEnd('\0');
            int p = meta + 16 + (int)verLen;
            p += 2;
            if (p + 2 > data.Length) return info;
            int streamCount = U16(data, p);
            p += 2;

            int usOffset = -1, usSize = 0, strOffset = -1, strSize = 0;
            for (int i = 0; i < streamCount && i < 16; i++)
            {
                if (p + 8 > data.Length) break;
                uint so = U32(data, p);
                uint ss = U32(data, p + 4);
                p += 8;
                var nameSb = new StringBuilder();
                while (p < data.Length && data[p] != 0 && nameSb.Length < 32) { nameSb.Append((char)data[p]); p++; }
                p++;
                while ((p - meta) % 4 != 0 && p < data.Length) p++;
                var name = nameSb.ToString();
                if (name == "#US") { usOffset = meta + (int)so; usSize = (int)ss; }
                else if (name == "#Strings") { strOffset = meta + (int)so; strSize = (int)ss; }
            }

            info.Parsed = true;
            if (usOffset > 0 && usSize > 0 && usOffset + usSize <= data.Length)
                ReadUserStrings(data, usOffset, usSize, info.UserStrings);
            if (strOffset > 0 && strSize > 0 && strOffset + strSize <= data.Length)
                ReadStringHeap(data, strOffset, strSize, info.Names);
            return info;
        }

        private static void ReadUserStrings(byte[] data, int offset, int size, List<string> output)
        {
            int p = offset + 1;
            int end = offset + size;
            while (p < end && output.Count < 4000)
            {
                int len = ReadCompressed(data, ref p);
                if (len <= 0 || p + len > end) break;
                int chars = (len - 1) / 2;
                if (chars > 0 && chars < 8192)
                {
                    try { output.Add(Encoding.Unicode.GetString(data, p, chars * 2)); }
                    catch (ArgumentException) { }
                }
                p += len;
            }
        }

        private static void ReadStringHeap(byte[] data, int offset, int size, List<string> output)
        {
            int p = offset;
            int end = offset + size;
            var sb = new StringBuilder();
            while (p < end && output.Count < 6000)
            {
                byte b = data[p++];
                if (b == 0)
                {
                    if (sb.Length > 2) output.Add(sb.ToString());
                    sb.Clear();
                    continue;
                }
                if (b >= 32 && b < 127) sb.Append((char)b);
            }
        }

        private static int ReadCompressed(byte[] data, ref int p)
        {
            if (p >= data.Length) return -1;
            byte b = data[p];
            if ((b & 0x80) == 0) { p += 1; return b; }
            if ((b & 0x40) == 0)
            {
                if (p + 1 >= data.Length) return -1;
                int v = ((b & 0x3F) << 8) | data[p + 1];
                p += 2;
                return v;
            }
            if (p + 3 >= data.Length) return -1;
            int v2 = ((b & 0x1F) << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3];
            p += 4;
            return v2;
        }

        private static readonly string[] ObfuscatorMarkers =
        { "ConfusedByAttribute", "SmartAssembly", "Babel", "Eazfuscator", "DotfuscatorAttribute", "NETReactor", "Agile.NET", "DeepSea", "Obfuscar" };

        private static readonly string[] SuspiciousApis =
        { "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory", "SetWindowsHookEx",
          "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "CreateProcessA", "ResumeThread", "SetThreadContext",
          "GetAsyncKeyState", "CryptUnprotectData", "AmsiScanBuffer", "LoadLibraryA", "GetProcAddress", "memcpy" };

        public static List<DeobHit> Evaluate(DotNetInfo info)
        {
            var hits = new List<DeobHit>();
            if (!info.Parsed) return hits;

            foreach (var marker in ObfuscatorMarkers)
            {
                if (info.Names.Any(n => n.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    hits.Add(new DeobHit(marker.StartsWith("Confused", StringComparison.Ordinal) ? "Dotnet.ObfuscatorConfuserEx" : "Dotnet.ObfuscatorGeneric",
                        $"assembly metadata references the {marker} obfuscator"));
                    break;
                }
            }

            int mangled = info.Names.Count(n => n.Length >= 8 && n.All(c => c == 'I' || c == 'l' || c == '1' || c == 'O' || c == '0'));
            if (mangled >= 5)
                hits.Add(new DeobHit("Dotnet.ObfuscatorGeneric", $"{mangled} homoglyph-mangled identifiers in the metadata string heap"));

            var apiHits = SuspiciousApis.Where(a => info.Names.Contains(a, StringComparer.Ordinal)).ToList();
            if (apiHits.Count >= 3)
                hits.Add(new DeobHit("Dotnet.SuspiciousPInvoke",
                    $"managed assembly declares native interop for {string.Join(", ", apiHits.Take(6))}"));

            if (info.Names.Any(n => string.Equals(n, "RunPE", StringComparison.OrdinalIgnoreCase)) ||
                info.Names.Any(n => n.IndexOf("Hollow", StringComparison.OrdinalIgnoreCase) >= 0) ||
                info.UserStrings.Any(u => u.IndexOf("RunPE", StringComparison.OrdinalIgnoreCase) >= 0))
                hits.Add(new DeobHit("Dotnet.RunPeMarker", "assembly contains a RunPE or process hollowing routine name"));

            return hits;
        }
    }

    public sealed class OleEntry
    {
        public string Name = "";
        public byte Type;
        public uint StartSector;
        public long Size;
    }

    public sealed class OleFile
    {
        public List<OleEntry> Entries = new List<OleEntry>();
        private byte[] _data = Array.Empty<byte>();
        private uint[] _fat = Array.Empty<uint>();
        private uint[] _miniFat = Array.Empty<uint>();
        private int _sectorSize = 512;
        private int _miniSectorSize = 64;
        private uint _miniCutoff = 4096;
        private uint _rootStart;
        public bool Parsed;

        private static ushort U16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
        private static uint U32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

        public static OleFile? Open(byte[] data)
        {
            try
            {
                var f = new OleFile();
                if (data.Length < 512) return null;
                if (!(data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0)) return null;
                f._data = data;
                f._sectorSize = 1 << U16(data, 0x1E);
                f._miniSectorSize = 1 << U16(data, 0x20);
                if (f._sectorSize < 128 || f._sectorSize > 65536) return null;
                uint numFat = U32(data, 0x2C);
                uint firstDir = U32(data, 0x30);
                f._miniCutoff = U32(data, 0x38);
                uint firstMiniFat = U32(data, 0x3C);
                uint numMiniFat = U32(data, 0x40);
                uint firstDifat = U32(data, 0x44);
                uint numDifat = U32(data, 0x48);

                var fatSectors = new List<uint>();
                for (int i = 0; i < 109 && i < numFat; i++)
                {
                    uint v = U32(data, 0x4C + i * 4);
                    if (v == 0xFFFFFFFFu) break;
                    fatSectors.Add(v);
                }
                uint difat = firstDifat;
                int difatGuard = 0;
                while (difat != 0xFFFFFFFEu && difat != 0xFFFFFFFFu && difatGuard++ < 64 && fatSectors.Count < numFat)
                {
                    int off = f.SectorOffset(difat);
                    if (off < 0 || off + f._sectorSize > data.Length) break;
                    int perSector = f._sectorSize / 4 - 1;
                    for (int i = 0; i < perSector; i++)
                    {
                        uint v = U32(data, off + i * 4);
                        if (v == 0xFFFFFFFFu) continue;
                        fatSectors.Add(v);
                    }
                    difat = U32(data, off + perSector * 4);
                }

                var fat = new List<uint>();
                foreach (var fs in fatSectors)
                {
                    int off = f.SectorOffset(fs);
                    if (off < 0 || off + f._sectorSize > data.Length) continue;
                    for (int i = 0; i < f._sectorSize / 4; i++) fat.Add(U32(data, off + i * 4));
                }
                f._fat = fat.ToArray();
                if (f._fat.Length == 0) return null;

                var miniFat = new List<uint>();
                uint mf = firstMiniFat;
                int mfGuard = 0;
                while (mf != 0xFFFFFFFEu && mf != 0xFFFFFFFFu && mfGuard++ < (int)Math.Max(numMiniFat, 1) + 64)
                {
                    int off = f.SectorOffset(mf);
                    if (off < 0 || off + f._sectorSize > data.Length) break;
                    for (int i = 0; i < f._sectorSize / 4; i++) miniFat.Add(U32(data, off + i * 4));
                    mf = f.NextSector(mf);
                }
                f._miniFat = miniFat.ToArray();

                uint dir = firstDir;
                int dirGuard = 0;
                while (dir != 0xFFFFFFFEu && dir != 0xFFFFFFFFu && dirGuard++ < 4096)
                {
                    int off = f.SectorOffset(dir);
                    if (off < 0 || off + f._sectorSize > data.Length) break;
                    int perSector = f._sectorSize / 128;
                    for (int i = 0; i < perSector; i++)
                    {
                        int eo = off + i * 128;
                        if (eo + 128 > data.Length) break;
                        int nameLen = U16(data, eo + 64);
                        if (nameLen < 2 || nameLen > 64) continue;
                        var name = Encoding.Unicode.GetString(data, eo, nameLen - 2);
                        var entry = new OleEntry
                        {
                            Name = name,
                            Type = data[eo + 66],
                            StartSector = U32(data, eo + 116),
                            Size = U32(data, eo + 120)
                        };
                        if (entry.Type == 5) f._rootStart = entry.StartSector;
                        if (entry.Type == 1 || entry.Type == 2 || entry.Type == 5) f.Entries.Add(entry);
                    }
                    dir = f.NextSector(dir);
                }

                f.Parsed = f.Entries.Count > 0;
                return f.Parsed ? f : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private int SectorOffset(uint sector)
        {
            long off = 512L + (long)sector * _sectorSize;
            if (off < 0 || off > int.MaxValue) return -1;
            return (int)off;
        }

        private uint NextSector(uint current)
        {
            if (current >= _fat.Length) return 0xFFFFFFFEu;
            return _fat[current];
        }

        public byte[] Read(OleEntry entry)
        {
            try
            {
                if (entry.Size <= 0 || entry.Size > 64 * 1024 * 1024) return Array.Empty<byte>();
                if (entry.Size < _miniCutoff && entry.Type != 5) return ReadMini(entry);
                var output = new List<byte>((int)entry.Size);
                uint sector = entry.StartSector;
                int guard = 0;
                while (sector != 0xFFFFFFFEu && sector != 0xFFFFFFFFu && output.Count < entry.Size && guard++ < 1 << 20)
                {
                    int off = SectorOffset(sector);
                    if (off < 0 || off + _sectorSize > _data.Length) break;
                    for (int i = 0; i < _sectorSize && output.Count < entry.Size; i++) output.Add(_data[off + i]);
                    sector = NextSector(sector);
                }
                return output.ToArray();
            }
            catch (Exception)
            {
                return Array.Empty<byte>();
            }
        }

        private byte[] ReadMini(OleEntry entry)
        {
            var root = Entries.FirstOrDefault(e => e.Type == 5);
            if (root == null) return Array.Empty<byte>();
            var miniStream = ReadChain(_rootStart, root.Size);
            var output = new List<byte>((int)entry.Size);
            uint sector = entry.StartSector;
            int guard = 0;
            while (sector != 0xFFFFFFFEu && sector != 0xFFFFFFFFu && output.Count < entry.Size && guard++ < 1 << 20)
            {
                long off = (long)sector * _miniSectorSize;
                if (off < 0 || off + _miniSectorSize > miniStream.Length) break;
                for (int i = 0; i < _miniSectorSize && output.Count < entry.Size; i++) output.Add(miniStream[off + i]);
                sector = sector < _miniFat.Length ? _miniFat[sector] : 0xFFFFFFFEu;
            }
            return output.ToArray();
        }

        private byte[] ReadChain(uint start, long size)
        {
            var output = new List<byte>();
            uint sector = start;
            int guard = 0;
            while (sector != 0xFFFFFFFEu && sector != 0xFFFFFFFFu && output.Count < size && guard++ < 1 << 20)
            {
                int off = SectorOffset(sector);
                if (off < 0 || off + _sectorSize > _data.Length) break;
                for (int i = 0; i < _sectorSize && output.Count < size; i++) output.Add(_data[off + i]);
                sector = NextSector(sector);
            }
            return output.ToArray();
        }
    }

    public static class VbaDecompressor
    {
        public static byte[] Decompress(byte[] data, int offset)
        {
            var output = new List<byte>();
            if (offset >= data.Length || data[offset] != 0x01) return Array.Empty<byte>();
            int pos = offset + 1;
            while (pos + 2 <= data.Length)
            {
                int header = data[pos] | (data[pos + 1] << 8);
                pos += 2;
                int chunkSize = (header & 0x0FFF) + 3;
                bool compressed = (header & 0x8000) != 0;
                int chunkEnd = Math.Min(pos + chunkSize - 2, data.Length);
                if (!compressed)
                {
                    for (int i = pos; i < chunkEnd; i++) output.Add(data[i]);
                    pos = chunkEnd;
                    continue;
                }
                int chunkStart = output.Count;
                while (pos < chunkEnd)
                {
                    byte flags = data[pos++];
                    for (int bit = 0; bit < 8 && pos < chunkEnd; bit++)
                    {
                        if ((flags & (1 << bit)) == 0)
                        {
                            output.Add(data[pos++]);
                            continue;
                        }
                        if (pos + 1 >= chunkEnd + 1 || pos + 1 >= data.Length) { pos = chunkEnd; break; }
                        int token = data[pos] | (data[pos + 1] << 8);
                        pos += 2;
                        int difference = output.Count - chunkStart;
                        int bitCount = 4;
                        while ((1 << bitCount) < difference && bitCount < 12) bitCount++;
                        if (difference == 0) bitCount = 4;
                        int lengthMask = 0xFFFF >> bitCount;
                        int copyLength = (token & lengthMask) + 3;
                        int copyOffset = ((token & ~lengthMask & 0xFFFF) >> (16 - bitCount)) + 1;
                        int src = output.Count - copyOffset;
                        if (src < 0) { pos = chunkEnd; break; }
                        for (int i = 0; i < copyLength; i++)
                        {
                            int idx = src + i;
                            if (idx < 0 || idx >= output.Count) break;
                            output.Add(output[idx]);
                        }
                        if (output.Count > 8 * 1024 * 1024) return output.ToArray();
                    }
                }
            }
            return output.ToArray();
        }

        public static string RecoverSource(byte[] streamData)
        {
            var best = new StringBuilder();
            for (int i = 0; i + 1 < streamData.Length && i < 1 << 20; i++)
            {
                if (streamData[i] != 0x01) continue;
                var decompressed = Decompress(streamData, i);
                if (decompressed.Length < 32) continue;
                double printable = Util.PrintableRatio(decompressed, decompressed.Length);
                if (printable < 0.8) continue;
                var text = Encoding.ASCII.GetString(decompressed);
                if (text.Length > best.Length) { best.Clear(); best.Append(text); }
                if (best.Length > 200000) break;
            }
            return best.ToString();
        }
    }

    public static class OleAnalyzer
    {
        private static readonly string[] AutoExec =
        { "auto_open", "autoopen", "auto_close", "autoexec", "document_open", "document_close", "workbook_open", "workbook_activate", "auto_exec" };

        private static readonly string[] ShellPrimitives =
        { "wscript.shell", "shell(", "shellexecute", "createobject(\"wscript", "vba.shell", "createprocess" };

        private static readonly string[] DownloadPrimitives =
        { "msxml2.xmlhttp", "winhttp.winhttprequest", "adodb.stream", "urldownloadtofile", "internetopenurl", "xmlhttp" };

        public static List<DeobHit> Analyze(byte[] data, out string recoveredMacroSource)
        {
            recoveredMacroSource = "";
            var hits = new List<DeobHit>();
            var ole = OleFile.Open(data);
            if (ole == null) return hits;

            var sourceBuilder = new StringBuilder();
            foreach (var entry in ole.Entries)
            {
                var lowerName = entry.Name.ToLowerInvariant();
                if (entry.Type == 2 && (lowerName.Contains("workbook", StringComparison.Ordinal) || lowerName.Contains("book", StringComparison.Ordinal)))
                {
                    var content = ole.Read(entry);
                    if (HasExcel4Macro(content))
                        hits.Add(new DeobHit("Ole.Excel4Macro", "workbook stream declares an Excel 4.0 macro sheet"));
                }
                if (lowerName.Contains("equation", StringComparison.Ordinal) || lowerName.Contains("eqnedt", StringComparison.Ordinal))
                    hits.Add(new DeobHit("Ole.EquationEditorObject", $"document embeds an Equation Editor object ({entry.Name})"));
                if (lowerName == "package" || lowerName.Contains("ole10native", StringComparison.Ordinal))
                {
                    var content = ole.Read(entry);
                    var detail = Util.IsPe(content) ? "embedded package stream carries an MZ/PE payload" : "document embeds a packaged file object";
                    hits.Add(new DeobHit("Ole.EmbeddedPackageStream", detail));
                }
                if (entry.Type != 2) continue;
                bool looksVba = lowerName == "vba" || lowerName.Contains("module", StringComparison.Ordinal) ||
                                lowerName.Contains("thisdocument", StringComparison.Ordinal) || lowerName.Contains("thisworkbook", StringComparison.Ordinal) ||
                                lowerName.StartsWith("sheet", StringComparison.Ordinal) || lowerName.Contains("form", StringComparison.Ordinal) ||
                                lowerName == "dir" || lowerName.Contains("class", StringComparison.Ordinal);
                if (!looksVba) continue;
                var raw = ole.Read(entry);
                if (raw.Length == 0) continue;
                var src = VbaDecompressor.RecoverSource(raw);
                if (src.Length > 24) sourceBuilder.Append(src).Append('\n');
            }

            recoveredMacroSource = sourceBuilder.ToString();
            if (recoveredMacroSource.Length > 24)
            {
                hits.Add(new DeobHit("Vba.MacroSourceRecovered", $"decompressed {recoveredMacroSource.Length} bytes of VBA source from the compound document"));
                var lower = recoveredMacroSource.ToLowerInvariant();
                foreach (var a in AutoExec)
                    if (lower.Contains(a, StringComparison.Ordinal))
                    {
                        hits.Add(new DeobHit("Vba.AutoExecHandler", $"VBA source defines the autostart handler '{a}'"));
                        break;
                    }
                foreach (var sp in ShellPrimitives)
                    if (lower.Contains(sp, StringComparison.Ordinal))
                    {
                        hits.Add(new DeobHit("Vba.ShellExecution", $"VBA source calls a shell primitive '{sp}'"));
                        break;
                    }
                foreach (var dp in DownloadPrimitives)
                    if (lower.Contains(dp, StringComparison.Ordinal))
                    {
                        hits.Add(new DeobHit("Vba.DownloadPrimitive", $"VBA source uses the download primitive '{dp}'"));
                        break;
                    }
                int concat = 0;
                for (int i = 0; i + 1 < recoveredMacroSource.Length; i++)
                    if (recoveredMacroSource[i] == '"' && recoveredMacroSource[i + 1] == ' ') concat++;
                if (lower.Contains("chr(", StringComparison.Ordinal) || lower.Contains("strreverse", StringComparison.Ordinal) || concat > 40)
                    hits.Add(new DeobHit("Vba.ObfuscatedSource", "VBA source is string-obfuscated with chr, reverse or heavy concatenation"));
            }
            return hits;
        }

        private static bool HasExcel4Macro(byte[] content)
        {
            if (content.Length < 16) return false;
            for (int i = 0; i + 4 < content.Length && i < 1 << 20; i++)
            {
                if (content[i] == 0x85 && content[i + 1] == 0x00)
                {
                    int len = content[i + 2] | (content[i + 3] << 8);
                    if (len > 6 && i + 4 + len <= content.Length && content[i + 4 + 4] == 0x01) return true;
                }
            }
            return false;
        }
    }

    public static class ResourceWalker
    {
        private static ushort U16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
        private static uint U32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

        public static List<DeobHit> Walk(byte[] data, PeImage pe)
        {
            var hits = new List<DeobHit>();
            if (pe.ResourceRva == 0 || pe.ResourceSize == 0) return hits;
            int root = PeParser.RvaToOffset(pe, pe.ResourceRva);
            if (root < 0 || root + 16 > data.Length) return hits;
            var leaves = new List<(uint Rva, uint Size)>();
            try { Descend(data, pe, root, root, 0, leaves); }
            catch (Exception) { }

            int pePayloads = 0, highEntropy = 0, scripts = 0;
            foreach (var leaf in leaves)
            {
                int off = PeParser.RvaToOffset(pe, leaf.Rva);
                if (off < 0 || leaf.Size == 0) continue;
                int count = (int)Math.Min(leaf.Size, (uint)Math.Max(0, data.Length - off));
                if (count < 32) continue;
                if (count > 0x40 && data[off] == 0x4D && data[off + 1] == 0x5A)
                {
                    uint el = U32(data, off + 0x3C);
                    long sig = (long)off + el;
                    if (el >= 0x40 && sig + 4 <= data.Length && data[sig] == 0x50 && data[sig + 1] == 0x45) pePayloads++;
                }
                double e = Util.Entropy(data, off, Math.Min(count, 1 << 20));
                if (e > 7.4 && count > 4096) highEntropy++;
                if (Util.PrintableRatio(data, Math.Min(count, 4096)) > 0.9)
                {
                    var text = Encoding.ASCII.GetString(data, off, Math.Min(count, 65536)).ToLowerInvariant();
                    if (text.Contains("powershell", StringComparison.Ordinal) || text.Contains("cmd.exe", StringComparison.Ordinal) ||
                        text.Contains("<script", StringComparison.Ordinal) || text.Contains("wscript.shell", StringComparison.Ordinal)) scripts++;
                }
            }
            if (pePayloads > 0) hits.Add(new DeobHit("PE.ResourceEmbeddedPe", $"{pePayloads} resource entr(y/ies) contain a complete PE image"));
            if (highEntropy > 0) hits.Add(new DeobHit("PE.ResourceHighEntropyBlob", $"{highEntropy} large resource blob(s) with entropy above 7.4"));
            if (scripts > 0) hits.Add(new DeobHit("PE.ResourceScriptContent", $"{scripts} resource entr(y/ies) contain script interpreter references"));
            return hits;
        }

        private static void Descend(byte[] data, PeImage pe, int root, int node, int depth, List<(uint, uint)> leaves)
        {
            if (depth > 3 || node < 0 || node + 16 > data.Length || leaves.Count > 4096) return;
            int named = U16(data, node + 12);
            int idc = U16(data, node + 14);
            int total = named + idc;
            if (total <= 0 || total > 4096) return;
            for (int i = 0; i < total; i++)
            {
                int eo = node + 16 + i * 8;
                if (eo + 8 > data.Length) return;
                uint offsetToData = U32(data, eo + 4);
                bool isDir = (offsetToData & 0x80000000u) != 0;
                int target = root + (int)(offsetToData & 0x7FFFFFFF);
                if (isDir) Descend(data, pe, root, target, depth + 1, leaves);
                else
                {
                    if (target + 16 > data.Length) continue;
                    leaves.Add((U32(data, target), U32(data, target + 4)));
                }
            }
        }
    }

    public static class Carver
    {
        public static List<DeobHit> Carve(byte[] data, int count, bool hostIsPe, bool hostIsZip)
        {
            var hits = new List<DeobHit>();
            int limit = Math.Min(count, 8 << 20);
            int embeddedPe = 0;
            long firstPeOffset = -1;
            for (int i = 1; i + 0x40 < limit; i++)
            {
                if (data[i] != 0x4D || data[i + 1] != 0x5A) continue;
                uint el = (uint)(data[i + 0x3C] | (data[i + 0x3D] << 8) | (data[i + 0x3E] << 16) | (data[i + 0x3F] << 24));
                if (el < 0x40 || el > 0x1000) continue;
                long sig = (long)i + el;
                if (sig + 24 > limit) continue;
                if (data[sig] == 0x50 && data[sig + 1] == 0x45 && data[sig + 2] == 0 && data[sig + 3] == 0)
                {
                    embeddedPe++;
                    if (firstPeOffset < 0) firstPeOffset = i;
                    if (embeddedPe > 8) break;
                }
            }
            if (embeddedPe > 0)
                hits.Add(new DeobHit("Carve.EmbeddedPeAtOffset",
                    $"{embeddedPe} complete PE image(s) carved from the file body, first at offset {firstPeOffset}"));

            if (!hostIsZip)
            {
                for (int i = 1; i + 30 < limit; i++)
                {
                    if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x03 && data[i + 3] == 0x04)
                    {
                        hits.Add(new DeobHit(hostIsPe ? "Carve.AppendedArchive" : "Carve.EmbeddedZipInNonArchive",
                            $"ZIP local file header found at offset {i} inside a non-archive host"));
                        break;
                    }
                }
            }
            return hits;
        }
    }

    public static class AdvancedXor
    {
        public static List<DeobHit> Analyze(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            int len = Math.Min(count, 1 << 18);
            if (len < 256) return hits;

            for (int keyLen = 2; keyLen <= 16; keyLen++)
            {
                var key = RecoverKey(data, len, keyLen);
                if (key == null) continue;
                bool allSame = true;
                for (int i = 1; i < key.Length; i++) if (key[i] != key[0]) { allSame = false; break; }
                if (allSame) continue;

                var decoded = new byte[Math.Min(len, 8192)];
                for (int i = 0; i < decoded.Length; i++) decoded[i] = (byte)(data[i] ^ key[i % keyLen]);

                if (decoded[0] == 0x4D && decoded[1] == 0x5A && HasPe(decoded))
                {
                    hits.Add(new DeobHit("Deob.MultiByteXorPe",
                        $"{keyLen}-byte repeating XOR key {Util.ToHex(key)} yields a structurally valid PE image"));
                    return hits;
                }
                double ratio = Util.PrintableRatio(decoded, decoded.Length);
                if (ratio > 0.92)
                {
                    var text = Encoding.ASCII.GetString(decoded).ToLowerInvariant();
                    string[] cribs = { "powershell", "http://", "https://", "cmd.exe", "function", "this program" };
                    foreach (var crib in cribs)
                    {
                        if (text.IndexOf(crib, StringComparison.Ordinal) >= 0)
                        {
                            hits.Add(new DeobHit("Deob.MultiByteXorScript",
                                $"{keyLen}-byte repeating XOR key {Util.ToHex(key)} yields printable text containing '{crib}'"));
                            return hits;
                        }
                    }
                }
            }
            return hits;
        }

        private static byte[]? RecoverKey(byte[] data, int len, int keyLen)
        {
            var key = new byte[keyLen];
            for (int k = 0; k < keyLen; k++)
            {
                var counts = new int[256];
                int samples = 0;
                for (int i = k; i < len; i += keyLen) { counts[data[i]]++; samples++; }
                if (samples < 8) return null;
                int bestIdx = 0, bestCount = -1;
                for (int b = 0; b < 256; b++) if (counts[b] > bestCount) { bestCount = counts[b]; bestIdx = b; }
                if (bestCount * 4 < samples) return null;
                key[k] = (byte)bestIdx;
            }
            return key;
        }

        private static bool HasPe(byte[] d)
        {
            if (d.Length < 0x40) return false;
            uint el = (uint)(d[0x3C] | (d[0x3D] << 8) | (d[0x3E] << 16) | (d[0x3F] << 24));
            if (el < 0x40 || el + 4 > d.Length) return false;
            return d[el] == 0x50 && d[el + 1] == 0x45;
        }
    }

    public static class CompressionCarver
    {
        public static List<DeobHit> Analyze(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            int limit = Math.Min(count, 4 << 20);
            int found = 0;
            for (int i = 0; i + 18 < limit && found < 4; i++)
            {
                if (data[i] == 0x1F && data[i + 1] == 0x8B && data[i + 2] == 0x08)
                {
                    var payload = TryGzip(data, i, limit - i);
                    if (payload != null && payload.Length > 32)
                    {
                        found++;
                        Classify(payload, hits, "gzip", i);
                    }
                }
                else if (data[i] == 0x78 && (data[i + 1] == 0x01 || data[i + 1] == 0x9C || data[i + 1] == 0xDA))
                {
                    var payload = TryDeflate(data, i + 2, limit - i - 2);
                    if (payload != null && payload.Length > 64)
                    {
                        found++;
                        Classify(payload, hits, "zlib", i);
                    }
                }
            }
            return hits;
        }

        private static void Classify(byte[] payload, List<DeobHit> hits, string kind, int offset)
        {
            if (Util.IsPe(payload))
            {
                hits.Add(new DeobHit("Deob.EmbeddedGzipPe", $"{kind} stream at offset {offset} decompresses to an MZ/PE image"));
                return;
            }
            var matches = PatternEngine.ScanBuffer(payload);
            string key = kind == "gzip" ? "Deob.EmbeddedGzipPayload" : "Deob.EmbeddedZlibPayload";
            if (matches.Count > 0)
                hits.Add(new DeobHit(key, $"{kind} stream at offset {offset} decompresses to content matching {matches[0].Signature.Name} (w={matches[0].Signature.Weight})", matches[0].Signature.Weight));
            else if (payload.Length > 4096)
                hits.Add(new DeobHit(key, $"{kind} stream at offset {offset} expands to {payload.Length} bytes"));
        }

        private static byte[]? TryGzip(byte[] data, int offset, int length)
        {
            try
            {
                using var input = new MemoryStream(data, offset, Math.Min(length, 4 << 20), false);
                using var gz = new GZipStream(input, CompressionMode.Decompress);
                return ReadCapped(gz);
            }
            catch (Exception) { return null; }
        }

        private static byte[]? TryDeflate(byte[] data, int offset, int length)
        {
            try
            {
                if (offset < 0 || offset >= data.Length) return null;
                using var input = new MemoryStream(data, offset, Math.Min(length, 4 << 20), false);
                using var df = new DeflateStream(input, CompressionMode.Decompress);
                return ReadCapped(df);
            }
            catch (Exception) { return null; }
        }

        private static byte[] ReadCapped(Stream s)
        {
            using var ms = new MemoryStream();
            var buf = new byte[65536];
            long total = 0;
            int r;
            while ((r = s.Read(buf, 0, buf.Length)) > 0)
            {
                total += r;
                if (total > 16 << 20) break;
                ms.Write(buf, 0, r);
            }
            return ms.ToArray();
        }
    }

    public static class MailAnalyzer
    {
        public static bool LooksLikeMail(byte[] head, int count)
        {
            int probe = Math.Min(count, 8192);
            if (probe < 64) return false;
            var text = Encoding.ASCII.GetString(head, 0, probe);
            bool hasMime = text.IndexOf("MIME-Version:", StringComparison.OrdinalIgnoreCase) >= 0;
            bool hasFrom = text.IndexOf("\nFrom:", StringComparison.OrdinalIgnoreCase) >= 0 || text.StartsWith("From:", StringComparison.OrdinalIgnoreCase);
            bool hasCt = text.IndexOf("Content-Type:", StringComparison.OrdinalIgnoreCase) >= 0;
            return hasCt && (hasMime || hasFrom);
        }

        public static List<DeobHit> Analyze(string text)
        {
            var hits = new List<DeobHit>();
            var lines = text.Split('\n');
            var buffer = new StringBuilder();
            string currentName = "";
            bool inBase64 = false;
            int attachments = 0;

            foreach (var rawLine in lines)
            {
                var line = rawLine.TrimEnd('\r');
                var lower = line.ToLowerInvariant();

                if (lower.StartsWith("content-disposition:", StringComparison.Ordinal) || lower.StartsWith("content-type:", StringComparison.Ordinal))
                {
                    int fn = lower.IndexOf("filename=", StringComparison.Ordinal);
                    if (fn < 0) fn = lower.IndexOf("name=", StringComparison.Ordinal);
                    if (fn >= 0)
                    {
                        var value = line.Substring(fn);
                        int eq = value.IndexOf('=');
                        if (eq >= 0)
                        {
                            currentName = value.Substring(eq + 1).Trim().Trim('"', ';', ' ');
                        }
                    }
                }
                if (lower.StartsWith("content-transfer-encoding:", StringComparison.Ordinal) && lower.Contains("base64", StringComparison.Ordinal))
                {
                    inBase64 = true;
                    buffer.Clear();
                    continue;
                }
                if (inBase64)
                {
                    if (line.Length == 0 && buffer.Length == 0) continue;
                    if (line.StartsWith("--", StringComparison.Ordinal) || (line.Length == 0 && buffer.Length > 0))
                    {
                        Flush(buffer, currentName, hits, ref attachments);
                        inBase64 = false;
                        currentName = "";
                        continue;
                    }
                    bool valid = line.Length > 0;
                    foreach (char c in line)
                    {
                        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) { valid = false; break; }
                    }
                    if (valid) buffer.Append(line);
                    else { Flush(buffer, currentName, hits, ref attachments); inBase64 = false; currentName = ""; }
                }
            }
            Flush(buffer, currentName, hits, ref attachments);
            return hits;
        }

        private static void Flush(StringBuilder buffer, string name, List<DeobHit> hits, ref int attachments)
        {
            if (buffer.Length < 32) { buffer.Clear(); return; }
            byte[] decoded;
            try { decoded = Convert.FromBase64String(buffer.ToString()); }
            catch (FormatException) { buffer.Clear(); return; }
            buffer.Clear();
            if (decoded.Length < 16) return;
            attachments++;
            string label = string.IsNullOrEmpty(name) ? "unnamed part" : name;
            hits.Add(new DeobHit("Mail.Base64Attachment", $"base64 MIME part '{label}' decoded to {decoded.Length} bytes"));

            if (Util.IsPe(decoded))
                hits.Add(new DeobHit("Mail.ExecutableAttachment", $"attachment '{label}' is a Windows executable"));
            if (!string.IsNullOrEmpty(name))
            {
                if (FileTyper.IsDoubleExtension(name))
                    hits.Add(new DeobHit("Mail.DoubleExtensionAttachment", $"attachment '{name}' uses a decoy double extension"));
                else if (FileTyper.IsExecutableExtension(name))
                    hits.Add(new DeobHit("Mail.ScriptAttachment", $"attachment '{name}' has an executable or script extension"));
            }
            var matches = PatternEngine.ScanBuffer(decoded);
            if (matches.Count > 0)
                hits.Add(new DeobHit("Mail.SuspiciousAttachmentContent",
                    $"attachment '{label}' content matched {matches[0].Signature.Name} (w={matches[0].Signature.Weight})", matches[0].Signature.Weight));
        }
    }

    public sealed class ScanCache
    {
        private sealed class Entry
        {
            public long Size;
            public long Ticks;
            public string Sha256 = "";
            public string Verdict = "";
            public int Score;
        }

        private readonly Dictionary<string, Entry> _entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        private readonly string _path;
        private readonly object _lock = new object();
        private readonly bool _enabled;
        public int Hits;

        public ScanCache(string baseDir, bool enabled)
        {
            _enabled = enabled;
            _path = Path.Combine(baseDir, "armorav-cache.tsv");
            if (!_enabled) return;
            try
            {
                if (!File.Exists(_path)) return;
                foreach (var line in File.ReadAllLines(_path))
                {
                    var p = line.Split('\t');
                    if (p.Length < 6) continue;
                    if (!long.TryParse(p[1], out var size) || !long.TryParse(p[2], out var ticks) || !int.TryParse(p[5], out var score)) continue;
                    _entries[p[0]] = new Entry { Size = size, Ticks = ticks, Sha256 = p[3], Verdict = p[4], Score = score };
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        public bool TryGet(string path, long size, long ticks, out string sha256, out string verdict, out int score)
        {
            sha256 = ""; verdict = ""; score = 0;
            if (!_enabled) return false;
            lock (_lock)
            {
                if (!_entries.TryGetValue(path, out var e)) return false;
                if (e.Size != size || e.Ticks != ticks) return false;
                sha256 = e.Sha256; verdict = e.Verdict; score = e.Score;
                Hits++;
                return true;
            }
        }

        public void Put(string path, long size, long ticks, string sha256, string verdict, int score)
        {
            if (!_enabled) return;
            lock (_lock)
            {
                _entries[path] = new Entry { Size = size, Ticks = ticks, Sha256 = sha256, Verdict = verdict, Score = score };
            }
        }

        public void Save()
        {
            if (!_enabled) return;
            try
            {
                var sb = new StringBuilder();
                lock (_lock)
                {
                    foreach (var kv in _entries)
                        sb.Append(kv.Key).Append('\t').Append(kv.Value.Size).Append('\t').Append(kv.Value.Ticks).Append('\t')
                          .Append(kv.Value.Sha256).Append('\t').Append(kv.Value.Verdict).Append('\t').Append(kv.Value.Score).Append('\n');
                }
                File.WriteAllText(_path, sb.ToString());
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    public static class Util
    {
        public static string ToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (var b in data) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        public static double Entropy(byte[] data, int offset, int count)
        {
            if (count <= 0) return 0.0;
            var counts = new int[256];
            int end = Math.Min(offset + count, data.Length);
            int n = 0;
            for (int i = offset; i < end; i++) { counts[data[i]]++; n++; }
            if (n == 0) return 0.0;
            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / n;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        public static double PrintableRatio(byte[] data, int count)
        {
            if (count <= 0) return 0.0;
            int printable = 0;
            int end = Math.Min(count, data.Length);
            for (int i = 0; i < end; i++)
            {
                byte b = data[i];
                if (b == 9 || b == 10 || b == 13 || (b >= 32 && b <= 126)) printable++;
            }
            return (double)printable / end;
        }

        public static bool IsPe(byte[] data)
        {
            return data.Length > 0x40 && data[0] == 0x4D && data[1] == 0x5A;
        }

        public static string JsonEscape(string s)
        {
            var sb = new StringBuilder(s.Length + 8);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20 || c > 0x7E) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        public static string HtmlEscape(string s)
        {
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        public static string CsvEscape(string s)
        {
            if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        public static string Iso8601Utc(DateTime dt)
        {
            return dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
        }

        public static string HumanSize(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            int u = 0;
            while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
            return v.ToString(u == 0 ? "F0" : "F2", CultureInfo.InvariantCulture) + " " + units[u];
        }
    }

    public sealed class HashTriple
    {
        public string Md5 = "";
        public string Sha1 = "";
        public string Sha256 = "";
        public long Length;
    }

    public static class Hasher
    {
        public static HashTriple FromFile(string path)
        {
            using var md5 = MD5.Create();
            using var sha1 = SHA1.Create();
            using var sha256 = SHA256.Create();
            var result = new HashTriple();
            var buffer = new byte[1 << 20];
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            {
                int read;
                while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    md5.TransformBlock(buffer, 0, read, null, 0);
                    sha1.TransformBlock(buffer, 0, read, null, 0);
                    sha256.TransformBlock(buffer, 0, read, null, 0);
                    result.Length += read;
                }
                md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                sha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            }
            result.Md5 = Util.ToHex(md5.Hash!);
            result.Sha1 = Util.ToHex(sha1.Hash!);
            result.Sha256 = Util.ToHex(sha256.Hash!);
            return result;
        }

        public static HashTriple FromBytes(byte[] data)
        {
            return new HashTriple
            {
                Md5 = Util.ToHex(MD5.HashData(data)),
                Sha1 = Util.ToHex(SHA1.HashData(data)),
                Sha256 = Util.ToHex(SHA256.HashData(data)),
                Length = data.LongLength
            };
        }
    }

    public sealed class AhoCorasick
    {
        private sealed class Node
        {
            public readonly Dictionary<byte, Node> Next = new Dictionary<byte, Node>();
            public Node? Fail;
            public List<int>? Outputs;
        }

        private readonly Node _root = new Node();
        private readonly int _maxLength;

        public int MaxPatternLength => _maxLength;

        public AhoCorasick(IReadOnlyList<byte[]> patterns)
        {
            int max = 1;
            for (int i = 0; i < patterns.Count; i++)
            {
                var p = patterns[i];
                if (p.Length == 0) continue;
                if (p.Length > max) max = p.Length;
                var node = _root;
                foreach (var b in p)
                {
                    if (!node.Next.TryGetValue(b, out var next))
                    {
                        next = new Node();
                        node.Next[b] = next;
                    }
                    node = next;
                }
                (node.Outputs ??= new List<int>()).Add(i);
            }
            _maxLength = max;
            BuildFailureLinks();
        }

        private void BuildFailureLinks()
        {
            var queue = new Queue<Node>();
            foreach (var child in _root.Next.Values)
            {
                child.Fail = _root;
                queue.Enqueue(child);
            }
            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                foreach (var kv in current.Next)
                {
                    var child = kv.Value;
                    var f = current.Fail;
                    while (f != null && !f.Next.ContainsKey(kv.Key)) f = f.Fail;
                    child.Fail = f == null ? _root : f.Next[kv.Key];
                    if (child.Fail.Outputs != null)
                    {
                        child.Outputs ??= new List<int>();
                        foreach (var o in child.Fail.Outputs)
                            if (!child.Outputs.Contains(o)) child.Outputs.Add(o);
                    }
                    queue.Enqueue(child);
                }
            }
        }

        public void Search(byte[] buffer, int count, long baseOffset, Action<int, long> onMatch)
        {
            var node = _root;
            for (int i = 0; i < count; i++)
            {
                byte b = buffer[i];
                if (b >= 65 && b <= 90) b = (byte)(b + 32);
                while (node != _root && !node.Next.ContainsKey(b)) node = node.Fail ?? _root;
                if (node.Next.TryGetValue(b, out var next)) node = next;
                if (node.Outputs != null)
                    foreach (var idx in node.Outputs)
                        onMatch(idx, baseOffset + i);
            }
        }
    }

    public sealed class PatternHit
    {
        public PatternSignature Signature;
        public long Offset;
        public string Encoding;
        public PatternHit(PatternSignature s, long o, string enc) { Signature = s; Offset = o; Encoding = enc; }
    }

    public static class PatternEngine
    {
        private static readonly AhoCorasick Automaton = BuildAutomaton();
        private static readonly int[] PatternLengths = SignatureTable.Patterns
            .Select(p => Encoding.ASCII.GetByteCount(p.Literal.ToLowerInvariant())).ToArray();

        private static AhoCorasick BuildAutomaton()
        {
            var needles = SignatureTable.Patterns
                .Select(p => Encoding.ASCII.GetBytes(p.Literal.ToLowerInvariant()))
                .ToList();
            return new AhoCorasick(needles);
        }

        public static int Overlap => Automaton.MaxPatternLength;

        public sealed class Session
        {
            private readonly Dictionary<int, (long Offset, string Enc)> _hits = new Dictionary<int, (long, string)>();

            public void Feed(byte[] buffer, int count, long baseOffset)
            {
                Automaton.Search(buffer, count, baseOffset, (idx, endOffset) =>
                {
                    if (!_hits.ContainsKey(idx))
                        _hits[idx] = (endOffset - PatternLengths[idx] + 1, "ascii");
                });

                var wide = Dewiden(buffer, count);
                if (wide.Length > 0)
                {
                    Automaton.Search(wide, wide.Length, baseOffset, (idx, endOffset) =>
                    {
                        if (!_hits.ContainsKey(idx))
                            _hits[idx] = ((endOffset - PatternLengths[idx] + 1) * 2, "utf-16le");
                    });
                }
            }

            public List<PatternHit> Results()
            {
                var list = new List<PatternHit>();
                foreach (var kv in _hits.OrderBy(k => k.Key))
                    list.Add(new PatternHit(SignatureTable.Patterns[kv.Key], kv.Value.Offset, kv.Value.Enc));
                return list;
            }
        }

        private static byte[] Dewiden(byte[] buffer, int count)
        {
            if (count < 16) return Array.Empty<byte>();
            int probe = Math.Min(count, 8192);
            int zeros = 0, checks = 0;
            for (int i = 1; i < probe; i += 2) { if (buffer[i] == 0) zeros++; checks++; }
            if (checks == 0 || zeros * 4 < checks) return Array.Empty<byte>();
            var outBuf = new byte[count / 2];
            for (int i = 0, j = 0; i + 1 < count; i += 2, j++) outBuf[j] = buffer[i];
            return outBuf;
        }

        public static List<PatternHit> ScanBuffer(byte[] data)
        {
            var s = new Session();
            s.Feed(data, data.Length, 0);
            return s.Results();
        }

        public static List<PatternHit> ScanBuffer(byte[] data, int count)
        {
            var s = new Session();
            s.Feed(data, count, 0);
            return s.Results();
        }

        public static int IndexOf(byte[] haystack, int hayLen, byte[] needle)
        {
            int n = needle.Length;
            if (n == 0 || hayLen < n) return -1;
            byte first = needle[0];
            int limit = hayLen - n;
            for (int i = 0; i <= limit; i++)
            {
                if (haystack[i] != first) continue;
                int k = 1;
                while (k < n && haystack[i + k] == needle[k]) k++;
                if (k == n) return i;
            }
            return -1;
        }
    }

    public sealed class TypeInfo
    {
        public string Type = "unknown";
        public string Category = "data";
        public bool IsPe;
        public bool IsZipContainer;
        public bool IsOle;
        public bool IsPdf;
        public bool IsRtf;
        public bool IsScriptText;
        public bool IsLnk;
        public bool IsIso;
        public bool IsOneNote;
    }

    public static class FileTyper
    {
        private static bool Starts(byte[] d, params byte[] magic)
        {
            if (d.Length < magic.Length) return false;
            for (int i = 0; i < magic.Length; i++) if (d[i] != magic[i]) return false;
            return true;
        }

        public static TypeInfo Identify(byte[] head, string path)
        {
            var t = new TypeInfo();
            if (head.Length == 0) { t.Type = "empty"; return t; }

            if (Starts(head, 0x4D, 0x5A)) { t.Type = "pe"; t.Category = "executable"; t.IsPe = true; return t; }
            if (Starts(head, 0x7F, 0x45, 0x4C, 0x46)) { t.Type = "elf"; t.Category = "executable"; return t; }
            if (Starts(head, 0x50, 0x4B, 0x03, 0x04) || Starts(head, 0x50, 0x4B, 0x05, 0x06) || Starts(head, 0x50, 0x4B, 0x07, 0x08))
            { t.Type = "zip"; t.Category = "archive"; t.IsZipContainer = true; return t; }
            if (Starts(head, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1))
            { t.Type = "ole-compound"; t.Category = "document"; t.IsOle = true; return t; }
            if (Starts(head, 0x25, 0x50, 0x44, 0x46)) { t.Type = "pdf"; t.Category = "document"; t.IsPdf = true; return t; }
            if (Starts(head, 0x7B, 0x5C, 0x72, 0x74, 0x66)) { t.Type = "rtf"; t.Category = "document"; t.IsRtf = true; return t; }
            if (Starts(head, 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02)) { t.Type = "lnk"; t.Category = "shortcut"; t.IsLnk = true; return t; }
            if (Starts(head, 0x52, 0x61, 0x72, 0x21)) { t.Type = "rar"; t.Category = "archive"; return t; }
            if (Starts(head, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)) { t.Type = "7z"; t.Category = "archive"; return t; }
            if (Starts(head, 0x1F, 0x8B)) { t.Type = "gzip"; t.Category = "archive"; return t; }
            if (Starts(head, 0x42, 0x5A, 0x68)) { t.Type = "bzip2"; t.Category = "archive"; return t; }
            if (Starts(head, 0x89, 0x50, 0x4E, 0x47)) { t.Type = "png"; t.Category = "image"; return t; }
            if (Starts(head, 0xFF, 0xD8, 0xFF)) { t.Type = "jpeg"; t.Category = "image"; return t; }
            if (Starts(head, 0x47, 0x49, 0x46, 0x38)) { t.Type = "gif"; t.Category = "image"; return t; }

            double printable = Util.PrintableRatio(head, Math.Min(head.Length, 8192));
            if (printable > 0.92)
            {
                t.Category = "text";
                t.IsScriptText = true;
                var lower = Encoding.ASCII.GetString(head, 0, Math.Min(head.Length, 4096)).ToLowerInvariant();
                if (lower.Contains("<?xml", StringComparison.Ordinal)) t.Type = "xml";
                else if (lower.Contains("<html", StringComparison.Ordinal) || lower.Contains("<!doctype html", StringComparison.Ordinal)) t.Type = "html";
                else if (lower.Contains("#!/", StringComparison.Ordinal)) t.Type = "shell-script";
                else if (lower.Contains("function ", StringComparison.Ordinal) || lower.Contains("var ", StringComparison.Ordinal)) t.Type = "script";
                else t.Type = "text";
                return t;
            }
            t.Type = "binary";
            return t;
        }

        private static readonly Dictionary<string, string[]> ExpectedMagic = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { ".exe", new[] { "pe" } },
            { ".dll", new[] { "pe" } },
            { ".sys", new[] { "pe" } },
            { ".scr", new[] { "pe" } },
            { ".ocx", new[] { "pe" } },
            { ".zip", new[] { "zip" } },
            { ".docx", new[] { "zip" } },
            { ".xlsx", new[] { "zip" } },
            { ".pptx", new[] { "zip" } },
            { ".docm", new[] { "zip" } },
            { ".xlsm", new[] { "zip" } },
            { ".jar", new[] { "zip" } },
            { ".doc", new[] { "ole-compound", "rtf" } },
            { ".xls", new[] { "ole-compound" } },
            { ".pdf", new[] { "pdf" } },
            { ".rtf", new[] { "rtf" } },
            { ".png", new[] { "png" } },
            { ".jpg", new[] { "jpeg" } },
            { ".jpeg", new[] { "jpeg" } },
            { ".gif", new[] { "gif" } },
            { ".lnk", new[] { "lnk" } },
        };

        public static bool IsMismatch(string path, TypeInfo info, out string declared)
        {
            declared = Path.GetExtension(path).ToLowerInvariant();
            if (string.IsNullOrEmpty(declared)) return false;
            if (!ExpectedMagic.TryGetValue(declared, out var expected)) return false;
            return !expected.Contains(info.Type, StringComparer.OrdinalIgnoreCase);
        }

        private static readonly string[] ExecExt =
        { ".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi", ".com", ".pif", ".jar" };

        private static readonly string[] DecoyExt =
        { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".csv" };

        public static bool IsDoubleExtension(string fileName)
        {
            var lower = fileName.ToLowerInvariant();
            var ext = Path.GetExtension(lower);
            if (!ExecExt.Contains(ext)) return false;
            var stem = Path.GetFileNameWithoutExtension(lower);
            var inner = Path.GetExtension(stem);
            if (string.IsNullOrEmpty(inner)) return false;
            return DecoyExt.Contains(inner);
        }

        public static bool HasRtlOverride(string fileName)
        {
            foreach (char c in fileName)
                if (c == '\u202E' || c == '\u202B' || c == '\u200F') return true;
            return false;
        }

        public static bool IsExecutableExtension(string name)
        {
            return ExecExt.Contains(Path.GetExtension(name).ToLowerInvariant());
        }
    }

    public sealed class PeSection
    {
        public string Name = "";
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint RawPointer;
        public uint RawSize;
        public uint Characteristics;
        public double Entropy;
        public bool IsExecutable => (Characteristics & 0x20000000u) != 0;
        public bool IsWritable => (Characteristics & 0x80000000u) != 0;
        public bool IsReadable => (Characteristics & 0x40000000u) != 0;
    }

    public sealed class PeImage
    {
        public bool IsPe;
        public bool Is64Bit;
        public bool IsDll;
        public bool IsDotNet;
        public string? ParseError;
        public uint EntryPointRva;
        public uint TimeDateStamp;
        public uint CheckSum;
        public uint SizeOfImage;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public bool HasAuthenticode;
        public bool HasTlsCallbacks;
        public long OverlayOffset;
        public long OverlaySize;
        public double OverlayEntropy;
        public string ImpHash = "";
        public uint ComDescriptorRva;
        public uint ResourceRva;
        public uint ResourceSize;
        public string RichHash = "";
        public bool HasRichHeader;
        public bool RichChecksumPlausible;
        public int RichEntryCount;
        public List<PeSection> Sections = new List<PeSection>();
        public List<string> Imports = new List<string>();
        public List<string> ImportedModules = new List<string>();
        public List<string> PackerHints = new List<string>();
        public bool ResourceContainsPe;
    }

    public static class PeParser
    {
        private static ushort U16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
        private static uint U32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
        private static ulong U64(byte[] b, int o) => U32(b, o) | ((ulong)U32(b, o + 4) << 32);

        private static readonly string[] StandardSections =
        { ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc", ".reloc", ".tls", ".bss", ".didat", ".sdata", ".gfids", ".00cfg" };

        public static PeImage Parse(byte[] data)
        {
            var pe = new PeImage();
            if (data.Length < 0x40 || data[0] != 0x4D || data[1] != 0x5A) return pe;
            uint elfanew = U32(data, 0x3C);
            if (elfanew < 0x40 || elfanew + 24 > (uint)data.Length) { pe.ParseError = "invalid e_lfanew"; return pe; }
            if (!(data[elfanew] == 0x50 && data[elfanew + 1] == 0x45 && data[elfanew + 2] == 0 && data[elfanew + 3] == 0))
            { pe.ParseError = "missing PE signature"; return pe; }

            pe.IsPe = true;
            int coff = (int)elfanew + 4;
            ushort numberOfSections = U16(data, coff + 2);
            pe.TimeDateStamp = U32(data, coff + 4);
            ushort sizeOfOptionalHeader = U16(data, coff + 16);
            ushort characteristics = U16(data, coff + 18);
            pe.IsDll = (characteristics & 0x2000) != 0;

            int optStart = coff + 20;
            if (sizeOfOptionalHeader < 2 || optStart + sizeOfOptionalHeader > data.Length)
            { pe.ParseError = "truncated optional header"; return pe; }

            ushort magic = U16(data, optStart);
            pe.Is64Bit = magic == 0x20B;
            if (optStart + 20 <= data.Length) pe.EntryPointRva = U32(data, optStart + 16);
            int checksumOff = optStart + 64;
            if (checksumOff + 4 <= data.Length) pe.CheckSum = U32(data, checksumOff);
            int subsystemOff = optStart + 68;
            if (subsystemOff + 4 <= data.Length)
            {
                pe.Subsystem = U16(data, subsystemOff);
                pe.DllCharacteristics = U16(data, subsystemOff + 2);
            }
            int sizeOfImageOff = optStart + 56;
            if (sizeOfImageOff + 4 <= data.Length) pe.SizeOfImage = U32(data, sizeOfImageOff);

            int nrvaOffset = optStart + (pe.Is64Bit ? 108 : 92);
            uint numberOfRvaAndSizes = nrvaOffset + 4 <= data.Length ? U32(data, nrvaOffset) : 0;
            int dirOffset = optStart + (pe.Is64Bit ? 112 : 96);

            int sectionTable = optStart + sizeOfOptionalHeader;
            long maxRawEnd = 0;
            for (int i = 0; i < numberOfSections && i < 96; i++)
            {
                int so = sectionTable + i * 40;
                if (so + 40 > data.Length) { pe.ParseError = "truncated section table"; break; }
                var sec = new PeSection();
                int nameLen = 0;
                while (nameLen < 8 && data[so + nameLen] != 0) nameLen++;
                sec.Name = Encoding.ASCII.GetString(data, so, nameLen);
                sec.VirtualSize = U32(data, so + 8);
                sec.VirtualAddress = U32(data, so + 12);
                sec.RawSize = U32(data, so + 16);
                sec.RawPointer = U32(data, so + 20);
                sec.Characteristics = U32(data, so + 36);
                if (sec.RawPointer < (uint)data.Length && sec.RawSize > 0)
                {
                    int count = (int)Math.Min(sec.RawSize, (uint)(data.Length - sec.RawPointer));
                    sec.Entropy = Util.Entropy(data, (int)sec.RawPointer, count);
                }
                long rawEnd = (long)sec.RawPointer + sec.RawSize;
                if (rawEnd > maxRawEnd) maxRawEnd = rawEnd;
                pe.Sections.Add(sec);
            }

            if (maxRawEnd > 0 && data.LongLength > maxRawEnd)
            {
                pe.OverlayOffset = maxRawEnd;
                pe.OverlaySize = data.LongLength - maxRawEnd;
                pe.OverlayEntropy = Util.Entropy(data, (int)Math.Min(maxRawEnd, int.MaxValue), (int)Math.Min(pe.OverlaySize, 1 << 20));
            }

            if (numberOfRvaAndSizes > 1 && dirOffset + 16 <= data.Length)
            {
                uint importRva = U32(data, dirOffset + 8);
                if (importRva != 0) ParseImports(data, pe, importRva);
            }
            if (numberOfRvaAndSizes > 2 && dirOffset + 24 <= data.Length)
            {
                uint rsrcRva = U32(data, dirOffset + 16);
                uint rsrcSize = U32(data, dirOffset + 16 + 4);
                pe.ResourceRva = rsrcRva;
                pe.ResourceSize = rsrcSize;
                if (rsrcRva != 0 && rsrcSize != 0) ScanResourceForPe(data, pe, rsrcRva, rsrcSize);
            }
            if (numberOfRvaAndSizes > 4 && dirOffset + 40 <= data.Length)
            {
                uint certRva = U32(data, dirOffset + 32);
                uint certSize = U32(data, dirOffset + 36);
                pe.HasAuthenticode = certRva != 0 && certSize != 0;
            }
            if (numberOfRvaAndSizes > 9 && dirOffset + 80 <= data.Length)
            {
                uint tlsRva = U32(data, dirOffset + 72);
                uint tlsSize = U32(data, dirOffset + 76);
                if (tlsRva != 0 && tlsSize != 0)
                {
                    int tlsOff = RvaToOffset(pe, tlsRva);
                    if (tlsOff > 0)
                    {
                        int cbOff = pe.Is64Bit ? tlsOff + 24 : tlsOff + 12;
                        int need = pe.Is64Bit ? 8 : 4;
                        if (cbOff + need <= data.Length)
                        {
                            ulong cbVa = pe.Is64Bit ? U64(data, cbOff) : U32(data, cbOff);
                            pe.HasTlsCallbacks = cbVa != 0;
                        }
                    }
                }
            }
            if (numberOfRvaAndSizes > 14 && dirOffset + 120 <= data.Length)
            {
                uint comRva = U32(data, dirOffset + 112);
                pe.IsDotNet = comRva != 0;
                pe.ComDescriptorRva = comRva;
            }

            pe.ImpHash = ComputeImpHash(pe);
            RichHeaderParser.Populate(data, pe);
            DetectPackers(data, pe, StandardSections);
            return pe;
        }

        public static int RvaToOffset(PeImage pe, uint rva)
        {
            foreach (var s in pe.Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.RawSize);
                if (size == 0) continue;
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    long off = s.RawPointer + (rva - s.VirtualAddress);
                    return off >= 0 && off < int.MaxValue ? (int)off : -1;
                }
            }
            return -1;
        }

        private static void ParseImports(byte[] data, PeImage pe, uint importRva)
        {
            int desc = RvaToOffset(pe, importRva);
            if (desc < 0) return;
            for (int i = 0; i < 512; i++)
            {
                int o = desc + i * 20;
                if (o + 20 > data.Length) break;
                uint origThunk = U32(data, o);
                uint nameRva = U32(data, o + 12);
                uint firstThunk = U32(data, o + 16);
                if (origThunk == 0 && nameRva == 0 && firstThunk == 0) break;

                string module = "";
                int modOff = RvaToOffset(pe, nameRva);
                if (modOff > 0 && modOff < data.Length)
                {
                    int e = modOff;
                    while (e < data.Length && data[e] != 0 && e - modOff < 64) e++;
                    module = Encoding.ASCII.GetString(data, modOff, e - modOff);
                    if (module.Length > 0 && !pe.ImportedModules.Contains(module, StringComparer.OrdinalIgnoreCase))
                        pe.ImportedModules.Add(module);
                }

                uint thunkRva = origThunk != 0 ? origThunk : firstThunk;
                if (thunkRva == 0) continue;
                int thunkOff = RvaToOffset(pe, thunkRva);
                if (thunkOff < 0) continue;
                int entrySize = pe.Is64Bit ? 8 : 4;
                for (int k = 0; k < 8192; k++)
                {
                    int to = thunkOff + k * entrySize;
                    if (to + entrySize > data.Length) break;
                    ulong value = pe.Is64Bit ? U64(data, to) : U32(data, to);
                    if (value == 0) break;
                    bool byOrdinal = pe.Is64Bit ? (value & 0x8000000000000000UL) != 0 : (value & 0x80000000UL) != 0;
                    if (byOrdinal)
                    {
                        pe.Imports.Add(module.ToLowerInvariant() + ".#" + (value & 0xFFFF));
                        continue;
                    }
                    int hintOff = RvaToOffset(pe, (uint)(value & 0x7FFFFFFF));
                    if (hintOff < 0 || hintOff + 2 >= data.Length) continue;
                    int strStart = hintOff + 2;
                    int end = strStart;
                    while (end < data.Length && data[end] != 0 && end - strStart < 200) end++;
                    if (end > strStart) pe.Imports.Add(Encoding.ASCII.GetString(data, strStart, end - strStart));
                }
            }
        }

        private static string ComputeImpHash(PeImage pe)
        {
            if (pe.Imports.Count == 0) return "";
            var parts = new List<string>();
            foreach (var imp in pe.Imports)
            {
                if (imp.Contains(".#", StringComparison.Ordinal)) { parts.Add(imp.ToLowerInvariant()); continue; }
                parts.Add(imp.ToLowerInvariant());
            }
            var joined = string.Join(",", parts);
            return Util.ToHex(MD5.HashData(Encoding.ASCII.GetBytes(joined)));
        }

        private static void ScanResourceForPe(byte[] data, PeImage pe, uint rsrcRva, uint rsrcSize)
        {
            int off = RvaToOffset(pe, rsrcRva);
            if (off < 0) return;
            int len = (int)Math.Min(rsrcSize, (uint)Math.Max(0, data.Length - off));
            if (len <= 0x40) return;
            for (int i = off; i + 0x40 < off + len && i + 0x40 < data.Length; i++)
            {
                if (data[i] != 0x4D || data[i + 1] != 0x5A) continue;
                uint el = U32(data, i + 0x3C);
                long p = (long)i + el;
                if (el < 0x40 || p + 4 > data.Length) continue;
                if (data[p] == 0x50 && data[p + 1] == 0x45 && data[p + 2] == 0 && data[p + 3] == 0)
                {
                    pe.ResourceContainsPe = true;
                    return;
                }
            }
        }

        private static void DetectPackers(byte[] data, PeImage pe, string[] standard)
        {
            foreach (var s in pe.Sections)
            {
                var n = s.Name.ToLowerInvariant();
                if (n.StartsWith("upx", StringComparison.Ordinal)) Hint(pe, "UPX");
                if (n.Contains("themida", StringComparison.Ordinal) || n == ".boom" || n == ".taz") Hint(pe, "Themida");
                if (n.StartsWith(".vmp", StringComparison.Ordinal)) Hint(pe, "VMProtect");
                if (n.StartsWith(".aspack", StringComparison.Ordinal) || n.StartsWith(".adata", StringComparison.Ordinal)) Hint(pe, "ASPack");
                if (n == ".mpress1" || n == ".mpress2") Hint(pe, "MPRESS");
                if (n == "pec1" || n == "pec2" || n.StartsWith("pecompact", StringComparison.Ordinal)) Hint(pe, "PECompact");
                if (n == ".enigma1" || n == ".enigma2") Hint(pe, "Enigma");
            }
            int probe = (int)Math.Min(data.LongLength, 2 << 20);
            var window = new byte[probe];
            Buffer.BlockCopy(data, 0, window, 0, probe);
            if (PatternEngine.IndexOf(window, probe, Encoding.ASCII.GetBytes("UPX!")) >= 0) Hint(pe, "UPX");
            if (PatternEngine.IndexOf(window, probe, Encoding.ASCII.GetBytes("VMProtect")) >= 0) Hint(pe, "VMProtect");
            if (PatternEngine.IndexOf(window, probe, Encoding.ASCII.GetBytes("Themida")) >= 0) Hint(pe, "Themida");
            if (PatternEngine.IndexOf(window, probe, Encoding.ASCII.GetBytes("MPRESS")) >= 0) Hint(pe, "MPRESS");
            if (PatternEngine.IndexOf(window, probe, Encoding.ASCII.GetBytes("PECompact2")) >= 0) Hint(pe, "PECompact");
        }

        private static void Hint(PeImage pe, string hint)
        {
            if (!pe.PackerHints.Contains(hint)) pe.PackerHints.Add(hint);
        }

        public static bool IsStandardSectionName(string name)
        {
            return StandardSections.Contains(name.ToLowerInvariant());
        }

        public static List<string> ExtractStrings(byte[] data, int offset, int count, int minLen, int maxCount)
        {
            var result = new List<string>();
            var sb = new StringBuilder();
            int end = Math.Min(offset + count, data.Length);
            for (int i = offset; i < end && result.Count < maxCount; i++)
            {
                byte b = data[i];
                if (b >= 32 && b <= 126) sb.Append((char)b);
                else
                {
                    if (sb.Length >= minLen) result.Add(sb.ToString());
                    sb.Clear();
                }
            }
            if (sb.Length >= minLen && result.Count < maxCount) result.Add(sb.ToString());
            return result;
        }
    }

    public static class ShellcodeHeuristics
    {
        private static readonly byte[] PebWalk64 = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };
        private static readonly byte[] PebWalk32 = { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 };
        private static readonly byte[] PebWalkMov = { 0x64, 0x8B, 0x35, 0x30, 0x00, 0x00, 0x00 };
        private static readonly byte[] MsfCallPop = { 0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00 };
        private static readonly byte[] MsfCallPop64 = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8 };

        public static List<(string Key, string Detail)> Analyze(byte[] data, int count)
        {
            var hits = new List<(string, string)>();
            if (count < 32) return hits;

            if (PatternEngine.IndexOf(data, count, PebWalk64) >= 0)
                hits.Add(("Shell.PebWalkStub", "x64 PEB access stub (gs:[0x60]) present"));
            else if (PatternEngine.IndexOf(data, count, PebWalk32) >= 0 || PatternEngine.IndexOf(data, count, PebWalkMov) >= 0)
                hits.Add(("Shell.PebWalkStub", "x86 PEB access stub (fs:[0x30]) present"));

            if (PatternEngine.IndexOf(data, count, MsfCallPop) >= 0 || PatternEngine.IndexOf(data, count, MsfCallPop64) >= 0)
                hits.Add(("Shell.MetasploitPattern", "Metasploit-style prologue (cld; call/pop) present"));

            int run = 0, best = 0;
            for (int i = 0; i < count; i++)
            {
                if (data[i] == 0x90) { run++; if (run > best) best = run; }
                else run = 0;
            }
            if (best >= 32) hits.Add(("Shell.EggHunterNopSled", $"NOP sled of {best} bytes"));
            return hits;
        }
    }

    public sealed class DeobHit
    {
        public string Key = "";
        public string Detail = "";
        public int RecoveredWeight;
        public DeobHit(string key, string detail) { Key = key; Detail = detail; }
        public DeobHit(string key, string detail, int recoveredWeight)
        {
            Key = key; Detail = detail; RecoveredWeight = recoveredWeight;
        }
    }

    public static class Deobfuscator
    {
        private const int MaxBase64Depth = 5;

        public static List<DeobHit> Analyze(byte[] content, int count, string text)
        {
            var hits = new List<DeobHit>();
            var lower = text.ToLowerInvariant();
            Base64Layers(text, hits);
            EncodedCommand(text, lower, hits);
            HexBlobs(text, hits);
            CharChains(text, lower, hits);
            SplitStrings(text, hits);
            FormatOperator(text, lower, hits);
            Backticks(text, lower, hits);
            Reversed(text, lower, hits);
            Density(text, hits);
            Compression(lower, hits);
            Xor(content, count, hits);
            return hits;
        }

        private static bool IsB64(char c) =>
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';

        public static List<string> ExtractBase64(string text, int minLen, int maxBlobs)
        {
            var blobs = new List<string>();
            int start = -1;
            for (int i = 0; i <= text.Length; i++)
            {
                bool ok = i < text.Length && IsB64(text[i]);
                if (ok && start < 0) start = i;
                else if (!ok && start >= 0)
                {
                    int len = i - start;
                    if (len >= minLen) blobs.Add(text.Substring(start, Math.Min(len, 1 << 20)));
                    start = -1;
                    if (blobs.Count >= maxBlobs) break;
                }
            }
            return blobs;
        }

        private static byte[]? TryB64(string s)
        {
            var trimmed = s.TrimEnd('=');
            if (trimmed.Length < 8) return null;
            int pad = (4 - (trimmed.Length % 4)) % 4;
            if (pad == 3) return null;
            try { return Convert.FromBase64String(trimmed + new string('=', pad)); }
            catch (FormatException) { return null; }
        }

        private static void Base64Layers(string text, List<DeobHit> hits)
        {
            foreach (var blob in ExtractBase64(text, 24, 48))
            {
                string current = blob;
                for (int depth = 1; depth <= MaxBase64Depth; depth++)
                {
                    var decoded = TryB64(current);
                    if (decoded == null || decoded.Length < 4) break;
                    if (Util.IsPe(decoded))
                    {
                        hits.Add(new DeobHit("Deob.Base64EmbeddedPE", $"base64 layer {depth} decodes to an MZ/PE image ({decoded.Length} bytes)"));
                        break;
                    }
                    if (decoded.Length > 3 && decoded[0] == 0x50 && decoded[1] == 0x4B && decoded[2] == 0x03)
                    {
                        hits.Add(new DeobHit("Deob.Base64Nested", $"base64 layer {depth} decodes to a ZIP container"));
                        break;
                    }
                    double printable = Util.PrintableRatio(decoded, decoded.Length);
                    if (printable <= 0.85) break;

                    var inner = PatternEngine.ScanBuffer(decoded);
                    if (inner.Count > 0)
                        hits.Add(new DeobHit("Deob.Base64Nested", $"base64 layer {depth} content matched {inner[0].Signature.Name} (w={inner[0].Signature.Weight})", inner[0].Signature.Weight));
                    else if (depth > 1)
                        hits.Add(new DeobHit("Deob.Base64Nested", $"recursive base64 layer {depth} detected"));

                    var asText = Encoding.ASCII.GetString(decoded);
                    var nested = ExtractBase64(asText, 24, 4);
                    if (nested.Count == 0) break;
                    current = nested[0];
                }
            }
        }

        private static void EncodedCommand(string text, string lower, List<DeobHit> hits)
        {
            string[] flags = { "-encodedcommand", "-enc ", "-ec ", "/encodedcommand", "-e " };
            foreach (var flag in flags)
            {
                int idx = lower.IndexOf(flag, StringComparison.Ordinal);
                int guard = 0;
                while (idx >= 0 && guard++ < 32)
                {
                    int p = idx + flag.Length;
                    while (p < text.Length && (text[p] == ' ' || text[p] == '\t' || text[p] == '"' || text[p] == '\'')) p++;
                    int q = p;
                    while (q < text.Length && IsB64(text[q])) q++;
                    if (q - p >= 16)
                    {
                        var decoded = TryB64(text.Substring(p, q - p));
                        if (decoded != null && decoded.Length >= 4)
                        {
                            string utf16 = Encoding.Unicode.GetString(decoded);
                            var bytes = Encoding.ASCII.GetBytes(utf16);
                            var matches = PatternEngine.ScanBuffer(bytes);
                            string detail = matches.Count > 0
                                ? $"UTF-16LE EncodedCommand payload matched {matches[0].Signature.Name} (w={matches[0].Signature.Weight})"
                                : $"UTF-16LE EncodedCommand payload decoded ({utf16.Length} chars)";
                            hits.Add(new DeobHit("Deob.EncodedCommandUtf16", detail, matches.Count > 0 ? matches[0].Signature.Weight : 0));
                        }
                    }
                    idx = lower.IndexOf(flag, Math.Min(lower.Length, idx + flag.Length), StringComparison.Ordinal);
                }
            }
        }

        private static void HexBlobs(string text, List<DeobHit> hits)
        {
            int start = -1, found = 0;
            for (int i = 0; i <= text.Length && found < 8; i++)
            {
                char c = i < text.Length ? text[i] : ' ';
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (hex && start < 0) start = i;
                else if (!hex && start >= 0)
                {
                    int len = i - start;
                    if (len >= 32 && len % 2 == 0)
                    {
                        var bytes = FromHex(text.Substring(start, Math.Min(len, 1 << 17)));
                        if (bytes != null)
                        {
                            if (Util.IsPe(bytes)) { hits.Add(new DeobHit("Deob.HexEmbeddedPE", $"hex blob of {bytes.Length} bytes decodes to an MZ/PE image")); found++; }
                            else
                            {
                                var m = PatternEngine.ScanBuffer(bytes);
                                if (m.Count > 0) { hits.Add(new DeobHit("Deob.Base64Nested", $"hex blob matched {m[0].Signature.Name}", m[0].Signature.Weight)); found++; }
                            }
                        }
                    }
                    start = -1;
                }
            }
        }

        private static byte[]? FromHex(string s)
        {
            if (s.Length % 2 != 0) return null;
            var outBuf = new byte[s.Length / 2];
            for (int i = 0; i < outBuf.Length; i++)
            {
                int hi = HexVal(s[i * 2]), lo = HexVal(s[i * 2 + 1]);
                if (hi < 0 || lo < 0) return null;
                outBuf[i] = (byte)((hi << 4) | lo);
            }
            return outBuf;
        }

        private static int HexVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        private static void CharChains(string text, string lower, List<DeobHit> hits)
        {
            string[] markers = { "string.fromcharcode", "chr(", "chrw(", "[char]" };
            foreach (var marker in markers)
            {
                var numbers = new List<int>();
                int idx = lower.IndexOf(marker, StringComparison.Ordinal);
                int guard = 0;
                while (idx >= 0 && guard++ < 4096)
                {
                    int p = idx + marker.Length;
                    var sb = new StringBuilder();
                    while (p < text.Length && (char.IsDigit(text[p]) || text[p] == ',' || text[p] == ' ' || text[p] == ')'))
                    {
                        if (char.IsDigit(text[p])) sb.Append(text[p]);
                        else
                        {
                            if (sb.Length > 0 && int.TryParse(sb.ToString(), out var v) && v > 0 && v < 65536) numbers.Add(v);
                            sb.Clear();
                            if (text[p] == ')') break;
                        }
                        p++;
                    }
                    if (sb.Length > 0 && int.TryParse(sb.ToString(), out var v2) && v2 > 0 && v2 < 65536) numbers.Add(v2);
                    idx = lower.IndexOf(marker, Math.Min(lower.Length, idx + marker.Length), StringComparison.Ordinal);
                }
                if (numbers.Count >= 6)
                {
                    var rebuilt = new string(numbers.Select(n => (char)n).ToArray());
                    var m = PatternEngine.ScanBuffer(Encoding.ASCII.GetBytes(rebuilt));
                    hits.Add(new DeobHit("Deob.CharChain", m.Count > 0
                        ? $"{marker} chain of {numbers.Count} codes rebuilt to content matching {m[0].Signature.Name}"
                        : $"{marker} chain of {numbers.Count} character codes reconstructed",
                        m.Count > 0 ? m[0].Signature.Weight : 0));
                }
            }
        }

        public static string NormalizeConcatenation(string text)
        {
            if (text.IndexOf('+') < 0 && text.IndexOf('&') < 0) return text;
            var sb = new StringBuilder(text.Length);
            bool changed = false;
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (c == '"' || c == '\'')
                {
                    char quote = c;
                    int j = i + 1;
                    while (j < text.Length && text[j] != quote) j++;
                    if (j >= text.Length) { sb.Append(text, i, text.Length - i); break; }
                    sb.Append(text, i + 1, j - i - 1);
                    int k = j + 1;
                    bool sawOp = false;
                    while (k < text.Length && (text[k] == ' ' || text[k] == '\t' || text[k] == '+' || text[k] == '&' || text[k] == '\r' || text[k] == '\n'))
                    {
                        if (text[k] == '+' || text[k] == '&') sawOp = true;
                        k++;
                    }
                    if (sawOp && k < text.Length && (text[k] == '"' || text[k] == '\'')) { changed = true; i = k; continue; }
                    i = j + 1;
                    continue;
                }
                sb.Append(c);
                i++;
            }
            return changed ? sb.ToString() : text;
        }

        private static void SplitStrings(string text, List<DeobHit> hits)
        {
            var normalized = NormalizeConcatenation(text);
            if (ReferenceEquals(normalized, text)) return;
            var baseline = new System.Collections.Generic.HashSet<string>(
                PatternEngine.ScanBuffer(Encoding.ASCII.GetBytes(text)).Select(x => x.Signature.Name), StringComparer.Ordinal);
            foreach (var hit in PatternEngine.ScanBuffer(Encoding.ASCII.GetBytes(normalized)))
                if (!baseline.Contains(hit.Signature.Name))
                    hits.Add(new DeobHit("Deob.SplitStringEvasion", $"concatenation-normalized text matched {hit.Signature.Name} (w={hit.Signature.Weight})", hit.Signature.Weight));
        }

        private static void FormatOperator(string text, string lower, List<DeobHit> hits)
        {
            int braces = 0;
            for (int i = 0; i + 2 < text.Length; i++)
                if (text[i] == '{' && char.IsDigit(text[i + 1]) && text[i + 2] == '}') braces++;
            bool hasFmt = lower.Contains("-f ", StringComparison.Ordinal) || lower.Contains("-f'", StringComparison.Ordinal) || lower.Contains("-f\"", StringComparison.Ordinal);
            if (braces >= 4 && hasFmt)
                hits.Add(new DeobHit("Deob.FormatOperatorEvasion", $"PowerShell -f format-operator obfuscation with {braces} placeholders"));
        }

        private static void Backticks(string text, string lower, List<DeobHit> hits)
        {
            int ticks = text.Count(c => c == '`');
            if (ticks < 8) return;
            var stripped = text.Replace("`", "");
            var baseline = new System.Collections.Generic.HashSet<string>(
                PatternEngine.ScanBuffer(Encoding.ASCII.GetBytes(text)).Select(x => x.Signature.Name), StringComparer.Ordinal);
            foreach (var hit in PatternEngine.ScanBuffer(Encoding.ASCII.GetBytes(stripped)))
                if (!baseline.Contains(hit.Signature.Name))
                    hits.Add(new DeobHit("Deob.BacktickEvasion", $"backtick-stripped text matched {hit.Signature.Name} (w={hit.Signature.Weight})", hit.Signature.Weight));
        }

        private static void Reversed(string text, string lower, List<DeobHit> hits)
        {
            if (!lower.Contains("reverse", StringComparison.Ordinal) && !lower.Contains("strreverse", StringComparison.Ordinal)) return;
            var arr = text.ToCharArray();
            Array.Reverse(arr);
            var rev = new string(arr);
            var m = PatternEngine.ScanBuffer(Encoding.ASCII.GetBytes(rev));
            if (m.Count > 0)
                hits.Add(new DeobHit("Deob.ReversedStringEvasion", $"reversed text matched {m[0].Signature.Name} (w={m[0].Signature.Weight})", m[0].Signature.Weight));
        }

        private static void Density(string text, List<DeobHit> hits)
        {
            if (text.Length < 512) return;
            int sample = Math.Min(text.Length, 200000);
            int special = 0, alnum = 0;
            for (int i = 0; i < sample; i++)
            {
                char c = text[i];
                if (char.IsLetterOrDigit(c)) alnum++;
                else if (c == '^' || c == '`' || c == '+' || c == '$' || c == '{' || c == '}' || c == '%') special++;
            }
            if (alnum == 0) return;
            double ratio = (double)special / alnum;
            if (ratio > 0.35)
                hits.Add(new DeobHit("Deob.HighObfuscationDensity", $"obfuscation character density {ratio:F2} over {sample} chars"));
        }

        private static void Compression(string lower, List<DeobHit> hits)
        {
            if (lower.Contains("gzipstream", StringComparison.Ordinal) || lower.Contains("deflatestream", StringComparison.Ordinal))
                if (lower.Contains("frombase64string", StringComparison.Ordinal) || lower.Contains("memorystream", StringComparison.Ordinal))
                    hits.Add(new DeobHit("Deob.GzipDeflateInMemory", "in-memory gzip/deflate decompression of an encoded blob"));
        }

        private static bool HasValidPeHeader(byte[] data, int len)
        {
            if (len < 0x40) return false;
            uint elfanew = (uint)(data[0x3C] | (data[0x3D] << 8) | (data[0x3E] << 16) | (data[0x3F] << 24));
            if (elfanew < 0x40 || elfanew + 24 > (uint)len) return false;
            return data[elfanew] == 0x50 && data[elfanew + 1] == 0x45 && data[elfanew + 2] == 0x00 && data[elfanew + 3] == 0x00;
        }

        private static readonly byte[][] XorKeywords =
        {
            Encoding.ASCII.GetBytes("powershell"),
            Encoding.ASCII.GetBytes("cmd.exe"),
            Encoding.ASCII.GetBytes("http://"),
            Encoding.ASCII.GetBytes("https://"),
            Encoding.ASCII.GetBytes("This program cannot"),
            Encoding.ASCII.GetBytes("CreateProcess"),
            Encoding.ASCII.GetBytes("kernel32.dll"),
            Encoding.ASCII.GetBytes("function "),
            Encoding.ASCII.GetBytes("<script"),
        };

        private static void Xor(byte[] content, int count, List<DeobHit> hits)
        {
            int len = Math.Min(count, 65536);
            if (len < 64) return;
            var decoded = new byte[len];
            for (int key = 0x01; key <= 0xFF; key++)
            {
                for (int i = 0; i < len; i++) decoded[i] = (byte)(content[i] ^ key);
                if (decoded[0] == 0x4D && decoded[1] == 0x5A && HasValidPeHeader(decoded, len))
                {
                    hits.Add(new DeobHit("Deob.XorDecodedPE", $"single-byte XOR key 0x{key:X2} yields a structurally valid MZ/PE image"));
                    return;
                }
                if (decoded[0] == 0x50 && decoded[1] == 0x4B && decoded[2] == 0x03 && decoded[3] == 0x04 && len > 64)
                {
                    hits.Add(new DeobHit("Deob.XorDecodedScript", $"single-byte XOR key 0x{key:X2} yields a PK archive header"));
                    return;
                }
                double ratio = Util.PrintableRatio(decoded, len);
                if (ratio < 0.9) continue;
                foreach (var kw in XorKeywords)
                {
                    if (PatternEngine.IndexOf(decoded, len, kw) >= 0)
                    {
                        hits.Add(new DeobHit("Deob.XorDecodedScript",
                            $"XOR key 0x{key:X2} yields printable text (ratio {ratio:F2}) containing '{Encoding.ASCII.GetString(kw)}'"));
                        return;
                    }
                }
            }
        }
    }

    public static class DocumentAnalyzer
    {
        public static List<DeobHit> AnalyzePdf(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            var text = Encoding.ASCII.GetString(data, 0, Math.Min(count, 4 << 20)).ToLowerInvariant();
            if (text.Contains("/javascript", StringComparison.Ordinal) || text.Contains("/js", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.PdfJavaScript", "PDF contains a /JavaScript action"));
            if (text.Contains("/openaction", StringComparison.Ordinal) || text.Contains("/aa", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.PdfOpenAction", "PDF contains an automatic /OpenAction"));
            if (text.Contains("/embeddedfile", StringComparison.Ordinal) || text.Contains("/filespec", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.PdfEmbeddedFile", "PDF contains an embedded file object"));
            if (text.Contains("/launch", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.PdfOpenAction", "PDF contains a /Launch action"));
            return hits;
        }

        public static List<DeobHit> AnalyzeRtf(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            var text = Encoding.ASCII.GetString(data, 0, Math.Min(count, 4 << 20)).ToLowerInvariant();
            if (text.Contains("\\objdata", StringComparison.Ordinal) || text.Contains("\\objupdate", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.RtfObjectData", "RTF embeds an OLE object payload (\\objdata)"));
            if (text.Contains("\\objocx", StringComparison.Ordinal) || text.Contains("equation.3", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.RtfObjectData", "RTF references an Equation/OCX object commonly used for exploits"));
            return hits;
        }

        public static List<DeobHit> AnalyzeOle(byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            var wide = new[] { "VBA", "Macros", "_VBA_PROJECT", "ThisDocument" };
            foreach (var marker in wide)
            {
                var utf16 = Encoding.Unicode.GetBytes(marker);
                if (PatternEngine.IndexOf(data, count, utf16) >= 0 ||
                    PatternEngine.IndexOf(data, count, Encoding.ASCII.GetBytes(marker)) >= 0)
                {
                    hits.Add(new DeobHit("Doc.OleCompoundMacroStream", $"OLE compound file contains a '{marker}' stream"));
                    break;
                }
            }
            return hits;
        }

        public static List<DeobHit> AnalyzeOoxmlEntry(string entryName, byte[] data, int count)
        {
            var hits = new List<DeobHit>();
            var lowerName = entryName.ToLowerInvariant();
            if (lowerName.EndsWith("vbaproject.bin", StringComparison.Ordinal))
                hits.Add(new DeobHit("Doc.OoxmlVbaProject", $"OOXML package contains a VBA project ({entryName})"));
            if (lowerName.Contains("_rels", StringComparison.Ordinal) || lowerName.EndsWith(".rels", StringComparison.Ordinal))
            {
                var text = Encoding.ASCII.GetString(data, 0, Math.Min(count, 1 << 20)).ToLowerInvariant();
                if (text.Contains("attachedtemplate", StringComparison.Ordinal) &&
                    (text.Contains("http://", StringComparison.Ordinal) || text.Contains("https://", StringComparison.Ordinal) || text.Contains("\\\\", StringComparison.Ordinal)))
                    hits.Add(new DeobHit("Doc.OoxmlRemoteTemplate", $"remote template injection relationship in {entryName}"));
                if (text.Contains("oleobject", StringComparison.Ordinal) && text.Contains("targetmode=\"external\"", StringComparison.Ordinal))
                    hits.Add(new DeobHit("Doc.OoxmlExternalOleObject", $"external OLE object relationship in {entryName}"));
            }
            return hits;
        }
    }

    public static class FuzzyFingerprint
    {
        public const int NGramSize = 8;
        public const int BucketCount = 256;
        public const double MatchThreshold = 0.80;

        public static string Compute(byte[] data, int count)
        {
            var buckets = new bool[BucketCount];
            int end = Math.Min(count, data.Length);
            if (end >= NGramSize)
            {
                ulong rolling = 0;
                const ulong basePrime = 1000003UL;
                for (int i = 0; i < end; i++)
                {
                    rolling = rolling * basePrime + data[i];
                    if (i >= NGramSize - 1)
                    {
                        ulong h = rolling;
                        h ^= h >> 33; h *= 0xff51afd7ed558ccdUL; h ^= h >> 33;
                        buckets[(int)(h % BucketCount)] = true;
                    }
                }
            }
            var bytes = new byte[BucketCount / 8];
            for (int i = 0; i < BucketCount; i++) if (buckets[i]) bytes[i / 8] |= (byte)(1 << (i % 8));
            return Util.ToHex(bytes);
        }

        public static double Similarity(string a, string b)
        {
            if (a.Length != b.Length || a.Length == 0) return 0.0;
            int inter = 0, union = 0;
            for (int i = 0; i + 1 < a.Length; i += 2)
            {
                int x, y;
                if (!int.TryParse(a.Substring(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out x)) return 0.0;
                if (!int.TryParse(b.Substring(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out y)) return 0.0;
                inter += System.Numerics.BitOperations.PopCount((uint)(x & y));
                union += System.Numerics.BitOperations.PopCount((uint)(x | y));
            }
            return union == 0 ? 0.0 : (double)inter / union;
        }
    }

    public sealed class QuarantineRecord
    {
        public string Id = "";
        public string OriginalPath = "";
        public string Md5 = "";
        public string Sha1 = "";
        public string Sha256 = "";
        public string Fingerprint = "";
        public string TimestampUtc = "";
        public int Score;
        public List<string> Reasons = new List<string>();
    }

    public sealed class QuarantineStore
    {
        private readonly string _dir;
        private readonly string _keyFile;
        private readonly string _indexFile;
        private readonly object _lock = new object();
        private byte[]? _key;
        private readonly List<QuarantineRecord> _known = new List<QuarantineRecord>();
        private readonly System.Collections.Generic.HashSet<string> _allowlist =
            new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly byte[] BlobMagic = Encoding.ASCII.GetBytes("AAV1");
        private const int NonceLength = 12;
        private const int TagLength = 16;

        public QuarantineStore(string baseDir, string? allowlistPath)
        {
            _dir = Path.Combine(baseDir, "quarantine");
            _keyFile = Path.Combine(_dir, "armorav.key");
            _indexFile = Path.Combine(_dir, "known.tsv");
            LoadIndex();
            LoadAllowlist(allowlistPath);
        }

        public string Directory => _dir;
        public IReadOnlyList<QuarantineRecord> Known => _known;

        private void EnsureDir()
        {
            if (!System.IO.Directory.Exists(_dir)) System.IO.Directory.CreateDirectory(_dir);
        }

        private byte[] Key()
        {
            lock (_lock)
            {
                if (_key != null) return _key;
                EnsureDir();
                if (File.Exists(_keyFile))
                {
                    _key = Convert.FromBase64String(File.ReadAllText(_keyFile).Trim());
                    if (_key.Length != 32) throw new InvalidOperationException("quarantine key file is corrupt");
                    return _key;
                }
                _key = RandomNumberGenerator.GetBytes(32);
                WriteTextAtomically(_keyFile, Convert.ToBase64String(_key));
                return _key;
            }
        }

        private static void WriteTextAtomically(string path, string content)
        {
            var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(temporary, content);
                File.Move(temporary, path, true);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private static void WriteBytesAtomically(string path, byte[] content)
        {
            var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(content, 0, content.Length);
                    stream.Flush(true);
                }
                File.Move(temporary, path, true);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private void LoadIndex()
        {
            try
            {
                if (!File.Exists(_indexFile)) return;
                foreach (var line in File.ReadAllLines(_indexFile))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var p = line.Split('\t');
                    if (p.Length < 4) continue;
                    _known.Add(new QuarantineRecord { Id = p[0], Sha256 = p[1], Fingerprint = p[2], OriginalPath = p[3] });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private void LoadAllowlist(string? path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
            try
            {
                foreach (var line in File.ReadAllLines(path))
                {
                    var t = line.Trim();
                    if (t.Length == 64 || t.Length == 40 || t.Length == 32) _allowlist.Add(t);
                }
            }
            catch (IOException) { }
        }

        public bool IsAllowlisted(HashTriple h)
        {
            return _allowlist.Contains(h.Sha256) || _allowlist.Contains(h.Sha1) || _allowlist.Contains(h.Md5);
        }

        public string? Match(string sha256, string fingerprint, out double similarity)
        {
            similarity = 0.0;
            lock (_lock)
            {
                foreach (var r in _known)
                    if (string.Equals(r.Sha256, sha256, StringComparison.OrdinalIgnoreCase)) { similarity = 1.0; return "exact"; }
                string? best = null;
                foreach (var r in _known)
                {
                    double s = FuzzyFingerprint.Similarity(r.Fingerprint, fingerprint);
                    if (s >= FuzzyFingerprint.MatchThreshold && s > similarity) { similarity = s; best = r.OriginalPath; }
                }
                return best == null ? null : "fuzzy:" + best;
            }
        }

        public QuarantineRecord Store(string path, HashTriple h, string fingerprint, int score, IEnumerable<string> reasons, bool dryRun)
        {
            var rec = new QuarantineRecord
            {
                Id = Guid.NewGuid().ToString("N"),
                OriginalPath = Path.GetFullPath(path),
                Md5 = h.Md5,
                Sha1 = h.Sha1,
                Sha256 = h.Sha256,
                Fingerprint = fingerprint,
                TimestampUtc = Util.Iso8601Utc(DateTime.UtcNow),
                Score = score,
                Reasons = reasons.ToList()
            };
            if (dryRun) return rec;

            lock (_lock)
            {
                EnsureDir();
                var blobPath = Path.Combine(_dir, rec.Id + ".bin");
                var metaPath = Path.Combine(_dir, rec.Id + ".json");
                bool committed = false;
                try
                {

                    var plain = File.ReadAllBytes(path);
                    var actual = Util.ToHex(SHA256.HashData(plain));
                    if (!string.Equals(actual, h.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new IOException("file changed after it was scanned; refusing to quarantine it");

                    var nonce = RandomNumberGenerator.GetBytes(NonceLength);
                    var tag = new byte[TagLength];
                    var cipher = new byte[plain.Length];
                    using (var aes = new AesGcm(Key(), TagLength))
                        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(rec.Id));

                    var blob = new byte[BlobMagic.Length + nonce.Length + tag.Length + cipher.Length];
                    Buffer.BlockCopy(BlobMagic, 0, blob, 0, BlobMagic.Length);
                    Buffer.BlockCopy(nonce, 0, blob, BlobMagic.Length, nonce.Length);
                    Buffer.BlockCopy(tag, 0, blob, BlobMagic.Length + nonce.Length, tag.Length);
                    Buffer.BlockCopy(cipher, 0, blob, BlobMagic.Length + nonce.Length + tag.Length, cipher.Length);
                    WriteBytesAtomically(blobPath, blob);
                    WriteTextAtomically(metaPath, Metadata(rec));

                    var beforeDelete = Hasher.FromFile(path).Sha256;
                    if (!string.Equals(beforeDelete, h.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new IOException("file changed before quarantine could be committed; source was not deleted");

                    File.AppendAllText(_indexFile, string.Join("\t", rec.Id, rec.Sha256, rec.Fingerprint, rec.OriginalPath.Replace('\t', ' ')) + Environment.NewLine);
                    File.Delete(path);
                    _known.Add(rec);
                    committed = true;
                }
                finally
                {

                    if (!committed)
                    {
                        if (File.Exists(blobPath)) File.Delete(blobPath);
                        if (File.Exists(metaPath)) File.Delete(metaPath);
                    }
                }
            }
            return rec;
        }

        private static string Metadata(QuarantineRecord r)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            sb.Append("  \"product\": \"").Append(Product.Name).Append("\",\n");
            sb.Append("  \"id\": \"").Append(Util.JsonEscape(r.Id)).Append("\",\n");
            sb.Append("  \"originalPath\": \"").Append(Util.JsonEscape(r.OriginalPath)).Append("\",\n");
            sb.Append("  \"md5\": \"").Append(r.Md5).Append("\",\n");
            sb.Append("  \"sha1\": \"").Append(r.Sha1).Append("\",\n");
            sb.Append("  \"sha256\": \"").Append(r.Sha256).Append("\",\n");
            sb.Append("  \"fingerprint\": \"").Append(r.Fingerprint).Append("\",\n");
            sb.Append("  \"score\": ").Append(r.Score).Append(",\n");
            sb.Append("  \"timestampUtc\": \"").Append(r.TimestampUtc).Append("\",\n");
            sb.Append("  \"reasons\": [");
            for (int i = 0; i < r.Reasons.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append('"').Append(Util.JsonEscape(r.Reasons[i])).Append('"');
            }
            sb.Append("]\n}\n");
            return sb.ToString();
        }

        public bool Restore(string id, out string message)
        {
            message = "";
            var blobPath = Path.Combine(_dir, id + ".bin");
            var metaPath = Path.Combine(_dir, id + ".json");
            if (!File.Exists(blobPath) || !File.Exists(metaPath)) { message = "quarantine item not found: " + id; return false; }
            var meta = File.ReadAllText(metaPath);
            string expected = ReadJson(meta, "sha256");
            string original = ReadJson(meta, "originalPath");
            var raw = File.ReadAllBytes(blobPath);
            int headerLength = BlobMagic.Length + NonceLength + TagLength;
            if (raw.Length < headerLength || !raw.Take(BlobMagic.Length).SequenceEqual(BlobMagic))
            {
                message = "unsupported or damaged quarantine blob";
                return false;
            }

            var nonce = new byte[NonceLength];
            var tag = new byte[TagLength];
            int cipherLength = raw.Length - headerLength;
            var cipher = new byte[cipherLength];
            Buffer.BlockCopy(raw, BlobMagic.Length, nonce, 0, NonceLength);
            Buffer.BlockCopy(raw, BlobMagic.Length + NonceLength, tag, 0, TagLength);
            Buffer.BlockCopy(raw, headerLength, cipher, 0, cipherLength);
            var plain = new byte[cipherLength];
            try
            {
                using var aes = new AesGcm(Key(), TagLength);
                aes.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(id));
            }
            catch (CryptographicException)
            {
                message = "authentication failed; the quarantine item may have been tampered with";
                return false;
            }

            var actual = Util.ToHex(SHA256.HashData(plain));
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                message = $"integrity check failed, refusing restore (expected {expected}, computed {actual})";
                return false;
            }
            if (string.IsNullOrWhiteSpace(original)) { message = "quarantine metadata has no original path"; return false; }
            if (File.Exists(original)) { message = "refusing to overwrite an existing file: " + original; return false; }

            var dir = Path.GetDirectoryName(original);
            if (!string.IsNullOrEmpty(dir) && !System.IO.Directory.Exists(dir)) System.IO.Directory.CreateDirectory(dir);
            WriteBytesAtomically(original, plain);
            message = "restored " + id + " to " + original;
            return true;
        }

        public List<QuarantineRecord> List()
        {
            var list = new List<QuarantineRecord>();
            if (!System.IO.Directory.Exists(_dir)) return list;
            foreach (var f in System.IO.Directory.EnumerateFiles(_dir, "*.json"))
            {
                try
                {
                    var meta = File.ReadAllText(f);
                    list.Add(new QuarantineRecord
                    {
                        Id = ReadJson(meta, "id"),
                        OriginalPath = ReadJson(meta, "originalPath"),
                        Sha256 = ReadJson(meta, "sha256"),
                        TimestampUtc = ReadJson(meta, "timestampUtc")
                    });
                }
                catch (IOException) { }
            }
            return list.OrderBy(x => x.TimestampUtc, StringComparer.Ordinal).ToList();
        }

        private static string ReadJson(string json, string key)
        {
            var marker = "\"" + key + "\":";
            int i = json.IndexOf(marker, StringComparison.Ordinal);
            if (i < 0) return "";
            int q1 = json.IndexOf('"', i + marker.Length);
            if (q1 < 0) return "";
            var sb = new StringBuilder();
            for (int p = q1 + 1; p < json.Length; p++)
            {
                if (json[p] == '\\' && p + 1 < json.Length) { sb.Append(json[p + 1] == 'n' ? '\n' : json[p + 1]); p++; continue; }
                if (json[p] == '"') break;
                sb.Append(json[p]);
            }
            return sb.ToString();
        }
    }

    public static class Scoring
    {
        public const int WeakCap = 15;
        public const int StrongThreshold = 50;
        public const int ConfirmedSingle = 85;
        public const int SuspiciousScore = 40;

        public static int Compute(IEnumerable<Finding> findings)
        {
            int weak = 0, strong = 0;
            foreach (var f in findings)
            {
                if (f.Weight >= StrongThreshold) strong += f.Weight;
                else weak += f.Weight;
            }
            if (weak > WeakCap) weak = WeakCap;
            return weak + strong;
        }

        public static Verdict Decide(IReadOnlyCollection<Finding> findings, int score)
        {
            int strongCount = findings.Count(f => f.Weight >= StrongThreshold);
            if (findings.Any(f => f.Weight >= ConfirmedSingle) || strongCount >= 2) return Verdict.Confirmed;
            if (score >= SuspiciousScore) return Verdict.Suspicious;
            return Verdict.Clean;
        }
    }

    public sealed class ScanEngine
    {
        private readonly Options _opt;
        private readonly ScanReport _report;
        private readonly QuarantineStore _store;
        private readonly ScanCache _cache;
        private readonly System.Collections.Generic.HashSet<string> _visited =
            new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _visitLock = new object();
        private const int DeepAnalysisCap = 8 * 1024 * 1024;

        public ScanEngine(Options opt, ScanReport report, QuarantineStore store, ScanCache cache)
        {
            _opt = opt; _report = report; _store = store; _cache = cache;
        }

        public void Run(string path)
        {
            var files = new List<string>();
            if (File.Exists(path)) files.Add(path);
            else if (System.IO.Directory.Exists(path)) Collect(path, 0, files);
            else { _report.SkippedBag.Add(new SkippedFile { Path = path, Reason = "path not found" }); return; }

            var po = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, _opt.Threads) };
            Parallel.ForEach(files, po, (f, state) =>
            {
                try
                {
                    ScanFile(f);
                    if (_opt.FailFast && _report.ResultsBag.Any(r => r.VerdictText == Verdict.Confirmed.ToString())) state.Stop();
                }
                catch (Exception ex) { _report.SkippedBag.Add(new SkippedFile { Path = f, Reason = ex.GetType().Name + ": " + ex.Message }); }
            });
            Correlate();
        }

        private void Correlate()
        {
            var all = _report.ResultsBag.ToList();
            if (all.Count < 2) return;

            var byImpHash = all.Where(r => !string.IsNullOrEmpty(r.ImpHash))
                               .GroupBy(r => r.ImpHash, StringComparer.OrdinalIgnoreCase)
                               .Where(g => g.Count() >= 3);
            foreach (var group in byImpHash)
                foreach (var r in group)
                    if (r.VerdictText != "Clean" || r.Findings.Count > 0)
                        Add(r, "Rep.RepeatedImpHashInScan", $"import hash {group.Key} shared by {group.Count()} files in this scan");

            var candidates = all.Where(r => r.Findings.Count > 0 && !string.IsNullOrEmpty(r.Fingerprint)).ToList();
            var clustered = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < candidates.Count; i++)
            {
                int members = 0;
                for (int j = 0; j < candidates.Count; j++)
                {
                    if (i == j) continue;
                    if (FuzzyFingerprint.Similarity(candidates[i].Fingerprint, candidates[j].Fingerprint) >= FuzzyFingerprint.MatchThreshold) members++;
                }
                if (members >= 2 && clustered.Add(candidates[i].Path))
                    Add(candidates[i], "Rep.RepeatedFuzzyClusterInScan", $"structurally similar to {members} other flagged files in this scan");
            }

            foreach (var r in all)
            {
                if (r.Findings.Count == 0) continue;
                int before = r.Score;
                r.Score = Scoring.Compute(r.Findings);
                var verdict = Scoring.Decide(r.Findings, r.Score);
                if (verdict.ToString() != r.VerdictText || before != r.Score)
                {
                    r.VerdictText = verdict.ToString();
                    r.Findings = r.Findings.OrderByDescending(f => f.Weight).ThenBy(f => f.Name, StringComparer.Ordinal).ToList();
                }
            }
        }

        private void Collect(string dir, int depth, List<string> files)
        {
            if (depth > _opt.MaxDepth)
            {
                _report.SkippedBag.Add(new SkippedFile { Path = dir, Reason = $"traversal depth limit {_opt.MaxDepth} exceeded" });
                return;
            }
            string real;
            try { real = Path.GetFullPath(dir); }
            catch (Exception ex) { _report.SkippedBag.Add(new SkippedFile { Path = dir, Reason = "canonicalization failed: " + ex.Message }); return; }
            if (!MarkVisited(real)) return;

            try
            {
                var di = new DirectoryInfo(real);
                if (di.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    _report.ReparseBag.Add(real);
                    return;
                }
                foreach (var f in System.IO.Directory.EnumerateFiles(real))
                {
                    try
                    {
                        var fi = new FileInfo(f);
                        if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint)) { _report.ReparseBag.Add(f); continue; }
                        if (fi.Length > _opt.MaxFileBytes)
                        {
                            _report.SkippedBag.Add(new SkippedFile { Path = f, Reason = $"file larger than limit ({Util.HumanSize(fi.Length)})" });
                            continue;
                        }
                        files.Add(f);
                    }
                    catch (Exception ex) { _report.SkippedBag.Add(new SkippedFile { Path = f, Reason = ex.GetType().Name + ": " + ex.Message }); }
                }
                foreach (var sub in System.IO.Directory.EnumerateDirectories(real)) Collect(sub, depth + 1, files);
            }
            catch (UnauthorizedAccessException ex) { _report.SkippedBag.Add(new SkippedFile { Path = real, Reason = "access denied: " + ex.Message }); }
            catch (IOException ex) { _report.SkippedBag.Add(new SkippedFile { Path = real, Reason = "io error: " + ex.Message }); }
        }

        private bool MarkVisited(string real)
        {
            lock (_visitLock) return _visited.Add(real);
        }

        private bool IsInsideQuarantine(string path)
        {
            var quarantine = Path.GetFullPath(_store.Directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var candidate = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return string.Equals(candidate, quarantine, StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith(quarantine + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                   candidate.StartsWith(quarantine + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        public void ScanFile(string path)
        {
            string real;
            try { real = Path.GetFullPath(path); }
            catch (Exception ex) { _report.SkippedBag.Add(new SkippedFile { Path = path, Reason = "canonicalization failed: " + ex.Message }); return; }
            if (IsInsideQuarantine(real)) return;
            try
            {
                if (File.GetAttributes(real).HasFlag(FileAttributes.ReparsePoint))
                {
                    _report.ReparseBag.Add(real);
                    return;
                }
            }
            catch (Exception ex)
            {
                _report.SkippedBag.Add(new SkippedFile { Path = real, Reason = "file attributes unavailable: " + ex.Message });
                return;
            }
            if (!MarkVisited(real)) return;

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var result = new FileResult { Path = real };
            try
            {
                long cachedTicks = 0;
                try { cachedTicks = File.GetLastWriteTimeUtc(real).Ticks; } catch (IOException) { }
                var fileLength = new FileInfo(real).Length;
                if (_cache.TryGet(real, fileLength, cachedTicks, out var cSha, out var cVerdict, out var cScore))
                {
                    result.Size = fileLength;
                    result.Sha256 = cSha;
                    result.VerdictText = cVerdict;
                    result.Score = cScore;
                    result.FromCache = true;
                    result.FileType = "cached";
                    sw.Stop();
                    result.ScanMilliseconds = sw.Elapsed.TotalMilliseconds;
                    _report.ResultsBag.Add(result);
                    return;
                }

                var hashes = Hasher.FromFile(real);
                result.Size = hashes.Length;
                result.Md5 = hashes.Md5;
                result.Sha1 = hashes.Sha1;
                result.Sha256 = hashes.Sha256;

                if (_store.IsAllowlisted(hashes))
                {
                    result.VerdictText = "Clean";
                    result.QuarantineNote = "hash allowlisted";
                    sw.Stop();
                    result.ScanMilliseconds = sw.Elapsed.TotalMilliseconds;
                    _report.ResultsBag.Add(result);
                    return;
                }

                StreamPatterns(real, result);

                var head = ReadHead(real, DeepAnalysisCap);
                result.Fingerprint = FuzzyFingerprint.Compute(head, head.Length);

                var known = _store.Match(hashes.Sha256, result.Fingerprint, out double sim);
                if (known == "exact") Add(result, "Hash.KnownQuarantinedHash", "sha256 matches a previously quarantined sample");
                else if (known != null) Add(result, "Fuzzy.NearDuplicateOfQuarantined", $"fuzzy similarity {sim:F2} (threshold {FuzzyFingerprint.MatchThreshold:F2}) against {known}");

                var type = FileTyper.Identify(head, real);
                if (ContainerAnalyzer.LooksLikeIso(head, hashes.Length)) { type.IsIso = true; type.Type = "iso"; }
                result.FileType = type.Type;
                NameHeuristics(real, type, result);
                foreach (var h in NameAnalyzer.Analyze(real)) Add(result, h.Key, h.Detail);

                if (type.IsPe) AnalyzePe(head, result, "");
                foreach (var bp in BytePatternEngine.Scan(head, head.Length))
                    result.Findings.Add(new Finding
                    {
                        Name = bp.Name,
                        Weight = bp.Weight,
                        Detector = "bytepattern",
                        Family = bp.Family,
                        Severity = bp.Severity,
                        Detail = bp.Description
                    });
                foreach (var h in Carver.Carve(head, head.Length, type.IsPe, type.IsZipContainer)) Add(result, h.Key, h.Detail);
                foreach (var h in AdvancedXor.Analyze(head, head.Length)) Add(result, h.Key, h.Detail);
                foreach (var h in CompressionCarver.Analyze(head, head.Length)) Add(result, h.Key, h.Detail, h.RecoveredWeight);
                if (type.IsPdf) foreach (var h in DocumentAnalyzer.AnalyzePdf(head, head.Length)) Add(result, h.Key, h.Detail);
                if (type.IsRtf) foreach (var h in DocumentAnalyzer.AnalyzeRtf(head, head.Length)) Add(result, h.Key, h.Detail);
                if (type.IsOle)
                {
                    foreach (var h in DocumentAnalyzer.AnalyzeOle(head, head.Length)) Add(result, h.Key, h.Detail);
                    foreach (var h in ContainerAnalyzer.AnalyzeOneNote(head, head.Length)) Add(result, h.Key, h.Detail);
                    string macroSource;
                    foreach (var h in OleAnalyzer.Analyze(head, out macroSource)) Add(result, h.Key, h.Detail);
                    if (macroSource.Length > 24)
                    {
                        var macroBytes = Encoding.ASCII.GetBytes(macroSource);
                        foreach (var hit in PatternEngine.ScanBuffer(macroBytes))
                            result.Findings.Add(new Finding
                            {
                                Name = hit.Signature.Name,
                                Weight = hit.Signature.Weight,
                                Detector = "vba",
                                Family = hit.Signature.Family,
                                Severity = hit.Signature.Severity,
                                Detail = $"recovered VBA source at offset {hit.Offset}"
                            });
                        var macroLower = macroSource.ToLowerInvariant();
                        foreach (var dh in Deobfuscator.Analyze(macroBytes, macroBytes.Length, macroSource)) Add(result, dh.Key, "VBA source: " + dh.Detail, dh.RecoveredWeight);
                        EvaluateRules(result, macroLower, "vba", "recovered VBA");
                    }
                }
                if (type.IsLnk) foreach (var h in LnkAnalyzer.Analyze(head, head.Length)) Add(result, h.Key, h.Detail);
                if (type.IsIso) foreach (var h in ContainerAnalyzer.AnalyzeIso(head, head.Length)) Add(result, h.Key, h.Detail);

                foreach (var s in ShellcodeHeuristics.Analyze(head, head.Length)) Add(result, s.Key, s.Detail);

                var text = Encoding.ASCII.GetString(head, 0, Math.Min(head.Length, DeepAnalysisCap));
                var lowerText = text.ToLowerInvariant();
                foreach (var h in Deobfuscator.Analyze(head, head.Length, text)) Add(result, h.Key, h.Detail, h.RecoveredWeight);
                if (type.IsScriptText) foreach (var h in ScriptAnalyzer.Analyze(text, lowerText)) Add(result, h.Key, h.Detail);
                if (type.IsScriptText && MailAnalyzer.LooksLikeMail(head, head.Length))
                {
                    result.FileType = "mail";
                    foreach (var h in MailAnalyzer.Analyze(text)) Add(result, h.Key, h.Detail, h.RecoveredWeight);
                }
                EvaluateRules(result, lowerText, type.Type, "");

                if (type.IsZipContainer) ScanZipFile(real, result, 0);

                Finalize(result, real, hashes);
            }
            catch (UnauthorizedAccessException ex) { _report.SkippedBag.Add(new SkippedFile { Path = real, Reason = "access denied: " + ex.Message }); return; }
            catch (IOException ex) { _report.SkippedBag.Add(new SkippedFile { Path = real, Reason = "io error: " + ex.Message }); return; }
            catch (Exception ex) { _report.SkippedBag.Add(new SkippedFile { Path = real, Reason = ex.GetType().Name + ": " + ex.Message }); return; }

            sw.Stop();
            result.ScanMilliseconds = sw.Elapsed.TotalMilliseconds;
            _report.ResultsBag.Add(result);
        }

        private void EvaluateRules(FileResult result, string lowerText, string fileType, string label)
        {
            foreach (var m in RuleSet.Evaluate(lowerText, fileType))
            {
                string prefix = string.IsNullOrEmpty(label) ? "" : label + ": ";
                result.RuleMatches.Add(m.Rule.Name);
                result.Findings.Add(new Finding
                {
                    Name = m.Rule.Name,
                    Weight = m.Rule.Weight,
                    Detector = "rule",
                    Family = m.Rule.Family,
                    Severity = m.Rule.Severity,
                    Detail = $"{prefix}{m.Rule.Description} [{m.MatchedIds.Count}/{m.Rule.Strings.Length} strings: {string.Join(",", m.MatchedIds)}]"
                });
            }
        }

        private void NameHeuristics(string path, TypeInfo type, FileResult result)
        {
            var name = Path.GetFileName(path);
            if (FileTyper.HasRtlOverride(name))
                Add(result, "Type.RtloName", "file name contains a right-to-left override character");
            if (FileTyper.IsDoubleExtension(name))
                Add(result, "Type.DoubleExtension", $"executable file masquerading with a double extension: {name}");
            if (FileTyper.IsMismatch(path, type, out var declared))
            {
                result.DeclaredType = declared;
                result.TypeMismatch = true;
                Add(result, "Type.ExtensionMismatch", $"extension {declared} does not match detected content type '{type.Type}'");
            }
        }

        private void Finalize(FileResult result, string real, HashTriple hashes)
        {
            Dedupe(result);
            ApplyComposites(result);
            Dedupe(result);
            result.Score = Scoring.Compute(result.Findings);
            var verdict = Scoring.Decide(result.Findings, result.Score);
            result.VerdictText = verdict.ToString();
            result.Families = result.Findings.Select(f => f.Family).Where(f => f != "info" && f != "trust" && f.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
            result.Techniques = AttackMap.Collect(result.Families);
            result.Findings = result.Findings.OrderByDescending(f => f.Weight).ThenBy(f => f.Name, StringComparer.Ordinal).ToList();

            try
            {
                long ticks = File.GetLastWriteTimeUtc(real).Ticks;
                _cache.Put(real, hashes.Length, ticks, hashes.Sha256, result.VerdictText, result.Score);
            }
            catch (IOException) { }

            if (verdict == Verdict.Confirmed)
            {
                try
                {
                    var reasons = result.Findings.Select(f => $"{f.Name}({f.Weight})").ToList();
                    var rec = _store.Store(real, hashes, result.Fingerprint, result.Score, reasons, !_opt.Quarantine);
                    result.Quarantined = _opt.Quarantine;
                    result.QuarantineNote = _opt.Quarantine
                        ? $"moved to quarantine, id {rec.Id}"
                        : "dry-run: would be quarantined (pass --quarantine to move)";
                }
                catch (Exception ex) { result.QuarantineNote = "quarantine failed: " + ex.Message; }
            }
        }

        private static void ApplyComposites(FileResult result)
        {
            var snapshot = result.Findings.ToList();
            foreach (var rule in CompositeRules.Rules)
            {
                if (!rule.Predicate(snapshot)) continue;
                var info = SignatureTable.DetectorInfo(rule.Name);
                result.Findings.Add(new Finding
                {
                    Name = rule.Name,
                    Weight = info.Weight,
                    Detector = "composite",
                    Family = info.Family,
                    Severity = info.Sev,
                    Detail = rule.Description
                });
            }
        }

        private static void Dedupe(FileResult result)
        {
            var seen = new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
            var keep = new List<Finding>();
            foreach (var f in result.Findings)
                if (seen.Add(f.Name + "|" + f.Detail)) keep.Add(f);
            result.Findings = keep;
        }

        private void StreamPatterns(string path, FileResult result)
        {
            var session = new PatternEngine.Session();
            int overlap = PatternEngine.Overlap;
            var buffer = new byte[Math.Max(1 << 20, overlap * 4)];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan);
            int carry = 0;
            long baseOffset = 0;
            int read;
            while ((read = fs.Read(buffer, carry, buffer.Length - carry)) > 0)
            {
                int total = carry + read;
                session.Feed(buffer, total, baseOffset);
                carry = Math.Min(overlap, total);
                Buffer.BlockCopy(buffer, total - carry, buffer, 0, carry);
                baseOffset += total - carry;
            }
            foreach (var hit in session.Results())
                result.Findings.Add(new Finding
                {
                    Name = hit.Signature.Name,
                    Weight = hit.Signature.Weight,
                    Detector = "pattern",
                    Family = hit.Signature.Family,
                    Severity = hit.Signature.Severity,
                    Detail = $"{hit.Encoding} literal match at offset {hit.Offset}"
                });
        }

        private static byte[] ReadHead(string path, int cap)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan);
            int len = (int)Math.Min(cap, fs.Length);
            var buf = new byte[len];
            int off = 0;
            while (off < len)
            {
                int r = fs.Read(buf, off, len - off);
                if (r <= 0) break;
                off += r;
            }
            if (off == len) return buf;
            var trimmed = new byte[off];
            Buffer.BlockCopy(buf, 0, trimmed, 0, off);
            return trimmed;
        }

        private void Add(FileResult result, string key, string detail, int recoveredWeight = 0)
        {
            var info = SignatureTable.DetectorInfo(key);
            if (info.Weight <= 0) return;
            int weight = Math.Max(info.Weight, recoveredWeight);
            var severity = weight >= 85 ? Severity.Critical : weight >= 50 ? Severity.High : info.Sev;
            result.Findings.Add(new Finding
            {
                Name = key,
                Weight = weight,
                Detector = key.Split('.')[0].ToLowerInvariant(),
                Family = info.Family,
                Severity = severity,
                Detail = detail
            });
        }

        private void AnalyzePe(byte[] data, FileResult result, string label)
        {
            if (data.Length < 0x40 || data[0] != 0x4D || data[1] != 0x5A) return;
            PeImage pe;
            try { pe = PeParser.Parse(data); }
            catch (Exception ex) { _report.SkippedBag.Add(new SkippedFile { Path = result.Path + label, Reason = "pe parse error: " + ex.Message }); return; }
            if (!pe.IsPe) return;

            string prefix = string.IsNullOrEmpty(label) ? "" : label + ": ";
            result.ImpHash = string.IsNullOrEmpty(result.ImpHash) ? pe.ImpHash : result.ImpHash;

            if (pe.Sections.Count == 0)
            {
                Add(result, "PE.NoSections", prefix + (pe.ParseError ?? "section table is empty"));
                return;
            }

            foreach (var s in pe.Sections)
            {
                if (s.Entropy > 7.8) Add(result, "PE.ExtremeEntropySection", $"{prefix}section {s.Name} entropy {s.Entropy:F2}");
                else if (s.Entropy > 7.2) Add(result, "PE.HighEntropySection", $"{prefix}section {s.Name} entropy {s.Entropy:F2}");
                if (s.IsExecutable && s.IsWritable) Add(result, "PE.RwxSection", $"{prefix}section {s.Name} is writable and executable");
                if (s.RawSize == 0 && s.VirtualSize > 0x1000)
                    Add(result, "PE.SectionRawVirtualMismatch", $"{prefix}section {s.Name} has zero raw size but virtual size 0x{s.VirtualSize:X}");
                else if (s.RawSize > 0 && s.VirtualSize > s.RawSize * 4 && s.VirtualSize > 0x10000)
                    Add(result, "PE.SectionRawVirtualMismatch", $"{prefix}section {s.Name} virtual size 0x{s.VirtualSize:X} greatly exceeds raw size 0x{s.RawSize:X}");
                if (!PeParser.IsStandardSectionName(s.Name) && s.Name.Length > 0)
                    Add(result, "PE.NonStandardSectionName", $"{prefix}non-standard section name '{s.Name}'");
            }

            if (pe.HasTlsCallbacks) Add(result, "PE.TlsCallbacks", prefix + "TLS directory declares callbacks that run before the entry point");

            var epSection = pe.Sections.FirstOrDefault(s =>
                pe.EntryPointRva >= s.VirtualAddress &&
                pe.EntryPointRva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize));
            if (epSection == null && pe.EntryPointRva != 0)
                Add(result, "PE.EntryPointOutsideSections", $"{prefix}entry point RVA 0x{pe.EntryPointRva:X} is outside every section");
            else if (epSection != null)
            {
                if (pe.Sections.Count > 1 && ReferenceEquals(epSection, pe.Sections[pe.Sections.Count - 1]))
                    Add(result, "PE.EntryPointLastSection", $"{prefix}entry point RVA 0x{pe.EntryPointRva:X} lies in the last section {epSection.Name}");
                if (epSection.IsWritable)
                    Add(result, "PE.EntryPointWritableSection", $"{prefix}entry point section {epSection.Name} is writable");
            }

            var importMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "WriteProcessMemory", "PE.ImportWriteProcessMemory" },
                { "NtWriteVirtualMemory", "PE.ImportWriteProcessMemory" },
                { "CreateRemoteThread", "PE.ImportCreateRemoteThread" },
                { "CreateRemoteThreadEx", "PE.ImportCreateRemoteThread" },
                { "RtlCreateUserThread", "PE.ImportCreateRemoteThread" },
                { "CryptUnprotectData", "PE.ImportCryptUnprotectData" },
                { "SetWindowsHookExA", "PE.ImportSetWindowsHookEx" },
                { "SetWindowsHookExW", "PE.ImportSetWindowsHookEx" },
                { "NtProtectVirtualMemory", "PE.ImportNtApiUnhook" },
                { "NtMapViewOfSection", "PE.ImportNtApiUnhook" },
                { "NtUnmapViewOfSection", "PE.ImportNtApiUnhook" },
            };
            foreach (var imp in pe.Imports)
                if (importMap.TryGetValue(imp, out var key)) Add(result, key, $"{prefix}imports {imp}");

            bool getProc = pe.Imports.Any(i => string.Equals(i, "GetProcAddress", StringComparison.OrdinalIgnoreCase));
            bool loadLib = pe.Imports.Any(i => i.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase));
            if (getProc && loadLib && pe.Imports.Count < 40)
                Add(result, "PE.ImportDynamicResolution", $"{prefix}small import table resolving APIs dynamically via LoadLibrary/GetProcAddress");
            if (pe.Imports.Count > 0 && pe.Imports.Count < 8 && !pe.IsDotNet)
                Add(result, "PE.MinimalImports", $"{prefix}only {pe.Imports.Count} imported symbols, typical of packed images");

            foreach (var hint in pe.PackerHints) Add(result, "PE.Packer" + hint, $"{prefix}packer indicator: {hint}");

            if (pe.ResourceContainsPe) Add(result, "PE.SuspiciousResourceExe", prefix + "resource directory embeds another PE image");
            if (!pe.HasAuthenticode) Add(result, "PE.NoAuthenticodeSignature", prefix + "no Authenticode certificate directory present");
            if (pe.CheckSum == 0 && !pe.IsDotNet) Add(result, "PE.CheckSumMismatch", prefix + "optional header checksum is zero");
            if (pe.TimeDateStamp == 0) Add(result, "PE.TimestampZero", prefix + "compile timestamp is zero");
            else
            {
                var stamp = DateTimeOffset.FromUnixTimeSeconds(pe.TimeDateStamp).UtcDateTime;
                if (stamp > DateTime.UtcNow.AddDays(1)) Add(result, "PE.TimestampInFuture", $"{prefix}compile timestamp {Util.Iso8601Utc(stamp)} is in the future");
            }
            if (pe.IsDotNet)
            {
                Add(result, "PE.DotNetAssembly", prefix + "managed .NET assembly");
                try
                {
                    var dn = DotNetParser.Parse(data, pe);
                    foreach (var h in DotNetParser.Evaluate(dn)) Add(result, h.Key, prefix + h.Detail);
                    if (dn.Parsed && dn.UserStrings.Count > 0)
                    {
                        var joined = string.Join("\n", dn.UserStrings);
                        var bytes = Encoding.ASCII.GetBytes(joined);
                        foreach (var hit in PatternEngine.ScanBuffer(bytes))
                            result.Findings.Add(new Finding
                            {
                                Name = hit.Signature.Name,
                                Weight = hit.Signature.Weight,
                                Detector = "dotnet",
                                Family = hit.Signature.Family,
                                Severity = hit.Signature.Severity,
                                Detail = $"{prefix}managed user string heap match"
                            });
                        foreach (var h in Deobfuscator.Analyze(bytes, bytes.Length, joined)) Add(result, h.Key, prefix + "user strings: " + h.Detail, h.RecoveredWeight);
                    }
                }
                catch (Exception) { }
            }
            if (!string.IsNullOrEmpty(pe.RichHash) && string.IsNullOrEmpty(result.RichHash)) result.RichHash = pe.RichHash;
            if (!pe.HasRichHeader && !pe.IsDotNet) Add(result, "PE.RichHeaderMissing", prefix + "Rich header absent, the image was not linked by a standard Microsoft toolchain");
            if (pe.Sections.Count > 12) Add(result, "PE.TooManySections", $"{prefix}{pe.Sections.Count} sections, well above a typical compiler output");
            foreach (var sec in pe.Sections)
            {
                bool nonAscii = sec.Name.Any(c => c < 32 || c > 126);
                if (nonAscii) { Add(result, "PE.NonAsciiSectionName", prefix + "section name contains non-printable bytes"); break; }
            }
            foreach (var h in ResourceWalker.Walk(data, pe)) Add(result, h.Key, prefix + h.Detail);
            if (pe.OverlaySize > 64 * 1024 && pe.OverlayEntropy > 7.0)
                Add(result, "PE.OverlayLargeHighEntropy", $"{prefix}overlay of {Util.HumanSize(pe.OverlaySize)} at offset {pe.OverlayOffset} with entropy {pe.OverlayEntropy:F2}");

            foreach (var s in pe.Sections)
            {
                if (s.RawPointer >= (uint)data.Length || s.RawSize == 0) continue;
                int count = (int)Math.Min(s.RawSize, (uint)(data.Length - s.RawPointer));
                if (count <= 0) continue;
                var strings = PeParser.ExtractStrings(data, (int)s.RawPointer, count, 6, 6000);
                if (strings.Count == 0) continue;
                var joined = string.Join("\n", strings);
                foreach (var h in Deobfuscator.Analyze(Encoding.ASCII.GetBytes(joined), joined.Length, joined))
                    Add(result, h.Key, $"{prefix}section {s.Name}: {h.Detail}", h.RecoveredWeight);
            }
        }

        private void ScanZipFile(string path, FileResult result, int depth)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                ScanZipStream(fs, result, depth, Path.GetFileName(path));
            }
            catch (InvalidDataException ex) { _report.SkippedBag.Add(new SkippedFile { Path = path, Reason = "invalid zip container: " + ex.Message }); }
            catch (IOException ex) { _report.SkippedBag.Add(new SkippedFile { Path = path, Reason = "zip io error: " + ex.Message }); }
        }

        private void ScanZipStream(Stream stream, FileResult result, int depth, string label)
        {
            if (depth > _opt.MaxNestedArchiveDepth)
            {
                Add(result, "Archive.NestedDepthExceeded", $"{label}: nested archive depth limit {_opt.MaxNestedArchiveDepth} reached");
                return;
            }
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, true);
            if (zip.Entries.Count > _opt.MaxArchiveEntries)
            {
                Add(result, "Archive.TooManyEntries", $"{label}: {zip.Entries.Count} entries exceed the cap of {_opt.MaxArchiveEntries}");
                return;
            }

            long totalCompressed = 0, totalDecompressed = 0;
            foreach (var entry in zip.Entries)
            {
                if (IsTraversal(entry.FullName))
                {
                    Add(result, "Archive.PathTraversal", $"{label}: entry '{entry.FullName}' escapes the extraction root");
                    continue;
                }
                if (FileTyper.IsDoubleExtension(entry.Name))
                    Add(result, "Archive.DoubleExtensionEntry", $"{label}: entry '{entry.Name}' uses a decoy double extension");
                if (entry.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    Add(result, "Archive.LnkDropper", $"{label}: archive delivers a shortcut file '{entry.Name}'");
                if (entry.Length == 0 && entry.CompressedLength == 0) continue;

                totalCompressed += entry.CompressedLength;
                totalDecompressed += entry.Length;
                if (totalDecompressed > _opt.MaxDecompressedBytes)
                {
                    Add(result, "Archive.ZipBombTotalSize", $"{label}: cumulative decompressed size {Util.HumanSize(totalDecompressed)} exceeds the cap {Util.HumanSize(_opt.MaxDecompressedBytes)}");
                    return;
                }
                long ratio = entry.CompressedLength > 0 ? entry.Length / entry.CompressedLength : 0;
                if (ratio > 100)
                {
                    Add(result, "Archive.ZipBombRatio", $"{label}: entry '{entry.FullName}' expands {ratio}:1, above the 100:1 limit");
                    continue;
                }

                byte[] data;
                try
                {
                    using var es = entry.Open();
                    using var ms = new MemoryStream();
                    var buf = new byte[1 << 20];
                    long copied = 0;
                    int r;
                    while ((r = es.Read(buf, 0, buf.Length)) > 0)
                    {
                        copied += r;
                        if (copied > _opt.MaxDecompressedBytes) break;
                        ms.Write(buf, 0, r);
                    }
                    data = ms.ToArray();
                }
                catch (Exception ex)
                {
                    if (FileTyper.IsExecutableExtension(entry.Name))
                        Add(result, "Archive.UnsupportedCompressedExecutable",
                            $"{label}: entry '{entry.FullName}' uses an unsupported compression method ({ex.GetType().Name}) and carries an executable extension");
                    else
                        _report.SkippedBag.Add(new SkippedFile { Path = label + "!" + entry.FullName, Reason = "unsupported compression method: " + ex.Message });
                    continue;
                }

                foreach (var hit in PatternEngine.ScanBuffer(data))
                    result.Findings.Add(new Finding
                    {
                        Name = hit.Signature.Name,
                        Weight = hit.Signature.Weight,
                        Detector = "archive",
                        Family = hit.Signature.Family,
                        Severity = hit.Signature.Severity,
                        Detail = $"{label}!{entry.FullName} at offset {hit.Offset}"
                    });

                foreach (var h in DocumentAnalyzer.AnalyzeOoxmlEntry(entry.FullName, data, data.Length)) Add(result, h.Key, h.Detail);

                var text = Encoding.ASCII.GetString(data, 0, Math.Min(data.Length, DeepAnalysisCap));
                foreach (var h in Deobfuscator.Analyze(data, data.Length, text)) Add(result, h.Key, $"{label}!{entry.FullName}: {h.Detail}", h.RecoveredWeight);
                EvaluateRules(result, text.ToLowerInvariant(), "zip-entry", label + "!" + entry.FullName);
                if (entry.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    foreach (var h in LnkAnalyzer.Analyze(data, data.Length)) Add(result, h.Key, $"{label}!{entry.FullName}: {h.Detail}");

                foreach (var s in ShellcodeHeuristics.Analyze(data, data.Length)) Add(result, s.Key, $"{label}!{entry.FullName}: {s.Detail}");

                AnalyzePe(data, result, label + "!" + entry.FullName);

                if (data.Length > 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03)
                {
                    using var nested = new MemoryStream(data, false);
                    try { ScanZipStream(nested, result, depth + 1, label + "!" + entry.FullName); }
                    catch (InvalidDataException) { }
                }
            }
            if (totalCompressed > 0 && totalDecompressed / totalCompressed > 100)
                Add(result, "Archive.ZipBombRatio", $"{label}: aggregate expansion {totalDecompressed / totalCompressed}:1 exceeds the 100:1 limit");
        }

        private static bool IsTraversal(string entryName)
        {
            if (string.IsNullOrEmpty(entryName)) return false;
            var n = entryName.Replace('\\', '/');
            if (n.StartsWith("/", StringComparison.Ordinal)) return true;
            if (n.Length > 1 && n[1] == ':') return true;
            foreach (var seg in n.Split('/')) if (seg == "..") return true;
            return false;
        }
    }

    public static class Reporter
    {
        public static void Console_(ScanReport report, Options opt)
        {
            if (opt.Quiet) return;
            Write($"{Product.Name} {Product.Version} — {Product.Banner}", ConsoleColor.Cyan, opt.NoColor);
            Write(new string('-', 72), ConsoleColor.DarkGray, opt.NoColor);
            Write($"root      : {report.RootPath}", ConsoleColor.Gray, opt.NoColor);
            Write($"started   : {report.StartedUtc}", ConsoleColor.Gray, opt.NoColor);
            Write($"duration  : {report.DurationSeconds:F3} s", ConsoleColor.Gray, opt.NoColor);
            Write($"scanned   : {report.FilesScanned} file(s), {Util.HumanSize(report.BytesScanned)}", ConsoleColor.Gray, opt.NoColor);
            Console.WriteLine();

            foreach (var r in report.Results)
            {
                if (r.VerdictText == "Clean" && !opt.Verbose) continue;
                if (r.Score < opt.MinScore) continue;
                var color = r.VerdictText switch
                {
                    "Confirmed" => ConsoleColor.Red,
                    "Suspicious" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };
                Write($"[{r.VerdictText.ToUpperInvariant()}] score={r.Score} type={r.FileType} {r.Path}", color, opt.NoColor);
                if (r.VerdictText == "Clean" && !opt.Verbose) continue;
                Write($"    sha256 {r.Sha256}", ConsoleColor.DarkGray, opt.NoColor);
                if (r.Families.Count > 0) Write($"    families: {string.Join(", ", r.Families)}", ConsoleColor.DarkGray, opt.NoColor);
                if (r.Techniques.Count > 0) Write($"    att&ck  : {string.Join(", ", r.Techniques)}", ConsoleColor.DarkGray, opt.NoColor);
                foreach (var f in r.Findings)
                    Write($"    - [{f.Severity}] {f.Name} (w={f.Weight}, {f.Detector}) {f.Detail}", ConsoleColor.DarkGray, opt.NoColor);
                if (!string.IsNullOrEmpty(r.QuarantineNote))
                    Write($"    quarantine: {r.QuarantineNote}", ConsoleColor.Magenta, opt.NoColor);
            }

            if (report.Skipped.Count > 0)
            {
                Console.WriteLine();
                Write($"skipped ({report.Skipped.Count}):", ConsoleColor.Yellow, opt.NoColor);
                foreach (var s in report.Skipped) Write($"    {s.Path} :: {s.Reason}", ConsoleColor.DarkYellow, opt.NoColor);
            }
            if (report.ReparsePoints.Count > 0)
            {
                Console.WriteLine();
                Write($"reparse points not followed ({report.ReparsePoints.Count}):", ConsoleColor.Yellow, opt.NoColor);
                foreach (var p in report.ReparsePoints) Write("    " + p, ConsoleColor.DarkYellow, opt.NoColor);
            }

            int confirmed = report.Results.Count(r => r.VerdictText == "Confirmed");
            int suspicious = report.Results.Count(r => r.VerdictText == "Suspicious");
            int clean = report.Results.Count(r => r.VerdictText == "Clean");
            Console.WriteLine();
            if (opt.ShowStats)
            {
                if (report.FamilyCounts.Count > 0)
                {
                    Write("families  :", ConsoleColor.Cyan, opt.NoColor);
                    foreach (var kv in report.FamilyCounts.OrderByDescending(k => k.Value).Take(12))
                        Write($"    {kv.Key,-22} {new string('#', Math.Min(40, kv.Value))} {kv.Value}", ConsoleColor.DarkGray, opt.NoColor);
                }
                if (report.TechniqueCounts.Count > 0)
                    Write("ATT&CK    : " + string.Join(", ", report.TechniqueCounts.OrderByDescending(k => k.Value).Take(14).Select(k => $"{k.Key}({k.Value})")),
                        ConsoleColor.Cyan, opt.NoColor);
                double mb = report.BytesScanned / 1048576.0;
                double rate = report.DurationSeconds > 0 ? mb / report.DurationSeconds : 0;
                Write($"throughput: {rate:F1} MB/s, {report.CacheHits} cache hit(s)", ConsoleColor.Cyan, opt.NoColor);
                Console.WriteLine();
            }
            Write($"summary   : {confirmed} confirmed, {suspicious} suspicious, {clean} clean", ConsoleColor.Cyan, opt.NoColor);
        }

        private static void Write(string text, ConsoleColor color, bool noColor)
        {
            if (noColor) { Console.WriteLine(text); return; }
            var prev = Console.ForegroundColor;
            try { Console.ForegroundColor = color; Console.WriteLine(text); }
            finally { Console.ForegroundColor = prev; }
        }

        public static string Json(ScanReport report)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            sb.Append("  \"schemaVersion\": 2,\n");
            sb.Append("  \"product\": \"").Append(Product.Name).Append("\",\n");
            sb.Append("  \"engineVersion\": \"").Append(Product.Version).Append("\",\n");
            sb.Append("  \"scan\": {\n");
            sb.Append("    \"path\": \"").Append(Util.JsonEscape(report.RootPath)).Append("\",\n");
            sb.Append("    \"timestampUtc\": \"").Append(report.StartedUtc).Append("\",\n");
            sb.Append("    \"durationSeconds\": ").Append(report.DurationSeconds.ToString("F3", CultureInfo.InvariantCulture)).Append(",\n");
            sb.Append("    \"filesScanned\": ").Append(report.FilesScanned).Append(",\n");
            sb.Append("    \"bytesScanned\": ").Append(report.BytesScanned).Append(",\n");
            sb.Append("    \"confirmed\": ").Append(report.Results.Count(r => r.VerdictText == "Confirmed")).Append(",\n");
            sb.Append("    \"suspicious\": ").Append(report.Results.Count(r => r.VerdictText == "Suspicious")).Append(",\n");
            sb.Append("    \"clean\": ").Append(report.Results.Count(r => r.VerdictText == "Clean")).Append('\n');
            sb.Append("  },\n");
            sb.Append("  \"results\": [\n");
            for (int i = 0; i < report.Results.Count; i++)
            {
                var r = report.Results[i];
                sb.Append("    {\n");
                sb.Append("      \"path\": \"").Append(Util.JsonEscape(r.Path)).Append("\",\n");
                sb.Append("      \"size\": ").Append(r.Size).Append(",\n");
                sb.Append("      \"fileType\": \"").Append(Util.JsonEscape(r.FileType)).Append("\",\n");
                sb.Append("      \"declaredType\": \"").Append(Util.JsonEscape(r.DeclaredType)).Append("\",\n");
                sb.Append("      \"typeMismatch\": ").Append(r.TypeMismatch ? "true" : "false").Append(",\n");
                sb.Append("      \"hashes\": { \"md5\": \"").Append(r.Md5).Append("\", \"sha1\": \"").Append(r.Sha1).Append("\", \"sha256\": \"").Append(r.Sha256).Append("\" },\n");
                sb.Append("      \"impHash\": \"").Append(r.ImpHash).Append("\",\n");
                sb.Append("      \"fuzzyFingerprint\": \"").Append(r.Fingerprint).Append("\",\n");
                sb.Append("      \"verdict\": \"").Append(r.VerdictText).Append("\",\n");
                sb.Append("      \"score\": ").Append(r.Score).Append(",\n");
                sb.Append("      \"scanMilliseconds\": ").Append(r.ScanMilliseconds.ToString("F2", CultureInfo.InvariantCulture)).Append(",\n");
                sb.Append("      \"families\": [").Append(string.Join(", ", r.Families.Select(f => "\"" + Util.JsonEscape(f) + "\""))).Append("],\n");
                sb.Append("      \"ruleMatches\": [").Append(string.Join(", ", r.RuleMatches.Distinct().Select(f => "\"" + Util.JsonEscape(f) + "\""))).Append("],\n");
                sb.Append("      \"quarantined\": ").Append(r.Quarantined ? "true" : "false").Append(",\n");
                sb.Append("      \"quarantineNote\": \"").Append(Util.JsonEscape(r.QuarantineNote)).Append("\",\n");
                sb.Append("      \"findings\": [\n");
                for (int k = 0; k < r.Findings.Count; k++)
                {
                    var f = r.Findings[k];
                    sb.Append("        { \"name\": \"").Append(Util.JsonEscape(f.Name))
                      .Append("\", \"weight\": ").Append(f.Weight)
                      .Append(", \"severity\": \"").Append(f.Severity)
                      .Append("\", \"family\": \"").Append(Util.JsonEscape(f.Family))
                      .Append("\", \"detector\": \"").Append(Util.JsonEscape(f.Detector))
                      .Append("\", \"detail\": \"").Append(Util.JsonEscape(f.Detail)).Append("\" }");
                    sb.Append(k < r.Findings.Count - 1 ? ",\n" : "\n");
                }
                sb.Append("      ]\n");
                sb.Append(i < report.Results.Count - 1 ? "    },\n" : "    }\n");
            }
            sb.Append("  ],\n");
            sb.Append("  \"skipped\": [\n");
            for (int i = 0; i < report.Skipped.Count; i++)
            {
                sb.Append("    { \"path\": \"").Append(Util.JsonEscape(report.Skipped[i].Path))
                  .Append("\", \"reason\": \"").Append(Util.JsonEscape(report.Skipped[i].Reason)).Append("\" }");
                sb.Append(i < report.Skipped.Count - 1 ? ",\n" : "\n");
            }
            sb.Append("  ],\n");
            sb.Append("  \"reparsePoints\": [\n");
            for (int i = 0; i < report.ReparsePoints.Count; i++)
            {
                sb.Append("    \"").Append(Util.JsonEscape(report.ReparsePoints[i])).Append('"');
                sb.Append(i < report.ReparsePoints.Count - 1 ? ",\n" : "\n");
            }
            sb.Append("  ]\n}\n");
            return sb.ToString();
        }

        public static string Sarif(ScanReport report)
        {
            var rules = new Dictionary<string, Finding>(StringComparer.Ordinal);
            foreach (var r in report.Results)
                foreach (var f in r.Findings)
                    if (!rules.ContainsKey(f.Name)) rules[f.Name] = f;

            var sb = new StringBuilder();
            sb.Append("{\n  \"version\": \"2.1.0\",\n");
            sb.Append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
            sb.Append("  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n");
            sb.Append("          \"name\": \"").Append(Product.Name).Append("\",\n");
            sb.Append("          \"version\": \"").Append(Product.Version).Append("\",\n");
            sb.Append("          \"rules\": [\n");
            int ri = 0;
            foreach (var kv in rules)
            {
                var f = kv.Value;
                sb.Append("            { \"id\": \"").Append(Util.JsonEscape(f.Name))
                  .Append("\", \"name\": \"").Append(Util.JsonEscape(f.Name))
                  .Append("\", \"shortDescription\": { \"text\": \"").Append(Util.JsonEscape(f.Family)).Append(" detector\" }")
                  .Append(", \"properties\": { \"weight\": ").Append(f.Weight)
                  .Append(", \"family\": \"").Append(Util.JsonEscape(f.Family)).Append("\", \"tags\": [")
                  .Append(string.Join(", ", AttackMap.For(f.Family).Select(t => "\"" + t + "\"")))
                  .Append("] } }");
                sb.Append(++ri < rules.Count ? ",\n" : "\n");
            }
            sb.Append("          ]\n        }\n      },\n");
            sb.Append("      \"results\": [\n");
            var entries = new List<string>();
            foreach (var r in report.Results)
            {
                foreach (var f in r.Findings)
                {
                    string level = f.Severity == Severity.Critical || f.Severity == Severity.High ? "error"
                                 : f.Severity == Severity.Medium ? "warning" : "note";
                    var e = new StringBuilder();
                    e.Append("        {\n          \"ruleId\": \"").Append(Util.JsonEscape(f.Name)).Append("\",\n");
                    e.Append("          \"level\": \"").Append(level).Append("\",\n");
                    e.Append("          \"message\": { \"text\": \"").Append(Util.JsonEscape(f.Detail)).Append("\" },\n");
                    e.Append("          \"properties\": { \"verdict\": \"").Append(r.VerdictText)
                     .Append("\", \"score\": ").Append(r.Score)
                     .Append(", \"sha256\": \"").Append(r.Sha256).Append("\" },\n");
                    e.Append("          \"locations\": [ { \"physicalLocation\": { \"artifactLocation\": { \"uri\": \"")
                     .Append(Util.JsonEscape(r.Path.Replace('\\', '/'))).Append("\" } } } ]\n        }");
                    entries.Add(e.ToString());
                }
            }
            sb.Append(string.Join(",\n", entries));
            sb.Append("\n      ]\n    }\n  ]\n}\n");
            return sb.ToString();
        }

        public static string Csv(ScanReport report)
        {
            var sb = new StringBuilder();
            sb.Append("path,verdict,score,fileType,size,sha256,families,findingCount,attackTechniques\n");
            foreach (var r in report.Results)
            {
                sb.Append(Util.CsvEscape(r.Path)).Append(',')
                  .Append(r.VerdictText).Append(',')
                  .Append(r.Score).Append(',')
                  .Append(r.FileType).Append(',')
                  .Append(r.Size).Append(',')
                  .Append(r.Sha256).Append(',')
                  .Append(Util.CsvEscape(string.Join("|", r.Families))).Append(',')
                  .Append(r.Findings.Count).Append(',')
                  .Append(Util.CsvEscape(string.Join("|", r.Techniques))).Append('\n');
            }
            return sb.ToString();
        }

        public static string Html(ScanReport report)
        {
            int confirmed = report.Results.Count(r => r.VerdictText == "Confirmed");
            int suspicious = report.Results.Count(r => r.VerdictText == "Suspicious");
            int clean = report.Results.Count(r => r.VerdictText == "Clean");

            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.Append("<title>").Append(Product.Name).Append(" scan report</title><style>");
            sb.Append("*{box-sizing:border-box}body{font-family:'Segoe UI',Roboto,Arial,sans-serif;background:#0e1116;color:#e4e9f0;margin:0;padding:32px}");
            sb.Append("h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px;color:#8fb3d9}");
            sb.Append(".sub{color:#7d8896;font-size:13px;margin-bottom:24px}");
            sb.Append(".cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px}");
            sb.Append(".card{background:#161b23;border:1px solid #242c38;border-radius:10px;padding:14px 20px;min-width:140px}");
            sb.Append(".card .n{font-size:26px;font-weight:700}.card .l{font-size:12px;color:#7d8896;text-transform:uppercase;letter-spacing:.5px}");
            sb.Append("table{border-collapse:collapse;width:100%;font-size:13px}");
            sb.Append("th,td{border:1px solid #242c38;padding:8px 10px;text-align:left;vertical-align:top}");
            sb.Append("th{background:#161b23;color:#8fb3d9;font-weight:600}");
            sb.Append("tr:nth-child(even) td{background:#12161d}");
            sb.Append(".Confirmed{color:#ff6b6b;font-weight:700}.Suspicious{color:#ffc857;font-weight:700}.Clean{color:#5fd08a;font-weight:700}");
            sb.Append("code{font-family:Consolas,'SF Mono',monospace;font-size:12px;color:#9fb3c8;word-break:break-all}");
            sb.Append("ul{margin:0;padding-left:18px}li{margin-bottom:3px}");
            sb.Append(".sev{display:inline-block;border-radius:4px;padding:0 6px;font-size:11px;margin-right:6px}");
            sb.Append(".Critical{background:#5c1a1a;color:#ff9d9d}.High{background:#5c3a12;color:#ffc07a}.Medium{background:#4a4413;color:#f2e28a}.Low{background:#1e3a4a;color:#95cfe8}.Info{background:#25303c;color:#a9b6c4}");

            sb.Append("</style></head><body>");
            sb.Append("<h1>").Append(Product.Name).Append(" scan report</h1>");
            sb.Append("<div class=\"sub\">").Append(Product.Engine).Append(" v").Append(Product.Version)
              .Append(" &middot; ").Append(report.StartedUtc).Append(" &middot; ")
              .Append(report.DurationSeconds.ToString("F3", CultureInfo.InvariantCulture)).Append(" s &middot; ")
              .Append(Util.HtmlEscape(report.RootPath)).Append("</div>");

            sb.Append("<div class=\"cards\">");
            sb.Append("<div class=\"card\"><div class=\"n\">").Append(report.FilesScanned).Append("</div><div class=\"l\">files</div></div>");
            sb.Append("<div class=\"card\"><div class=\"n\" style=\"color:#ff6b6b\">").Append(confirmed).Append("</div><div class=\"l\">confirmed</div></div>");
            sb.Append("<div class=\"card\"><div class=\"n\" style=\"color:#ffc857\">").Append(suspicious).Append("</div><div class=\"l\">suspicious</div></div>");
            sb.Append("<div class=\"card\"><div class=\"n\" style=\"color:#5fd08a\">").Append(clean).Append("</div><div class=\"l\">clean</div></div>");
            sb.Append("<div class=\"card\"><div class=\"n\">").Append(Util.HumanSize(report.BytesScanned)).Append("</div><div class=\"l\">scanned</div></div>");
            sb.Append("</div>");

            sb.Append("<h2>Results</h2><table><tr><th>Path</th><th>Verdict</th><th>Score</th><th>Type</th><th>SHA-256</th><th>Findings</th></tr>");
            foreach (var r in report.Results)
            {
                sb.Append("<tr><td><code>").Append(Util.HtmlEscape(r.Path)).Append("</code>");
                if (r.Families.Count > 0) sb.Append("<div style=\"color:#7d8896;font-size:11px\">").Append(Util.HtmlEscape(string.Join(", ", r.Families))).Append("</div>");
                if (r.Techniques.Count > 0) sb.Append("<div style=\"color:#5f7a99;font-size:11px\">").Append(Util.HtmlEscape(string.Join(" ", r.Techniques))).Append("</div>");
                sb.Append("</td>");
                sb.Append("<td class=\"").Append(r.VerdictText).Append("\">").Append(r.VerdictText).Append("</td>");
                sb.Append("<td>").Append(r.Score).Append("</td>");
                sb.Append("<td>").Append(Util.HtmlEscape(r.FileType)).Append("</td>");
                sb.Append("<td><code>").Append(r.Sha256).Append("</code></td><td>");
                if (r.Findings.Count == 0) sb.Append("&mdash;");
                else
                {
                    sb.Append("<ul>");
                    foreach (var f in r.Findings)
                        sb.Append("<li><span class=\"sev ").Append(f.Severity).Append("\">").Append(f.Severity).Append("</span><b>")
                          .Append(Util.HtmlEscape(f.Name)).Append("</b> (w=").Append(f.Weight).Append(") ")
                          .Append(Util.HtmlEscape(f.Detail)).Append("</li>");
                    sb.Append("</ul>");
                }
                if (!string.IsNullOrEmpty(r.QuarantineNote))
                    sb.Append("<div style=\"color:#d98fd9;font-size:12px\">").Append(Util.HtmlEscape(r.QuarantineNote)).Append("</div>");
                sb.Append("</td></tr>");
            }
            sb.Append("</table>");

            if (report.FamilyCounts.Count > 0)
            {
                sb.Append("<h2>Threat families</h2><table><tr><th>Family</th><th>Files</th><th>ATT&amp;CK</th><th></th></tr>");
                int maxCount = report.FamilyCounts.Values.Max();
                foreach (var kv in report.FamilyCounts.OrderByDescending(k => k.Value))
                {
                    int pct = maxCount > 0 ? (int)(100.0 * kv.Value / maxCount) : 0;
                    sb.Append("<tr><td>").Append(Util.HtmlEscape(kv.Key)).Append("</td><td>").Append(kv.Value).Append("</td><td><code>")
                      .Append(string.Join(" ", AttackMap.For(kv.Key))).Append("</code></td><td style=\"width:40%\">")
                      .Append("<div style=\"background:#2a3340;border-radius:4px;height:12px\"><div style=\"width:")
                      .Append(pct).Append("%;background:#4d8fd6;height:12px;border-radius:4px\"></div></div></td></tr>");
                }
                sb.Append("</table>");
            }

            sb.Append("<h2>Skipped</h2><table><tr><th>Path</th><th>Reason</th></tr>");
            if (report.Skipped.Count == 0) sb.Append("<tr><td colspan=\"2\">None</td></tr>");
            foreach (var s in report.Skipped)
                sb.Append("<tr><td><code>").Append(Util.HtmlEscape(s.Path)).Append("</code></td><td>").Append(Util.HtmlEscape(s.Reason)).Append("</td></tr>");
            sb.Append("</table>");

            sb.Append("<h2>Reparse points (not followed)</h2><table><tr><th>Path</th></tr>");
            if (report.ReparsePoints.Count == 0) sb.Append("<tr><td>None</td></tr>");
            foreach (var p in report.ReparsePoints)
                sb.Append("<tr><td><code>").Append(Util.HtmlEscape(p)).Append("</code></td></tr>");
            sb.Append("</table></body></html>");
            return sb.ToString();
        }
    }

    public static class Program
    {
        public static int Main(string[] args)
        {
            try
            {
                if (args.Any(a => a == "-h" || a == "--help")) { Usage(); return 0; }
                var opt = Parse(args);
                if (opt == null) { Usage(); return 3; }

                var dataDirectory = string.IsNullOrWhiteSpace(opt.DataDirectory)
                    ? ArmorAVPaths.DataDirectory
                    : Path.GetFullPath(opt.DataDirectory);
                System.IO.Directory.CreateDirectory(dataDirectory);
                var store = new QuarantineStore(dataDirectory, opt.AllowlistPath);
                var cache = new ScanCache(dataDirectory, opt.UseCache);

                if (opt.ListQuarantine)
                {
                    foreach (var r in store.List())
                        Console.WriteLine($"{r.Id}  {r.TimestampUtc}  {r.Sha256}  {r.OriginalPath}");
                    return 0;
                }
                if (opt.Restore)
                {
                    if (string.IsNullOrEmpty(opt.RestoreId)) { Console.Error.WriteLine("fatal: --restore requires an id"); return 3; }
                    bool ok = store.Restore(opt.RestoreId!, out var msg);
                    Console.WriteLine(msg);
                    return ok ? 0 : 3;
                }
                if (string.IsNullOrEmpty(opt.Path) || (!File.Exists(opt.Path) && !System.IO.Directory.Exists(opt.Path)))
                {
                    Console.Error.WriteLine("fatal: path not found: " + opt.Path);
                    return 3;
                }

                var report = new ScanReport
                {
                    RootPath = Path.GetFullPath(opt.Path),
                    StartedUtc = Util.Iso8601Utc(DateTime.UtcNow)
                };
                var sw = System.Diagnostics.Stopwatch.StartNew();
                new ScanEngine(opt, report, store, cache).Run(opt.Path);
                sw.Stop();
                report.DurationSeconds = sw.Elapsed.TotalSeconds;
                report.CacheHits = cache.Hits;
                report.Consolidate();
                cache.Save();

                Reporter.Console_(report, opt);

                try { File.WriteAllText(opt.JsonPath, Reporter.Json(report)); }
                catch (Exception ex) { Console.Error.WriteLine("warning: JSON report not written: " + ex.Message); }
                if (!string.IsNullOrEmpty(opt.HtmlPath))
                {
                    try { File.WriteAllText(opt.HtmlPath!, Reporter.Html(report)); }
                    catch (Exception ex) { Console.Error.WriteLine("warning: HTML report not written: " + ex.Message); }
                }
                if (!string.IsNullOrEmpty(opt.CsvPath))
                {
                    try { File.WriteAllText(opt.CsvPath!, Reporter.Csv(report)); }
                    catch (Exception ex) { Console.Error.WriteLine("warning: CSV report not written: " + ex.Message); }
                }
                if (!string.IsNullOrEmpty(opt.SarifPath))
                {
                    try { File.WriteAllText(opt.SarifPath!, Reporter.Sarif(report)); }
                    catch (Exception ex) { Console.Error.WriteLine("warning: SARIF report not written: " + ex.Message); }
                }

                if (report.Results.Any(r => r.VerdictText == "Confirmed")) return 2;
                if (report.Results.Any(r => r.VerdictText == "Suspicious")) return 1;
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("fatal: " + ex.GetType().Name + ": " + ex.Message);
                return 3;
            }
        }

        private static Options? Parse(string[] args)
        {
            if (args.Length == 0) return null;
            var o = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--json": if (++i >= args.Length) return null; o.JsonPath = args[i]; break;
                    case "--html": if (++i >= args.Length) return null; o.HtmlPath = args[i]; break;
                    case "--csv": if (++i >= args.Length) return null; o.CsvPath = args[i]; break;
                    case "--quarantine": o.Quarantine = true; break;
                    case "--no-color": o.NoColor = true; break;
                    case "--verbose": o.Verbose = true; break;
                    case "--quiet": o.Quiet = true; break;
                    case "--allowlist": if (++i >= args.Length) return null; o.AllowlistPath = args[i]; break;
                    case "--data-dir": if (++i >= args.Length) return null; o.DataDirectory = args[i]; break;
                    case "--sarif": if (++i >= args.Length) return null; o.SarifPath = args[i]; break;
                    case "--cache": o.UseCache = true; break;
                    case "--stats": o.ShowStats = true; break;
                    case "--fail-fast": o.FailFast = true; break;
                    case "--min-score": if (++i >= args.Length || !int.TryParse(args[i], out var ms)) return null; o.MinScore = ms; break;
                    case "--list-quarantine": o.ListQuarantine = true; break;
                    case "--restore": if (++i >= args.Length) return null; o.Restore = true; o.RestoreId = args[i]; break;
                    case "--max-depth": if (++i >= args.Length || !int.TryParse(args[i], out var d)) return null; o.MaxDepth = d; break;
                    case "--threads": if (++i >= args.Length || !int.TryParse(args[i], out var t)) return null; o.Threads = Math.Max(1, t); break;
                    case "--max-nested-depth": if (++i >= args.Length || !int.TryParse(args[i], out var nd)) return null; o.MaxNestedArchiveDepth = nd; break;
                    case "--max-decompressed": if (++i >= args.Length || !long.TryParse(args[i], out var md)) return null; o.MaxDecompressedBytes = md; break;
                    case "--max-entries": if (++i >= args.Length || !int.TryParse(args[i], out var me)) return null; o.MaxArchiveEntries = me; break;
                    case "--max-file-size": if (++i >= args.Length || !long.TryParse(args[i], out var mf)) return null; o.MaxFileBytes = mf; break;
                    case "-h":
                    case "--help": return null;
                    default:
                        if (args[i].StartsWith("--", StringComparison.Ordinal)) return null;
                        if (string.IsNullOrEmpty(o.Path)) o.Path = args[i];
                        else return null;
                        break;
                }
            }
            if (!o.Restore && !o.ListQuarantine && string.IsNullOrEmpty(o.Path)) return null;
            if (o.MaxDepth < 0 || o.MaxNestedArchiveDepth < 0 || o.MaxDecompressedBytes < 1 ||
                o.MaxArchiveEntries < 1 || o.MaxFileBytes < 1 || o.MinScore < 0) return null;
            return o;
        }

        private static void Usage()
        {
            Console.WriteLine($"{Product.Name} {Product.Version} — {Product.Banner}");
            Console.WriteLine();
            Console.WriteLine("usage: armorav <path> [--json <file>] [--html <file>] [--quarantine] [--max-depth N] [--no-color]");
            Console.WriteLine("       armorav --restore <id> | --list-quarantine");
            Console.WriteLine();
            Console.WriteLine("options:");
            Console.WriteLine("  --json <file>            JSON report path (default ./scan-report.json)");
            Console.WriteLine("  --html <file>            optional HTML report");
            Console.WriteLine("  --csv <file>             optional CSV summary");
            Console.WriteLine("  --sarif <file>           optional SARIF 2.1.0 report for CI pipelines");
            Console.WriteLine("  --data-dir <directory>   app data, cache and encrypted quarantine location");
            Console.WriteLine("  --cache                  reuse results for unchanged files across runs");
            Console.WriteLine("  --stats                  print family and ATT&CK breakdown with throughput");
            Console.WriteLine("  --fail-fast              stop scheduling new files after a confirmed detection");
            Console.WriteLine("  --min-score N            only print files scoring at least N");
            Console.WriteLine("  --quarantine             move confirmed malware (omit for dry-run)");
            Console.WriteLine("  --max-depth N            filesystem recursion limit (default 10)");
            Console.WriteLine("  --max-nested-depth N     nested archive limit (default 5)");
            Console.WriteLine("  --max-decompressed N     decompression cap in bytes (default 524288000)");
            Console.WriteLine("  --max-entries N          archive entry cap (default 10000)");
            Console.WriteLine("  --max-file-size N        skip files above this size");
            Console.WriteLine("  --threads N              parallel workers");
            Console.WriteLine("  --allowlist <file>       hash allowlist, one md5/sha1/sha256 per line");
            Console.WriteLine("  --verbose                print clean files and all findings");
            Console.WriteLine("  --quiet                  suppress console output");
            Console.WriteLine("  --no-color               disable ANSI colors");
            Console.WriteLine();
            Console.WriteLine("exit codes: 0 clean, 1 suspicious, 2 confirmed infected, 3 fatal error");
        }
    }

}
