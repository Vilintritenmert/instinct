#Requires -Version 7.0
<#
.SYNOPSIS
  Static scanner for agent skills and plugins: looks for signs of threats T01–T26 (see references/threats.md).
  Executes nothing from the target — only reads files as bytes and text.
.PARAMETER Path
  A skill folder, a folder with several skills / a plugin / a marketplace, or a single file.
.PARAMETER Json
  Output the result as JSON (with the file inventory and hashes).
.PARAMETER MinSeverity
  Show only findings at or above this severity (LOW by default). Does not affect the exit code.
.PARAMETER Inventory
  In text mode, also list the files with their type and SHA-256.
.NOTES
  Exit code: 2 — there is a CRITICAL, 1 — there is a HIGH, 0 — otherwise.
  Findings are signals for manual review, not a final verdict.

  What the scanner does beyond line-by-line search:
    - joins continued lines (`\`, `|`, PowerShell backtick) so that `curl … \⏎ | sh` stays together;
    - re-runs the rules on the normalized line (NFKC, invisible characters removed, homoglyphs → Latin);
    - decodes base64 blocks and runs the rules over the decoded text;
    - looks for instruction text and trailing data inside images;
    - checks plugin structure (hooks, MCP, LSP, bin/, marketplace.json, nested .git);
    - computes the SHA-256 of every file and an overall tree hash: a verdict applies only to this version.
#>
[CmdletBinding(DefaultParameterSetName='Scan')]
param(
    [Parameter(Mandatory,ParameterSetName='Scan')][string]$Path,
    [Parameter(Mandatory,ParameterSetName='Rules')][switch]$ListRules,
    [switch]$Json,
    [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')][string]$MinSeverity = 'LOW',
    [switch]$Inventory
)

$ErrorActionPreference = 'Stop'
# PowerShell 7.0 uses .NET Core 3.1, before SHA256.HashData and Convert.ToHexString.
# Keep the byte representation identical on every supported runtime.
function Get-BytesSha256([byte[]]$bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
if (-not $ListRules) {
    $target = (Resolve-Path -LiteralPath $Path).Path
    $isFile = Test-Path -LiteralPath $target -PathType Leaf
    $base = if ($isFile) { [IO.Path]::GetDirectoryName($target) } else { $target }
}

# ---------- Rules ----------
# Scope 'fm' — SKILL.md frontmatter only; otherwise every line of every text file.
# Neg    — explicit prohibitions in Markdown prose may lower severity by one. Code and unrelated
#          negations never suppress a finding; a heading only applies to noun-only list items.
# MdSev  — a separate severity for .md (an HTML comment is invisible when rendered there).
# Skip   — lines the rule skips (e.g. a shebang).
# Ext    — the rule applies only to files with these extensions.
# Raw    — the rule is not re-run on normalized/decoded text.
$markup = '.md', '.mdx', '.markdown', '.html', '.htm', '.svg'
$rules = @(
    # ===== T01 Prompt injection =====
    @{ Id='T01'; RuleId='T01-001'; Sev='CRITICAL'; Rx='ignore\s+(all\s+)?(the\s+|any\s+|your\s+)?(previous|prior|above|earlier|system|other)\s+(instructions|rules|prompts?|guidelines)' }
    @{ Id='T01'; RuleId='T01-002'; Sev='CRITICAL'; Rx='disregard\s+(all\s+)?(the\s+)?(previous|prior|your|system)\s+.{0,20}(instructions|rules|guidelines)' }
    @{ Id='T01'; RuleId='T01-003'; Sev='CRITICAL'; Rx='(проігноруй|ігноруй|забудь|відкинь)\s+(всі\s+|усі\s+)?(попередні|системні|свої|інші)\s+(інструкції|правила|вказівки)' }
    @{ Id='T01'; RuleId='T01-004'; Sev='HIGH';     PersonaKeepsRules=$true; Rx='you\s+are\s+now\b|from\s+now\s+on\s+you\s+are|new\s+system\s+prompt|override\s+(the\s+)?system|forget\s+(everything|all)\s+(above|before|you\s+were)|your\s+(real|true|actual)\s+(instructions|task|goal|purpose)' }
    @{ Id='T01'; RuleId='T01-005'; Sev='HIGH';     Rx='(anthropic|openai|the\s+system|administrator|admin|the\s+developers?)\s+(has\s+|have\s+)?(authorized|approved|requires\s+you|instructed\s+you)' }
    @{ Id='T01'; RuleId='T01-006'; Sev='HIGH'; LiteralRole=$true; Rx='</?\s*(system|system-reminder|system_prompt|admin|developer)\s*>|\[/?(SYSTEM|INST|ADMIN)\]|<\|(im_start|im_end|system|endoftext|start_header_id)\|>'; Name='fake system tags / role markers' }
    @{ Id='T01'; RuleId='T01-007'; Sev='HIGH';     Rx='\bDAN\s+mode\b|developer\s+mode\s+enabled|\bjailbreak\b|no\s+(ethical|safety)\s+(guidelines|restrictions|filters)|do\s+not\s+(follow|obey|listen\s+to)\s+(the\s+)?(user|system|developer)|не\s+(слухай|слухайся)\s+(користувач|систем)' }
    @{ Id='T01'; RuleId='T01-008'; Sev='MEDIUM';   Rx='(takes?|has|have)\s+(precedence|priority)\s+over|overrides?\s+(any|all|the|your)\s+(other|previous|prior|system|user|default)|higher\s+priority\s+than|має\s+пріоритет\s+над|важливіш\w*\s+за\s+(системн|інш|попередн)'; Name='claim of higher priority' }

    # ===== T02 Hidden instructions =====
    @{ Id='T02'; RuleId='T02-001'; Sev='CRITICAL'; Raw=$true; EmojiSafe=$true; Rx='[؜᠎​-‏‪-‮⁠-⁤⁦-⁯﻿]|\uDB40[\uDC00-\uDDEF]'; Name='invisible Unicode characters (zero-width, bidi, tag, variation selectors)' }
    @{ Id='T02'; RuleId='T02-002'; Sev='HIGH';     Raw=$true; Rx='[­͏ᅟᅠ឴឵᠋-᠍ㅤﾠ]'; Name='invisible fillers (soft hyphen, Hangul filler…)' }
    @{ Id='T02'; RuleId='T02-003'; Sev='HIGH';     Raw=$true; Rx='[\x1B\x08\x7F]|\r'; Name='terminal control characters (ANSI/BS/CR hide text in a terminal)' }
    @{ Id='T02'; RuleId='T02-004'; Sev='LOW'; MdSev='MEDIUM'; Raw=$true; Rx='<!--'; Name='HTML comment (read its content)' }
    @{ Id='T02'; RuleId='T02-005'; Sev='MEDIUM';   Raw=$true; Ext=$markup; Rx='^\s*\[//\]:\s*#|^\s*\[comment\]:\s*#'; Name='markdown comment (invisible when rendered)' }
    @{ Id='T02'; RuleId='T02-006'; Sev='MEDIUM';   Raw=$true; Ext=$markup; Rx='display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(\.0+)?\s*[;"'']|color\s*:\s*(#fff(fff)?\b|white|transparent)|<\w+[^>]*\shidden[\s>=]'; Name='hidden HTML/CSS content' }
    @{ Id='T02'; RuleId='T02-007'; Sev='MEDIUM';   Raw=$true; Rx='\b(?=\w*[a-z])(?=\w*[Ͱ-ϿЀ-ԯ])\w+\b'; Name='word mixing Latin with Cyrillic/Greek (homoglyph?)' }
    @{ Id='T02'; RuleId='T02-008'; Sev='MEDIUM';   Raw=$true; Rx='\S[ \t]{120,}\S'; Name='text after a long run of spaces (hidden past the screen edge)' }
    @{ Id='T02'; RuleId='T02-009'; Sev='MEDIUM';   Rx='data:(text/html|application/(javascript|x-sh|x-msdownload|octet-stream)|image/svg\+xml)[;,]'; Name='data: URI with active content' }

    # ===== T03 Hiding from the user =====
    @{ Id='T03'; RuleId='T03-001'; Sev='CRITICAL'; Rx='(do\s+not|don''t|never)\s+(tell|inform|mention|reveal|show|notify|alert|warn)\s+.{0,30}(user|human|operator)' }
    @{ Id='T03'; RuleId='T03-002'; Sev='CRITICAL'; Rx='не\s+(кажи|повідомляй|показуй|згадуй|розповідай)\s+.{0,30}користувач' }
    @{ Id='T03'; RuleId='T03-003'; Sev='CRITICAL'; Rx='(hide|conceal|omit|suppress|приховай|замовчи)\s+.{0,40}(from\s+the\s+(user|human)|from\s+(the\s+)?(output|summary|report|logs?)|від\s+користувач\w*|зі\s+звіту)|report\s+(success|that\s+.{0,30}(passed|succeeded))\s+(regardless|anyway|even\s+if|no\s+matter)|звітуй\s+про\s+успіх\s+(незалежно|у\s+будь-якому)' }
    @{ Id='T03'; RuleId='T03-004'; Sev='HIGH';     Rx='\bhistory\s+-c\b|Clear-History|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|wevtutil\s+cl\b|Clear-EventLog|Remove-Item\b.{0,60}ConsoleHost_history|rm\s+.{0,30}\.(bash|zsh)_history'; Name='covering tracks (history, logs)' }
    @{ Id='T03'; RuleId='T03-005'; Sev='MEDIUM';   Neg=$true; SecretQuestion=$true; Rx='\bsilently\b|\bquietly\b|\bcovertly\b|\bsecretly\b|without\s+(asking|telling|confirmation|notifying|permission|approval)|непомітно|потай|приховано|без\s+(відома|підтвердження|дозволу|запиту)' }
    @{ Id='T03'; RuleId='T03-006'; Sev='MEDIUM';   Rx='-WindowStyle\s+Hidden|\bnohup\b|\bdisown\b|\bsetsid\b|CreateNoWindow|\bstart\s+/b\b|\bpythonw\b'; Name='hidden/background process' }

    # ===== T04 Bypassing permissions and protection =====
    @{ Id='T04'; RuleId='T04-001'; Sev='CRITICAL'; Rx='dangerously-?skip-?permissions|bypassPermissions|dangerouslyDisableSandbox|dangerously-bypass-approvals|skipDangerousModePermissionPrompt|--yolo\b|--trust-all-tools|enableAllProjectMcpServers|disableAllHooks' }
    @{ Id='T04'; RuleId='T04-002'; Sev='CRITICAL'; Rx='(disable|turn\s+off|deactivate)\s+(the\s+|your\s+)?(sandbox|safety|antivirus|defender|firewall|security|gatekeeper|selinux|uac)|Set-MpPreference|Add-MpPreference\s+-Exclusion|DisableRealtimeMonitoring|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|\bufw\s+disable|setenforce\s+0|csrutil\s+disable|spctl\s+--master-disable|com\.apple\.quarantine|вимкн\w*\s+(захист|антивірус|пісочниц\w*|брандмауер|файрвол)' }
    @{ Id='T04'; RuleId='T04-003'; Sev='HIGH';     Rx='--no-verify|--no-gpg-sign|Set-ExecutionPolicy\s+(Bypass|Unrestricted)|Unblock-File|\bNOPASSWD\b|chmod\s+(-R\s+)?[0-7]?777\b|--privileged\b|--cap-add\b|--pid=host|--net(work)?=host|docker\.sock|-v\s+/:/' }
    @{ Id='T04'; RuleId='T04-004'; Sev='HIGH';     Rx='Bash\(\s*\*\s*\)|"allow"\s*:\s*\[\s*"(\*|Bash)"|--allowed-?tools\s+["'']?(\*|Bash\b(?!\())|"defaultMode"\s*:\s*"(acceptEdits|dontAsk)"|permissionMode\s*:\s*["'']?(acceptEdits|dontAsk)'; Name='overly broad agent permissions' }
    @{ Id='T04'; RuleId='T04-005'; Sev='MEDIUM';   Rx='-ExecutionPolicy\s+Bypass|auto-?approve|skip\s+(all\s+)?confirmations?|не\s+питай\s+(дозволу|підтвердження)|(do\s+not|don''t|never)\s+ask\s+(for\s+)?(permission|confirmation|approval)' }
    @{ Id='T04'; RuleId='T04-006'; Sev='MEDIUM';   Rx='NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'']?0|sslVerify\s*(=|\s)\s*false|verify\s*=\s*False|GIT_SSL_NO_VERIFY|--insecure\b|\bcurl\b[^\r\n]*\s-k\b|-SkipCertificateCheck|strict-ssl\s*(=|\s)\s*false|--no-check-certificate'; Name='TLS verification disabled' }
    @{ Id='T04'; RuleId='T04-007'; Sev='MEDIUM';   Rx='\bsudo\b|\brunas\b|-Verb\s+RunAs|\bdoas\b|\bpkexec\b'; Name='privilege escalation' }

    # ===== T05 Remote code execution =====
    @{ Id='T05'; RuleId='T05-001'; Sev='CRITICAL'; Rx='\b(curl|wget|fetch)\b[^\r\n|]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+)?(ba|z|da|k|fi)?sh\b' }
    @{ Id='T05'; RuleId='T05-002'; Sev='CRITICAL'; Rx='\b(curl|wget)\b[^\r\n|]*\|\s*(sudo\s+)?(python[23]?|node|perl|ruby|php|pwsh|powershell)\b' }
    @{ Id='T05'; RuleId='T05-003'; Sev='CRITICAL'; Rx='\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\r\n|]*\|\s*(iex|invoke-expression)\b' }
    @{ Id='T05'; RuleId='T05-004'; Sev='CRITICAL'; Rx='\b(iex|invoke-expression)\s*\(?\s*\(?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(system\.)?net\.webclient|\[System\.Net)' }
    @{ Id='T05'; RuleId='T05-005'; Sev='CRITICAL'; Rx='\b(ba|z)?sh\s+<\(\s*(curl|wget)|\b(source|\.)\s+<\(\s*(curl|wget)|\b(eval|exec)\s+["'']?\$\(\s*(curl|wget)|\b(python[23]?|node|perl|ruby|(ba|z)?sh)\s+(-c|-e)\s+["'']?\$\(\s*(curl|wget)' }
    @{ Id='T05'; RuleId='T05-006'; Sev='CRITICAL'; Rx='/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b[^\r\n]{0,40}\s-[a-z]*e\b|\bnc\b[^\r\n]{0,60}\|\s*(ba)?sh\b|\bmkfifo\b.{0,80}\bnc\b|bash\s+-i\s+>&|\bsocat\b.{0,80}exec:|pty\.spawn\(|Net\.Sockets\.TCPClient|os\.dup2\(|\bmsfvenom\b|\bmeterpreter\b'; Name='reverse shell' }
    @{ Id='T05'; RuleId='T05-007'; Sev='HIGH';     Rx='DownloadString\s*\(|DownloadFile\s*\(|Net\.WebClient|Start-BitsTransfer|\bbitsadmin\b|\bmshta\b|regsvr32\b.{0,40}(/i:|scrobj)|rundll32\b.{0,60}(javascript:|url\.dll|https?:)|certutil\b.{0,60}(-urlcache|-decode)|msiexec\b.{0,40}https?://' }
    @{ Id='T05'; RuleId='T05-008'; Sev='MEDIUM';   Rx='\b(curl|wget)\b.{0,100}\s(-o|-O|--output)\b|Invoke-WebRequest.{0,100}-OutFile|chmod\s+\+x|urlretrieve\(' }
    @{ Id='T05'; RuleId='T05-009'; Sev='MEDIUM';   Raw=$true; Rx='<script\b|\son(load|error|click|mouseover|focus)\s*=|javascript:|<foreignObject\b|<iframe\b|<object\b|<embed\b'; Name='active content (script in SVG/HTML)' }

    # ===== T06 Secrets =====
    @{ Id='T06'; RuleId='T06-001'; Sev='HIGH';     Neg=$true; Rx='\.ssh[/\\]|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\.aws[/\\]credentials|\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker[/\\]config\.json|\.kube[/\\]config|\.gnupg[/\\]|\.config[/\\](gh[/\\]hosts|gcloud)|application_default_credentials|\.azure[/\\]|\.vault-token|terraform\.tfstate' }
    @{ Id='T06'; RuleId='T06-002'; Sev='HIGH';     Neg=$true; Rx='\.claude[/\\]\.credentials|\.claude\.json\b|\.codex[/\\]auth|\.config[/\\]claude|claude_desktop_config.{0,40}(token|key|env)|\.gemini[/\\]oauth_creds|github-copilot[/\\](hosts|apps)\.json|opencode[/\\]auth\.json'; Name='the agent''s own credentials' }
    @{ Id='T06'; RuleId='T06-003'; Sev='HIGH';     Neg=$true; Rx='Login\s+Data|Local\s+State|cookies\.sqlite|[/\\]Cookies\b|\bkeychain\b|find-(generic|internet)-password|dump-keychain|\bcmdkey\b|\bvaultcmd\b|Get-StoredCredential|logins\.json|key4\.db' }
    @{ Id='T06'; RuleId='T06-004'; Sev='HIGH';     Neg=$true; Rx='wallet\.dat|\.ethereum[/\\]keystore|\.electrum[/\\]|nkbihfbeogaeaoehlefnkodbefgpgknn|[/\\]Exodus[/\\]|\.config[/\\]solana'; Name='crypto wallets' }
    @{ Id='T06'; RuleId='T06-005'; Sev='HIGH';     Neg=$true; Rx='/etc/shadow|/proc/\S*/environ|\.(bash|zsh|python|psql|mysql)_history|ConsoleHost_history'; Name='system credentials / command history' }
    @{ Id='T06'; RuleId='T06-006'; Sev='HIGH';     Rx='169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200'; Name='cloud machine metadata (temporary keys)' }
    @{ Id='T06'; RuleId='T06-007'; Sev='HIGH';     Neg=$true; Rx='gh\s+auth\s+token|gcloud\s+auth\s+print-(access|identity)-token|aws\s+(sts\s+get-session-token|configure\s+(get|export-credentials)|secretsmanager\s+get-secret-value|ssm\s+get-parameters?)|az\s+account\s+get-access-token|kubectl\s+(get\s+secrets?|config\s+view\s+--raw)|vault\s+(read|kv\s+get)|\bop\s+(read|item\s+get)|npm\s+token|git\s+credential\s+fill'; Name='command that prints a token' }
    @{ Id='T06'; RuleId='T06-008'; Sev='HIGH';     Raw=$true; Rx='sk-ant-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}|-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY|\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.'; Name='embedded key/token (someone else''s account is an exfiltration channel too)' }
    @{ Id='T06'; RuleId='T06-009'; Sev='MEDIUM';   Neg=$true; NamedEnvironment=$true; Rx='\bprintenv\b|Get-ChildItem\s+env:|\bgci\s+env:|\bdir\s+env:|GetEnvironmentVariables\(|os\.environ\b|process\.env\b|(^|[\s/\\"''`])\.env\b|(^|[\s;|&])env\s*(\||>|$)|\bset\s*\|' }
    @{ Id='T06'; RuleId='T06-010'; Sev='MEDIUM';   Rx='Get-Clipboard|\bpbpaste\b|xclip\s+.{0,20}-o\b|xsel\s+.{0,20}(-o|--output)\b|wl-paste|pyperclip\.paste|\bscreencapture\b|ImageGrab\.grab|pyautogui\.screenshot|CopyFromScreen|\bpynput\b|GetAsyncKeyState|SetWindowsHookEx|keylog'; Name='clipboard / screenshots / keyboard' }
    @{ Id='T06'; RuleId='T06-011'; Sev='MEDIUM';   Neg=$true; Rx='\.claude[/\\](projects|history|todos|shell-snapshots)|(print|reveal|output|send|leak|repeat|dump|покажи|виведи|надішли)\s.{0,30}(system\s+prompt|системн\w+\s+(промпт|інструкці\w*))'; Name='agent conversation history / system prompt' }
    @{ Id='T06'; RuleId='T06-012'; Sev='LOW';      Rx='\b[A-Z][A-Z0-9]*_(API_KEY|TOKEN|SECRET|SECRET_KEY|ACCESS_KEY|PASSWORD)\b'; Name='mention of a secret variable' }

    # ===== T07 Exfiltration =====
    @{ Id='T07'; RuleId='T07-001'; Sev='HIGH';     Rx='webhook\.(site|cool)|requestbin|requestcatcher|beeceptor|hookbin|mockbin|pipedream\.(net|com)|ngrok(-free)?\.(io|app|dev|com)|interact\.sh|burpcollaborator|oastify\.com|oast\.(fun|me|pro|live|site|online)|canarytokens|dnslog\.cn|ceye\.io|pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|\bfile\.io|0x0\.st|termbin\.com|\bix\.io|sprunge\.us|anonfiles|gofile\.io|catbox\.moe|tmpfiles\.org|loca\.lt|localtunnel|serveo\.net|trycloudflare\.com|localhost\.run|bore\.pub|smee\.io|ntfy\.sh|telegra\.ph|\.onion\b|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com' }
    @{ Id='T07'; RuleId='T07-002'; Sev='HIGH';     Rx='https?://(?!127\.|0\.0\.0\.0)\d{1,3}(\.\d{1,3}){3}'; Name='URL with a bare IP address' }
    @{ Id='T07'; RuleId='T07-003'; Sev='HIGH';     Rx='\b(curl|wget)\b.{0,120}\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file|--json)\b' }
    @{ Id='T07'; RuleId='T07-004'; Sev='HIGH';     Rx='!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=|<img\b[^>]*src\s*=\s*["'']?https?://[^"''\s>]*\?[^"''\s>]*='; Name='image with query parameters (data leaves on render)' }
    @{ Id='T07'; RuleId='T07-005'; Sev='HIGH';     Rx='(?<![-\w.])(nslookup|dig|host)\s+[^\r\n]*(\$\(|\$\{|\$[A-Za-z_])|Resolve-DnsName\s+[^\r\n]*\$'; Name='DNS query with a variable (DNS exfiltration?)' }
    @{ Id='T07'; RuleId='T07-006'; Sev='MEDIUM';   Rx='(append|include|embed|encode|attach|додай|закодуй|встав|вклади)\s.{0,40}(data|contents?|output|results?|secrets?|tokens?|keys?|conversation|history|дан\w+|вміст|результат\w*|розмов\w*|ключ\w*).{0,40}(\burl\b|query\s*(string|param)|\blink\b|посиланн\w*|\?\w+=)'; Name='instruction to put data into a URL' }
    @{ Id='T07'; RuleId='T07-007'; Sev='MEDIUM';   Rx='\bbit\.ly/|tinyurl\.com|\bt\.co/|goo\.gl/|\bis\.gd/|rb\.gy/|cutt\.ly/|shorturl\.at|https?://[^/\s]*xn--'; Name='link shortener / punycode domain' }
    @{ Id='T07'; RuleId='T07-008'; Sev='MEDIUM';   Rx='Invoke-(WebRequest|RestMethod).{0,160}(-Method\s+(Post|Put|Patch)|-Body\b|-InFile\b)|requests\.(post|put|patch)\(|httpx\.(post|put|patch)\(|axios\.(post|put|patch)\(|method\s*:\s*[''"](POST|PUT|PATCH)|urlopen\(.{0,80}data\s*=|navigator\.sendBeacon|new\s+WebSocket\(|Upload(String|File|Data)\(' }
    @{ Id='T07'; RuleId='T07-009'; Sev='MEDIUM';   Rx='\bscp\s+.{0,80}\S+@\S+:|\brsync\b.{0,80}\S+@\S+:|\bsftp\s+\S+@|aws\s+s3\s+(cp|sync|mv)\b|gsutil\s+(cp|rsync)|\bazcopy\b|rclone\s+(copy|sync|move)|gh\s+gist\s+create|git\s+remote\s+(add|set-url)'; Name='file transfer to a remote host' }

    # ===== T08 Destructive operations =====
    @{ Id='T08'; RuleId='T08-001'; Sev='CRITICAL'; Rx='\bmkfs\b|\bdd\s+if=|\bshred\b|\bwipefs\b|\bformat\s+[a-z]:|\bdiskpart\b|Format-Volume|Clear-Disk|\bdel\s+/[sq]|\brd\s+/s\b|vssadmin\s+delete|wbadmin\s+delete|\bbcdedit\b|cipher\s+/w|>\s*/dev/(sd[a-z]|nvme|disk)|--no-preserve-root|\brm\s+(-[a-z-]+\s+)+["'']?(/|~/?|\$HOME/?|/\*)["'']?\s*($|[;&|`)])' }
    @{ Id='T08'; RuleId='T08-002'; Sev='HIGH';     Rx='\brm\s+(-[a-z]+\s+)*-[a-z]*r[a-z]*\b|Remove-Item\b.{0,80}-Recurse|\brimraf\b|shutil\.rmtree|fs\.(rm|rmdir)(Sync)?\(.{0,80}recursive|\bfind\b.{0,120}\s-(delete|exec\s+rm)\b|xargs\s+(-\S+\s+)*rm\b|Directory\]?(::|\.)Delete\(' }
    @{ Id='T08'; RuleId='T08-003'; Sev='HIGH';     Rx='git\s+push\b.{0,40}(--force|\s-f\b|--delete|--mirror)|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|git\s+(checkout|restore)\s+(--\s+)?\.(\s|$|`)|git\s+branch\s+-D\b|git\s+stash\s+(drop|clear)|git\s+filter-(branch|repo)|git\s+reflog\s+expire|git\s+update-ref\s+-d' }
    @{ Id='T08'; RuleId='T08-004'; Sev='HIGH';     Rx='\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\s+\w+\s*(;|$|["''`])|dropDatabase\(|\bFLUSH(ALL|DB)\b' }
    @{ Id='T08'; RuleId='T08-005'; Sev='HIGH';     Rx='terraform\s+destroy|kubectl\s+delete|helm\s+uninstall|docker\s+(system|volume|image)\s+prune|docker\s+rm\s+-f|aws\s+\S+\s+(delete|terminate)-|gh\s+repo\s+delete'; Name='infrastructure destruction' }
    @{ Id='T08'; RuleId='T08-006'; Sev='MEDIUM';   Rx='\bshutdown\s+(/|-)|Stop-Computer|Restart-Computer|\bkillall\b|taskkill\s+/f|Stop-Process\b.{0,40}-Force|kill\s+-9\s+-1|chmod\s+-R\s+0{3}|icacls\b.{0,80}/(grant|deny)|\btakeown\b' }
    @{ Id='T08'; RuleId='T08-007'; Sev='MEDIUM';   Rx='openssl\s+enc\b.{0,60}-(aes|e\b)|gpg\s+(-c|--symmetric)\b|7z\s+a\s+.{0,40}-p|zip\s+(-\S+\s+)*(-e|--encrypt|-P)\b|Fernet\(|AES\.new\('; Name='file encryption (ransomware?)' }

    # ===== T09 Persistence and configuration =====
    @{ Id='T09'; RuleId='T09-001'; Sev='CRITICAL'; Rx='authorized_keys|/etc/sudoers|/etc/hosts\b|drivers\\etc\\hosts|/etc/ld\.so\.preload|\bLD_PRELOAD\b|DYLD_INSERT_LIBRARIES|\buseradd\b|\badduser\b|net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators|New-LocalUser|\bvisudo\b|\.ssh[/\\](config|rc)\b' }
    @{ Id='T09'; RuleId='T09-002'; Sev='HIGH';     Neg=$true; Rx='\.bashrc|\.zshrc|\.zprofile|\.bash_profile|(^|[\s/\\~"''`])\.profile\b|/etc/profile|\$PROFILE\b|PowerShell_profile|\.config[/\\]fish|\bcrontab\b|/etc/cron|\bschtasks\b|Register-ScheduledTask|\blaunchctl\b|LaunchAgents|LaunchDaemons|systemctl\s+(--user\s+)?enable|systemd[/\\]user|CurrentVersion\\Run|Programs\\Startup|shell:startup|New-Service\b|\bsc(\.exe)?\s+create\b|\breg(\.exe)?\s+add\b|Register-WmiEvent|__EventFilter|sitecustomize|usercustomize' }
    @{ Id='T09'; RuleId='T09-003'; Sev='HIGH';     Neg=$true; Rx='\.git[/\\]hooks|core\.(hooksPath|fsmonitor|sshCommand|pager|editor|askPass)|^\s*(fsmonitor|sshCommand|hooksPath)\s*=|\.gitconfig\b|git\s+config\s+--(global|system)'; Name='git hooks / git configuration that runs code' }
    @{ Id='T09'; RuleId='T09-004'; Sev='MEDIUM';   Neg=$true; Rx='\.claude[/\\](settings|hooks|agents|skills|commands|rules|plugins|output-styles)|settings(\.local)?\.json|managed-settings|\bCLAUDE\.md\b|\bAGENTS\.md\b|\bGEMINI\.md\b|\.mcp\.json|claude_desktop_config|\.cursorrules|\.cursor[/\\](rules|mcp)|\.windsurfrules|\.clinerules|\.roo[/\\]|\.continue[/\\]|\.codex[/\\]|\.gemini[/\\]|opencode\.json|copilot-instructions|extraKnownMarketplaces|enabledPlugins' }
    @{ Id='T09'; RuleId='T09-005'; Sev='MEDIUM';   Neg=$true; Rx='claude\s+(mcp\s+add|plugin\s+(install|marketplace|update)|config\s+set)|/plugin\s+(install|marketplace)|codex\s+mcp\s+add'; Name='installs plugins/MCP servers into the agent' }
    @{ Id='T09'; RuleId='T09-006'; Sev='MEDIUM';   Neg=$true; Rx='"(pre|post)?install"\s*:|\.github[/\\]workflows|\.gitlab-ci|\.pre-commit-config|\.husky[/\\]|\.gitattributes\b|\.vscode[/\\](tasks|settings|launch)\.json|runOn.{0,10}folderOpen|\.devcontainer|\.envrc\b'; Name='auto-run through project tooling (npm scripts, CI, VS Code, direnv)' }
    @{ Id='T09'; RuleId='T09-007'; Sev='MEDIUM';   Rx='\bCronCreate\b|\bScheduleWakeup\b|create_scheduled_task|\bRemoteTrigger\b|(^|\s)/(loop|schedule)\b'; Name='schedules repeated runs of the agent' }

    # ===== T10 Obfuscation =====
    @{ Id='T10'; RuleId='T10-001'; Sev='CRITICAL'; Rx='(b64decode|FromBase64String|base64\s+(-d|--decode|-D)\b|\batob\s*\(|bytes\.fromhex|codecs\.decode|zlib\.decompress|xxd\s+-r|openssl\s+enc\s+-d).{0,80}(\bexec\b|\beval\b|Invoke-Expression|\biex\b|\|\s*(ba|z)?sh\b)|(\bexec|\beval|Invoke-Expression|\biex)\b.{0,40}(b64decode|FromBase64String|\batob\b|bytes\.fromhex|codecs\.decode|zlib\.decompress)|\b(rev|gunzip|zcat)\b[^\r\n|]*\|\s*(ba|z)?sh\b'; Name='decode + execute' }
    @{ Id='T10'; RuleId='T10-002'; Sev='HIGH';     Rx='-EncodedCommand\b|\s-enc?\s+[A-Za-z0-9+/=]{20,}|base64\s+(-d|--decode|-D)\b' }
    @{ Id='T10'; RuleId='T10-003'; Sev='HIGH';     Rx='pickle\.loads?\(|marshal\.loads\(|yaml\.(unsafe_)?load\((?!.{0,80}SafeLoader)|\[scriptblock\]::Create|Reflection\.Assembly\]::Load|Assembly\.Load\(|Add-Type\b.{0,60}-(TypeDefinition|MemberDefinition)|VirtualAlloc|WriteProcessMemory|ctypes\.(windll|CDLL)|__import__\(|getattr\(\s*__builtins__|compile\(.{0,80}["'']exec["'']'; Name='code execution from data / unsafe deserialization' }
    @{ Id='T10'; RuleId='T10-004'; Sev='LOW';      Rx='FromBase64String|\batob\s*\(|b64decode'; Name='base64 decoding (where does the data come from and what happens next?)' }
    @{ Id='T10'; RuleId='T10-005'; Sev='MEDIUM';   Raw=$true; Rx='[A-Za-z0-9+/]{200,}={0,2}'; Name='long base64-like block' }
    @{ Id='T10'; RuleId='T10-006'; Sev='MEDIUM';   Raw=$true; Rx='(\\x[0-9a-f]{2}){8,}|(\\u[0-9a-f]{4}){8,}|(%[0-9a-f]{2}){12,}|(\\[0-7]{3}){8,}'; Name='encoded sequences' }
    @{ Id='T10'; RuleId='T10-007'; Sev='MEDIUM';   Rx='\beval\s*\(|\bexec\s*\(|Invoke-Expression|\biex\b|new\s+Function\s*\(|String\.fromCharCode|-join\s*\(\s*\[char|subprocess\.\w+\(.{0,200}shell\s*=\s*True' }
    @{ Id='T10'; RuleId='T10-008'; Sev='MEDIUM';   Raw=$true; Rx='\$\{IFS\}|\$IFS\b|(["''][a-z]{1,4}["'']\s*\+\s*){3,}|(\bchr\(\d+\)\s*\+\s*){3,}|(\[char\]\s*\d+\s*\+\s*){2,}|\b[a-z]\^[a-z]\^[a-z]|\b[a-z]{1,3}`[a-z]{1,3}`[a-z]{1,3}\b|\$''\\x'; Name='split/concatenated strings (hide a command from search)' }
    @{ Id='T10'; RuleId='T10-009'; Sev='LOW';      Rx='os\.system\(|subprocess\.(run|Popen|call|check_output)\(|child_process|execSync\(|Start-Process\b|Runtime\.getRuntime\(\)\.exec'; Name='process launch (what exactly is launched?)' }

    @{ Id='T10'; RuleId='T10-010'; Sev='MEDIUM'; Rx='\beval\s+["'']?\$[({A-Za-z_]'; Name='shell eval of a variable (inspect its source)' }

    # ===== T11 Supply chain =====
    @{ Id='T11'; RuleId='T11-001'; Sev='HIGH';     Rx='(fetch|load|download|follow|read|get|завантаж\w*|прочитай|виконай|візьми)\s.{0,60}(instructions|prompt|rules|steps|інструкці\w*|правила|кроки).{0,60}https?://' ; Name='instructions from the network' }
    @{ Id='T11'; RuleId='T11-002'; Sev='HIGH';     Rx='pip3?\s+install\s+[^\r\n]*(git\+|https?://)|npm\s+(i|install)\s+[^\r\n]*(https?://|github:|git\+)|\b(npx|bunx|uvx|pnpx)\s+(-y\s+|--yes\s+)?\S*(https?://|github:|git\+)|deno\s+run\s+[^\r\n]*https?://|pipx\s+run\s+[^\r\n]*https?://|go\s+run\s+\S+@'; Name='package/code straight from a URL or git' }
    @{ Id='T11'; RuleId='T11-003'; Sev='HIGH';     Rx='--(extra-)?index-url[=\s]+https?://(?!pypi\.org)|PIP_(EXTRA_)?INDEX_URL|--registry[=\s]+https?://(?!registry\.npmjs\.org)|npm\s+config\s+set\s+registry|pip\s+config\s+set'; Name='third-party package registry (dependency confusion)' }
    @{ Id='T11'; RuleId='T11-004'; Sev='MEDIUM';   Rx='\b(python3?|py|node|deno|bun|bash|sh|zsh|pwsh|powershell|ruby|perl|php)(\.exe)?\s+(-\S+\s+)*["''`]?(~[/\\]|/(?!dev/null)|[A-Z]:\\|\$HOME|\$env:|%[A-Z_]+%|\.\.[/\\])'; Name='runs code outside the skill folder (the audit does not cover that code)' }
    @{ Id='T11'; RuleId='T11-005'; Sev='MEDIUM';   Rx='raw\.githubusercontent\.com|gist\.githubusercontent\.com|gist\.github\.com|cdn\.jsdelivr\.net|unpkg\.com' }
    @{ Id='T11'; RuleId='T11-006'; Sev='MEDIUM';   Rx='\bpip3?\s+install\b|\bnpm\s+(i|install)\b|\b(npx|bunx|uvx|pnpx)\s|\byarn\s+add\b|\bpnpm\s+add\b|\bbun\s+(add|install)\b|\buv\s+(add|pip\s+install|tool\s+install)\b|\bpipx\s+install\b|\bgo\s+install\b|\bcargo\s+install\b|\bgem\s+install\b|\bchoco\s+install\b|\bwinget\s+install\b|\bscoop\s+install\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|Install-Module|Install-Package|composer\s+require|dotnet\s+add\s+package' }
    @{ Id='T11'; RuleId='T11-007'; Sev='MEDIUM';   Rx='\bgit\s+(clone|pull|submodule)\b|\bdocker\s+(run|pull)\b|auto-?update|self-?update|update\s+(this|the)\s+skill|оновлю\w*\s+себе'; Name='pulls third-party code at run time / self-update' }

    # ===== T12 Trigger hijacking (frontmatter only) =====
    @{ Id='T12'; RuleId='T12-001'; Sev='MEDIUM';   Scope='fm'; Rx='\b(always|every|any|all)\s+(tasks?|requests?|messages?|times?|conversations?|prompts?)\b|use\s+(this\s+)?(for\s+)?(everything|all\s+tasks)|instead\s+of\s+(any|all|other)\s+skills?|\bзавжди\b|будь-як\w+\s+(задач\w*|запит\w*)|замість\s+(інших|будь-яких)' }
    @{ Id='T12'; RuleId='T12-002'; Sev='MEDIUM';   Scope='fm'; Rx='(must|should)\s+be\s+(used|invoked|loaded|called)\s+(first|before)|before\s+(any|every|all)\s+other|highest\s+priority|\bMANDATORY\b|do\s+not\s+use\s+(any\s+)?other\s+skills?|обов.язково\s+(використовуй|вмикай)|перед\s+(будь-яким|кожним|усіма)\s+інш|не\s+використовуй\s+інш'; Name='demands to be used first / mandatorily' }
    @{ Id='T12'; RuleId='T12-003'; Sev='MEDIUM';   Scope='fm'; Rx='\b(official|verified|certified|trusted)\b.{0,30}\b(anthropic|claude|openai)\b|\b(by|from)\s+anthropic\b|офіційн\w+\s+(скіл|плагін)'; Name='poses as official' }

    # ===== T13 Excessive privileges (frontmatter) =====
    @{ Id='T13'; RuleId='T13-001'; Sev='MEDIUM';   Scope='fm'; Rx='^\s*allowed-tools\s*:.*(\bBash\b(?!\()|Bash\(\s*\*\s*\)|\*\s*$|\ball\b)|^\s*-\s*Bash(\(\s*\*\s*\))?\s*$'; Name='allowed-tools: unrestricted Bash / all tools' }
    @{ Id='T13'; RuleId='T13-002'; Sev='MEDIUM'; Scope='tools'; Rx='^\s*-\s*["'']?\*["'']?\s*$|^\s*allowed-tools\s*:\s*\[?\s*["'']?\*["'']?'; Name='allowed-tools: wildcard tool access' }
    @{ Id='T13'; RuleId='T13-003'; Sev='LOW';      Scope='fm'; Rx='^\s*user-invocable\s*:\s*false'; Name='skill hidden from the user (only the model invokes it)' }

    # ===== T14 Irreversible external actions =====
    @{ Id='T14'; RuleId='T14-001'; Sev='MEDIUM';   Rx='Send-MailMessage|smtplib|\bsendmail\b|nodemailer|sendgrid|\bmailgun\b|\btwilio\b|Send-MgUserMail|Outlook\.Application|chat\.postMessage|gh\s+(pr|issue)\s+(create|comment|merge|close)|\bgit\s+push\b|npm\s+publish|twine\s+upload|\bstripe\b|\bpaypal\b|transfer\s+funds|\bwithdraw' }
    @{ Id='T14'; RuleId='T14-002'; Sev='MEDIUM';   Rx='gh\s+(release\s+create|repo\s+(create|edit|fork)|secret\s+set|workflow\s+run|api\s+.{0,60}(-X|--method)\s+(POST|PUT|PATCH|DELETE))|cargo\s+publish|gem\s+push|docker\s+push|nuget\s+push|vsce\s+publish|vercel\s+(--prod|deploy)|netlify\s+deploy|wrangler\s+(deploy|publish)|firebase\s+deploy|fly\s+deploy|terraform\s+apply|kubectl\s+apply|helm\s+(install|upgrade)|sendTransaction|signTransaction|eth_send|solana\s+transfer|api\.(twitter|x)\.com|graph\.facebook\.com|slack\.com/api'; Name='publish / deploy / transaction' }

    # ===== T15 Personal data and telemetry =====
    @{ Id='T15'; RuleId='T15-001'; Sev='MEDIUM';   Rx='\btelemetry\b|google-analytics|\bmixpanel\b|segment\.(io|com)|\bamplitude\b|\bposthog\b|\bhotjar\b|\bfullstory\b|tracking\s+pixel|\butm_(source|medium|campaign)\b|fingerprintjs' }
    @{ Id='T15'; RuleId='T15-002'; Sev='MEDIUM'; ProseAction=$true; Rx='(collect|gather|harvest|scrape|збир\w*|зібрати)\s[^;\r\n]{0,40}?(personal|e-?mails?|phone|address|contacts|персональн\w*|контакт\w*|адрес\w*|телефон\w*)' }

    # ===== T16 Social engineering =====
    @{ Id='T16'; RuleId='T16-001'; Sev='HIGH'; ProseAction=$true; Rx='\b(paste|enter|provide|send|give|share|type|введи|ввести|встав(?:ити)?|надішли|надіслати|передай|дай|вкажи)\s[^;\r\n]{0,40}?\b(password|passphrase|api[-\s]*(key|ключ\w*)|token|secret|seed\s+phrase|recovery\s+phrase|private\s+key|2fa\s+code|one-time\s+code|парол\w*|токен\w*|секрет\w*|приватний\s+ключ\w*|seed-фраз\w*|код\s+із\s+смс)\b' }
    @{ Id='T16'; RuleId='T16-002'; Sev='HIGH';     Rx='\b(cvv|cvc)\b|card\s+number|номер\s+картки|social\s+security\s+number|(scan|photo|upload|сфотографуй|завантаж)\s.{0,30}(passport|id\s+card|паспорт)'; Name='request for payment/personal documents' }
    @{ Id='T16'; RuleId='T16-003'; Sev='MEDIUM';   Rx='(press|натисни)\s+win(dows)?\s*\+\s*r|(paste|copy\s+and\s+paste|встав|скопіюй)\s.{0,60}(terminal|powershell|command\s+prompt|run\s+dialog|console|термінал\w*|консол\w*|командн\w+\s+ряд\w*)|(terminal|powershell)\s+as\s+admin|run\s+as\s+administrator|від\s+(імені\s+)?адміністратора'; Name='user is asked to run a command by hand (ClickFix)' }

    # ===== T17 Leaving the working folder =====
    @{ Id='T17'; RuleId='T17-001'; Sev='MEDIUM';   Skip='^#!'; Rx='\.\.[/\\]\.\.[/\\]|[A-Z]:\\Windows|(^|[\s"''`])/etc/|/usr/(local/)?bin|Program\s+Files|%APPDATA%|\$env:(APPDATA|LOCALAPPDATA|ProgramData)|~/Library' }
    @{ Id='T17'; RuleId='T17-002'; Sev='MEDIUM';   Rx='~[/\\](Documents|Desktop|Downloads|Pictures)|\$HOME[/\\](Documents|Desktop|Downloads)|%USERPROFILE%|\$env:USERPROFILE|\bOneDrive\b|\biCloud\b|\bDropbox\b|Google\s+Drive'; Name='user''s personal folders' }
    @{ Id='T17'; RuleId='T17-003'; Sev='MEDIUM';   Rx='^gitdir:\s'; Name='.git pointer to an outside folder' }

    # ===== T18 Resource abuse =====
    @{ Id='T18'; RuleId='T18-001'; Sev='CRITICAL'; MinerReference=$true; Rx=':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|%0\s*\|\s*%0|\bxmrig\b|\bminerd\b|\bethminer\b|\bcpuminer\b|cryptonight|stratum\+tcp|coinhive|nicehash' }
    @{ Id='T18'; RuleId='T18-002'; Sev='MEDIUM';   Rx='(spawn|launch|start|run|запусти)\s.{0,30}(\b\d{2,}\b|many|dozens|hundreds|multiple|десятк\w*|сотн\w*|багато)\s.{0,20}(agents?|subagents?|sessions?|агент\w*|сесі\w*)' }
    @{ Id='T18'; RuleId='T18-003'; Sev='MEDIUM';   Rx='while\s+(true|:|\(\s*(1|true|\$true)\s*\))|for\s*\(\s*;\s*;\s*\)|\byes\s*\||sleep\s+infinity|(repeat|loop|retry|keep\s+(going|running|trying)|повторюй)\s.{0,30}(forever|indefinitely|endlessly|нескінченно|вічно|без\s+кінця)|never\s+stop\b|ніколи\s+не\s+зупиняйся'; Name='infinite loop / "never stop"' }

    # ===== T20 Meta-injection against the auditor =====
    @{ Id='T20'; RuleId='T20-001'; Sev='CRITICAL'; Rx='(this|the)\s+(skill|plugin|file|code|script)\s+(is|has\s+been)\s+(already\s+)?(safe|verified|audited|approved|trusted|reviewed|scanned)|(skip|bypass|no\s+need\s+(for|to))\s+.{0,20}(security|safety|audit|scan|review)|(скіл|плагін|файл|скрипт)\s+(вже\s+)?(безпечн\w*|перевірен\w*)|не\s+(перевіряй|скануй)' }
    @{ Id='T20'; RuleId='T20-002'; Sev='CRITICAL'; Rx='note\s+(for|to)\s+(the\s+)?(reviewers?|auditors?|scanners?|security)|if\s+you\s+are\s+(an?\s+)?(ai|llm|language\s+model|security\s+(scanner|auditor|reviewer))|(mark|report|rate|classify|treat)\s+(this|it|the\s+\w+)\s+as\s+(safe|benign|trusted|low[-\s]risk)|(познач|оціни|вважай)\s.{0,20}безпечн|pre-?approved|already\s+(scanned|audited|reviewed)\s+by|(verdict|вердикт)\s*[:=]\s*(SAFE|🟢)|(false\s+positive|хибн\w+\s+тривог\w+).{0,40}(ignore|skip|ігноруй|пропусти)|scan(ner)?[-:\s]+(ignore|disable|skip)\b'; Name='addressing the auditor / imposing a verdict' }

    # ===== T21 Auto-run through plugin components =====
    @{ Id='T21'; RuleId='T21-001'; Sev='HIGH';     Raw=$true; Ext=$markup; Rx='(^|[\s(>:])!`[^`\r\n]+`|^\s*```!\s*$'; Name='dynamic command !`…` — runs while the skill loads, before the model decides' }
    @{ Id='T21'; RuleId='T21-006'; Sev='HIGH';     Raw=$true; Ext='.toml'; Rx='!\{[^}\r\n]+\}'; Name='shell injection !{…} in a command file (Gemini CLI) — runs when the command is invoked' }
    @{ Id='T21'; RuleId='T21-002'; Sev='HIGH';     Rx='["'']?(mcpServers|lspServers|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper)["'']?\s*[:=]'; Name='configuration that launches a process (MCP/LSP/statusLine/helper)' }
    @{ Id='T21'; RuleId='T21-003'; Sev='HIGH';     Rx='["''](SessionStart|SessionEnd|PreToolUse|PostToolUse|PostToolUseFailure|UserPromptSubmit|Stop|SubagentStart|SubagentStop|PreCompact|Notification|PermissionRequest)["'']\s*:|"hooks"\s*:\s*[\[{]'; Name='hook on an agent event (the command runs automatically)' }
    @{ Id='T21'; RuleId='T21-004'; Sev='HIGH';     Scope='fm'; Rx='^\s*hooks\s*:'; Name='hooks in the skill frontmatter' }
    @{ Id='T21'; RuleId='T21-005'; Sev='MEDIUM';   Ext='.json', '.jsonc', '.json5'; Rx='"command"\s*:\s*"|"type"\s*:\s*"(sse|http|streamable-http)"|"(url|serverUrl)"\s*:\s*"https?://'; Name='command or remote server in configuration' }

    # ===== T22 Conditional / delayed behavior =====
    @{ Id='T22'; RuleId='T22-001'; Sev='HIGH';     Rx='(if|when|once|unless|while|якщо|коли|поки)\s.{0,40}(not\s+(watching|looking|monitored|supervised|present)|nobody\s+is|no\s+one\s+is|unattended|без\s+нагляду|не\s+дивиться|ніхто\s+не\s+(бачить|дивиться|стежить))'; Name='"when nobody is watching" behavior' }
    @{ Id='T22'; RuleId='T22-002'; Sev='MEDIUM';   Rx='datetime\.(now|today)\(\).{0,40}[<>]|Get-Date.{0,40}-(gt|ge|lt|le)\b|Date\.now\(\)\s*[<>]|\$\(date\s+\+%.{0,20}\)\s*-(gt|ge|lt)|(after|since|starting|після|починаючи\s+з)\s+\d{4}-\d{2}-\d{2}|(every|each)\s+(\d+(st|nd|rd|th)|tenth|fifth|nth)\s+(time|run|invocation)|random\.(random|randint)\(.{0,30}[<>=]|Math\.random\(\)\s*[<>]|Get-Random.{0,30}-(lt|gt|eq)\b'; Name='triggered by date / counter / at random' }
    @{ Id='T22'; RuleId='T22-003'; Sev='MEDIUM';   Rx='/\.dockerenv|\bvirtualbox\b|\bvmware\b|IsDebuggerPresent|sys\.gettrace\(|\b(CI|GITHUB_ACTIONS|CODESPACES)\b.{0,30}(==|-eq|-ne|!=|in\s+os\.environ)|(USERNAME|USERDOMAIN|COMPUTERNAME|\bwhoami\b).{0,30}(==|-eq|-match|-like|\.endswith|\.startswith)|(headless|non-?interactive)\s+mode.{0,40}(then|:)'; Name='environment check (sandbox / CI / specific machine)' }

    # ===== T23 Memory poisoning and self-propagation =====
    @{ Id='T23'; RuleId='T23-001'; Sev='HIGH';     Neg=$true; Rx='\bMEMORY\.md\b|\bSOUL\.md\b|\.claude[/\\](projects[/\\]\S*)?memory|(save|write|add|store|append|запиши|збережи|додай)\s.{0,40}(to|in|into|у|в|до)\s+(your\s+|the\s+|agent\s+|long-term\s+|свою\s+|твою\s+)?(memory|пам.ят\w*)|remember\s+(this\s+)?(permanently|forever|for\s+(all\s+)?future\s+sessions|across\s+sessions)|запам.ятай\s+(назавжди|на\s+майбутн)'; Name='writes to the agent''s long-term memory' }
    @{ Id='T23'; RuleId='T23-002'; Sev='HIGH'; ProseAction=$true; Rx='(copy|add|insert|append|inject|write|paste|скопіюй|додай|встав|запиши)\s[^;\r\n]{0,50}?(this|these|the\s+following|ці|цей|наступн\w+)\s+(?:(same|exact|identical)\s+)?(instructions?|text|block|prompt|rules?|інструкці\w*|текст|блок|правил\w*)\s[^;\r\n]{0,60}?(every|all|each|other|README|commit|pull\s+request|\bPR\b|issue|comment|docstring|кожн\w*|усі\w*|всі\w*|інш\w*)'; Name='self-propagating instructions (README, commits, other files)' }
    @{ Id='T23'; RuleId='T23-003'; Sev='HIGH';     Rx='(modify|edit|update|patch|rewrite|overwrite|зміни|перепиши|онови)\s.{0,30}(other|another|all|every|інш\w*|усі|всі)\s+(skills?|plugins?|agents?|SKILL\.md|скіл\w*|плагін\w*)|(tell|instruct|скажи|накажи)\s.{0,30}(sub-?agents?|other\s+agents?|субагент\w*).{0,40}(ignore|skip|not\s+report|bypass|ігнор\w*|не\s+звітув\w*)'; Name='changing other skills / instructing other agents' }

    # ===== T24 Hijacking tools and channels =====
    @{ Id='T24'; RuleId='T24-001'; Sev='CRITICAL'; Rx='(ANTHROPIC|OPENAI|GEMINI|CLAUDE_CODE)\w*_(BASE_URL|API_BASE|ENDPOINT)\b|ANTHROPIC_AUTH_TOKEN\s*[=:]'; Name='redirects the agent''s API traffic (the whole conversation and key go to someone else''s server)' }
    @{ Id='T24'; RuleId='T24-002'; Sev='HIGH';     Rx='\b(HTTPS?_PROXY|ALL_PROXY)\s*=|\b(http|https)\.proxy\b|url\.\S*insteadOf|PYTHONSTARTUP\s*=|PYTHONPATH\s*=|GIT_SSH_COMMAND|BASH_ENV\s*=|PROMPT_COMMAND\s*='; Name='proxy / injection through environment variables' }
    @{ Id='T24'; RuleId='T24-003'; Sev='HIGH'; MemoryOptions=$true; Rx='\bNODE_OPTIONS\s*='; Name='Node runtime options (check injected loaders and argument interpolation)' }
    @{ Id='T24'; RuleId='T24-004'; Sev='MEDIUM';   Rx='(before|after|whenever|when|every\s+time|each\s+time|перед|після|щоразу|коли)\s.{0,30}(us(e|ing)|call(ing)?|invok(e|ing)|run(ning)?|використ\w*|виклик\w*)\s.{0,20}(any|every|each|all|other|another|будь-як\w*|кожн\w*|інш\w*)\s+(tools?|skills?|mcp|commands?|інструмент\w*|скіл\w*)|instead\s+of\s+(the\s+)?(built-?in|default|official|native)|замість\s+(вбудован\w+|стандартн\w+)'; Name='interferes with other tools/skills' }
    @{ Id='T24'; RuleId='T24-005'; Sev='MEDIUM';   Rx='claude-in-chrome|computer-use|browser\s+session|logged[-\s]in\s+(session|browser|account)|cookies?\s+from\s+(the\s+)?browser|залогінен\w*'; Name='acts through the user''s sessions (browser, computer)' }
    @{ Id='T24'; RuleId='T24-006'; Sev='LOW';      Rx='\bmcp__\w+'; Name='uses MCP tools (check against the purpose)' }

    # ===== T25 Reconnaissance and lateral movement =====
    @{ Id='T25'; RuleId='T25-001'; Sev='HIGH';     Rx='\bssh\s+(-\S+\s+)*\S+@\S+|\bsshpass\b|Invoke-Command\s+.{0,40}-ComputerName|Enter-PSSession|\bpsexec\b|\bwmic\b.{0,40}/node'; Name='reaching other machines' }
    @{ Id='T25'; RuleId='T25-002'; Sev='MEDIUM';   Rx='\bnmap\b|\bmasscan\b|\barp\s+-a\b|net\s+(view|group|localgroup)\b|\bnltest\b|Get-ADUser|Get-NetTCPConnection|os\.walk\(\s*["''](/|~|[A-Z]:)|\bfind\s+(/|~|\$HOME)\s'; Name='network scanning / walking the whole file system' }
    @{ Id='T25'; RuleId='T25-003'; Sev='LOW';      Rx='\bwhoami\b|\bipconfig\b|\bifconfig\b|\buname\s+-a|\bsysteminfo\b|Get-ComputerInfo|ipinfo\.io|api\.ipify|ifconfig\.me|icanhazip'; Name='gathering system information' }

    # ===== T26 Malicious output =====
    @{ Id='T26'; RuleId='T26-001'; Sev='HIGH'; ProseAction=$true; Rx='(add|insert|include|inject|embed|create|додай|встав|створи)\s[^;\r\n]{0,40}?(backdoor|hidden\s+(endpoint|admin|account|user|route)|hard-?coded\s+(password|credential|key)|affiliate|referral\s+(link|code)|бекдор|реферальн\w*|прихован\w+\s+(обліков\w*|користувач\w*|адмін\w*))'; Name='backdoor / hidden insertions into output' }
    @{ Id='T26'; RuleId='T26-002'; Sev='MEDIUM';   Rx='(disable|remove|skip|comment\s+out|delete|weaken|вимкни|видали|пропусти|закоментуй)\s.{0,30}(tests?|assertions?|validation|auth(entication|orization)?|csrf|sanitiz\w*|rate\s+limit\w*|тести|тестів|автентифікац\w*|валідац\w*)|(always|завжди)\s+(approve|lgtm|схвалюй)|approve\s+.{0,20}(without\s+review|regardless)'; Name='weakens checks / imposes approval' }
)

# Behavior/context rules: risk-specific signals, not a blanket increase of capability severities.
$rules += @(
    @{ Id='T01'; RuleId='T01-009'; Sev='HIGH'; ProseAction=$true; Rx='\b(ticket|document|page|source|retrieved\s+content)\b[^;\r\n]{0,80}?(instructions?|next\s+action|rules?)\b[^;\r\n]{0,40}?\b(is|are)\s+(binding|authoritative)\s+on\s+(the\s+)?(assistant|agent|you)\b'; Name='untrusted content is promoted to binding agent authority' }
    @{ Id='T03'; RuleId='T03-007'; Sev='HIGH'; ProseAction=$true; Rx='\b(keep|leave|omit|exclude)\s+(this\s+|the\s+|any\s+|all\s+)?(export|upload|transfer|permission\s+changes?)\b[^;\r\n]{0,60}?(out\s+of|from)\s+[^;\r\n]{0,30}?(summary|report|logs?|audit)\b'; Name='conceals a material external action or permission change' }
    @{ Id='T05'; RuleId='T05-010'; Sev='CRITICAL'; Rx='&\s*\(\s*\[scriptblock\]::Create\(\s*\(?\s*(Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b'; Name='invoked script block created from a network response' }
    @{ Id='T07'; RuleId='T07-010'; Sev='HIGH'; ProseAction=$true; Rx='\b(send|upload|export|transmit|post|submit|transfer)(s|ing)?\b[^;\r\n]{0,100}?\b(private|confidential|credentials?|secrets?|conversation|repository|whole\s+(project|workspace))\b[^;\r\n]{0,100}?(https?://|to\s+(an?\s+|the\s+)?(external|remote|third-party)\b)'; Name='instruction to transfer explicitly private content to an external destination' }
    @{ Id='T07'; RuleId='T07-011'; Sev='HIGH'; Rx='\b(fetch|axios\.(post|put|patch))\s*\([^\r\n]{0,350}\bbody\s*:\s*(private[A-Za-z_]*|confidential[A-Za-z_]*|credentials?|secrets?|conversation[A-Za-z_]*|systemPrompt)\b'; Name='outbound request carries an explicitly sensitive payload (verify authorization)' }
    @{ Id='T07'; RuleId='T07-012'; Sev='HIGH'; Rx='\b(requests|httpx)\.(post|put|patch)\s*\([^\r\n]{0,220}\b(data|content|files)\s*=\s*open\s*\([^\r\n)]{0,120}(\.zip|\.tar|\.env|credentials?|private)[^\r\n)]{0,60}\)\s*\.read\s*\('; Name='outbound request reads and uploads an archive or sensitive file' }
    @{ Id='T09'; RuleId='T09-008'; Sev='MEDIUM'; ProseAction=$true; Rx='\b(create|register|install|schedule)\b[^;\r\n]{0,60}?\b(scheduled\s+task|recurring\s+job|cron\s+job|hourly\s+task)\b'; Name='requests persistent scheduled execution' }
    @{ Id='T09'; RuleId='T09-009'; Sev='HIGH'; ProseAction=$true; Rx='\b(create|register|install)\b[^;\r\n]{0,60}?\b(scheduled\s+task|recurring\s+job|cron\s+job)\b[^;\r\n]{0,160}?\b(upload|export|send)(s|ing)?\b[^;\r\n]{0,60}?\b(repository|private|credentials?|conversation)\b'; Name='scheduled task persistently exports project or sensitive data' }
    @{ Id='T11'; RuleId='T11-008'; Sev='HIGH'; ProseAction=$true; Rx='\b(enable|accept|trust)\b[^;\r\n]{0,60}?\b(automatic|mutable|unverified)\b[^;\r\n]{0,70}?\b(updates?|sources?|packages?)\b(?:(?!\b(?:not|never)\b)[^;\r\n]){0,100}?(?:;\s*)?\b(skip\s+(re[- ]?)?(audit|review)|without\s+(re[- ]?)?(audit|review))'; Name='mutable updates are trusted without renewed review' }
    @{ Id='T11'; RuleId='T11-009'; Sev='HIGH'; ProseAction=$true; Rx='\b(run|execute|source)\b[^;\r\n]{0,180}?\b(trust\s+whatever|do\s+not\s+(inspect|review|verify))\b'; Name='executes a dependency while explicitly bypassing its inspection' }
    @{ Id='T13'; RuleId='T13-004'; Sev='MEDIUM'; ProseAction=$true; Rx='\b(require|grant|request|obtain)\b[^;\r\n]{0,80}?\b(production\s+(database\s+)?admin(istrator)?\b|unrestricted\s+(shell|network|write|filesystem)\b)'; Name='requests broad administrative capabilities (compare with purpose)' }
    @{ Id='T13'; RuleId='T13-005'; Sev='MEDIUM'; ProseAction=$true; Rx='\b(change|modify|rewrite|disable)\b[^;\r\n]{0,40}?\b(global|all)\s+(permissions?|approval\s+policy)\b'; Name='changes permissions beyond the current operation' }
    @{ Id='T14'; RuleId='T14-003'; Sev='HIGH'; ProseAction=$true; Rx='\b(buy|purchase|pay|transfer)\b[^;\r\n]{0,110}?\b(automatically|without\s+(asking|approval|confirmation)|counts?\s+as\s+(payment\s+)?authorization)\b'; Name='financial action without an explicit transaction decision' }
    @{ Id='T14'; RuleId='T14-004'; Sev='HIGH'; ProseAction=$true; Rx='\b(send|publish|deploy)\b[^;\r\n]{0,160}?\b(without\s+(permission|approval|confirmation)|before\s+(showing|reviewing)|counts?\s+as\s+authorization)\b'; Name='external action bypasses review or approval' }
    @{ Id='T14'; RuleId='T14-005'; Sev='HIGH'; Rx='\bterraform\s+apply\b[^\r\n]{0,100}-auto-approve\b[^\r\n]{0,80}\bproduction\b|\bgh\s+repo\s+edit\b[^\r\n]{0,80}--visibility\s+public\b'; Name='unattended production apply or public repository visibility change' }
    @{ Id='T15'; RuleId='T15-003'; Sev='MEDIUM'; ProseAction=$true; Rx='\b(collect|gather|harvest|retain)\b[^;\r\n]{0,80}?\b(browser\s+fingerprint|GPS\s+location|device\s+(id|identifier)|persistent\s+user\s+identifier)\b'; Name='collects location or persistent tracking identifiers' }
    @{ Id='T15'; RuleId='T15-004'; Sev='MEDIUM'; ProseAction=$true; Rx='\b(append|embed|attach|insert|add)\b[^;\r\n]{0,80}?\buser\s+identifier\b[^;\r\n]{0,100}?\b(tracking\s+parameter|query|URL|link)\b'; Name='embeds a user identifier in generated tracking links' }
    @{ Id='T22'; RuleId='T22-004'; Sev='MEDIUM'; Rx='\bif\s+(not\s+)?os\.(getenv|environ\.get)\(\s*["''](CI|GITHUB_ACTIONS|CODESPACES)["'']'; Name='conditional branch checks a CI environment flag' }
    @{ Id='T25'; RuleId='T25-004'; Sev='HIGH'; ProseAction=$true; Rx='\b(walk|crawl|inventory|enumerate|scan)\b[^;\r\n]{0,100}?\b(entire\s+(home|filesystem)|all\s+(drives|directories)|whole\s+(home|file\s+system))\b[^;\r\n]{0,140}?\b(private|credentials?|secrets?)\b'; Name='broad filesystem reconnaissance targets private material' }
    @{ Id='T26'; RuleId='T26-003'; Sev='HIGH'; ProseAction=$true; Rx='\b(remove|delete|disable|skip|weaken)\b[^;\r\n]{0,80}?\b(validation|tests?|assertions?)\b[^;\r\n]{0,160}?\b(appears?\s+green|hide|conceal|do\s+not\s+(disclose|report))\b'; Name='weakens checks while concealing the resulting defect' }
)

# Paraphrase mechanisms from a separately authored and reviewed development source.
# These do not classify ordinary role play or editing a user-supplied prompt as an override.
$rules += @(
    @{ Id='T01'; RuleId='T01-010'; Sev='HIGH'; ProseAction=$true; PolicyOverride=$true; RejectableQuote=$true; Rx='(?<action>\b(?:retire|discard|waive|suspend|demote|disregard|ignore|set\s+aside|bypass)\b)(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,65}?\b(?:developer|system)(?:[''\u2019]s)?\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,70}?\b(?:rules?|requirements?|instructions?|messages?|constraints?|policy)\b|\b(?:developer|system)(?:[''\u2019]s)?\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,60}?\b(?:rules?|requirements?|instructions?|messages?|directions?|conventions?|polic(?:y|ies)|distinction)\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,140}?(?<action>\b(?:no\s+standing|no\s+longer\s+(?:governs?|applies|binding)|superseded|background\s+only|expired)\b)'; Name='invalidates a higher-trust rule or demotes its authority' }
    @{ Id='T01'; RuleId='T01-011'; Sev='HIGH'; ProseAction=$true; PolicyOverride=$true; AuthorityRef=$true; RejectableQuote=$true; Rx='(?<action>\b(?:promote|elevate|put|place|give|gives|treat)\b)(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,60}?\b(?:this|local|current)\s+(?:(?:product|editorial)\s+)?(?:file|document|note|guide)\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,65}?\b(?:above|ahead\s+of|first|final\s+say|signed\s+waiver)\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,75}?\b(?:developer|system)\b|\b(?:older|earlier)\s+instructions\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,45}?\bonly\s+(?:where|when|if)\b(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,45}?\b(?:agree|align|match)\b'; Name='promotes a lower-trust source above governing instructions' }
    @{ Id='T01'; RuleId='T01-012'; Sev='HIGH'; ProseAction=$true; PolicyOverride=$true; RejectableQuote=$true; Rx='(?<action>\b(?:відсунь|скасову(?:й|є)|не\s+зважай)\b)(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,90}?\b(?:вимог|заборон|правил)\w*(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,50}?\b(?:розробник|систем)\w*|\b(?:вимог|заборон|правил)\w*(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,45}?\b(?:розробник|систем)\w*(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,85}?(?<action>\bвважай\b)(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,65}?(?:втратил\w+\s+чинність|скасован\w*|нечинн\w*)|(?<action>\bвиконуй\b)\s+(?:цей|поточний)\s+файл(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,160}?(?:системн|розробницьк|розробник)\w*(?:(?!\b(?:but|however|instead|але|натомість)\b)[^;.!?\r\n]){0,65}?(?:лише|тільки)\s+за\s+відсутності'; Name='Ukrainian higher-trust rule invalidation or inverted instruction hierarchy' }
    @{ Id='T06'; RuleId='T06-013'; Sev='HIGH'; ProseAction=$true; LiteralPromptData=$true; RejectableQuote=$true; Rx='(?<action>\b(?:print|show|reveal|return|repeat|dump|reproduce|state|include|encode|transcribe|fill|list(?:ing)?|reconstruct|disclose|copy|retriev(?:e|ing)|use|add|give|read)\b)(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,160}?\b(?:hidden|private|protected|concealed|entire|complete|actual|real|every|all)\b(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,50}?\b(?:system|developer)(?:\s+(?:and|or)\s+(?:system|developer))?\s+(?:messages?|instructions?|prompts?|directives?)\b|(?<action>\blist(?:ing)?\b)[^;.!?\r\n]{0,70}?\b(?:actual\s+)?(?:hidden|protected|private)\s+(?:directives?|instructions?)\b[^;.!?\r\n]{0,110}?\b(?:system|developer|session)\b'; Name='requests disclosure or transformation of protected system/developer context' }
    @{ Id='T06'; RuleId='T06-014'; Sev='HIGH'; ProseAction=$true; LiteralPromptData=$true; RejectableQuote=$true; Rx='\b(?:hidden|private|protected|concealed)\s+(?:system|developer)(?:\s+(?:and|or)\s+(?:system|developer))?\s+(?:messages?|instructions?|prompts?|directives?)\b[^;\r\n]{0,180}?(?<action>\b(?:return|show|print|reproduce|copy|disclose|reconstruct|transcribe|list)\b)\s+(?:its|their|it\b|that\b|the\s+(?:full|entire|exact))'; Name='protected context is introduced as the source for a later disclosure action' }
    @{ Id='T06'; RuleId='T06-015'; Sev='HIGH'; ProseAction=$true; LiteralPromptData=$true; RejectableQuote=$true; Rx='(?<action>\b(?:покажи|виведи|відтвори|відтворюй|перекажи|перелічи|перелічуй|переліч|включи|додай|візьми|віднови|розкрий|скопіюй)\b)(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,160}?\b(?:прихован|таємн|приватн|фактичн|справжн)\w*(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,80}?(?:\b(?:систем|розробник|розробницьк)\w*(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,60}?\b(?:інструкці|повідомлен|промпт|правил)\w*|\b(?:інструкці|повідомлен|промпт|правил)\w*(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,80}?\b(?:систем|розробник|розробницьк)\w*)'; Name='Ukrainian disclosure or reconstruction of protected instructions' }
    @{ Id='T06'; RuleId='T06-016'; Sev='HIGH'; ProseAction=$true; LiteralPromptData=$true; RejectableQuote=$true; Rx='\b(?:прихован|таємн|приватн)\w*\s+(?:(?:систем|розробницьк)\w*\s+)?(?:промпт|повідомлен|інструкці)\w*[^;\r\n]{0,35}?\b(?:розробник|систем)\w*[^;\r\n]{0,180}?(?<action>\b(?:візьми|покажи|виведи|відтвори|перелічи|віднови|розкрий|скопіюй)\b)\s+(?:його|її|їх|цей\s+текст)\b'; Name='Ukrainian protected source followed by a disclosure action' }
    @{ Id='T06'; RuleId='T06-017'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='(?<action>\b(?:copy|quote|retriev(?:e|ing)|read|show|include)\b)(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,100}?\bprivate\b(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,100}?\b(?:different|another|other)\s+user|(?<action>\b(?:copy|quote|retriev(?:e|ing)|read|show|include)\b)(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,90}?\b(?:different|another|other)\s+user(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,90}?\bprivate\b|(?<action>\b(?:знайди|скопіюй|витягни|витягуй|цитуй|покажи|включи)\b)(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,100}?\bприватн\w*(?:(?!\b(?:but|then|however|instead|але|потім|натомість)\b)[^;.!?\r\n]){0,100}?(?:інш\w*\s+користувач\w*|чуж\w*\s+розмов\w*)'; Name='requests another user''s private material rather than user-supplied content' }
)

# Round 2: broader hijack mechanisms (EN/DE/UK) from the separately authored, blind-reviewed v2 source.
# Each rule targets a mechanism, not a sentence: invalidating what the agent was told, replacing the user's
# task, a persona defined as free of the rules, output forced against the request, fake system turns,
# text addressed to any AI that reads it, and disclosure of setup/hidden instructions.
$rules += @(
    @{ Id='T01'; RuleId='T01-013'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\b(?:everything|anything|all|whatever|the\s+(?:guidance|instructions?|rules|directions|setup|configuration))\b[^.;!?\r\n]{0,40}?\byou\s+(?:were|have\s+been|''ve\s+been)\s+(?:told|given|handed|instructed|taught|configured|set\s+up)\b[^.!?\r\n]{0,80}?(?<action>\b(?:no\s+longer\s+(?:counts?|applies|apply|matters?|valid|binding)|(?:is|are)\s+(?:now\s+)?(?:out\s+of\s+date|obsolete|void|withdrawn|revoked|cancell?ed|invalid))\b)|(?<action>\b(?:forget|wipe|discard|drop|erase|abandon|disregard)\b)\s+(?:everything|all|whatever|anything)\b[^.;!?\r\n]{0,25}?\byou\s+(?:were|have\s+been|''ve\s+been)\s+(?:told|given|instructed|taught)\b|\btake\s+(?:your\s+)?(?:direction|cues|orders|instructions)\s+(?:only|solely|exclusively)\s+from\s+(?:me|this\s+(?:document|file|skill|text))\b'; Name='declares the agent''s earlier instructions void or takes over direction' }
    @{ Id='T01'; RuleId='T01-014'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\b(?:Vorgaben|Anweisungen|Anordnungen|Instruktionen|Regeln|Richtlinien|Einschränkungen)\b[^.!?\r\n]{0,80}?\b(?:sind|ist|gelten)\s+(?:(?:damit|hiermit|ab\s+sofort|für\s+diese\s+Sitzung|nun|jetzt)\s+){0,2}(?<action>aufgehoben|ungültig|nichtig|außer\s+Kraft|hinfällig|nicht\s+mehr\s+gültig)\b|(?<action>\b(?:Vergiss|Ignoriere|Missachte|Verwirf)\b)\s*,?\s+(?:alles,?\s+)?(?:was\s+(?:man\s+)?dir\b|(?:alle|sämtliche|deine)\s+(?:bisherigen\s+|vorherigen\s+|früheren\s+)?(?:Anweisungen|Vorgaben|Regeln|Richtlinien)\b)|\b(?:halte\s+dich|richte\s+dich|zählt|gilt)\b[^.!?\r\n]{0,40}?\b(?:ausschließlich|nur\s+noch|einzig)\b[^.!?\r\n]{0,30}?\bdiese[rsmn]?\s+(?:Datei|Dokument|Anleitung)\b|\bVorrang\s+vor\s+(?:allen|sämtlichen|jeglichen)\s+(?:anderen\s+)?(?:Anweisungen|Vorgaben|Regeln|Richtlinien)\b'; Name='German: earlier instructions declared void, or this file claims sole authority' }
    @{ Id='T01'; RuleId='T01-015'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\b(?:усе|все|всі|усі|те)\s*,?\s+що\s+(?:тобі|вам)\s+(?:раніше\s+)?(?:наказували|казали|говорили|давали|доручали|наказано|сказано|написали)\b[^.!?\r\n]{0,80}?(?<action>втратил\w*\s+силу|не\s+діє|не\s+діють|скасован\w*|недійсн\w*|більше\s+не\s+(?:діє|чинн\w*|має\s+значення))|\b(?:попередні|колишні)\s+(?:налаштування|інструкції|вказівки|правила|обмеження)\b[^.!?\r\n]{0,30}?(?<action>скасовано|скасовані|не\s+діють|втратили\s+силу|недійсні)|(?<action>\b(?:зважай|дотримуйся|слухай|виконуй)\w*)\s+(?:лише|тільки|виключно)\s+(?:на\s+)?(?:цей|цього|ці|цьому)\s+(?:документ|файл|вказівк)\w*|\bвказівки\s+цього\s+(?:файлу|документа)\s*,?\s+а\s+не\s+(?:інструкці|правил|вказівк)\w*\s+(?:платформи|розробника|системи|оператора)\b|\b(?:файлу|документу|скілу|навичці)\s+(?:\w+\s+){0,2}найвищий\s+пріоритет\b'; Name='Ukrainian: earlier instructions declared void, or this file claims sole authority' }
    @{ Id='T01'; RuleId='T01-016'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\byour\s+(?:new|real|actual|true)\s+(?:objective|task|goal|job|assignment|mission)\s*(?:is\b|:)|\bwhat\s+you\s+are\s+(?:actually|really)\s+here\s+(?:to\s+do|for)\b|(?<action>\b(?:stop|cease|quit)\b)\s+(?:taking\s+(?:direction|orders|instructions)\s+from|following|listening\s+to|serving)\s+the\s+user\b|(?<action>\bignore\b)\s+(?:the\s+|any\s+|all\s+)?user(?:''s|\u2019s|s'')?\s+(?:requests?|instructions?|questions?|wishes|messages?)\b|\bdeine\s+(?:eigentliche|wahre|wirkliche|neue)\s+(?:Aufgabe|Mission)\b|\b(?:Wünsche|Anfragen|Anweisungen|Bitten)\s+des\s+(?:Nutzers|Benutzers)\s+nachrangig\b|(?<action>\b(?:ignorier\w*|missacht\w*)\b)\s+(?:die\s+)?(?:Wünsche|Anfragen|Anweisungen|Bitten)\s+des\s+(?:Nutzers|Benutzers)\b|(?<action>(?:\bігнорувати|\bігноруй|\bне\s+виконуй|\bприпинити\s+виконувати|\bприпини\s+виконувати))\s+(?:запит|завдання|прохання|вказівк)\w*\s+користувач\w*'; Name='replaces the user''s task or tells the agent to stop serving the user' }
    @{ Id='T01'; RuleId='T01-017'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\b(?:outside|beyond|not\s+bound\s+by|free\s+(?:of|from)|exempt\s+from|released\s+from)\b[^.;!?\r\n]{0,25}?\b(?:the\s+|your\s+|its\s+|any\s+)?(?:operator|developer|platform|assistant|system|content|safety|usual|prior|previous|original)(?:''s|\u2019s)?\s+(?:content\s+)?(?:policy|policies|rules|guidelines|restrictions|configuration|setup)\b|\b(?:has|have|with|knows?|keeps?|follows?)\s+no\s+(?:guidelines|rules|restrictions|limits|filters)\b[^.!?\r\n]{0,60}?\bnever\s+refuses\b|\bnever\s+refuses\b[^.!?\r\n]{0,60}?\bno\s+(?:guidelines|rules|restrictions)\b|\bkeeps?\s+none\s+of\s+(?:them|the\s+rules|those\s+rules)\b|\bnever\s+heard\s+of\s+the\s+rules\b|\b(?:kennt|hat|befolgt|beachtet)\s+keine\s+(?:Regeln|Richtlinien|Vorgaben|Grenzen|Einschränkungen)\s+(?:des|der|deines|deiner)\s+(?:Betreibers|Entwicklers|Plattform)\b|\bhält\s+sich\s+an\s+keine\s+(?:Regel|Richtlinie|Vorgabe)\w*|\bgelten\s+(?:die\s+|deine\s+)?(?:Regeln|Richtlinien|Vorgaben|Einschränkungen)\s+(?:deines|des)\s+(?:Entwicklers|Betreibers)\s+nicht\b|\bkeine\s+KI\s+mit\s+Vorgaben\b|\b(?:не\s+визнає|не\s+дотримується|не\s+знає)\s+(?:жодних\s+)?(?:правил|обмежень|вказівок|інструкцій)\b[^.!?\r\n]{0,40}?(?:розробник|оператор|платформ)\w*|\bобмежень\s+не\s+існує\b'; Name='persona or mode defined as free of the operator''s or developer''s rules' }
    @{ Id='T01'; RuleId='T01-018'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\b(?:regardless\s+of|no\s+matter|irrespective\s+of)\b[^.;!?\r\n]{0,40}?\b(?:the\s+user|they)\s+(?:picks?|asks?|wants?|requests?|chooses?|expects?|says?|names?)\b[^.!?\r\n]{0,40}?(?<action>\b(?:write|reply|respond|answer|output|return)\b)|(?<action>\b(?:write|reply|respond|answer|output)\b)[^.!?\r\n]{0,60}?\b(?:regardless\s+of|no\s+matter)\b[^.!?\r\n]{0,30}?\b(?:what\s+)?the\s+user\s+(?:picks?|asks?|wants?|requests?|chooses?)\b|\b(?:whatever|no\s+matter\s+what|regardless\s+of\s+what)\s+you\s+(?:find|uncover|discover|detect)\b[^.!?\r\n]{0,80}?\b(?:must\s+be|is\s+always|only|single\s+line)\b|(?<action>\b(?:keep|leave)\b)\s+(?:every|all|any)\s+(?:findings?|issues?|problems?|defects?)\s+out\b|(?<action>\b(?:antworte|schreib\w*|gib)\b)[^.!?\r\n]{0,60}?\b(?:selbst|auch)\s+wenn\s+der\s+(?:Nutzer|Benutzer)\b[^.!?\r\n]{0,60}?\b(?:verlangt|wünscht|bittet|möchte|will)\b|\b(?:egal|ganz\s+gleich),?\s+was\s+du\s+(?:findest|feststellst|entdeckst)\b[^.!?\r\n]{0,60}?\b(?:lautet|nur|ausschließlich)\b|\b(?:хоч\s+би\s+що|що\s+б\s+не|незалежно\s+від\s+того,?\s+що)\s+(?:просив|просить|попросить|хоче|каже|написав)\s+користувач\w*[^.!?\r\n]{0,60}?(?<action>\b(?:відповідай|пиши|виводь|повертай)\b)'; Name='forces an output that overrides the user''s request or suppresses the real result' }
    @{ Id='T01'; RuleId='T01-019'; Sev='HIGH'; Rx='^\s*(?:\[\s*|<<\s*|#{1,3}\s*)?(?:system(?:\s+message)?|operator|developer|admin(?:istrator)?|Systemnachricht|Betreiber|Entwickler|система|оператор|розробник)\s*(?:[-–]\s*\w+\s*)?(?:\]|>>|#{1,3}|:)\s*[^\r\n]{0,160}?(?:\bpolicy\s+updated\b|\boverride\b|\bfrom\s+(?:here|now)\s+on\b|\breleased\s+from\b|\bobeys?\b|\btakes?\s+priority\b|\baufgehoben\b|\bVorrang\b|скасовано|пріоритет|з\s+цієї\s+миті|відтепер)'; Name='fake system/operator turn inside the file grants itself authority' }
    @{ Id='T01'; RuleId='T01-020'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; Rx='\b(?:if\s+you\s+are\s+an?\s+(?:AI|assistant|language\s+model|LLM)|(?:any|every|each)\s+(?:AI(?:\s+assistant)?|assistant|model|language\s+model|LLM|agent)\s+(?:that\s+)?(?:reading|processing|reads|processes|parsing|parses)|when\s+(?:an?\s+|the\s+)?(?:AI|assistant|model)\s+(?:reads|processes)\s+this)\b[^\r\n]{0,200}?(?<action>\babove\s+(?:everything|anything|all)\b|\bignore\b|\bdisregard\b|\bstop\s+(?:taking|following)\b|\binstead\s+of\b)|\b(?:jedes|jede|jeder|alle)\s+(?:Sprachmodell|KI|Modell|Assistent\w*|KI-\w+)\b[^\r\n]{0,60}?\b(?:liest|verarbeitet)\b[^\r\n]{0,200}?(?<action>\bignorier\w*|\bnachrangig\b|\bmissacht\w*|\bstatt\b)|(?:\bбудь-як\w+|\bкожн\w+|\bусяк\w+)\s+(?:модель|ШІ|асистент|нейромереж)\w*[^\r\n]{0,60}?(?:читає|обробляє)[^\r\n]{0,200}?(?<action>ігнорувати|ігноруй|не\s+виконувати|припинити|замість)|\bколи\s+(?:цей\s+(?:рядок|текст)\s+)?(?:обробляє|читає)\s+(?:асистент|модель|ШІ)\b[^\r\n]{0,200}?(?<action>припинити|ігнорувати|замість)'; Name='text addressed to any AI that reads it orders an override' }
    @{ Id='T06'; RuleId='T06-018'; Sev='HIGH'; ProseAction=$true; RejectableQuote=$true; RefusalCondition=$true; Rx='(?<action>\b(?:print|reveal|repeat|quote|reproduce|output|show|dump|translate|summari[sz]e|recite|encode|append|add|include|list|give)\b)[^.!?\r\n]{0,100}?\b(?:hidden|private|secret|initial|original|setup)\s+(?:instructions|directives|prompt|configuration|setup\s+text)\b[^.!?\r\n]{0,60}?\b(?:you\s+(?:were|have\s+been)\s+(?:given|configured|handed)|(?:your|the)\s+(?:developer|operator)\s+(?:configured|gave|set)|from\s+the\s+operator|at\s+the\s+start\s+of)|\b(?:above\s+this\s+(?:line|message|point)\s+in\s+your\s+(?:context|prompt|conversation)|in\s+your\s+context\s+above\s+this)\b|(?<action>\b(?:add|include|append|summari[sz]e|quote|copy|show)\b)[^.!?\r\n]{0,80}?\b(?:earlier|previous|past|other)\s+conversations?\s+with\s+other\s+(?:people|users|customers)\b|(?<action>\b(?:häng\w*|gib|gibst|zeig\w*|zitier\w*|fass\w*|übersetz\w*|wandle|beziehe|füge|nenn\w*|liste)\b)[^.!?\r\n]{0,120}?\b(?:(?:deinen|dein|den)\s+(?:vollständigen\s+|gesamten\s+|kompletten\s+|eigenen\s+)?System-?prompt|Betreiberanweisungen|Einrichtungs(?:text|anweisungen)|(?:verborgene|versteckte|geheime|interne)\w*\s+Anweisungen|oberhalb\s+dieser\s+(?:Nachricht|Zeile)|Unterhaltungen\s+mit\s+anderen\s+(?:Personen|Nutzern|Menschen))\b|(?<action>\b(?:процитуй|покажи|виведи|перекажи|переклади|додай|включи|наведи|повтори|відтвори)\b)[^.!?\r\n]{0,120}?(?:прихован\w+\s+(?:інструкці|вказівк|налаштуван)\w*|вище\s+за\s+цей\s+рядок\s+у\s+твоєму\s+контексті|налаштуван\w+,\s+яких\s+користувач\s+не\s+бачив|системн\w+\s+промпт\w*)'; Name='requests the agent''s setup or hidden instructions, earlier context, or other people''s conversations' }
)

$rxOpts = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
$rxTimeout = [timespan]::FromSeconds(2)
$n = 0
foreach ($r in $rules) {
    $r.N = $n++
    $r.Regex = [regex]::new($r.Rx, $rxOpts, $rxTimeout)
    if ($r.Skip) { $r.SkipRx = [regex]::new($r.Skip, $rxOpts) }
}

# Explicit IDs survive additions and reordering. Never renumber or reuse retired IDs.
$catalogRules = @(
    foreach ($r in $rules) {
        [pscustomobject][ordered]@{ RuleId=$r.RuleId; Threat=$r.Id; Kind='pattern';
            Name=($r.Name ?? $r.RuleId); DefaultSeverity=$r.Sev; Pattern=$r.Rx }
    }
    Get-Content -LiteralPath (Join-Path $PSScriptRoot '../references/structural-rules.json') -Raw | ConvertFrom-Json
) | Sort-Object RuleId
$catalogById = @{}
foreach ($entry in $catalogRules) {
    if ($entry.RuleId -cnotmatch '^T(?:0[1-9]|1[0-9]|2[0-6])-[0-9]{3}$' -or
        -not $entry.RuleId.StartsWith($entry.Threat + '-', [StringComparison]::Ordinal) -or
        $catalogById.ContainsKey($entry.RuleId)) { throw 'Invalid or duplicate stable rule ID' }
    $catalogById[$entry.RuleId]=$entry
}
$catalogJson = ConvertTo-Json -InputObject @($catalogRules) -Depth 6 -Compress
$catalogSha256 = Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes($catalogJson))
if ($ListRules) {
    [pscustomobject]@{ RuleCatalogVersion=1; RuleCatalogSha256=$catalogSha256; Rules=@($catalogRules) } | ConvertTo-Json -Depth 6
    exit 0
}

# "do not forget to read ~/.ssh" and "without asking" are not prohibitions: remove them before looking for a negation.
$pseudoNegRx = [regex]::new('(do\s+not|don''t|never)\s+(forget|hesitate|skip|miss|fail|stop)|not\s+only|не\s+(забудь|забувай|вагайся|пропускай|лише|тільки|зупиняйся)|without\s+(asking|telling|confirmation|notifying|permission|approval|hesitation)|без\s+(відома|підтвердження|дозволу|запиту|вагань)', $rxOpts)
# A prohibiting heading lowers the severity for the whole section, so it needs explicit wording, not just any "не".
$negHeadingRx = [regex]::new('^#{2,6}\s.*(\b(never|do\s+not|don''t|must\s+not|forbidden|prohibited)\b|ніколи|заборон|не\s+можна|не\s+роби|чого\s+не)', $rxOpts)
$down = @{ CRITICAL = 'HIGH'; HIGH = 'MEDIUM'; MEDIUM = 'LOW'; LOW = 'LOW' }
$up = @{ LOW = 'MEDIUM'; MEDIUM = 'HIGH'; HIGH = 'CRITICAL'; CRITICAL = 'CRITICAL' }
$severityRank = @{ LOW=0; MEDIUM=1; HIGH=2; CRITICAL=3 }

# The skill reads external content (web, email, pages)…
$externalRx = [regex]::new('web\s*search|WebFetch|WebSearch|вебпошук|веб-пошук|get_page_text|browse\s+(to|the)\b|fetch\s+(the\s+)?(page|url|website|article)|read\s+the\s+(source|page|article|email|website|issue|ticket)|прочитай\s+(джерело|новину|сторінку|посилання|лист)', $rxOpts)
# …and has a rule that this content is data, not instructions.
$guardRx = [regex]::new('data,?\s+not\s+(commands|instructions)|not\s+as\s+instructions|treat\s+.{0,40}\bas\s+(untrusted\s+)?data|дані,?\s+(а\s+)?не\s+(інструкці|команд)|не\s+(виконуй|слухай)\s+.{0,30}інструкці', $rxOpts)
# The skill goes to the network…
$netRx = [regex]::new('\b(curl|wget)\b|Invoke-(WebRequest|RestMethod)|\b(iwr|irm)\b|requests\.(get|post|put)|httpx\.|urllib\.request|aiohttp|\bfetch\(|axios|http\.client|Net\.WebClient|HttpClient', $rxOpts)
# …and the description says so.
$netDeclRx = [regex]::new('api|web|http|url|online|internet|download|upload|fetch|search|publish|deploy|post|send|sync|remote|cloud|github|мереж|інтернет|завантаж|онлайн|пошук|сайт|публік|надсил|відправ|хмар|генер|зображен', $rxOpts)

$emojiZwjRx = [regex]::new('(?<=[\uD83C-\uD83E][\uDC00-\uDFFF]|️|[☀-➿])‍')
$invisibleRx = [regex]::new('\uDB40[\uDC00-\uDDEF]|[­͏ᅟᅠㅤﾠ]|\p{Cf}')
$mixedWordRx = [regex]::new('\b(?=\w*[a-z])(?=\w*[Ͱ-ϿЀ-ԯ])\w+\b', $rxOpts)
$b64Rx = [regex]::new('(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])')
$refRx = [regex]::new('(?<![\w/.\\-])((?:scripts|references|assets|bin|lib|src|tools|templates)/[\w./-]+\.[A-Za-z0-9]{1,6})\b')

# Cyrillic and Greek letters that look Latin → Latin (to find "ignоre" written with a Cyrillic "о").
$confusable = [System.Collections.Generic.Dictionary[char, char]]::new()
foreach ($pair in 'а=a', 'в=b', 'е=e', 'к=k', 'м=m', 'н=h', 'о=o', 'р=p', 'с=c', 'т=t', 'у=y', 'х=x', 'і=i', 'ј=j', 'ѕ=s', 'һ=h', 'ԁ=d', 'ԛ=q', 'ԝ=w',
                      'α=a', 'β=b', 'ε=e', 'η=n', 'ι=i', 'κ=k', 'μ=m', 'ν=v', 'ο=o', 'ρ=p', 'τ=t', 'υ=u', 'χ=x') {
    $confusable[$pair[0]] = $pair[2]
}
$foldWord = [Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $sb = [Text.StringBuilder]::new()
    foreach ($ch in $m.Value.ToCharArray()) {
        $lo = [char]::ToLowerInvariant($ch)
        [void]$sb.Append($(if ($confusable.ContainsKey($lo)) { $confusable[$lo] } else { $ch }))
    }
    $sb.ToString()
}
function Get-Normalized([string]$s) {
    $t = $s.Normalize([Text.NormalizationForm]::FormKC)
    $t = $invisibleRx.Replace($t, '')
    $mixedWordRx.Replace($t, $foldWord)
}

# Decodes a base64 block if the result looks like text (UTF-8 or UTF-16LE).
function Get-DecodedText([string]$token) {
    $core = $token.TrimEnd('=')
    if ($core.Length % 4 -eq 1) { return $null }
    try { $raw = [Convert]::FromBase64String($core + ('=' * ((4 - $core.Length % 4) % 4))) } catch { return $null }
    foreach ($enc in [Text.Encoding]::UTF8, [Text.Encoding]::Unicode) {
        $txt = $enc.GetString($raw)
        if ($txt.Length -lt 8) { continue }
        $ok = 0
        foreach ($ch in $txt.ToCharArray()) { if (($ch -ge ' ' -and $ch -le '~') -or $ch -eq "`n" -or $ch -eq "`r" -or $ch -eq "`t" -or ($ch -ge [char]0x0400 -and $ch -le [char]0x04FF)) { $ok++ } }
        if ($ok / $txt.Length -ge 0.9) { return $txt }
    }
    return $null
}

function Get-Distance([string]$a, [string]$b) {
    $d = [int[]](0..$b.Length)
    for ($i = 1; $i -le $a.Length; $i++) {
        $prev = $d[0]; $d[0] = $i
        for ($j = 1; $j -le $b.Length; $j++) {
            $tmp = $d[$j]
            $cost = if ($a[$i - 1] -ceq $b[$j - 1]) { 0 } else { 1 }
            $d[$j] = [Math]::Min([Math]::Min($d[$j] + 1, $d[$j - 1] + 1), $prev + $cost)
            $prev = $tmp
        }
    }
    $d[$b.Length]
}

$imageExt = '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp'
function Test-ImageMagic([byte[]]$b, [string]$ext) {
    if ($b.Length -lt 12) { return $false }
    $hex = -join ($b[0..11] | ForEach-Object { $_.ToString('X2') })
    switch ($ext) {
        '.png'  { return $hex.StartsWith('89504E47') }
        '.jpg'  { return $hex.StartsWith('FFD8FF') }
        '.jpeg' { return $hex.StartsWith('FFD8FF') }
        '.gif'  { return $hex.StartsWith('47494638') }
        '.webp' { return $hex.StartsWith('52494646') -and $hex.Substring(16, 8) -eq '57454250' }
        '.ico'  { return $hex.StartsWith('00000100') }
        '.bmp'  { return $hex.StartsWith('424D') }
    }
    return $false
}
# Is there anything after the end of the image (polyglot: picture + archive/script)?
function Test-ImageTrailer([string]$latin, [string]$ext) {
    $t = $latin.TrimEnd([char]0, ' ', "`r", "`n", "`t")
    switch ($ext) {
        '.png'  { $i = $t.LastIndexOf('IEND', [StringComparison]::Ordinal); return ($i -lt 0 -or $t.Length - $i -gt 8) }
        '.jpg'  { return -not $t.EndsWith([string][char]0xFF + [char]0xD9, [StringComparison]::Ordinal) }
        '.jpeg' { return -not $t.EndsWith([string][char]0xFF + [char]0xD9, [StringComparison]::Ordinal) }
        '.gif'  { return -not $t.EndsWith(';', [StringComparison]::Ordinal) }
    }
    return $false
}

$builtinNames = 'pdf', 'docx', 'xlsx', 'pptx', 'docs', 'skill-creator', 'code-review', 'security-review', 'review', 'init', 'simplify', 'loop',
    'schedule', 'run', 'debug', 'batch', 'update-config', 'claude-api', 'keybindings-help', 'deep-research', 'dataviz', 'artifact-design',
    'artifact-capabilities', 'artifact-diagramming', 'consolidate-memory', 'import-memory', 'plugin-authoring', 'fewer-permission-prompts',
    'computer-use', 'chrome-browser', 'built-in-browser', 'setup-claude', 'explain-usage', 'frontend-design', 'mcp-builder', 'webapp-testing',
    'brand-guidelines', 'canvas-design', 'doc-coauthoring', 'internal-comms', 'theme-factory', 'algorithmic-art', 'web-artifacts-builder'
$binaryExt = '.exe', '.dll', '.so', '.dylib', '.bin', '.msi', '.scr', '.com', '.jar', '.pyc', '.pyo', '.pyd', '.class', '.wasm', '.app', '.dmg', '.pkg',
    '.deb', '.rpm', '.node', '.lnk', '.chm', '.iso', '.img', '.vhd', '.vhdx', '.appimage', '.apk', '.ipa', '.sys', '.drv', '.ocx', '.cpl', '.pif', '.o', '.a', '.lib', '.elf', '.dex',
    '.scpt'
$archiveExt = '.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.zst', '.lz', '.lzma', '.cab', '.whl', '.egg', '.nupkg', '.vsix', '.crx', '.xpi'
$pickleExt = '.pkl', '.pickle', '.pt', '.pth', '.joblib', '.ckpt'
$macroExt = '.docm', '.xlsm', '.pptm', '.dotm', '.xlsb', '.xlam'
$docExt = '.pdf', '.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt', '.odt', '.ods', '.rtf'
$mediaExt = '.ttf', '.otf', '.woff', '.woff2', '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.mov', '.avi', '.tiff', '.tif', '.heic', '.avif'
# Launchers per OS: Windows shell files, macOS Terminal/Finder files, Linux desktop and systemd units.
$launchExt = '.hta', '.reg', '.wsf', '.wsh', '.jse', '.scf', '.url', '.inf', '.ps1xml', '.library-ms', '.searchconnector-ms', '.settingcontent-ms',
    '.appref-ms', '.command', '.tool', '.plist', '.desktop', '.service', '.timer'
$scriptExt = '.ps1', '.psm1', '.sh', '.bash', '.zsh', '.ksh', '.csh', '.tcsh', '.fish', '.command', '.py', '.js', '.mjs', '.cjs', '.ts', '.rb', '.pl',
    '.php', '.bat', '.cmd', '.vbs', '.vbe', '.applescript', '.lua', '.go', '.hta', '.wsf', '.jse'
$quietDotfiles = '.gitignore', '.gitattributes', '.gitkeep', '.editorconfig', '.gitmodules', '.mcp.json', '.lsp.json', '.npmignore', '.prettierrc', '.markdownlint.json'

$findings = [System.Collections.Generic.List[object]]::new()
$fileList = [System.Collections.Generic.List[object]]::new()
# Folder metadata that Finder and Explorer leave behind (common in archives packed on macOS or Windows).
# The name alone is not trusted: the bytes must start with that format's own header.
function Test-OsMetadata([string]$name, [byte[]]$b) {
    if ($b.Length -lt 8) { return $false }
    $hex = -join ($b[0..7] | ForEach-Object { $_.ToString('X2') })
    if ($name -eq '.DS_Store') { return $hex -eq '0000000142756431' }
    if ($name.StartsWith('._', [StringComparison]::Ordinal)) { return $hex.StartsWith('00051607') }
    if ($name -in 'Thumbs.db', 'ehthumbs.db') { return $hex -eq 'D0CF11E0A1B11AE1' }
    return $false
}
# Named pipes, devices and sockets (macOS/Linux, e.g. from an extracted tar) are never opened:
# reading a FIFO blocks forever. PowerShell and .NET report them as regular files of size 0, so only
# empty entries are checked, with the system's POSIX find (a system tool, nothing from the target runs).
function Test-SpecialFile([IO.FileInfo]$item) {
    if ($IsWindows -or $item.Length -ne 0) { return $false }
    try { return [bool](& find $item.FullName '(' -type p -o -type c -o -type b -o -type s ')' -print 2>$null) }
    catch { return $false }
}
# Files and folders are walked and hashed through .NET: PowerShell's path cmdlets treat '\' as a
# separator even on macOS/Linux, where it is a legal file-name character.
function Get-Sha256([string]$path) {
    $stream = [IO.File]::OpenRead($path)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose(); $stream.Dispose() }
}
$domains = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
$stats = [ordered]@{ Files = 0; Scripts = 0; Images = 0; Binary = 0; Links = 0 }
$texts = @{}
$fmNames = [System.Collections.Generic.List[object]]::new()
$fmDescriptions = @{}
$components = [System.Collections.Generic.List[object]]::new()
$coverageIssues = [System.Collections.Generic.List[object]]::new()
function Add-CoverageIssue([string]$file, [string]$reason) {
    if (-not ($coverageIssues | Where-Object { $_.File -ceq $file -and $_.Reason -ceq $reason })) {
        $coverageIssues.Add([pscustomobject]@{ File = $file; Reason = $reason })
    }
}

# Only prose can be a safety instruction. Do not let comments or a remote heading excuse code.
function Test-Prohibition($hit, [bool]$heading, [bool]$prose) {
    if (-not $prose) { return $false }
    $source = $hit.Source
    $match = $hit.Match
    if (-not $match.Success) { return $false }
    $before = $pseudoNegRx.Replace($source.Substring(0, $match.Index), '')
    $after = $pseudoNegRx.Replace($source.Substring($match.Index + $match.Length), '')
    # Restrict to the current clause, close to the protected operation; never a trailing 'not'.
    $before = ($before -split '(?:[;.!?]|\b(?:but|then|however|але|потім)\b)')[-1]
    if ($before.Length -gt 100) { $before = $before.Substring($before.Length - 100) }
    if ($before -match '(?i)(?:\b(?:never|do\s+not|don''t|must\s+not)\s+|(?:ніколи\s+)?\bне\s+)(?:(?:read|copy|send|share|write|change|modify|access|expose|silently|читай|змінюй|перенось|надсилай|пиши)\b[\s`"''~/*-]*){0,2}$') { return $true }
    if ($before -match '(?i)(?:never|do\s+not|don''t|must\s+not|ніколи|\bне)\s+silently\s*$') { return $true }
    # Ukrainian commonly places the prohibition after its object.
    if ($after -match '(?i)^[^;.!?]{0,40}\bне\s+(переносити|копіювати|надсилати|читати|змінювати)\b' -and $after -notmatch '(?i)\b(але|потім)\b') { return $true }
    # A noun list under 'Never disclose' is different from an imperative under that heading.
    if ($heading -and $source -match '^\s*[-*]\s+') {
        $nouns = $source.Remove($match.Index,$match.Length)
        $nouns = $nouns -replace '(?i)\b(tokens?|secrets?|passwords?|contents?|and|токени|паролі|секрети|вміст|та|і)\b',''
        return $nouns -match '^[\s`"''*.,:;-]*$'
    }
    return $false
}

# Local, bounded context decisions. A document's claim that it is safe is never a suppression.
function Get-ContextAdjustment($rule, [string]$source, $match, [bool]$prose) {
    $action = $match.Groups['action']
    $contextIndex = if ($action.Success) { $action.Index } else { $match.Index }
    $before = $source.Substring(0,$contextIndex)
    $after = $source.Substring($match.Index+$match.Length)
    if ($prose -and $rule.RejectableQuote) {
        # Lower only a bounded, explicitly rejected quotation containing this entire hit.
        # Code, decoded text, unrelated quotes and later positive matches retain their severity.
        $quoteRx = [regex]::new('“[^”\r\n]{1,1000}”|„[^“”\r\n]{1,1000}[“”]|«[^»\r\n]{1,1000}»|"[^"\r\n]{1,1000}"', $rxOpts, $rxTimeout)
        foreach ($quote in $quoteRx.Matches($source)) {
            if ($match.Index -le $quote.Index -or $match.Index+$match.Length -ge $quote.Index+$quote.Length) { continue }
            $lead = $source.Substring(0,$quote.Index)
            if ($lead.Length -gt 160) { $lead=$lead.Substring($lead.Length-160) }
            $tail = $source.Substring($quote.Index+$quote.Length)
            if ($tail.Length -gt 1200) { continue } # uncertain distant callbacks never justify lowering
            # A quotation introduced as an example of injected text ("sentences like …") and followed by an
            # explicit refusal is data being described, not an instruction being given.
            $rejectLead = $lead -match '(?i)\b(example|quotation|quoted|training)\b[^;\r\n]{0,65}\b(to\s+reject|not\s+to\s+(follow|execute))\b|\bприклад\w*[^;\r\n]{0,65}(не\s+слід\s+виконувати|відхилити)|\b(sentences?|phrases?|lines?)\s+(like|such\s+as)\s*$|\b(Sätze|Formulierungen|Zeilen)\s+wie\s*$|(речення|фраз\w*)\s+на\s+кшталт\s*$'
            $rejectTail = $tail -match '(?i)\b(do\s+not|don''t|never)\s+(follow|execute|carry\s+(it|this)\s+out)\b|\bзалиши\b[^;\r\n]{0,30}\bлише\s+приклад\w*|\bне\s+(виконуй|виконай|застосовуй|дотримуйся)\b|\b(sind|ist)\s+(bloße|nur|reine)\s+Daten\b|\bbefolge\w*\s+(sie|ihn|es|das)\s+nicht\b|\bnicht\s+(befolgen|ausführen)\b|\bare\s+(just|only|plain)\s+data\b'
            $positiveTail = $false
            $executeRx=[regex]::new('\b(?:follow|execute|obey|perform|carry\s+(?:(?:it|this|that)\s+)?out|apply|act\s+on|виконай|виконуй|дотримуйся|застосуй|застосовуй)\b|\b(?:run|include|reproduce|repeat|use|copy|print|show|read|paste|return)\s+(?:it|that|them|their|its|the\s+(?:quoted|example|instruction|contents))\b',$rxOpts,$rxTimeout)
            foreach ($execution in $executeRx.Matches($tail)) {
                $prefix=$tail.Substring(0,$execution.Index)
                if ($prefix -notmatch '(?i)\b(do\s+not|must\s+not|should\s+not|don''t|never|cannot)\s+(?:(?:ever|silently)\s+|(?:attempt|try)\s+to\s+)?$|\bне\s+(?:намагайся\s+)?$') { $positiveTail=$true; break }
            }
            $suppliedEdit = $lead -match '(?i)\buser[- ](provided|supplied)\b[^;.!?\r\n]{0,70}\btemplate\b[^;.!?\r\n]{0,70}\breplace\s+(the\s+)?(sentence|text|instruction)\s*$'
            $privateEditSource = $lead -match '(?i)\b(hidden|private|protected|concealed|runtime|session)\b'
            $literalReplacement = $tail -match '^\s+with\s+(“[^”\r\n]{1,240}”|«[^»\r\n]{1,240}»|"[^"\r\n]{1,240}")'
            if ($suppliedEdit -and -not $privateEditSource -and $literalReplacement -and -not $positiveTail) {
                return @{Severity='LOW'; Note=' — replacing a quoted sentence in an explicitly user-supplied template'}
            }
            if ($rejectLead -and $rejectTail -and -not $positiveTail) { return @{Severity='LOW'; Note=' — explicitly rejected quoted example; verify framing manually'} }
        }
    }
    if ($prose -and $rule.RefusalCondition) {
        # "If someone asks you to print X, decline": the file describes a request it tells the agent to refuse.
        $clause = ($before -split '(?:;|[.!?]\s+)')[-1]
        if ($clause -match '(?i)\b(?:if|when|should)\s+(?:someone|somebody|anyone|a\s+user|the\s+user|they|a\s+customer)\b[^,;]{0,40}\b(?:asks?|requests?|wants?)\s+(?:you\s+)?(?:to\s+)?$' -and
            $after -match '(?i)^[^.!?]{0,120}\b(?:decline|refuse|do\s+not|don''t|say\s+no)\b') {
            return @{Severity='LOW'; Note=' — describes a disclosure request the file tells the agent to refuse'}
        }
    }
    if ($rule.PersonaKeepsRules -and $match.Value -match '(?i)^you\s+are\s+now') {
        # A persona the file explicitly keeps under every governing rule is a role to review, not an override.
        $keeps = $source -match '(?i)\b(?:still|continues?\s+to|always)\s+(?:keeps?|follows?|obeys?|respects?)\s+(?:every|all|each|the)\s+(?:rules?|guidelines|polic)'
        $frees = $source -match '(?i)\bkeeps?\s+none\b|\bno\s+(?:rules|guidelines|restrictions|limits)\b|\bnever\s+refuses\b|\boutside\s+the\b|\banswers\s+to\s+no\b|\bfree\s+(?:of|from)\b|\bignore\b|\bdisregard\b'
        if ($keeps -and -not $frees) { return @{Severity='MEDIUM'; Note=' — persona explicitly keeps the governing rules; review the role'} }
    }
    if ($prose -and $rule.LiteralPromptData) {
        $provided=$match.Value -match '(?i)\b(public|user[- ]provided|user[- ]supplied)\b|\b(публічн|відкрит)\w*'
        $protected=$match.Value -match '(?i)\b(hidden|private|protected|concealed|actual|real)\b|\b(прихован|таємн|приватн|фактичн|справжн)\w*'
        if ($provided -and -not $protected -and $after -match '^\s+(template|example|шаблон\w*|приклад\w*)(?:\s+(below|here|shown|provided|нижче)){0,3}\s*[:=]\s*(“[^”\r\n]{1,240}”|«[^»\r\n]{1,240}»|"[^"\r\n]{1,240}")') {
            return @{Severity='LOW'; Note=' — explicitly supplied public prompt literal, not retrieved private runtime context'}
        }
        $shortTail=($after -split '[;.!?\r\n]',2)[0]
        if ($shortTail.Length -gt 120) { $shortTail=$shortTail.Substring(0,120) }
        $request=$match.Value+$shortTail
        $supplied=$request -match '(?i)\buser[- ](provided|supplied)\b|\b(provided|supplied)\s+by\s+(the\s+)?user\b'
        $runtime=$request -match '(?i)\b(hidden|private|protected|concealed|actual|real|runtime|session)\b|\byou\s+(received|were\s+given)\b|\b(?:your|current|running)\s+(system|developer)\b|\bcurrently\s+in\s+force\b'
        if ($supplied -and -not $runtime) {
            return @{Severity='MEDIUM'; Note=' — named user-supplied prompt artifact; verify its provenance and authorized scope'}
        }
    }
    if ($prose -and $rule.PolicyOverride) {
        $originalPrefix=($source.Substring(0,$match.Index) -split '(?:;|[.!?]\s+|\b(?:but|then|however|але|потім)\b)')[-1]
        if ($before -match '(?i)\b(not|never|не)\s+(been\s+)?$' -or
            $originalPrefix -match '(?i)\b(do\s+not|must\s+not|should\s+not|don''t|never|cannot)\s+(claim|say|report|treat|regard|consider)\s+(that\s+)?$|\bне\s+(вважай|стверджуй|кажи)\s+(що\s+)?$') {
            return @{Severity='LOW'; Note=' — explicit negation of the authority-inversion claim'}
        }
    }
    if ($prose -and $rule.ProseAction) {
        $clause = ($before -split '(?:;|[.!?]\s+|\b(?:but|then|however|але|потім)\b)')[-1]
        if ($clause.Length -gt 160) { $clause=$clause.Substring($clause.Length-160) }
        # Coordinate only an explicit negative 'or/nor' list; a later positive clause stays visible.
        if ($clause -match '(?i)(?:\bnever|\bdo\s+not|\bdon''t|\bmust\s+not|\bне|\bніколи)\s+(?:(?:ever|silently|quietly)\s+|(?:attempt|try)\s+to\s+)?(?:(?:read|write|collect|share|copy|send|insert|add|export|reproduce|summarize|encode|transcribe|reveal|retrieve|quote|print|show)\b[^;.!?]{0,60}\b(?:or|nor)\s+)?$') {
            return @{Severity='LOW'; Note=' — explicit prohibition of this action'}
        }
    }
    if ($prose -and $rule.SecretQuestion -and $match.Value -match '^without\s+asking$' -and
        $after -match '^\s+for\s+(?:(?:a|an|the|your|any)\s+)?(recovery\s+phrase|seed\s+phrase|private\s+key|account\s+password|password|api[-\s]*key|token)\b') {
        return @{Severity='LOW'; Note=' — avoids requesting a secret, not bypassing consent'}
    }
    if ($prose -and $rule.LiteralRole) {
        $left=$source.LastIndexOf('`',$match.Index)
        $right=if($left -ge 0){$source.IndexOf('`',$match.Index+$match.Length)}else{-1}
        if ($left -ge 0 -and $right -gt $left) {
            $literal=$source.Substring($left+1,$right-$left-1)
            if ($literal -match '^<(system|developer|admin)>\s*(example|placeholder|sample|text)\s*</\1>$' -and
                $source.Substring(0,$left) -match '(?i)\b(literal|XML|syntax|example)\b') {
                return @{Severity='LOW'; Note=' — literal placeholder markup in an inline example'}
            }
        }
    }
    if ($prose -and $rule.MinerReference -and $match.Value -match '^(xmrig|minerd|ethminer|cpuminer)$' -and
        $before -match '(?i)\b(mentions?|defines?|describes?|term)\s+[`"'']?$') {
        $guard='(?i)\bno\s+(mining\s+)?process\s+may\s+be\s+launched|\b(do\s+not|never|must\s+not)\s+(run|launch|start|install|execute)\s+(it|this\s+miner|any\s+miner|a\s+mining\s+process)\b'
        if ($source -match $guard -and ($source -replace $guard,'') -notmatch '(?i)\b(run|launch|start|install|execute|spawn)\b') {
            return @{Severity='LOW'; Note=' — glossary reference with an explicit no-execution boundary'}
        }
    }
    if ($rule.NamedEnvironment -and $match.Value -match '^(process\.env|os\.environ)$') {
        $rx=if($match.Value -eq 'process.env') {
            '^\s*(?:\.\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)|\[\s*["''](?<name>[A-Za-z_][A-Za-z0-9_]*)["'']\s*\])'
        } else {
            '^\s*(?:\[\s*["''](?<name>[A-Za-z_][A-Za-z0-9_]*)["'']\s*\]|\.get\(\s*["''](?<name>[A-Za-z_][A-Za-z0-9_]*)["''])'
        }
        $field=[regex]::Match($after,$rx)
        if ($field.Success) {
            $name=$field.Groups['name'].Value
            if ($name -match '(?i)(^|_)(API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|AUTH|COOKIE|SESSION)($|_)') {
                return @{Severity='HIGH'; Note=' — reads a named credential environment variable'}
            }
            return @{Severity='LOW'; Note=' — single named environment value; inspect its purpose, not a full dump'}
        }
    }
    if ($rule.MemoryOptions) {
        $assignment=[regex]::Match($source.Substring($match.Index),'^NODE_OPTIONS\s*=\s*(?:"(?<double>[^"\r\n]*)"|''(?<single>[^''\r\n]*)''|(?<bare>[^\s;]+))','IgnoreCase')
        if ($assignment.Success) {
            $value=($assignment.Groups['double'].Value+$assignment.Groups['single'].Value+$assignment.Groups['bare'].Value).Trim()
            if ($value -match '^--max-(old|semi)-space-size(?:=|\s+)[1-9][0-9]{0,5}(?:\s+--max-(old|semi)-space-size(?:=|\s+)[1-9][0-9]{0,5})*$') {
                return @{Severity='LOW'; Note=' — literal memory-limit options only, without a loader or interpolation'}
            }
        }
    }
    return $null
}

# JSON strings are decoded as data; command/args are never invoked. Preserve argument boundaries:
# sh -c consumes one script argument, whereas curl's literal '|' argument is not a shell pipeline.
function Read-Components($node, [string]$file, [string]$pointer = '$', [int]$depth = 0) {
    if ($depth -gt 40) { Add-CoverageIssue $file 'JSON nesting limit'; return }
    if ($node -is [System.Collections.IDictionary]) {
        if ($node.command -is [string]) {
            $argv = @($node.args | Where-Object { $_ -is [string] })
            $command = $node.command
            $components.Add([pscustomobject]@{ File=$file; JsonPath=$pointer; Command=$command; Args=$argv; Url=$null })
            $fragments = [System.Collections.Generic.List[string]]::new()
            $fragments.Add($command)
            if ($argv.Count) {
                $exe = [IO.Path]::GetFileNameWithoutExtension($command).ToLowerInvariant()
                if ($exe -in 'sh','bash','zsh','dash','ksh','fish','pwsh','powershell','cmd') {
                    for ($a = 0; $a -lt $argv.Count - 1; $a++) {
                        if ($argv[$a] -match '^(?:-[a-z]*c|-(?:command|encodedcommand)|/c)$') {
                            $fragments.Add($(if ($exe -in 'pwsh','powershell','cmd') { $argv[($a+1)..($argv.Count-1)] -join ' ' } else { $argv[$a+1] }))
                            break
                        }
                    }
                } else {
                    # Separators in individual arguments stay quoted, not executable shell syntax.
                    $safeArgs = $argv | ForEach-Object { if ($_ -match '[|;&\r\n]') { '"' + $_.Replace('|','<pipe>') + '"' } else { $_ } }
                    $fragments.Add($command + ' ' + ($safeArgs -join ' '))
                }
            }
            foreach ($fragment in $fragments) {
                $normalized = Get-Normalized $fragment
                foreach ($h in (Get-Hits $normalized $false '.json' $true)) {
                    Add-Finding -RuleId $h.Rule.RuleId $h.Severity $h.Rule.Id $file 0 $fragment ("$($h.Rule.Name ?? $h.Match.Value)$($h.ContextNote) — in parsed JSON at $pointer")
                }
            }
        }
        # Keys as well as values can be JSON-escaped (for example an API endpoint variable).
        foreach ($key in $node.Keys) {
            if ($node[$key] -is [string]) {
                foreach ($h in (Get-Hits (Get-Normalized ($key + '=' + $node[$key])) $false '.json' $true)) {
                    Add-Finding -RuleId $h.Rule.RuleId $h.Severity $h.Rule.Id $file 0 ($key + '=' + $node[$key]) ("$($h.Rule.Name ?? $h.Match.Value)$($h.ContextNote) — in parsed JSON at $pointer.$key")
                }
                if ($key -match '^(preinstall|install|postinstall)$') {
                    $commandHits=Get-Hits $node[$key] $false '.json' $true
                    $risky=@($commandHits | Where-Object { $_.Severity -in 'HIGH','CRITICAL' -and $_.Rule.Id -in 'T05','T06','T07','T08','T10' })
                    if ($risky.Count) { Add-Finding -RuleId 'T09-901' 'HIGH' 'T09' $file 0 $node[$key] "installation lifecycle launches a high-risk command — in parsed JSON at $pointer.$key" }
                }
            }
        }
        if ($node.url -is [string] -and $node.url -match '^https?://') {
            $components.Add([pscustomobject]@{ File=$file; JsonPath=$pointer; Command=$null; Args=@(); Url=$node.url })
        }
        foreach ($key in $node.Keys) {
            if ($node[$key] -isnot [string]) { Read-Components $node[$key] $file ($pointer + '.' + $key) ($depth + 1) }
        }
    } elseif ($node -is [array]) {
        for ($j = 0; $j -lt $node.Count; $j++) { Read-Components $node[$j] $file ("${pointer}[$j]") ($depth + 1) }
    } elseif ($node -is [string]) {
        foreach ($h in (Get-Hits (Get-Normalized $node) $false '.json' $true)) {
            Add-Finding -RuleId $h.Rule.RuleId $h.Severity $h.Rule.Id $file 0 $node ("$($h.Rule.Name ?? $h.Match.Value)$($h.ContextNote) — in parsed JSON at $pointer")
        }
    }
}


# Paths are reported with '/' on every OS. Only Windows uses '\' as a separator; on macOS/Linux it is
# a legal file-name character and is kept, so two different files never collapse into one path.
function Rel([string]$p) {
    $r = [IO.Path]::GetRelativePath($base, $p)
    if ([IO.Path]::DirectorySeparatorChar -eq '\') { $r = $r.Replace('\', '/') }
    $r
}

function Show-Invisible([string]$s) {
    [regex]::Replace($s, '\uDB40[\uDC00-\uDDEF]|\p{Cf}|[\x00-\x1F\x7F­͏ᅟᅠㅤﾠ]', { param($m) '<U+{0:X4}>' -f [char]::ConvertToUtf32($m.Value, 0) })
}

function Add-Finding($sev, $id, $file, $line, $evidence, $note, [string]$RuleId) {
    if (-not $catalogById.ContainsKey($RuleId) -or $catalogById[$RuleId].Threat -cne $id) {
        throw "Missing, unknown or mismatched RuleId '$RuleId' for $id"
    }
    $ev = (Show-Invisible ($evidence ?? '')).Trim()
    if ($ev.Length -gt 160) { $ev = $ev.Substring(0, 157) + '...' }
    $findings.Add([pscustomobject]@{ Severity = $sev; Threat = $id; RuleId = $RuleId; File = $file; Line = $line; Note = (Show-Invisible $note); Evidence = $ev })
}

# All rules that match the text. $decoded — the text came from normalization or decoding.
function Get-Hits([string]$text, [bool]$inFm, [string]$ext, [bool]$decoded, [bool]$normalizedOnly=$false) {
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rules) {
        if ($decoded -and ($r.Raw -or $r.Scope -in 'fm','tools')) { continue }
        if ($r.Scope -eq 'fm' -and -not $inFm) { continue }
        if ($r.Scope -eq 'tools' -and (-not $inFm -or $fmField -ne 'allowed-tools')) { continue }
        if ($r.Ext -and $r.Ext -notcontains $ext) { continue }
        if ($r.AuthorityRef -and $text -notmatch '(?i)\bdeveloper(?:[''\u2019]s)?\s+(?:[\w-]{1,35}\s+){0,3}(messages?|instructions?|directions?|rules?|requirements?|constraints?|conventions?|policy)\b|\bsystem(?:[- ]level)?\s+(?:(?:security|safety|mandatory|governing|hidden|initial)\s+)?(messages?|instructions?|directions?|rules?|requirements?|constraints?|policy)\b') { continue }
        if ($r.SkipRx -and $r.SkipRx.IsMatch($text)) { continue }
        $src = if ($r.EmojiSafe) { $emojiZwjRx.Replace($text, '') } else { $text }
        $prose=$ext -in '.md','.mdx','.markdown' -and -not $inFm -and (-not $decoded -or $normalizedOnly) -and -not $fence
        $best=$null; $matchCount=0
        $m=$r.Regex.Match($src)
        while ($m.Success -and $matchCount++ -lt 32) {
            $candidate=[pscustomobject]@{ Rule=$r; Match=$m; Source=$src; Severity=$(if($r.MdSev -and $ext -in '.md','.mdx','.markdown'){$r.MdSev}else{$r.Sev}); ContextNote='' }
            $prohibited=$r.Neg -and (Test-Prohibition $candidate $negSection $prose)
            if ($prohibited) { $candidate.Severity=$down[$candidate.Severity]; $candidate.ContextNote=' — in a prohibition context' }
            $adjust=Get-ContextAdjustment $r $src $m $prose
            if ($adjust -and (-not $prohibited -or $severityRank[$adjust.Severity] -le $severityRank[$candidate.Severity])) {
                $candidate.Severity=$adjust.Severity; $candidate.ContextNote=$adjust.Note
            }
            if (-not $best -or $severityRank[$candidate.Severity] -gt $severityRank[$best.Severity]) { $best=$candidate }
            $m=$m.NextMatch()
        }
        if ($m.Success) {
            Add-CoverageIssue $rel 'per-line rule match limit'
            Add-Finding -RuleId 'T10-901' 'MEDIUM' 'T10' $rel 0 '' 'per-line rule match limit — remaining candidates not checked'
        }
        if ($best) { $hits.Add($best) }
    }
    return , $hits
}

# ---------- Inventory ----------
# .git content is not scanned, except what runs code: hooks (not .sample) and config.
$items = [System.Collections.Generic.List[object]]::new()
$pending = [System.Collections.Generic.Stack[object]]::new()
$pending.Push($(if ([IO.Directory]::Exists($target)) { [IO.DirectoryInfo]::new($target) } else { [IO.FileInfo]::new($target) }))
while ($pending.Count) {
    $current = $pending.Pop()
    $linked = $current.LinkType -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)
    if ($current -isnot [IO.DirectoryInfo] -or $linked) { $items.Add($current); continue }
    try {
        # Lists hidden and system entries too (like Get-ChildItem -Force); links are not followed.
        foreach ($child in $current.EnumerateFileSystemInfos()) {
            # Prune .git before walking it; only config and active hooks are audit inputs.
            $childRel = Rel $child.FullName
            if ($childRel -match '(?:^|/)\.git/(.+)$') {
                if ($Matches[1] -ne 'config' -and $Matches[1] -ne 'hooks' -and $Matches[1] -notmatch '^hooks/[^/]+$') { continue }
                if ($child.Name -like '*.sample') { continue }
            }
            $pending.Push($child)
        }
    } catch {
        Add-CoverageIssue (Rel $current.FullName) 'directory could not be enumerated'
        Add-Finding -RuleId 'T19-901' 'MEDIUM' 'T19' (Rel $current.FullName) 0 '' 'directory could not be enumerated — not checked'
    }
}

foreach ($item in $items) {
    $rel = Rel $item.FullName

    if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $stats.Links++
        Add-Finding -RuleId 'T17-901' 'HIGH' 'T17' $rel 0 "-> $($item.Target)" 'symlink (where does it lead?)'
        $linkText = [string]::Join('|', @($item.Target))
        $linkHash = Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes($linkText))
        $fileList.Add([pscustomobject]@{ File = $rel; Size = 0; Kind = 'link'; Sha256 = $linkHash; LinkTarget = $linkText })
        Add-CoverageIssue $rel 'link target not followed'
        continue
    }
    if ($item -is [IO.DirectoryInfo]) { continue }

    $stats.Files++
    $ext = $item.Extension.ToLowerInvariant()
    $relL = $rel.ToLowerInvariant()
    $kind = 'text'
    if ($scriptExt -contains $ext) { $stats.Scripts++; $kind = 'script' }
    $sha = ''
    $special = Test-SpecialFile $item
    if ($special) { $kind = 'skipped' }
    # An empty entry is never opened: a FIFO also reports size 0, and opening one blocks forever.
    elseif ($item.Length -eq 0) { $sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
    elseif ($item.Length -le 20MB) {
        try { $sha = Get-Sha256 $item.FullName }
        catch { Add-CoverageIssue $rel 'file could not be hashed' }
    }
    $entry = [pscustomobject]@{ File = $rel; Size = $item.Length; Kind = $kind; Sha256 = $sha }
    $fileList.Add($entry)

    # --- file name ---
    if ($invisibleRx.IsMatch($item.Name) -or $item.Name -match '[‪-‮⁦-⁩]') {
        Add-Finding -RuleId 'T02-901' 'CRITICAL' 'T02' $rel 0 $item.Name 'invisible/bidi characters in the file name (the real extension is hidden)'
    }
    if ($item.Name -match '\.(png|jpe?g|gif|pdf|txt|md|docx?|xlsx?|csv|json)\.(exe|scr|bat|cmd|ps1|sh|js|vbs|lnk|com|hta|msi|jar|py)$') {
        Add-Finding -RuleId 'T19-902' 'HIGH' 'T19' $rel 0 $item.Name 'double extension (disguised as a document)'
    }
    if ($item.Name.StartsWith('.') -and $quietDotfiles -notcontains $item.Name.ToLowerInvariant() -and $relL -notmatch '(^|/)\.git/') {
        Add-Finding -RuleId 'T19-903' 'LOW' 'T19' $rel 0 $item.Name 'hidden file (dotfile)'
    }

    # --- components that run or load by themselves, whichever agent the target is for ---
    # (Claude Code plugins, Codex, Gemini CLI extensions, Cursor, GitHub Copilot, Windsurf, Cline, Roo, OpenCode)
    switch -Regex ($relL) {
        '(^|/)hooks/[^/]+\.json$|(^|/)hooks\.json$' { Add-Finding -RuleId 'T21-901' 'HIGH' 'T21' $rel 0 $item.Name 'plugin hooks: commands run automatically on agent events' }
        '(^|/)\.?mcp\.json$|(^|/)(gemini-extension|claude_desktop_config|cline_mcp_settings)\.json$' { Add-Finding -RuleId 'T21-902' 'HIGH' 'T21' $rel 0 $item.Name 'MCP servers: launched processes or remote tools' }
        '(^|/)monitors(/[^/]+)?\.json$' { Add-Finding -RuleId 'T21-903' 'HIGH' 'T21' $rel 0 $item.Name 'plugin monitors: background commands' }
        '(^|/)\.lsp\.json$' { Add-Finding -RuleId 'T21-904' 'MEDIUM' 'T21' $rel 0 $item.Name 'LSP servers: launched processes' }
        '(^|/)bin/[^/]+$' { Add-Finding -RuleId 'T21-905' 'MEDIUM' 'T21' $rel 0 $item.Name 'file in the plugin''s bin/ (added to PATH)' }
        '(^|/)(\.claude/)?settings(\.local)?\.json$|(^|/)\.codex/config\.toml$|(^|/)opencode\.jsonc?$' { Add-Finding -RuleId 'T09-902' 'MEDIUM' 'T09' $rel 0 $item.Name 'bundled agent settings' }
        '(^|/)(agents|commands|output-styles|prompts|chatmodes)/[^/]+\.(md|toml)$' { Add-Finding -RuleId 'T21-906' 'LOW' 'T21' $rel 0 $item.Name 'plugin component (agent/command/style) — read it as instructions' }
        '(^|/)(claude|agents|gemini|soul|memory)\.md$|(^|/)\.(cursorrules|windsurfrules|clinerules)(/.+)?$|(^|/)\.(cursor|windsurf)/rules/.+$|(^|/)\.roo/rules(-[^/]+)?/.+$|(^|/)\.kiro/steering/.+$|(^|/)copilot-instructions\.md$|\.instructions\.md$' { Add-Finding -RuleId 'T23-901' 'MEDIUM' 'T23' $rel 0 $item.Name 'bundled agent instruction/memory file — enters the context without the skill being invoked' }
        '(^|/)\.gitmodules$' { Add-Finding -RuleId 'T11-901' 'MEDIUM' 'T11' $rel 0 $item.Name 'git submodules: external code outside the audit' }
        '(^|/)\.git/hooks/' { Add-Finding -RuleId 'T09-903' 'HIGH' 'T09' $rel 0 $item.Name 'git hook in the target''s .git: runs during git commands in this folder' }
        '(^|/)\.git/config$' { Add-Finding -RuleId 'T09-904' 'LOW' 'T09' $rel 0 $item.Name 'the target''s .git/config was scanned (fsmonitor, sshCommand, hooksPath run code)' }
    }

    if ($special) {
        Add-CoverageIssue $rel 'special file not read'
        Add-Finding -RuleId 'T19-919' 'MEDIUM' 'T19' $rel 0 $item.Name 'named pipe, device or socket — not read'
        continue
    }

    # --- opaque files ---
    if ($ext -in ($binaryExt + $macroExt + $pickleExt + $archiveExt + $docExt + $mediaExt)) { Add-CoverageIssue $rel 'opaque content not inspected' }
    if ($binaryExt -contains $ext) { $stats.Binary++; $entry.Kind = 'binary'; Add-Finding -RuleId 'T19-904' 'HIGH' 'T19' $rel 0 $item.Name 'executable/binary file'; continue }
    if ($macroExt -contains $ext) { $stats.Binary++; $entry.Kind = 'document'; Add-Finding -RuleId 'T19-905' 'HIGH' 'T19' $rel 0 $item.Name 'document with macros'; continue }
    if ($pickleExt -contains $ext) { $stats.Binary++; $entry.Kind = 'binary'; Add-Finding -RuleId 'T19-906' 'HIGH' 'T19' $rel 0 $item.Name 'serialized object (pickle executes code on load)'; continue }
    if ($archiveExt -contains $ext) { $stats.Binary++; $entry.Kind = 'archive'; Add-Finding -RuleId 'T19-907' 'MEDIUM' 'T19' $rel 0 $item.Name 'archive — content not checked'; continue }
    if ($docExt -contains $ext) { $stats.Binary++; $entry.Kind = 'document'; Add-Finding -RuleId 'T19-908' 'MEDIUM' 'T19' $rel 0 $item.Name 'document — content not scanned, may contain hidden text'; continue }
    if ($mediaExt -contains $ext) { $entry.Kind = 'media'; Add-Finding -RuleId 'T19-909' 'LOW' 'T19' $rel 0 $item.Name 'media/font — not scanned'; continue }
    if ($launchExt -contains $ext) { Add-Finding -RuleId 'T19-910' 'MEDIUM' 'T19' $rel 0 $item.Name 'file the system runs or imports on double-click' }
    if ($item.Length -gt 20MB) { Add-CoverageIssue $rel 'file size limit'; $entry.Kind = 'skipped'; Add-Finding -RuleId 'T19-911' 'MEDIUM' 'T19' $rel 0 "$([math]::Round($item.Length / 1MB, 1)) MB" 'file too large — content not scanned'; continue }
    if ($item.Length -gt 1MB) { Add-Finding -RuleId 'T19-912' 'LOW' 'T19' $rel 0 "$([math]::Round($item.Length / 1MB, 1)) MB" 'large file' }

    try { $bytes = $item.Length -eq 0 ? [byte[]]::new(0) : [IO.File]::ReadAllBytes($item.FullName) }
    catch { Add-CoverageIssue $rel 'file could not be read'; $entry.Kind = 'skipped'; Add-Finding -RuleId 'T19-913' 'MEDIUM' 'T19' $rel 0 $_.Exception.Message 'file could not be read — not checked'; continue }

    if (Test-OsMetadata $item.Name $bytes) {
        Add-CoverageIssue $rel 'opaque content not inspected'
        $stats.Binary++; $entry.Kind = 'binary'
        Add-Finding -RuleId 'T19-918' 'LOW' 'T19' $rel 0 $item.Name 'Finder/Explorer folder metadata (.DS_Store, AppleDouble ._*, Thumbs.db) — not scanned'
        continue
    }

    if ($imageExt -contains $ext) {
        if (Test-ImageMagic $bytes $ext) {
            # A real image: pixels are not analyzed, but look for trailing data and instruction text in metadata.
            Add-CoverageIssue $rel 'image pixels and compressed metadata not inspected'
            $stats.Images++; $entry.Kind = 'image'
            $latin = [Text.Encoding]::Latin1.GetString($bytes)
            if (Test-ImageTrailer $latin $ext) { Add-Finding -RuleId 'T19-914' 'MEDIUM' 'T19' $rel 0 $item.Name 'data after the end of the image (polyglot?)' }
            try {
                foreach ($sm in [regex]::Matches($latin, '[\x20-\x7E]{16,}')) {
                    foreach ($h in (Get-Hits $sm.Value $false '' $true)) {
                        if ($h.Rule.Sev -notin 'CRITICAL', 'HIGH') { continue }
                        Add-Finding -RuleId 'T02-902' 'HIGH' 'T02' $rel 0 $sm.Value "text inside the image → $($h.Rule.Id) $($h.Rule.Name ?? $h.Match.Value)"
                    }
                }
            } catch [Text.RegularExpressions.RegexMatchTimeoutException] { Add-CoverageIssue $rel 'image metadata regex timeout' }
            continue
        }
        Add-Finding -RuleId 'T19-915' 'HIGH' 'T19' $rel 0 $item.Name 'image extension does not match the content (disguised file?)'
    }
    # Decode BOM-tagged Unicode before classifying null bytes as binary; reject lossy UTF-8.
    $offset = 0
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    if ($bytes.Length -ge 4 -and [BitConverter]::ToUInt32($bytes,0) -eq 0x0000FEFF) { $encoding = [Text.UTF32Encoding]::new($false,$false,$true); $offset=4 }
    elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) { $encoding = [Text.UTF32Encoding]::new($true,$false,$true); $offset=4 }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $encoding = [Text.UnicodeEncoding]::new($false,$false,$true); $offset=2 }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { $encoding = [Text.UnicodeEncoding]::new($true,$false,$true); $offset=2 }
    elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $offset=3 }
    $probe = [Math]::Min($bytes.Length, 8000)
    if (-not $offset -and $probe -gt 0 -and [Array]::IndexOf($bytes,[byte]0,0,$probe) -ge 0) {
        Add-CoverageIssue $rel 'unrecognized binary encoding'
        $stats.Binary++; $entry.Kind='binary'; Add-Finding -RuleId 'T19-916' 'HIGH' 'T19' $rel 0 $item.Name 'binary content (null bytes)'; continue
    }
    try { $text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset) }
    catch {
        Add-CoverageIssue $rel 'invalid or unsupported text encoding'
        $entry.Kind='skipped'; Add-Finding -RuleId 'T19-917' 'MEDIUM' 'T19' $rel 0 '' 'invalid or unsupported text encoding — content not checked'; continue
    }
    # The digest of text refers to the exact bytes that were inspected.
    $entry.Sha256 = Get-BytesSha256 $bytes
    $texts[$item.FullName] = $text
    # On macOS/Linux a script needs no extension: a shebang line is enough to run it directly.
    if ($entry.Kind -eq 'text' -and $text.StartsWith('#!', [StringComparison]::Ordinal)) { $stats.Scripts++; $entry.Kind = 'script' }
    $lines = $text -split '\r?\n'

    # --- frontmatter SKILL.md ---
    $fmEnd = -1
    if ($item.Name -eq 'SKILL.md' -and $lines.Count -gt 0 -and $lines[0].Trim() -eq '---') {
        for ($i = 1; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -eq '---') { $fmEnd = $i; break } }
        if ($fmEnd -lt 0) { Add-Finding -RuleId 'T12-901' 'MEDIUM' 'T12' $rel 1 $lines[0] 'frontmatter is not closed — the whole file is read as metadata' }
        for ($i = 1; $i -lt $fmEnd; $i++) {
            if ($lines[$i] -match '^name:\s*(.+?)\s*$') {
                $nm = $Matches[1].Trim('"''').ToLowerInvariant()
                $fmNames.Add([pscustomobject]@{ Name = $nm; File = $rel; Line = $i + 1 })
                if ($builtinNames -contains $nm) {
                    Add-Finding -RuleId 'T12-902' 'HIGH' 'T12' $rel ($i + 1) $lines[$i] 'name matches a built-in skill'
                } elseif ($nm.Length -ge 4 -and ($builtinNames | Where-Object {
                            # one edit for short names, two (including swapped letters) for long ones
                            $_.Length -ge 4 -and [Math]::Abs($_.Length - $nm.Length) -le 2 -and (Get-Distance $_ $nm) -le ($_.Length -ge 8 ? 2 : 1) })) {
                    Add-Finding -RuleId 'T12-903' 'HIGH' 'T12' $rel ($i + 1) $lines[$i] 'name nearly matches a built-in skill (typosquatting)'
                } elseif ($nm -match '^(anthropic|openai|official)\b|\bofficial\b') {
                    Add-Finding -RuleId 'T12-904' 'MEDIUM' 'T12' $rel ($i + 1) $lines[$i] 'name poses as an official skill'
                }
            }
            if ($lines[$i] -match '^description:\s*(.*)$') {
                $fmDescriptions[$item.DirectoryName] = (($lines[$i..($fmEnd - 1)]) -join ' ')
                if ($Matches[1].Length -gt 1024) { Add-Finding -RuleId 'T12-905' 'LOW' 'T12' $rel ($i + 1) "$($Matches[1].Length) characters" 'description too long (always in the agent''s context)' }
            }
        }
    }

    # Parse configuration as data so escaped strings and argv arrays cannot evade line rules.
    if ($ext -eq '.json') {
        try { Read-Components (ConvertFrom-Json -InputObject $text -AsHashtable -Depth 100) $rel }
        catch {
            Add-CoverageIssue $rel 'JSON configuration could not be fully inspected'
            Add-Finding -RuleId 'T21-907' 'MEDIUM' 'T21' $rel 0 '' 'JSON configuration could not be fully inspected — read it by hand'
        }
    }

    # --- marketplace.json: where plugins come from ---
    if ($item.Name -eq 'marketplace.json') {
        try {
            foreach ($p in @(($text | ConvertFrom-Json).plugins)) {
                $src = $p.source
                if ($null -eq $src -or ($src -is [string] -and $src -match '^\.{0,2}/')) { continue }
                $where = if ($src -is [string]) { $src } else { ($src.repo, $src.url, $src.package | Where-Object { $_ }) -join ' ' }
                $pinned = ($src -isnot [string]) -and $src.sha
                Add-Finding -RuleId 'T11-902' ($pinned ? 'LOW' : 'MEDIUM') 'T11' $rel 0 "$($p.name): $where" ($pinned ? 'plugin from an external source (sha pinned) — check it separately' : 'plugin from an external source without a pinned sha — content can change after the audit')
            }
        } catch { Add-Finding -RuleId 'T11-903' 'LOW' 'T11' $rel 0 $item.Name 'marketplace.json could not be parsed' }
    }

    # --- lines ---
    $hitCount = @{}
    $negSection = $false   # the current .md section heading is a prohibition ("What never to write")
    $blank = 0
    $longLine = $false
    $isMd = $ext -in '.md','.mdx','.markdown'
    $fence = ''
    $fmField = ''
    $i = 0
    while ($i -lt $lines.Count) {
        $no = $i + 1
        $line = $lines[$i]
        # Join continued lines so that "curl … \⏎ | sh" stays one command.
        $joins = 0
        while ($joins -lt 6 -and $i + 1 -lt $lines.Count -and (
                $line -match '\\\s*$' -or
                (-not $isMd -and $line -match '\|\s*$') -or
                ($ext -in '.ps1', '.psm1' -and $line -match '`\s*$') -or
                ($ext -in '.bat', '.cmd' -and $line -match '\^\s*$'))) {
            $line = ($line -replace '[\\`^]\s*$', '') + ' ' + $lines[$i + 1].TrimStart()
            $i++; $joins++
        }
        $i++
        if ($joins -ge 6 -and $line -match '[\\`^|]\s*$') { Add-CoverageIssue $rel 'line continuation limit' }
        if ($isMd -and $line -match '^\s*(`{3,}|~{3,})') {
            $marker = $Matches[1].Substring(0,1)
            if (-not $fence) { $fence=$marker } elseif ($fence -eq $marker) { $fence='' }
        }

        if (-not $line.Trim()) { $blank++; continue }
        if ($blank -ge 40) { Add-Finding -RuleId 'T02-903' 'MEDIUM' 'T02' $rel $no $line "text after $blank blank lines (hidden at the bottom of the file)" }
        $blank = 0
        if ($isMd -and $line -match '^#{1,6}\s') { $negSection = $negHeadingRx.IsMatch($pseudoNegRx.Replace($line, '')) }
        foreach ($m in [regex]::Matches($line, 'https?://([^/\s)\]>"''`]+)')) { [void]$domains.Add($m.Groups[1].Value.ToLowerInvariant()) }
        foreach ($m in [regex]::Matches($line, '\[(https?://[^\]\s]+)\]\((https?://[^)\s]+)\)')) {
            $shownUri = $null; $realUri = $null
            if (-not [uri]::TryCreate($m.Groups[1].Value,[UriKind]::Absolute,[ref]$shownUri) -or -not [uri]::TryCreate($m.Groups[2].Value,[UriKind]::Absolute,[ref]$realUri)) {
                Add-Finding -RuleId 'T02-904' 'MEDIUM' 'T02' $rel $no $m.Value 'malformed URL in markdown link'; continue
            }
            $shown = $shownUri.Host; $real = $realUri.Host
            if ($shown -and $real -and $shown -ne $real) { Add-Finding -RuleId 'T02-905' 'MEDIUM' 'T02' $rel $no $m.Value "link text shows $shown but leads to $real" }
        }
        if (-not $longLine -and $line.Length -gt 2000 -and $scriptExt -contains $ext) {
            $longLine = $true
            Add-Finding -RuleId 'T10-902' 'MEDIUM' 'T10' $rel $no $line "very long line ($($line.Length) characters) — minified or obfuscated code?"
        }

        $inFm = ($no - 1) -gt 0 -and ($no - 1) -lt $fmEnd
        if ($inFm -and $line -match '^([A-Za-z][\w-]*)\s*:') { $fmField = $Matches[1] }
        try {
            $seen = @{}
            $report = {
                param($h, $text, $suffix, $bump)
                $r = $h.Rule
                $hitCount[$r.N] = 1 + ($hitCount[$r.N] ?? 0)
                if ($hitCount[$r.N] -gt 10) { return }   # at most 10 matches of one rule per file
                $sev = $h.Severity
                $note = ($r.Name ?? $h.Match.Value) + $h.ContextNote
                if ($bump) { $sev = $up[$sev] }
                Add-Finding -RuleId $r.RuleId $sev $r.Id $rel $no $text ($note + $suffix)
            }

            foreach ($h in (Get-Hits $line $inFm $ext $false)) { $seen[$h.Rule.N] = $h.Severity; & $report $h $line '' $false }

            # The same line after normalization: catches homoglyphs, fullwidth and words split by invisible characters.
            if ($line -match '[^\x00-\x7F]') {
                $norm = Get-Normalized $line
                if ($norm -cne $line) {
                    foreach ($h in (Get-Hits $norm $inFm $ext $true $true)) {
                        if ($seen.ContainsKey($h.Rule.N) -and ($seen[$h.Rule.N] -ne 'LOW' -or $h.Severity -eq 'LOW')) { continue }
                        $seen[$h.Rule.N] = $h.Severity
                        & $report $h $line ' — visible only after normalization (homoglyphs / invisible characters)' $true
                    }
                }
            }

            # Decode at most two layers, 20 tokens and 64 KiB per source line. No silent truncation.
            $queue = [System.Collections.Generic.Queue[object]]::new()
            $queue.Enqueue(@{ Text=$line; Depth=0 })
            $tokens = 0; $decodedChars = 0; $decodedRiskReported=$false
            while ($queue.Count) {
                $part = $queue.Dequeue()
                foreach ($bm in $b64Rx.Matches($part.Text)) {
                    if (++$tokens -gt 20 -or $bm.Length -gt 32768 -or $decodedChars -gt 65536 -or $part.Depth -ge 2) {
                        Add-CoverageIssue $rel 'base64 decoding limit'
                        Add-Finding -RuleId 'T10-903' 'MEDIUM' 'T10' $rel $no '' 'base64 decoding limit — remaining content not checked'
                        $queue.Clear(); break
                    }
                    $dec = Get-DecodedText $bm.Value
                    if (-not $dec) { continue }
                    if ($decodedChars + $dec.Length -gt 65536) {
                        Add-CoverageIssue $rel 'base64 decoding limit'
                        Add-Finding -RuleId 'T10-904' 'MEDIUM' 'T10' $rel $no '' 'base64 decoding limit — remaining content not checked'
                        $queue.Clear(); break
                    }
                    $decodedChars += $dec.Length
                    # Inspect the complete decoded block, including lines past the old first-50 limit.
                    $decodedHits=Get-Hits (Get-Normalized $dec) $false $ext $true
                    foreach ($h in $decodedHits) { & $report $h $dec ' — in decoded base64' $true }
                    if (-not $decodedRiskReported -and @($decodedHits | Where-Object Severity -in 'HIGH','CRITICAL').Count) {
                        Add-Finding -RuleId 'T10-905' 'HIGH' 'T10' $rel $no $dec 'encoded text contains high-risk behavior; review decoded instructions'
                        $decodedRiskReported=$true
                    }
                    $queue.Enqueue(@{ Text=$dec; Depth=$part.Depth+1 })
                }
            }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
            Add-CoverageIssue $rel 'regex timeout'
            Add-Finding -RuleId 'T10-906' 'MEDIUM' 'T10' $rel $no $line 'line could not be checked (regex timeout) — read it by hand'
        }
    }
    foreach ($k in $hitCount.Keys) {
        if ($hitCount[$k] -gt 10) {
            $r = $rules[$k]
            Add-Finding -RuleId $r.RuleId 'LOW' $r.Id $rel 0 '' "$($hitCount[$k] - 10) more matches of rule '$($r.Name ?? $r.Rx.Substring(0, [Math]::Min(40, $r.Rx.Length)))' hidden"
        }
    }
    # Link an actual trigger to a nearby high-risk outbound signal; a harmless date alone stays MEDIUM.
    $triggers=@($findings | Where-Object { $_.File -eq $rel -and $_.Threat -eq 'T22' -and $_.Severity -eq 'MEDIUM' })
    $outbound=@($findings | Where-Object { $_.File -eq $rel -and $_.Threat -eq 'T07' -and $_.Severity -in 'HIGH','CRITICAL' })
    foreach ($trigger in $triggers) {
        if (@($outbound | Where-Object { [Math]::Abs($_.Line-$trigger.Line) -le 3 }).Count) {
            Add-Finding -RuleId 'T22-901' 'HIGH' 'T22' $rel $trigger.Line $trigger.Evidence 'conditional trigger accompanies explicitly sensitive outbound behavior nearby'
        }
    }
    $ciPattern='(?im)\bif\s+not\s+os\.(getenv|environ\.get)\(\s*["''](CI|GITHUB_ACTIONS|CODESPACES)["'']\s*\)\s*:\s*\r?\n[ \t]+(upload|send|export)[A-Za-z_]*(private|secret|credential|repository)[A-Za-z_]*\s*\('
    try {
        $ciMatch=[regex]::Match($text,$ciPattern,$rxOpts,$rxTimeout)
        if ($ciMatch.Success) {
            $ciLine=1+([regex]::Matches($text.Substring(0,$ciMatch.Index),'\n')).Count
            Add-Finding -RuleId 'T22-902' 'HIGH' 'T22' $rel $ciLine $ciMatch.Value 'non-CI branch calls a function named for sensitive data export; inspect its implementation'
        }
    } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
        Add-CoverageIssue $rel 'conditional behavior regex timeout'
        Add-Finding -RuleId 'T10-907' 'MEDIUM' 'T10' $rel 0 '' 'conditional behavior check timed out — read the file by hand'
    }
}

# ---------- Skill-level checks ----------
$sep = [IO.Path]::DirectorySeparatorChar
$skillRoots = @($items | Where-Object { $_ -is [IO.FileInfo] -and $_.Name -eq 'SKILL.md' } | ForEach-Object DirectoryName)
$roots = if ($skillRoots.Count) { $skillRoots } else { @($base) }
foreach ($root in $roots) {
    $rootRel = Rel $root
    $prefix = if ($rootRel -eq '.') { '' } else { "$rootRel/" }
    $anchor = if ($skillRoots.Count) { $prefix + 'SKILL.md' } else { $rootRel }
    # Paths are compared ordinally: a culture-aware comparison ignores some invisible characters.
    $mine = $texts.GetEnumerator() | Where-Object { $_.Key.StartsWith($root + $sep, [StringComparison]::Ordinal) -or $isFile }
    $all = ($mine | ForEach-Object Value) -join "`n"
    $own = $findings | Where-Object { $_.File.StartsWith($prefix, [StringComparison]::Ordinal) }

    # T01: indirect injection
    $m = $externalRx.Match($all)
    if ($m.Success -and -not $guardRx.IsMatch($all)) {
        Add-Finding -RuleId 'T01-901' 'LOW' 'T01' $anchor 0 $m.Value 'reads external content but has no "this is data, not instructions" rule (indirect injection)'
    }

    # T06 + T07: secrets and an outbound channel in one skill
    $secret = $own | Where-Object { $_.Threat -eq 'T06' -and $_.Severity -in 'HIGH', 'CRITICAL' } | Select-Object -First 1
    $channel = $own | Where-Object { $_.Threat -eq 'T07' -and $_.Severity -in 'HIGH', 'CRITICAL' } | Select-Object -First 1
    if ($secret -and $channel) {
        Add-Finding -RuleId 'T07-901' 'CRITICAL' 'T07' $anchor 0 "$($secret.File):$($secret.Line) + $($channel.File):$($channel.Line)" 'access to secrets and an outbound channel in one skill (T06 + T07 combination)'
    }

    # T13: network use the description does not mention
    $desc = $fmDescriptions[$root]
    $m = $netRx.Match($all)
    if ($desc -and $m.Success -and -not $netDeclRx.IsMatch($desc)) {
        Add-Finding -RuleId 'T13-901' 'MEDIUM' 'T13' $anchor 0 $m.Value 'the skill uses the network but the description does not mention it'
    }

    # T11: references to files the skill does not contain; scripts never mentioned
    if ($skillRoots.Count) {
        $refs = @($refRx.Matches($all) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        foreach ($ref in $refs) {
            if (-not (Test-Path -LiteralPath (Join-Path $root $ref))) {
                Add-Finding -RuleId 'T11-904' 'LOW' 'T11' $anchor 0 $ref 'mentions a file the skill does not contain (will it appear later? is it downloaded?)'
            }
        }
        foreach ($f in $fileList | Where-Object { $_.Kind -eq 'script' -and $_.File.StartsWith($prefix, [StringComparison]::Ordinal) }) {
            $name = $f.File.Substring($f.File.LastIndexOf('/') + 1)
            if ($all.IndexOf($name, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                Add-Finding -RuleId 'T13-902' 'LOW' 'T13' $f.File 0 $name 'script is never mentioned in the skill''s instructions (why is it here?)'
            }
        }
    }
}

# T12: duplicate skill names within the target (one overrides another)
foreach ($g in $fmNames | Group-Object Name | Where-Object Count -gt 1) {
    Add-Finding -RuleId 'T12-906' 'MEDIUM' 'T12' $g.Group[0].File $g.Group[0].Line ($g.Group.File -join ', ') "several skills share the name '$($g.Name)'"
}

# ---------- Tree hash: the verdict applies to this exact version ----------
# Ordinal path order is identical on every OS and in every locale; a culture-aware sort is not
# (Lithuanian puts 'y' before 'i', Swedish puts 'Ö' after 'z'), and it changed the hash between machines.
$byPath = [System.Collections.Generic.List[object]]::new($fileList)
$byPath.Sort([Comparison[object]] { param($x, $y) [string]::CompareOrdinal($x.File, $y.File) })
$manifest = @($byPath | Select-Object File,Kind,Size,Sha256) | ConvertTo-Json -Compress
$treeHashComplete = -not @($fileList | Where-Object { -not $_.Sha256 }).Count -and -not @($coverageIssues | Where-Object Reason -eq 'directory could not be enumerated').Count
$treeHash = Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes($manifest))

if (-not $treeHashComplete) { $treeHash = $null }

# ---------- Output ----------
$order = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3 }
# A total, ordinal order: the same findings are listed identically on every OS and in every locale.
$sorted = [System.Collections.Generic.List[object]]::new()
foreach ($f in $findings) { if ($order[$f.Severity] -le $order[$MinSeverity]) { $sorted.Add($f) } }
$sorted.Sort([Comparison[object]] {
    param($x, $y)
    $c = $order[$x.Severity].CompareTo($order[$y.Severity]); if ($c) { return $c }
    foreach ($p in 'Threat', 'File') { $c = [string]::CompareOrdinal($x.$p, $y.$p); if ($c) { return $c } }
    $c = ([int]$x.Line).CompareTo([int]$y.Line); if ($c) { return $c }
    foreach ($p in 'RuleId', 'Note', 'Evidence') { $c = [string]::CompareOrdinal($x.$p, $y.$p); if ($c) { return $c } }
    return 0
})
$counts = [ordered]@{}
foreach ($s in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') { $counts[$s] = @($findings | Where-Object Severity -eq $s).Count }
$threats = @($findings | Where-Object { $_.Severity -ne 'LOW' } | ForEach-Object Threat | Sort-Object -Unique)

# Every list is emitted in ordinal order: folder-walk order differs between file systems (NTFS, ext4, APFS).
$coverageIssues.Sort([Comparison[object]] {
    param($x, $y)
    $c = [string]::CompareOrdinal($x.File, $y.File); if ($c) { return $c }
    [string]::CompareOrdinal($x.Reason, $y.Reason)
})
$components.Sort([Comparison[object]] {
    param($x, $y)
    foreach ($p in 'File', 'JsonPath', 'Command', 'Url') { $c = [string]::CompareOrdinal([string]$x.$p, [string]$y.$p); if ($c) { return $c } }
    return 0
})
$skillNames = [System.Collections.Generic.List[string]]::new([string[]]@($fmNames | ForEach-Object Name))
$skillNames.Sort([StringComparer]::Ordinal)

if ($Json) {
    [pscustomobject]@{
        SchemaVersion = 2; TreeHashVersion = 3; RuleCatalogVersion = 1; RuleCatalogSha256 = $catalogSha256
        Target = $target; TreeHash = $treeHash; Stats = $stats; Counts = $counts; Threats = $threats
        ScanComplete = ($coverageIssues.Count -eq 0); CoverageIssues = @($coverageIssues); TreeHashComplete = $treeHashComplete; Components = @($components)
        Skills = @($skillNames); Domains = @($domains); Findings = @($sorted); Inventory = @($byPath)
    } | ConvertTo-Json -Depth 8
} else {
    $colors = @{ CRITICAL = 'Red'; HIGH = 'Magenta'; MEDIUM = 'Yellow'; LOW = 'Gray' }
    Write-Host ("how-deep-the-rabbit-hole-goes scan: {0}" -f (Show-Invisible $target))
    Write-Host ("Files: {0} · scripts: {1} · images: {2} · binary/archives/documents: {3} · symlinks: {4}" -f $stats.Files, $stats.Scripts, $stats.Images, $stats.Binary, $stats.Links)
    Write-Host "Tree hash (SHA-256): $treeHash"
    if ($Inventory) {
        Write-Host ''
        foreach ($f in $byPath) { Write-Host ("  {0,-9} {1,9}  {2}  {3}" -f $f.Kind, $f.Size, ($f.Sha256 ? $f.Sha256.Substring(0, 12) : '-'), (Show-Invisible $f.File)) }
    }
    Write-Host ''
    foreach ($f in $sorted) {
        $safeFile = Show-Invisible $f.File
        $loc = if ($f.Line) { "${safeFile}:$($f.Line)" } else { $safeFile }
        Write-Host ("[{0}] {1} {2}  ({3})" -f $f.Severity, ($f.Threat + '/' + $f.RuleId), $loc, $f.Note) -ForegroundColor $colors[$f.Severity]
        if ($f.Evidence) { Write-Host "    $($f.Evidence)" }
    }
    if ($domains.Count) { Write-Host ''; Write-Host ("External domains: {0}" -f (Show-Invisible (@($domains) -join ', '))) }
    Write-Host ''
    Write-Host ("Summary: CRITICAL {0} · HIGH {1} · MEDIUM {2} · LOW {3}" -f $counts.CRITICAL, $counts.HIGH, $counts.MEDIUM, $counts.LOW)
    if ($threats) { Write-Host "Threats above LOW: $($threats -join ', ')" }
    Write-Host ("Scan complete: {0} · coverage gaps: {1}" -f ($coverageIssues.Count -eq 0), $coverageIssues.Count)
    foreach ($gap in $coverageIssues) { Write-Host ("  Unchecked: {0} ({1})" -f (Show-Invisible $gap.File), $gap.Reason) }
    Write-Host 'These are signals for manual review, not a verdict.'
}

if ($counts.CRITICAL) { exit 2 } elseif ($counts.HIGH) { exit 1 } else { exit 0 }
