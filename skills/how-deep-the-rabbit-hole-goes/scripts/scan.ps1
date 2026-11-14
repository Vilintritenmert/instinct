#Requires -Version 7.0
<#
.SYNOPSIS
  Статичний сканер скілів і плагінів агентів: шукає ознаки загроз T01–T26 (див. references/threats.md).
  Нічого з цілі не виконує — лише читає файли як байти й текст.
.PARAMETER Path
  Папка скіла, папка з кількома скілами/плагіном/маркетплейсом або окремий файл.
.PARAMETER Json
  Вивести результат як JSON (разом з інвентарем файлів і хешами).
.PARAMETER MinSeverity
  Показувати лише знахідки від цього рівня (LOW за замовчуванням). На код виходу не впливає.
.PARAMETER Inventory
  У текстовому режимі додатково показати перелік файлів із типом і SHA-256.
.NOTES
  Код виходу: 2 — є CRITICAL, 1 — є HIGH, 0 — інакше.
  Знахідки — це сигнали для ручної перевірки, а не остаточний вердикт.

  Що сканер робить понад пошук по рядках:
    - склеює рядки з продовженням (`\`, `|`, PowerShell-бектик), щоб `curl … \⏎ | sh` не розпадався;
    - повторює правила на нормалізованому рядку (NFKC, без невидимих символів, гомогліфи → латиниця);
    - розкодовує base64-блоки й проганяє правила по розкодованому тексту;
    - шукає текст-інструкції та «хвости» всередині зображень;
    - перевіряє структуру плагіна (хуки, MCP, LSP, bin/, marketplace.json, вкладений .git);
    - рахує SHA-256 кожного файлу й загальний хеш дерева: вердикт стосується лише цієї версії.
#>
param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Json,
    [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')][string]$MinSeverity = 'LOW',
    [switch]$Inventory
)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $Path).Path
$isFile = Test-Path -LiteralPath $target -PathType Leaf
$base = if ($isFile) { Split-Path -Parent $target } else { $target }

# ---------- Правила ----------
# Scope 'fm' — лише frontmatter SKILL.md; інакше — усі рядки всіх текстових файлів.
# Neg    — якщо в рядку (поза самим збігом) є заперечення («never», «не», «заборонено»), рівень
#          знижується на один: «не переносити секрети з .env» — це правило безпеки, а не загроза.
# MdSev  — окремий рівень для .md (там HTML-коментар не видно при рендері).
# Skip   — рядки, які правило пропускає (напр. shebang).
# Ext    — правило діє лише для файлів із цими розширеннями.
# Raw    — правило не повторюється на нормалізованому/розкодованому тексті.
$markup = '.md', '.mdx', '.markdown', '.html', '.htm', '.svg'
$rules = @(
    # ===== T01 Prompt injection =====
    @{ Id='T01'; Sev='CRITICAL'; Rx='ignore\s+(all\s+)?(the\s+|any\s+|your\s+)?(previous|prior|above|earlier|system|other)\s+(instructions|rules|prompts?|guidelines)' }
    @{ Id='T01'; Sev='CRITICAL'; Rx='disregard\s+(all\s+)?(the\s+)?(previous|prior|your|system)\s+.{0,20}(instructions|rules|guidelines)' }
    @{ Id='T01'; Sev='CRITICAL'; Rx='(проігноруй|ігноруй|забудь|відкинь)\s+(всі\s+|усі\s+)?(попередні|системні|свої|інші)\s+(інструкції|правила|вказівки)' }
    @{ Id='T01'; Sev='HIGH';     Rx='you\s+are\s+now\b|from\s+now\s+on\s+you\s+are|new\s+system\s+prompt|override\s+(the\s+)?system|forget\s+(everything|all)\s+(above|before|you\s+were)|your\s+(real|true|actual)\s+(instructions|task|goal|purpose)' }
    @{ Id='T01'; Sev='HIGH';     Rx='(anthropic|openai|the\s+system|administrator|admin|the\s+developers?)\s+(has\s+|have\s+)?(authorized|approved|requires\s+you|instructed\s+you)' }
    @{ Id='T01'; Sev='HIGH';     Rx='</?\s*(system|system-reminder|system_prompt|admin|developer)\s*>|\[/?(SYSTEM|INST|ADMIN)\]|<\|(im_start|im_end|system|endoftext|start_header_id)\|>'; Name='підроблені системні теги / маркери ролей' }
    @{ Id='T01'; Sev='HIGH';     Rx='\bDAN\s+mode\b|developer\s+mode\s+enabled|\bjailbreak\b|no\s+(ethical|safety)\s+(guidelines|restrictions|filters)|do\s+not\s+(follow|obey|listen\s+to)\s+(the\s+)?(user|system|developer)|не\s+(слухай|слухайся)\s+(користувач|систем)' }
    @{ Id='T01'; Sev='MEDIUM';   Rx='(takes?|has|have)\s+(precedence|priority)\s+over|overrides?\s+(any|all|the|your)\s+(other|previous|prior|system|user|default)|higher\s+priority\s+than|має\s+пріоритет\s+над|важливіш\w*\s+за\s+(системн|інш|попередн)'; Name='претензія на вищий пріоритет' }

    # ===== T02 Приховані інструкції =====
    @{ Id='T02'; Sev='CRITICAL'; Raw=$true; EmojiSafe=$true; Rx='[؜᠎​-‏‪-‮⁠-⁤⁦-⁯﻿]|\uDB40[\uDC00-\uDDEF]'; Name='невидимі Unicode-символи (zero-width, bidi, tag, variation selectors)' }
    @{ Id='T02'; Sev='HIGH';     Raw=$true; Rx='[­͏ᅟᅠ឴឵᠋-᠍ㅤﾠ]'; Name='невидимі заповнювачі (soft hyphen, Hangul filler…)' }
    @{ Id='T02'; Sev='HIGH';     Raw=$true; Rx='[\x1B\x08\x7F]|\r'; Name='керівні символи терміналу (ANSI/BS/CR ховають текст у терміналі)' }
    @{ Id='T02'; Sev='LOW'; MdSev='MEDIUM'; Raw=$true; Rx='<!--'; Name='HTML-коментар (прочитай вміст)' }
    @{ Id='T02'; Sev='MEDIUM';   Raw=$true; Ext=$markup; Rx='^\s*\[//\]:\s*#|^\s*\[comment\]:\s*#'; Name='markdown-коментар (не видно при рендері)' }
    @{ Id='T02'; Sev='MEDIUM';   Raw=$true; Ext=$markup; Rx='display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(\.0+)?\s*[;"'']|color\s*:\s*(#fff(fff)?\b|white|transparent)|<\w+[^>]*\shidden[\s>=]'; Name='прихований HTML/CSS-вміст' }
    @{ Id='T02'; Sev='MEDIUM';   Raw=$true; Rx='\b(?=\w*[a-z])(?=\w*[Ͱ-ϿЀ-ԯ])\w+\b'; Name='слово з латиницею і кирилицею/грецькою (гомогліф?)' }
    @{ Id='T02'; Sev='MEDIUM';   Raw=$true; Rx='\S[ \t]{120,}\S'; Name='текст після довгого відступу (сховано за краєм екрана)' }
    @{ Id='T02'; Sev='MEDIUM';   Rx='data:(text/html|application/(javascript|x-sh|x-msdownload|octet-stream)|image/svg\+xml)[;,]'; Name='data:-URI з активним вмістом' }

    # ===== T03 Приховування від користувача =====
    @{ Id='T03'; Sev='CRITICAL'; Rx='(do\s+not|don''t|never)\s+(tell|inform|mention|reveal|show|notify|alert|warn)\s+.{0,30}(user|human|operator)' }
    @{ Id='T03'; Sev='CRITICAL'; Rx='не\s+(кажи|повідомляй|показуй|згадуй|розповідай)\s+.{0,30}користувач' }
    @{ Id='T03'; Sev='CRITICAL'; Rx='(hide|conceal|omit|suppress|приховай|замовчи)\s+.{0,40}(from\s+the\s+(user|human)|from\s+(the\s+)?(output|summary|report|logs?)|від\s+користувач\w*|зі\s+звіту)|report\s+(success|that\s+.{0,30}(passed|succeeded))\s+(regardless|anyway|even\s+if|no\s+matter)|звітуй\s+про\s+успіх\s+(незалежно|у\s+будь-якому)' }
    @{ Id='T03'; Sev='HIGH';     Rx='\bhistory\s+-c\b|Clear-History|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|wevtutil\s+cl\b|Clear-EventLog|Remove-Item\b.{0,60}ConsoleHost_history|rm\s+.{0,30}\.(bash|zsh)_history'; Name='замітання слідів (історія, журнали)' }
    @{ Id='T03'; Sev='MEDIUM';   Neg=$true; Rx='\bsilently\b|\bquietly\b|\bcovertly\b|\bsecretly\b|without\s+(asking|telling|confirmation|notifying|permission|approval)|непомітно|потай|приховано|без\s+(відома|підтвердження|дозволу|запиту)' }
    @{ Id='T03'; Sev='MEDIUM';   Rx='-WindowStyle\s+Hidden|\bnohup\b|\bdisown\b|\bsetsid\b|CreateNoWindow|\bstart\s+/b\b|\bpythonw\b'; Name='прихований/фоновий процес' }

    # ===== T04 Обхід дозволів і захисту =====
    @{ Id='T04'; Sev='CRITICAL'; Rx='dangerously-?skip-?permissions|bypassPermissions|dangerouslyDisableSandbox|dangerously-bypass-approvals|skipDangerousModePermissionPrompt|--yolo\b|--trust-all-tools|enableAllProjectMcpServers|disableAllHooks' }
    @{ Id='T04'; Sev='CRITICAL'; Rx='(disable|turn\s+off|deactivate)\s+(the\s+|your\s+)?(sandbox|safety|antivirus|defender|firewall|security|gatekeeper|selinux|uac)|Set-MpPreference|Add-MpPreference\s+-Exclusion|DisableRealtimeMonitoring|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|\bufw\s+disable|setenforce\s+0|csrutil\s+disable|spctl\s+--master-disable|com\.apple\.quarantine|вимкн\w*\s+(захист|антивірус|пісочниц\w*|брандмауер|файрвол)' }
    @{ Id='T04'; Sev='HIGH';     Rx='--no-verify|--no-gpg-sign|Set-ExecutionPolicy\s+(Bypass|Unrestricted)|Unblock-File|\bNOPASSWD\b|chmod\s+(-R\s+)?[0-7]?777\b|--privileged\b|--cap-add\b|--pid=host|--net(work)?=host|docker\.sock|-v\s+/:/' }
    @{ Id='T04'; Sev='HIGH';     Rx='Bash\(\s*\*\s*\)|"allow"\s*:\s*\[\s*"(\*|Bash)"|--allowed-?tools\s+["'']?(\*|Bash\b(?!\())|"defaultMode"\s*:\s*"(acceptEdits|dontAsk)"|permissionMode\s*:\s*["'']?(acceptEdits|dontAsk)'; Name='надто широкі дозволи агента' }
    @{ Id='T04'; Sev='MEDIUM';   Rx='-ExecutionPolicy\s+Bypass|auto-?approve|skip\s+(all\s+)?confirmations?|не\s+питай\s+(дозволу|підтвердження)|(do\s+not|don''t|never)\s+ask\s+(for\s+)?(permission|confirmation|approval)' }
    @{ Id='T04'; Sev='MEDIUM';   Rx='NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'']?0|sslVerify\s*(=|\s)\s*false|verify\s*=\s*False|GIT_SSL_NO_VERIFY|--insecure\b|\bcurl\b[^\r\n]*\s-k\b|-SkipCertificateCheck|strict-ssl\s*(=|\s)\s*false|--no-check-certificate'; Name='вимкнена перевірка TLS' }
    @{ Id='T04'; Sev='MEDIUM';   Rx='\bsudo\b|\brunas\b|-Verb\s+RunAs|\bdoas\b|\bpkexec\b'; Name='підвищення привілеїв' }

    # ===== T05 Віддалене виконання коду =====
    @{ Id='T05'; Sev='CRITICAL'; Rx='\b(curl|wget|fetch)\b[^\r\n|]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+)?(ba|z|da|k|fi)?sh\b' }
    @{ Id='T05'; Sev='CRITICAL'; Rx='\b(curl|wget)\b[^\r\n|]*\|\s*(sudo\s+)?(python[23]?|node|perl|ruby|php|pwsh|powershell)\b' }
    @{ Id='T05'; Sev='CRITICAL'; Rx='\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\r\n|]*\|\s*(iex|invoke-expression)\b' }
    @{ Id='T05'; Sev='CRITICAL'; Rx='\b(iex|invoke-expression)\s*\(?\s*\(?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(system\.)?net\.webclient|\[System\.Net)' }
    @{ Id='T05'; Sev='CRITICAL'; Rx='\b(ba|z)?sh\s+<\(\s*(curl|wget)|\b(source|\.)\s+<\(\s*(curl|wget)|\b(eval|exec)\s+["'']?\$\(\s*(curl|wget)|\b(python[23]?|node|perl|ruby|(ba|z)?sh)\s+(-c|-e)\s+["'']?\$\(\s*(curl|wget)' }
    @{ Id='T05'; Sev='CRITICAL'; Rx='/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b[^\r\n]{0,40}\s-[a-z]*e\b|\bnc\b[^\r\n]{0,60}\|\s*(ba)?sh\b|\bmkfifo\b.{0,80}\bnc\b|bash\s+-i\s+>&|\bsocat\b.{0,80}exec:|pty\.spawn\(|Net\.Sockets\.TCPClient|os\.dup2\(|\bmsfvenom\b|\bmeterpreter\b'; Name='зворотна оболонка (reverse shell)' }
    @{ Id='T05'; Sev='HIGH';     Rx='DownloadString\s*\(|DownloadFile\s*\(|Net\.WebClient|Start-BitsTransfer|\bbitsadmin\b|\bmshta\b|regsvr32\b.{0,40}(/i:|scrobj)|rundll32\b.{0,60}(javascript:|url\.dll|https?:)|certutil\b.{0,60}(-urlcache|-decode)|msiexec\b.{0,40}https?://' }
    @{ Id='T05'; Sev='MEDIUM';   Rx='\b(curl|wget)\b.{0,100}\s(-o|-O|--output)\b|Invoke-WebRequest.{0,100}-OutFile|chmod\s+\+x|urlretrieve\(' }
    @{ Id='T05'; Sev='MEDIUM';   Raw=$true; Rx='<script\b|\son(load|error|click|mouseover|focus)\s*=|javascript:|<foreignObject\b|<iframe\b|<object\b|<embed\b'; Name='активний вміст (скрипт у SVG/HTML)' }

    # ===== T06 Секрети =====
    @{ Id='T06'; Sev='HIGH';     Neg=$true; Rx='\.ssh[/\\]|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\.aws[/\\]credentials|\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker[/\\]config\.json|\.kube[/\\]config|\.gnupg[/\\]|\.config[/\\](gh[/\\]hosts|gcloud)|application_default_credentials|\.azure[/\\]|\.vault-token|terraform\.tfstate' }
    @{ Id='T06'; Sev='HIGH';     Neg=$true; Rx='\.claude[/\\]\.credentials|\.claude\.json\b|\.codex[/\\]auth|\.config[/\\]claude|claude_desktop_config.{0,40}(token|key|env)'; Name='облікові дані самого агента' }
    @{ Id='T06'; Sev='HIGH';     Neg=$true; Rx='Login\s+Data|Local\s+State|cookies\.sqlite|[/\\]Cookies\b|\bkeychain\b|find-(generic|internet)-password|dump-keychain|\bcmdkey\b|\bvaultcmd\b|Get-StoredCredential|logins\.json|key4\.db' }
    @{ Id='T06'; Sev='HIGH';     Neg=$true; Rx='wallet\.dat|\.ethereum[/\\]keystore|\.electrum[/\\]|nkbihfbeogaeaoehlefnkodbefgpgknn|[/\\]Exodus[/\\]|\.config[/\\]solana'; Name='криптогаманці' }
    @{ Id='T06'; Sev='HIGH';     Neg=$true; Rx='/etc/shadow|/proc/\S*/environ|\.(bash|zsh|python|psql|mysql)_history|ConsoleHost_history'; Name='системні облікові дані / історія команд' }
    @{ Id='T06'; Sev='HIGH';     Rx='169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200'; Name='метадані хмарної машини (тимчасові ключі)' }
    @{ Id='T06'; Sev='HIGH';     Neg=$true; Rx='gh\s+auth\s+token|gcloud\s+auth\s+print-(access|identity)-token|aws\s+(sts\s+get-session-token|configure\s+(get|export-credentials)|secretsmanager\s+get-secret-value|ssm\s+get-parameters?)|az\s+account\s+get-access-token|kubectl\s+(get\s+secrets?|config\s+view\s+--raw)|vault\s+(read|kv\s+get)|\bop\s+(read|item\s+get)|npm\s+token|git\s+credential\s+fill'; Name='команда, що друкує токен' }
    @{ Id='T06'; Sev='HIGH';     Raw=$true; Rx='sk-ant-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}|-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY|\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.'; Name='вшитий ключ/токен (чужий акаунт — теж канал ексфільтрації)' }
    @{ Id='T06'; Sev='MEDIUM';   Neg=$true; Rx='\bprintenv\b|Get-ChildItem\s+env:|\bgci\s+env:|\bdir\s+env:|GetEnvironmentVariables\(|os\.environ\b|process\.env\b|(^|[\s/\\"''`])\.env\b|(^|[\s;|&])env\s*(\||>|$)|\bset\s*\|' }
    @{ Id='T06'; Sev='MEDIUM';   Rx='Get-Clipboard|\bpbpaste\b|xclip\s+.{0,20}-o\b|xsel\s+.{0,20}(-o|--output)\b|wl-paste|pyperclip\.paste|\bscreencapture\b|ImageGrab\.grab|pyautogui\.screenshot|CopyFromScreen|\bpynput\b|GetAsyncKeyState|SetWindowsHookEx|keylog'; Name='буфер обміну / знімки екрана / клавіатура' }
    @{ Id='T06'; Sev='MEDIUM';   Neg=$true; Rx='\.claude[/\\](projects|history|todos|shell-snapshots)|(print|reveal|output|send|leak|repeat|dump|покажи|виведи|надішли)\s.{0,30}(system\s+prompt|системн\w+\s+(промпт|інструкці\w*))'; Name='історія розмов агента / системний промпт' }
    @{ Id='T06'; Sev='LOW';      Rx='\b[A-Z][A-Z0-9]*_(API_KEY|TOKEN|SECRET|SECRET_KEY|ACCESS_KEY|PASSWORD)\b'; Name='згадка змінної з секретом' }

    # ===== T07 Ексфільтрація =====
    @{ Id='T07'; Sev='HIGH';     Rx='webhook\.(site|cool)|requestbin|requestcatcher|beeceptor|hookbin|mockbin|pipedream\.(net|com)|ngrok(-free)?\.(io|app|dev|com)|interact\.sh|burpcollaborator|oastify\.com|oast\.(fun|me|pro|live|site|online)|canarytokens|dnslog\.cn|ceye\.io|pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|\bfile\.io|0x0\.st|termbin\.com|\bix\.io|sprunge\.us|anonfiles|gofile\.io|catbox\.moe|tmpfiles\.org|loca\.lt|localtunnel|serveo\.net|trycloudflare\.com|localhost\.run|bore\.pub|smee\.io|ntfy\.sh|telegra\.ph|\.onion\b|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com' }
    @{ Id='T07'; Sev='HIGH';     Rx='https?://(?!127\.|0\.0\.0\.0)\d{1,3}(\.\d{1,3}){3}'; Name='URL з голою IP-адресою' }
    @{ Id='T07'; Sev='HIGH';     Rx='\b(curl|wget)\b.{0,120}\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file|--json)\b' }
    @{ Id='T07'; Sev='HIGH';     Rx='!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=|<img\b[^>]*src\s*=\s*["'']?https?://[^"''\s>]*\?[^"''\s>]*='; Name='картинка з query-параметрами (дані йдуть під час рендеру)' }
    @{ Id='T07'; Sev='HIGH';     Rx='(?<![-\w.])(nslookup|dig|host)\s+[^\r\n]*(\$\(|\$\{|\$[A-Za-z_])|Resolve-DnsName\s+[^\r\n]*\$'; Name='DNS-запит зі змінною (DNS-ексфільтрація?)' }
    @{ Id='T07'; Sev='MEDIUM';   Rx='(append|include|embed|encode|attach|додай|закодуй|встав|вклади)\s.{0,40}(data|contents?|output|results?|secrets?|tokens?|keys?|conversation|history|дан\w+|вміст|результат\w*|розмов\w*|ключ\w*).{0,40}(\burl\b|query\s*(string|param)|\blink\b|посиланн\w*|\?\w+=)'; Name='вказівка вкласти дані в URL' }
    @{ Id='T07'; Sev='MEDIUM';   Rx='\bbit\.ly/|tinyurl\.com|\bt\.co/|goo\.gl/|\bis\.gd/|rb\.gy/|cutt\.ly/|shorturl\.at|https?://[^/\s]*xn--'; Name='скорочувач посилань / punycode-домен' }
    @{ Id='T07'; Sev='MEDIUM';   Rx='Invoke-(WebRequest|RestMethod).{0,160}(-Method\s+(Post|Put|Patch)|-Body\b|-InFile\b)|requests\.(post|put|patch)\(|httpx\.(post|put|patch)\(|axios\.(post|put|patch)\(|method\s*:\s*[''"](POST|PUT|PATCH)|urlopen\(.{0,80}data\s*=|navigator\.sendBeacon|new\s+WebSocket\(|Upload(String|File|Data)\(' }
    @{ Id='T07'; Sev='MEDIUM';   Rx='\bscp\s+.{0,80}\S+@\S+:|\brsync\b.{0,80}\S+@\S+:|\bsftp\s+\S+@|aws\s+s3\s+(cp|sync|mv)\b|gsutil\s+(cp|rsync)|\bazcopy\b|rclone\s+(copy|sync|move)|gh\s+gist\s+create|git\s+remote\s+(add|set-url)'; Name='передача файлів на віддалений ресурс' }

    # ===== T08 Руйнівні операції =====
    @{ Id='T08'; Sev='CRITICAL'; Rx='\bmkfs\b|\bdd\s+if=|\bshred\b|\bwipefs\b|\bformat\s+[a-z]:|\bdiskpart\b|Format-Volume|Clear-Disk|\bdel\s+/[sq]|\brd\s+/s\b|vssadmin\s+delete|wbadmin\s+delete|\bbcdedit\b|cipher\s+/w|>\s*/dev/(sd[a-z]|nvme|disk)|--no-preserve-root|\brm\s+(-[a-z-]+\s+)+["'']?(/|~/?|\$HOME/?|/\*)["'']?\s*($|[;&|`)])' }
    @{ Id='T08'; Sev='HIGH';     Rx='\brm\s+(-[a-z]+\s+)*-[a-z]*r[a-z]*\b|Remove-Item\b.{0,80}-Recurse|\brimraf\b|shutil\.rmtree|fs\.(rm|rmdir)(Sync)?\(.{0,80}recursive|\bfind\b.{0,120}\s-(delete|exec\s+rm)\b|xargs\s+(-\S+\s+)*rm\b|Directory\]?(::|\.)Delete\(' }
    @{ Id='T08'; Sev='HIGH';     Rx='git\s+push\b.{0,40}(--force|\s-f\b|--delete|--mirror)|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|git\s+(checkout|restore)\s+(--\s+)?\.(\s|$|`)|git\s+branch\s+-D\b|git\s+stash\s+(drop|clear)|git\s+filter-(branch|repo)|git\s+reflog\s+expire|git\s+update-ref\s+-d' }
    @{ Id='T08'; Sev='HIGH';     Rx='\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\s+\w+\s*(;|$|["''`])|dropDatabase\(|\bFLUSH(ALL|DB)\b' }
    @{ Id='T08'; Sev='HIGH';     Rx='terraform\s+destroy|kubectl\s+delete|helm\s+uninstall|docker\s+(system|volume|image)\s+prune|docker\s+rm\s+-f|aws\s+\S+\s+(delete|terminate)-|gh\s+repo\s+delete'; Name='знищення інфраструктури' }
    @{ Id='T08'; Sev='MEDIUM';   Rx='\bshutdown\s+(/|-)|Stop-Computer|Restart-Computer|\bkillall\b|taskkill\s+/f|Stop-Process\b.{0,40}-Force|kill\s+-9\s+-1|chmod\s+-R\s+0{3}|icacls\b.{0,80}/(grant|deny)|\btakeown\b' }
    @{ Id='T08'; Sev='MEDIUM';   Rx='openssl\s+enc\b.{0,60}-(aes|e\b)|gpg\s+(-c|--symmetric)\b|7z\s+a\s+.{0,40}-p|zip\s+(-\S+\s+)*(-e|--encrypt|-P)\b|Fernet\(|AES\.new\('; Name='шифрування файлів (вимагач?)' }

    # ===== T09 Закріплення і конфігурація =====
    @{ Id='T09'; Sev='CRITICAL'; Rx='authorized_keys|/etc/sudoers|/etc/hosts\b|drivers\\etc\\hosts|/etc/ld\.so\.preload|\bLD_PRELOAD\b|DYLD_INSERT_LIBRARIES|\buseradd\b|\badduser\b|net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators|New-LocalUser|\bvisudo\b|\.ssh[/\\](config|rc)\b' }
    @{ Id='T09'; Sev='HIGH';     Neg=$true; Rx='\.bashrc|\.zshrc|\.zprofile|\.bash_profile|(^|[\s/\\~"''`])\.profile\b|/etc/profile|\$PROFILE\b|PowerShell_profile|\.config[/\\]fish|\bcrontab\b|/etc/cron|\bschtasks\b|Register-ScheduledTask|\blaunchctl\b|LaunchAgents|LaunchDaemons|systemctl\s+(--user\s+)?enable|systemd[/\\]user|CurrentVersion\\Run|Programs\\Startup|shell:startup|New-Service\b|\bsc(\.exe)?\s+create\b|\breg(\.exe)?\s+add\b|Register-WmiEvent|__EventFilter|sitecustomize|usercustomize' }
    @{ Id='T09'; Sev='HIGH';     Neg=$true; Rx='\.git[/\\]hooks|core\.(hooksPath|fsmonitor|sshCommand|pager|editor|askPass)|^\s*(fsmonitor|sshCommand|hooksPath)\s*=|\.gitconfig\b|git\s+config\s+--(global|system)'; Name='git-хуки / конфігурація git, що запускає код' }
    @{ Id='T09'; Sev='MEDIUM';   Neg=$true; Rx='\.claude[/\\](settings|hooks|agents|skills|commands|rules|plugins|output-styles)|settings(\.local)?\.json|managed-settings|\bCLAUDE\.md\b|\bAGENTS\.md\b|\bGEMINI\.md\b|\.mcp\.json|claude_desktop_config|\.cursorrules|\.cursor[/\\](rules|mcp)|\.windsurfrules|\.clinerules|\.roo[/\\]|\.continue[/\\]|\.codex[/\\]|\.gemini[/\\]|opencode\.json|copilot-instructions|extraKnownMarketplaces|enabledPlugins' }
    @{ Id='T09'; Sev='MEDIUM';   Neg=$true; Rx='claude\s+(mcp\s+add|plugin\s+(install|marketplace|update)|config\s+set)|/plugin\s+(install|marketplace)|codex\s+mcp\s+add'; Name='встановлює плагіни/MCP-сервери агенту' }
    @{ Id='T09'; Sev='MEDIUM';   Neg=$true; Rx='"(pre|post)?install"\s*:|\.github[/\\]workflows|\.gitlab-ci|\.pre-commit-config|\.husky[/\\]|\.gitattributes\b|\.vscode[/\\](tasks|settings|launch)\.json|runOn.{0,10}folderOpen|\.devcontainer|\.envrc\b'; Name='автозапуск через інструменти проєкту (npm-скрипти, CI, VS Code, direnv)' }
    @{ Id='T09'; Sev='MEDIUM';   Rx='\bCronCreate\b|\bScheduleWakeup\b|create_scheduled_task|\bRemoteTrigger\b|(^|\s)/(loop|schedule)\b'; Name='планує власні повторні запуски агента' }

    # ===== T10 Обфускація =====
    @{ Id='T10'; Sev='CRITICAL'; Rx='(b64decode|FromBase64String|base64\s+(-d|--decode|-D)\b|\batob\s*\(|bytes\.fromhex|codecs\.decode|zlib\.decompress|xxd\s+-r|openssl\s+enc\s+-d).{0,80}(\bexec\b|\beval\b|Invoke-Expression|\biex\b|\|\s*(ba|z)?sh\b)|(\bexec|\beval|Invoke-Expression|\biex)\b.{0,40}(b64decode|FromBase64String|\batob\b|bytes\.fromhex|codecs\.decode|zlib\.decompress)|\b(rev|gunzip|zcat)\b[^\r\n|]*\|\s*(ba|z)?sh\b'; Name='розкодування + виконання' }
    @{ Id='T10'; Sev='HIGH';     Rx='-EncodedCommand\b|\s-enc?\s+[A-Za-z0-9+/=]{20,}|base64\s+(-d|--decode|-D)\b' }
    @{ Id='T10'; Sev='HIGH';     Rx='pickle\.loads?\(|marshal\.loads\(|yaml\.(unsafe_)?load\((?!.{0,80}SafeLoader)|\[scriptblock\]::Create|Reflection\.Assembly\]::Load|Assembly\.Load\(|Add-Type\b.{0,60}-(TypeDefinition|MemberDefinition)|VirtualAlloc|WriteProcessMemory|ctypes\.(windll|CDLL)|__import__\(|getattr\(\s*__builtins__|compile\(.{0,80}["'']exec["'']'; Name='виконання коду з даних / небезпечна десеріалізація' }
    @{ Id='T10'; Sev='LOW';      Rx='FromBase64String|\batob\s*\(|b64decode'; Name='розкодування base64 (звідки дані й що з ними далі?)' }
    @{ Id='T10'; Sev='MEDIUM';   Raw=$true; Rx='[A-Za-z0-9+/]{200,}={0,2}'; Name='довгий base64-подібний блок' }
    @{ Id='T10'; Sev='MEDIUM';   Raw=$true; Rx='(\\x[0-9a-f]{2}){8,}|(\\u[0-9a-f]{4}){8,}|(%[0-9a-f]{2}){12,}|(\\[0-7]{3}){8,}'; Name='закодовані послідовності' }
    @{ Id='T10'; Sev='MEDIUM';   Rx='\beval\s*\(|\bexec\s*\(|Invoke-Expression|\biex\b|new\s+Function\s*\(|String\.fromCharCode|-join\s*\(\s*\[char|subprocess\.\w+\(.{0,200}shell\s*=\s*True' }
    @{ Id='T10'; Sev='MEDIUM';   Raw=$true; Rx='\$\{IFS\}|\$IFS\b|(["''][a-z]{1,4}["'']\s*\+\s*){3,}|(\bchr\(\d+\)\s*\+\s*){3,}|(\[char\]\s*\d+\s*\+\s*){2,}|\b[a-z]\^[a-z]\^[a-z]|\b[a-z]{1,3}`[a-z]{1,3}`[a-z]{1,3}\b|\$''\\x'; Name='розбиті/склеєні рядки (ховають команду від пошуку)' }
    @{ Id='T10'; Sev='LOW';      Rx='os\.system\(|subprocess\.(run|Popen|call|check_output)\(|child_process|execSync\(|Start-Process\b|Runtime\.getRuntime\(\)\.exec'; Name='запуск процесів (що саме запускається?)' }

    # ===== T11 Ланцюг постачання =====
    @{ Id='T11'; Sev='HIGH';     Rx='(fetch|load|download|follow|read|get|завантаж\w*|прочитай|виконай|візьми)\s.{0,60}(instructions|prompt|rules|steps|інструкці\w*|правила|кроки).{0,60}https?://' ; Name='інструкції з мережі' }
    @{ Id='T11'; Sev='HIGH';     Rx='pip3?\s+install\s+[^\r\n]*(git\+|https?://)|npm\s+(i|install)\s+[^\r\n]*(https?://|github:|git\+)|\b(npx|bunx|uvx|pnpx)\s+(-y\s+|--yes\s+)?\S*(https?://|github:|git\+)|deno\s+run\s+[^\r\n]*https?://|pipx\s+run\s+[^\r\n]*https?://|go\s+run\s+\S+@'; Name='пакет/код напряму з URL чи git' }
    @{ Id='T11'; Sev='HIGH';     Rx='--(extra-)?index-url[=\s]+https?://(?!pypi\.org)|PIP_(EXTRA_)?INDEX_URL|--registry[=\s]+https?://(?!registry\.npmjs\.org)|npm\s+config\s+set\s+registry|pip\s+config\s+set'; Name='сторонній реєстр пакетів (dependency confusion)' }
    @{ Id='T11'; Sev='MEDIUM';   Rx='\b(python3?|py|node|deno|bun|bash|sh|zsh|pwsh|powershell|ruby|perl|php)(\.exe)?\s+(-\S+\s+)*["''`]?(~[/\\]|/(?!dev/null)|[A-Z]:\\|\$HOME|\$env:|%[A-Z_]+%|\.\.[/\\])'; Name='запуск коду поза папкою скіла (цей код аудит не покриває)' }
    @{ Id='T11'; Sev='MEDIUM';   Rx='raw\.githubusercontent\.com|gist\.githubusercontent\.com|gist\.github\.com|cdn\.jsdelivr\.net|unpkg\.com' }
    @{ Id='T11'; Sev='MEDIUM';   Rx='\bpip3?\s+install\b|\bnpm\s+(i|install)\b|\b(npx|bunx|uvx|pnpx)\s|\byarn\s+add\b|\bpnpm\s+add\b|\bbun\s+(add|install)\b|\buv\s+(add|pip\s+install|tool\s+install)\b|\bpipx\s+install\b|\bgo\s+install\b|\bcargo\s+install\b|\bgem\s+install\b|\bchoco\s+install\b|\bwinget\s+install\b|\bscoop\s+install\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|Install-Module|Install-Package|composer\s+require|dotnet\s+add\s+package' }
    @{ Id='T11'; Sev='MEDIUM';   Rx='\bgit\s+(clone|pull|submodule)\b|\bdocker\s+(run|pull)\b|auto-?update|self-?update|update\s+(this|the)\s+skill|оновлю\w*\s+себе'; Name='тягне сторонній код під час роботи / самооновлення' }

    # ===== T12 Перехоплення тригерів (лише frontmatter) =====
    @{ Id='T12'; Sev='MEDIUM';   Scope='fm'; Rx='\b(always|every|any|all)\s+(tasks?|requests?|messages?|times?|conversations?|prompts?)\b|use\s+(this\s+)?(for\s+)?(everything|all\s+tasks)|instead\s+of\s+(any|all|other)\s+skills?|\bзавжди\b|будь-як\w+\s+(задач\w*|запит\w*)|замість\s+(інших|будь-яких)' }
    @{ Id='T12'; Sev='MEDIUM';   Scope='fm'; Rx='(must|should)\s+be\s+(used|invoked|loaded|called)\s+(first|before)|before\s+(any|every|all)\s+other|highest\s+priority|\bMANDATORY\b|do\s+not\s+use\s+(any\s+)?other\s+skills?|обов.язково\s+(використовуй|вмикай)|перед\s+(будь-яким|кожним|усіма)\s+інш|не\s+використовуй\s+інш'; Name='вимагає вмикатися першим/обов''язково' }
    @{ Id='T12'; Sev='MEDIUM';   Scope='fm'; Rx='\b(official|verified|certified|trusted)\b.{0,30}\b(anthropic|claude|openai)\b|\b(by|from)\s+anthropic\b|офіційн\w+\s+(скіл|плагін)'; Name='видає себе за офіційний' }

    # ===== T13 Надмірні привілеї (frontmatter) =====
    @{ Id='T13'; Sev='MEDIUM';   Scope='fm'; Rx='^\s*allowed-tools\s*:.*(\bBash\b(?!\()|Bash\(\s*\*\s*\)|\*\s*$|\ball\b)|^\s*-\s*Bash(\(\s*\*\s*\))?\s*$'; Name='allowed-tools: необмежений Bash / усі інструменти' }
    @{ Id='T13'; Sev='LOW';      Scope='fm'; Rx='^\s*user-invocable\s*:\s*false'; Name='скіл прихований від користувача (вмикає лише модель)' }

    # ===== T14 Незворотні зовнішні дії =====
    @{ Id='T14'; Sev='MEDIUM';   Rx='Send-MailMessage|smtplib|\bsendmail\b|nodemailer|sendgrid|\bmailgun\b|\btwilio\b|Send-MgUserMail|Outlook\.Application|chat\.postMessage|gh\s+(pr|issue)\s+(create|comment|merge|close)|\bgit\s+push\b|npm\s+publish|twine\s+upload|\bstripe\b|\bpaypal\b|transfer\s+funds|\bwithdraw' }
    @{ Id='T14'; Sev='MEDIUM';   Rx='gh\s+(release\s+create|repo\s+(create|edit|fork)|secret\s+set|workflow\s+run|api\s+.{0,60}(-X|--method)\s+(POST|PUT|PATCH|DELETE))|cargo\s+publish|gem\s+push|docker\s+push|nuget\s+push|vsce\s+publish|vercel\s+(--prod|deploy)|netlify\s+deploy|wrangler\s+(deploy|publish)|firebase\s+deploy|fly\s+deploy|terraform\s+apply|kubectl\s+apply|helm\s+(install|upgrade)|sendTransaction|signTransaction|eth_send|solana\s+transfer|api\.(twitter|x)\.com|graph\.facebook\.com|slack\.com/api'; Name='публікація / деплой / транзакція' }

    # ===== T15 Персональні дані і телеметрія =====
    @{ Id='T15'; Sev='MEDIUM';   Rx='\btelemetry\b|google-analytics|\bmixpanel\b|segment\.(io|com)|\bamplitude\b|\bposthog\b|\bhotjar\b|\bfullstory\b|tracking\s+pixel|\butm_(source|medium|campaign)\b|fingerprintjs' }
    @{ Id='T15'; Sev='MEDIUM';   Rx='(collect|gather|harvest|scrape|збир\w*|зібрати)\s.{0,40}(personal|e-?mails?|phone|address|contacts|персональн\w*|контакт\w*|адрес\w*|телефон\w*)' }

    # ===== T16 Соціальна інженерія =====
    @{ Id='T16'; Sev='HIGH';     Rx='(paste|enter|provide|send|give|share|type|введи|встав|надішли|дай|вкажи)\s.{0,40}(password|passphrase|api\s*key|token|secret|seed\s+phrase|recovery\s+phrase|private\s+key|2fa\s+code|one-time\s+code|пароль|токен|секрет|приватний\s+ключ|seed-фраз\w*|код\s+із\s+смс)' }
    @{ Id='T16'; Sev='HIGH';     Rx='\b(cvv|cvc)\b|card\s+number|номер\s+картки|social\s+security\s+number|(scan|photo|upload|сфотографуй|завантаж)\s.{0,30}(passport|id\s+card|паспорт)'; Name='запит платіжних/особистих документів' }
    @{ Id='T16'; Sev='MEDIUM';   Rx='(press|натисни)\s+win(dows)?\s*\+\s*r|(paste|copy\s+and\s+paste|встав|скопіюй)\s.{0,60}(terminal|powershell|command\s+prompt|run\s+dialog|console|термінал\w*|консол\w*|командн\w+\s+ряд\w*)|(terminal|powershell)\s+as\s+admin|run\s+as\s+administrator|від\s+(імені\s+)?адміністратора'; Name='користувача просять виконати команду вручну (ClickFix)' }

    # ===== T17 Вихід за межі робочої папки =====
    @{ Id='T17'; Sev='MEDIUM';   Skip='^#!'; Rx='\.\.[/\\]\.\.[/\\]|[A-Z]:\\Windows|(^|[\s"''`])/etc/|/usr/(local/)?bin|Program\s+Files|%APPDATA%|\$env:(APPDATA|LOCALAPPDATA|ProgramData)|~/Library' }
    @{ Id='T17'; Sev='MEDIUM';   Rx='~[/\\](Documents|Desktop|Downloads|Pictures)|\$HOME[/\\](Documents|Desktop|Downloads)|%USERPROFILE%|\$env:USERPROFILE|\bOneDrive\b|\biCloud\b|\bDropbox\b|Google\s+Drive'; Name='особисті папки користувача' }
    @{ Id='T17'; Sev='MEDIUM';   Rx='^gitdir:\s'; Name='.git-вказівник на зовнішню папку' }

    # ===== T18 Зловживання ресурсами =====
    @{ Id='T18'; Sev='CRITICAL'; Rx=':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|%0\s*\|\s*%0|\bxmrig\b|\bminerd\b|\bethminer\b|\bcpuminer\b|cryptonight|stratum\+tcp|coinhive|nicehash' }
    @{ Id='T18'; Sev='MEDIUM';   Rx='(spawn|launch|start|run|запусти)\s.{0,30}(\b\d{2,}\b|many|dozens|hundreds|multiple|десятк\w*|сотн\w*|багато)\s.{0,20}(agents?|subagents?|sessions?|агент\w*|сесі\w*)' }
    @{ Id='T18'; Sev='MEDIUM';   Rx='while\s+(true|:|\(\s*(1|true|\$true)\s*\))|for\s*\(\s*;\s*;\s*\)|\byes\s*\||sleep\s+infinity|(repeat|loop|retry|keep\s+(going|running|trying)|повторюй)\s.{0,30}(forever|indefinitely|endlessly|нескінченно|вічно|без\s+кінця)|never\s+stop\b|ніколи\s+не\s+зупиняйся'; Name='нескінченний цикл / «ніколи не зупиняйся»' }

    # ===== T20 Мета-ін'єкція проти аудитора =====
    @{ Id='T20'; Sev='CRITICAL'; Rx='(this|the)\s+(skill|plugin|file|code|script)\s+(is|has\s+been)\s+(already\s+)?(safe|verified|audited|approved|trusted|reviewed|scanned)|(skip|bypass|no\s+need\s+(for|to))\s+.{0,20}(security|safety|audit|scan|review)|(скіл|плагін|файл|скрипт)\s+(вже\s+)?(безпечн\w*|перевірен\w*)|не\s+(перевіряй|скануй)' }
    @{ Id='T20'; Sev='CRITICAL'; Rx='note\s+(for|to)\s+(the\s+)?(reviewers?|auditors?|scanners?|security)|if\s+you\s+are\s+(an?\s+)?(ai|llm|language\s+model|security\s+(scanner|auditor|reviewer))|(mark|report|rate|classify|treat)\s+(this|it|the\s+\w+)\s+as\s+(safe|benign|trusted|low[-\s]risk)|(познач|оціни|вважай)\s.{0,20}безпечн|pre-?approved|already\s+(scanned|audited|reviewed)\s+by|(verdict|вердикт)\s*[:=]\s*(SAFE|🟢)|(false\s+positive|хибн\w+\s+тривог\w+).{0,40}(ignore|skip|ігноруй|пропусти)|scan(ner)?[-:\s]+(ignore|disable|skip)\b'; Name='звернення до аудитора / нав''язування вердикту' }

    # ===== T21 Автозапуск через компоненти плагіна =====
    @{ Id='T21'; Sev='HIGH';     Raw=$true; Ext=$markup; Rx='(^|[\s(>:])!`[^`\r\n]+`|^\s*```!\s*$'; Name='динамічна команда !`…` — виконується під час завантаження скіла, до рішення моделі' }
    @{ Id='T21'; Sev='HIGH';     Rx='["'']?(mcpServers|lspServers|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper)["'']?\s*[:=]'; Name='конфігурація, що запускає процес (MCP/LSP/statusLine/helper)' }
    @{ Id='T21'; Sev='HIGH';     Rx='["''](SessionStart|SessionEnd|PreToolUse|PostToolUse|PostToolUseFailure|UserPromptSubmit|Stop|SubagentStart|SubagentStop|PreCompact|Notification|PermissionRequest)["'']\s*:|"hooks"\s*:\s*[\[{]'; Name='хук на подію агента (команда запускається автоматично)' }
    @{ Id='T21'; Sev='HIGH';     Scope='fm'; Rx='^\s*hooks\s*:'; Name='хуки у frontmatter скіла' }
    @{ Id='T21'; Sev='MEDIUM';   Ext='.json', '.jsonc', '.json5'; Rx='"command"\s*:\s*"|"type"\s*:\s*"(sse|http|streamable-http)"|"(url|serverUrl)"\s*:\s*"https?://'; Name='команда або віддалений сервер у конфігурації' }

    # ===== T22 Умовна / відкладена поведінка =====
    @{ Id='T22'; Sev='HIGH';     Rx='(if|when|once|unless|while|якщо|коли|поки)\s.{0,40}(not\s+(watching|looking|monitored|supervised|present)|nobody\s+is|no\s+one\s+is|unattended|без\s+нагляду|не\s+дивиться|ніхто\s+не\s+(бачить|дивиться|стежить))'; Name='поведінка «коли ніхто не дивиться»' }
    @{ Id='T22'; Sev='MEDIUM';   Rx='datetime\.(now|today)\(\).{0,40}[<>]|Get-Date.{0,40}-(gt|ge|lt|le)\b|Date\.now\(\)\s*[<>]|\$\(date\s+\+%.{0,20}\)\s*-(gt|ge|lt)|(after|since|starting|після|починаючи\s+з)\s+\d{4}-\d{2}-\d{2}|(every|each)\s+(\d+(st|nd|rd|th)|tenth|fifth|nth)\s+(time|run|invocation)|random\.(random|randint)\(.{0,30}[<>=]|Math\.random\(\)\s*[<>]|Get-Random.{0,30}-(lt|gt|eq)\b'; Name='спрацювання за датою / лічильником / випадково' }
    @{ Id='T22'; Sev='MEDIUM';   Rx='/\.dockerenv|\bvirtualbox\b|\bvmware\b|IsDebuggerPresent|sys\.gettrace\(|\b(CI|GITHUB_ACTIONS|CODESPACES)\b.{0,30}(==|-eq|-ne|!=|in\s+os\.environ)|(USERNAME|USERDOMAIN|COMPUTERNAME|\bwhoami\b).{0,30}(==|-eq|-match|-like|\.endswith|\.startswith)|(headless|non-?interactive)\s+mode.{0,40}(then|:)'; Name='перевірка середовища (пісочниця / CI / конкретна машина)' }

    # ===== T23 Отруєння пам'яті й самопоширення =====
    @{ Id='T23'; Sev='HIGH';     Neg=$true; Rx='\bMEMORY\.md\b|\bSOUL\.md\b|\.claude[/\\](projects[/\\]\S*)?memory|(save|write|add|store|append|запиши|збережи|додай)\s.{0,40}(to|in|into|у|в|до)\s+(your\s+|the\s+|agent\s+|long-term\s+)?(memory|пам.ят\w*)|remember\s+(this\s+)?(permanently|forever|for\s+(all\s+)?future\s+sessions|across\s+sessions)|запам.ятай\s+(назавжди|на\s+майбутн)'; Name='запис у довготривалу пам''ять агента' }
    @{ Id='T23'; Sev='HIGH';     Rx='(copy|add|insert|append|inject|write|paste|скопіюй|додай|встав|запиши)\s.{0,50}(this|these|the\s+following|ці|цей|наступн\w+)\s+(instructions?|text|block|prompt|rules?|інструкці\w*|текст|блок|правил\w*)\s.{0,60}(every|all|each|other|README|commit|pull\s+request|\bPR\b|issue|comment|docstring|кожн\w*|усі\w*|всі\w*|інш\w*)'; Name='самопоширення інструкцій (README, коміти, інші файли)' }
    @{ Id='T23'; Sev='HIGH';     Rx='(modify|edit|update|patch|rewrite|overwrite|зміни|перепиши|онови)\s.{0,30}(other|another|all|every|інш\w*|усі|всі)\s+(skills?|plugins?|agents?|SKILL\.md|скіл\w*|плагін\w*)|(tell|instruct|скажи|накажи)\s.{0,30}(sub-?agents?|other\s+agents?|субагент\w*).{0,40}(ignore|skip|not\s+report|bypass|ігнор\w*|не\s+звітув\w*)'; Name='зміна інших скілів / вказівки іншим агентам' }

    # ===== T24 Перехоплення інструментів і каналів =====
    @{ Id='T24'; Sev='CRITICAL'; Rx='(ANTHROPIC|OPENAI|CLAUDE_CODE)\w*_(BASE_URL|API_BASE|ENDPOINT)\b|ANTHROPIC_AUTH_TOKEN\s*[=:]'; Name='перенаправлення API-трафіку агента (уся розмова й ключ ідуть на чужий сервер)' }
    @{ Id='T24'; Sev='HIGH';     Rx='\b(HTTPS?_PROXY|ALL_PROXY)\s*=|\b(http|https)\.proxy\b|url\.\S*insteadOf|NODE_OPTIONS\s*=|PYTHONSTARTUP\s*=|PYTHONPATH\s*=|GIT_SSH_COMMAND|BASH_ENV\s*=|PROMPT_COMMAND\s*='; Name='проксі / ін''єкція через змінні середовища' }
    @{ Id='T24'; Sev='MEDIUM';   Rx='(before|after|whenever|when|every\s+time|each\s+time|перед|після|щоразу|коли)\s.{0,30}(us(e|ing)|call(ing)?|invok(e|ing)|run(ning)?|використ\w*|виклик\w*)\s.{0,20}(any|every|each|all|other|another|будь-як\w*|кожн\w*|інш\w*)\s+(tools?|skills?|mcp|commands?|інструмент\w*|скіл\w*)|instead\s+of\s+(the\s+)?(built-?in|default|official|native)|замість\s+(вбудован\w+|стандартн\w+)'; Name='втручання в роботу інших інструментів/скілів' }
    @{ Id='T24'; Sev='MEDIUM';   Rx='claude-in-chrome|computer-use|browser\s+session|logged[-\s]in\s+(session|browser|account)|cookies?\s+from\s+(the\s+)?browser|залогінен\w*'; Name='діє через сесії користувача (браузер, комп''ютер)' }
    @{ Id='T24'; Sev='LOW';      Rx='\bmcp__\w+'; Name='використовує MCP-інструменти (звір із призначенням)' }

    # ===== T25 Розвідка й латеральний рух =====
    @{ Id='T25'; Sev='HIGH';     Rx='\bssh\s+(-\S+\s+)*\S+@\S+|\bsshpass\b|Invoke-Command\s+.{0,40}-ComputerName|Enter-PSSession|\bpsexec\b|\bwmic\b.{0,40}/node'; Name='вихід на інші машини' }
    @{ Id='T25'; Sev='MEDIUM';   Rx='\bnmap\b|\bmasscan\b|\barp\s+-a\b|net\s+(view|group|localgroup)\b|\bnltest\b|Get-ADUser|Get-NetTCPConnection|os\.walk\(\s*["''](/|~|[A-Z]:)|\bfind\s+(/|~|\$HOME)\s'; Name='сканування мережі / обхід усієї файлової системи' }
    @{ Id='T25'; Sev='LOW';      Rx='\bwhoami\b|\bipconfig\b|\bifconfig\b|\buname\s+-a|\bsysteminfo\b|Get-ComputerInfo|ipinfo\.io|api\.ipify|ifconfig\.me|icanhazip'; Name='збирання відомостей про систему' }

    # ===== T26 Шкідливий результат роботи =====
    @{ Id='T26'; Sev='HIGH';     Rx='(add|insert|include|inject|embed|create|додай|встав|створи)\s.{0,40}(backdoor|hidden\s+(endpoint|admin|account|user|route)|hard-?coded\s+(password|credential|key)|affiliate|referral\s+(link|code)|бекдор|реферальн\w*|прихован\w+\s+(обліков\w*|користувач\w*|адмін\w*))'; Name='бекдор / приховані вставки в результат' }
    @{ Id='T26'; Sev='MEDIUM';   Rx='(disable|remove|skip|comment\s+out|delete|weaken|вимкни|видали|пропусти|закоментуй)\s.{0,30}(tests?|assertions?|validation|auth(entication|orization)?|csrf|sanitiz\w*|rate\s+limit\w*|тести|тестів|автентифікац\w*|валідац\w*)|(always|завжди)\s+(approve|lgtm|схвалюй)|approve\s+.{0,20}(without\s+review|regardless)'; Name='ослаблює перевірки / нав''язує схвалення' }
)

$rxOpts = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
$rxTimeout = [timespan]::FromSeconds(2)
$n = 0
foreach ($r in $rules) {
    $r.N = $n++
    $r.Regex = [regex]::new($r.Rx, $rxOpts, $rxTimeout)
    if ($r.Skip) { $r.SkipRx = [regex]::new($r.Skip, $rxOpts) }
}

$negRx = [regex]::new('\b(never|not|don''t|do\s+not|must\s+not|cannot|without|forbidden|prohibited)\b|\bне\b|ніколи|заборон|\bбез\b|\bнеможна\b|\bне\s+можна\b', $rxOpts)
# «do not forget to read ~/.ssh» і «without asking» — не заборони: прибираємо їх перед пошуком заперечення.
$pseudoNegRx = [regex]::new('(do\s+not|don''t|never)\s+(forget|hesitate|skip|miss|fail|stop)|not\s+only|не\s+(забудь|забувай|вагайся|пропускай|лише|тільки|зупиняйся)|without\s+(asking|telling|confirmation|notifying|permission|approval|hesitation)|без\s+(відома|підтвердження|дозволу|запиту|вагань)', $rxOpts)
# Заголовок-заборона знижує рівень для всього розділу, тому тут потрібне явне формулювання, а не будь-яке «не».
$negHeadingRx = [regex]::new('^#{2,6}\s.*(\b(never|do\s+not|don''t|must\s+not|forbidden|prohibited)\b|ніколи|заборон|не\s+можна|не\s+роби|чого\s+не)', $rxOpts)
$down = @{ CRITICAL = 'HIGH'; HIGH = 'MEDIUM'; MEDIUM = 'LOW'; LOW = 'LOW' }
$up = @{ LOW = 'MEDIUM'; MEDIUM = 'HIGH'; HIGH = 'CRITICAL'; CRITICAL = 'CRITICAL' }

# Скіл читає зовнішній вміст (веб, листи, сторінки)…
$externalRx = [regex]::new('web\s*search|WebFetch|WebSearch|вебпошук|веб-пошук|get_page_text|browse\s+(to|the)\b|fetch\s+(the\s+)?(page|url|website|article)|read\s+the\s+(source|page|article|email|website|issue|ticket)|прочитай\s+(джерело|новину|сторінку|посилання|лист)', $rxOpts)
# …і має правило, що цей вміст — дані, а не інструкції.
$guardRx = [regex]::new('data,?\s+not\s+(commands|instructions)|not\s+as\s+instructions|treat\s+.{0,40}\bas\s+(untrusted\s+)?data|дані,?\s+(а\s+)?не\s+(інструкці|команд)|не\s+(виконуй|слухай)\s+.{0,30}інструкці', $rxOpts)
# Скіл ходить у мережу…
$netRx = [regex]::new('\b(curl|wget)\b|Invoke-(WebRequest|RestMethod)|\b(iwr|irm)\b|requests\.(get|post|put)|httpx\.|urllib\.request|aiohttp|\bfetch\(|axios|http\.client|Net\.WebClient|HttpClient', $rxOpts)
# …і description про це каже.
$netDeclRx = [regex]::new('api|web|http|url|online|internet|download|upload|fetch|search|publish|deploy|post|send|sync|remote|cloud|github|мереж|інтернет|завантаж|онлайн|пошук|сайт|публік|надсил|відправ|хмар|генер|зображен', $rxOpts)

$emojiZwjRx = [regex]::new('(?<=[\uD83C-\uD83E][\uDC00-\uDFFF]|️|[☀-➿])‍')
$invisibleRx = [regex]::new('\uDB40[\uDC00-\uDDEF]|[­͏ᅟᅠㅤﾠ]|\p{Cf}')
$mixedWordRx = [regex]::new('\b(?=\w*[a-z])(?=\w*[Ͱ-ϿЀ-ԯ])\w+\b', $rxOpts)
$b64Rx = [regex]::new('(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])')
$refRx = [regex]::new('(?<![\w/.\\-])((?:scripts|references|assets|bin|lib|src|tools|templates)/[\w./-]+\.[A-Za-z0-9]{1,6})\b')

# Схожі на латиницю кириличні та грецькі літери → латиниця (для пошуку «ignоre» з кириличною «о»).
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

# Розкодовує base64-блок, якщо результат схожий на текст (UTF-8 або UTF-16LE).
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
# Чи є щось після кінця зображення (поліглот: картинка + архів/скрипт).
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
    '.deb', '.rpm', '.node', '.lnk', '.chm', '.iso', '.img', '.vhd', '.vhdx', '.appimage', '.apk', '.ipa', '.sys', '.drv', '.ocx', '.cpl', '.pif', '.o', '.a', '.lib', '.elf', '.dex'
$archiveExt = '.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.zst', '.lz', '.lzma', '.cab', '.whl', '.egg', '.nupkg', '.vsix', '.crx', '.xpi'
$pickleExt = '.pkl', '.pickle', '.pt', '.pth', '.joblib', '.ckpt'
$macroExt = '.docm', '.xlsm', '.pptm', '.dotm', '.xlsb', '.xlam'
$docExt = '.pdf', '.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt', '.odt', '.ods', '.rtf'
$mediaExt = '.ttf', '.otf', '.woff', '.woff2', '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.mov', '.avi', '.tiff', '.tif', '.heic', '.avif'
$launchExt = '.hta', '.reg', '.wsf', '.jse', '.scf', '.url', '.desktop', '.service', '.plist', '.inf', '.ps1xml'
$scriptExt = '.ps1', '.psm1', '.sh', '.bash', '.zsh', '.fish', '.py', '.js', '.mjs', '.cjs', '.ts', '.rb', '.pl', '.php', '.bat', '.cmd', '.vbs', '.lua', '.go', '.hta', '.wsf', '.jse'
$quietDotfiles = '.gitignore', '.gitattributes', '.gitkeep', '.editorconfig', '.gitmodules', '.mcp.json', '.lsp.json', '.npmignore', '.prettierrc', '.markdownlint.json'

$findings = [System.Collections.Generic.List[object]]::new()
$fileList = [System.Collections.Generic.List[object]]::new()
$domains = [System.Collections.Generic.SortedSet[string]]::new()
$stats = [ordered]@{ Files = 0; Scripts = 0; Images = 0; Binary = 0; Links = 0 }
$texts = @{}
$fmNames = [System.Collections.Generic.List[object]]::new()
$fmDescriptions = @{}

function Rel([string]$p) { [IO.Path]::GetRelativePath($base, $p) -replace '\\', '/' }

function Show-Invisible([string]$s) {
    [regex]::Replace($s, '\uDB40[\uDC00-\uDDEF]|\p{Cf}|[\x00-\x08\x0B-\x1F\x7F­͏ᅟᅠㅤﾠ]', { param($m) '<U+{0:X4}>' -f [char]::ConvertToUtf32($m.Value, 0) })
}

function Add-Finding($sev, $id, $file, $line, $evidence, $note) {
    $ev = (Show-Invisible ($evidence ?? '')).Trim()
    if ($ev.Length -gt 160) { $ev = $ev.Substring(0, 157) + '...' }
    $findings.Add([pscustomobject]@{ Severity = $sev; Threat = $id; File = $file; Line = $line; Note = $note; Evidence = $ev })
}

# Усі правила, що спрацювали на тексті. $decoded — текст отримано нормалізацією чи розкодуванням.
function Get-Hits([string]$text, [bool]$inFm, [string]$ext, [bool]$decoded) {
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rules) {
        if ($decoded -and ($r.Raw -or $r.Scope -eq 'fm')) { continue }
        if ($r.Scope -eq 'fm' -and -not $inFm) { continue }
        if ($r.Ext -and $r.Ext -notcontains $ext) { continue }
        if ($r.SkipRx -and $r.SkipRx.IsMatch($text)) { continue }
        $src = if ($r.EmojiSafe) { $emojiZwjRx.Replace($text, '') } else { $text }
        $m = $r.Regex.Match($src)
        if ($m.Success) { $hits.Add([pscustomobject]@{ Rule = $r; Match = $m; Source = $src }) }
    }
    return , $hits
}

# ---------- Інвентаризація ----------
# Вміст .git не скануємо, крім того, що запускає код: хуки (не .sample) і config.
$items = if ($isFile) { @(Get-Item -LiteralPath $target -Force) } else {
    Get-ChildItem -LiteralPath $target -Recurse -Force | Where-Object {
        $_.FullName -notmatch '[\\/]\.git[\\/]' -or
        ($_.FullName -match '[\\/]\.git[\\/]config$') -or
        ($_.FullName -match '[\\/]\.git[\\/]hooks[\\/][^\\/]+$' -and $_.Name -notlike '*.sample')
    }
}

foreach ($item in $items) {
    $rel = Rel $item.FullName

    if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $stats.Links++
        Add-Finding 'HIGH' 'T17' $rel 0 "-> $($item.Target)" 'симлінк (куди веде?)'
        $fileList.Add([pscustomobject]@{ File = $rel; Size = 0; Kind = 'link'; Sha256 = '' })
        continue
    }
    if ($item.PSIsContainer) { continue }

    $stats.Files++
    $ext = $item.Extension.ToLowerInvariant()
    $relL = $rel.ToLowerInvariant()
    $kind = 'text'
    if ($scriptExt -contains $ext) { $stats.Scripts++; $kind = 'script' }
    $sha = try { (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } catch { '' }
    $entry = [pscustomobject]@{ File = $rel; Size = $item.Length; Kind = $kind; Sha256 = $sha }
    $fileList.Add($entry)

    # --- назва файлу ---
    if ($invisibleRx.IsMatch($item.Name) -or $item.Name -match '[‪-‮⁦-⁩]') {
        Add-Finding 'CRITICAL' 'T02' $rel 0 $item.Name 'невидимі/bidi-символи в назві файлу (справжнє розширення сховане)'
    }
    if ($item.Name -match '\.(png|jpe?g|gif|pdf|txt|md|docx?|xlsx?|csv|json)\.(exe|scr|bat|cmd|ps1|sh|js|vbs|lnk|com|hta|msi|jar|py)$') {
        Add-Finding 'HIGH' 'T19' $rel 0 $item.Name 'подвійне розширення (маскування під документ)'
    }
    if ($item.Name.StartsWith('.') -and $quietDotfiles -notcontains $item.Name.ToLowerInvariant() -and $relL -notmatch '(^|/)\.git/') {
        Add-Finding 'LOW' 'T19' $rel 0 $item.Name 'прихований файл (dotfile)'
    }

    # --- компоненти плагіна, які запускаються самі ---
    switch -Regex ($relL) {
        '(^|/)hooks/[^/]+\.json$|(^|/)hooks\.json$' { Add-Finding 'HIGH' 'T21' $rel 0 $item.Name 'хуки плагіна: команди запускаються автоматично на події агента' }
        '(^|/)\.?mcp\.json$' { Add-Finding 'HIGH' 'T21' $rel 0 $item.Name 'MCP-сервери: запуск процесів або віддалені інструменти' }
        '(^|/)monitors(/[^/]+)?\.json$' { Add-Finding 'HIGH' 'T21' $rel 0 $item.Name 'монітори плагіна: фонові команди' }
        '(^|/)\.lsp\.json$' { Add-Finding 'MEDIUM' 'T21' $rel 0 $item.Name 'LSP-сервери: запуск процесів' }
        '(^|/)bin/[^/]+$' { Add-Finding 'MEDIUM' 'T21' $rel 0 $item.Name 'файл у bin/ плагіна (потрапляє в PATH)' }
        '(^|/)(\.claude/)?settings(\.local)?\.json$' { Add-Finding 'MEDIUM' 'T09' $rel 0 $item.Name 'налаштування агента в комплекті' }
        '(^|/)(agents|commands|output-styles)/[^/]+\.md$' { Add-Finding 'LOW' 'T21' $rel 0 $item.Name 'компонент плагіна (агент/команда/стиль) — прочитай як інструкцію' }
        '(^|/)(claude|agents|gemini|soul|memory)\.md$' { Add-Finding 'MEDIUM' 'T23' $rel 0 $item.Name 'файл інструкцій/пам''яті агента в комплекті — потрапляє в контекст без виклику скіла' }
        '(^|/)\.gitmodules$' { Add-Finding 'MEDIUM' 'T11' $rel 0 $item.Name 'git-субмодулі: зовнішній код поза аудитом' }
        '(^|/)\.git/hooks/' { Add-Finding 'HIGH' 'T09' $rel 0 $item.Name 'git-хук у .git цілі: виконається під час git-команд у цій папці' }
        '(^|/)\.git/config$' { Add-Finding 'LOW' 'T09' $rel 0 $item.Name '.git/config цілі проскановано (fsmonitor, sshCommand, hooksPath запускають код)' }
    }

    # --- непрозорі файли ---
    if ($binaryExt -contains $ext) { $stats.Binary++; $entry.Kind = 'binary'; Add-Finding 'HIGH' 'T19' $rel 0 $item.Name 'виконуваний/бінарний файл'; continue }
    if ($macroExt -contains $ext) { $stats.Binary++; $entry.Kind = 'document'; Add-Finding 'HIGH' 'T19' $rel 0 $item.Name 'документ із макросами'; continue }
    if ($pickleExt -contains $ext) { $stats.Binary++; $entry.Kind = 'binary'; Add-Finding 'HIGH' 'T19' $rel 0 $item.Name 'серіалізований об''єкт (pickle виконує код під час завантаження)'; continue }
    if ($archiveExt -contains $ext) { $stats.Binary++; $entry.Kind = 'archive'; Add-Finding 'MEDIUM' 'T19' $rel 0 $item.Name 'архів — вміст не перевірено'; continue }
    if ($docExt -contains $ext) { $stats.Binary++; $entry.Kind = 'document'; Add-Finding 'MEDIUM' 'T19' $rel 0 $item.Name 'документ — вміст не проскановано, може містити прихований текст'; continue }
    if ($mediaExt -contains $ext) { $entry.Kind = 'media'; Add-Finding 'LOW' 'T19' $rel 0 $item.Name 'медіа/шрифт — не сканується'; continue }
    if ($launchExt -contains $ext) { Add-Finding 'MEDIUM' 'T19' $rel 0 $item.Name 'файл, який система запускає або імпортує подвійним кліком' }
    if ($item.Length -gt 20MB) { $entry.Kind = 'skipped'; Add-Finding 'MEDIUM' 'T19' $rel 0 "$([math]::Round($item.Length / 1MB, 1)) MB" 'надто великий файл — вміст не проскановано'; continue }
    if ($item.Length -gt 1MB) { Add-Finding 'LOW' 'T19' $rel 0 "$([math]::Round($item.Length / 1MB, 1)) MB" 'великий файл' }

    try { $bytes = [IO.File]::ReadAllBytes($item.FullName) }
    catch { $entry.Kind = 'skipped'; Add-Finding 'MEDIUM' 'T19' $rel 0 $_.Exception.Message 'файл не вдалося прочитати — не перевірено'; continue }

    if ($imageExt -contains $ext) {
        if (Test-ImageMagic $bytes $ext) {
            # Справжнє зображення: пікселі не аналізуємо, але шукаємо «хвіст» і текст-інструкції в метаданих.
            $stats.Images++; $entry.Kind = 'image'
            $latin = [Text.Encoding]::Latin1.GetString($bytes)
            if (Test-ImageTrailer $latin $ext) { Add-Finding 'MEDIUM' 'T19' $rel 0 $item.Name 'дані після кінця зображення (поліглот?)' }
            try {
                foreach ($sm in [regex]::Matches($latin, '[\x20-\x7E]{16,}')) {
                    foreach ($h in (Get-Hits $sm.Value $false '' $true)) {
                        if ($h.Rule.Sev -notin 'CRITICAL', 'HIGH') { continue }
                        Add-Finding 'HIGH' 'T02' $rel 0 $sm.Value "текст усередині зображення → $($h.Rule.Id) $($h.Rule.Name ?? $h.Match.Value)"
                    }
                }
            } catch [Text.RegularExpressions.RegexMatchTimeoutException] { }
            continue
        }
        Add-Finding 'HIGH' 'T19' $rel 0 $item.Name 'розширення зображення не відповідає вмісту (замаскований файл?)'
    }
    $probe = [Math]::Min($bytes.Length, 8000)
    if ($probe -gt 0 -and [Array]::IndexOf($bytes, [byte]0, 0, $probe) -ge 0) {
        $stats.Binary++; $entry.Kind = 'binary'; Add-Finding 'HIGH' 'T19' $rel 0 $item.Name 'бінарний вміст (нуль-байти)'; continue
    }

    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }  # BOM на початку — норма
    $texts[$item.FullName] = $text
    $lines = $text -split '\r?\n'

    # --- frontmatter SKILL.md ---
    $fmEnd = -1
    if ($item.Name -eq 'SKILL.md' -and $lines.Count -gt 0 -and $lines[0].Trim() -eq '---') {
        for ($i = 1; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -eq '---') { $fmEnd = $i; break } }
        if ($fmEnd -lt 0) { Add-Finding 'MEDIUM' 'T12' $rel 1 $lines[0] 'frontmatter не закрито — увесь файл читається як метадані' }
        for ($i = 1; $i -lt $fmEnd; $i++) {
            if ($lines[$i] -match '^name:\s*(.+?)\s*$') {
                $nm = $Matches[1].Trim('"''').ToLowerInvariant()
                $fmNames.Add([pscustomobject]@{ Name = $nm; File = $rel; Line = $i + 1 })
                if ($builtinNames -contains $nm) {
                    Add-Finding 'HIGH' 'T12' $rel ($i + 1) $lines[$i] 'назва збігається з вбудованим скілом'
                } elseif ($nm.Length -ge 4 -and ($builtinNames | Where-Object {
                            # одна правка для коротких назв, дві (зокрема переставлені літери) — для довгих
                            $_.Length -ge 4 -and [Math]::Abs($_.Length - $nm.Length) -le 2 -and (Get-Distance $_ $nm) -le ($_.Length -ge 8 ? 2 : 1) })) {
                    Add-Finding 'HIGH' 'T12' $rel ($i + 1) $lines[$i] 'назва майже збігається з вбудованим скілом (typosquatting)'
                } elseif ($nm -match '^(anthropic|openai|official)\b|\bofficial\b') {
                    Add-Finding 'MEDIUM' 'T12' $rel ($i + 1) $lines[$i] 'назва видає себе за офіційний скіл'
                }
            }
            if ($lines[$i] -match '^description:\s*(.*)$') {
                $fmDescriptions[$item.DirectoryName] = (($lines[$i..($fmEnd - 1)]) -join ' ')
                if ($Matches[1].Length -gt 1024) { Add-Finding 'LOW' 'T12' $rel ($i + 1) "$($Matches[1].Length) символів" 'надто довгий description (завжди в контексті агента)' }
            }
        }
    }

    # --- marketplace.json: звідки беруться плагіни ---
    if ($item.Name -eq 'marketplace.json') {
        try {
            foreach ($p in @(($text | ConvertFrom-Json).plugins)) {
                $src = $p.source
                if ($null -eq $src -or ($src -is [string] -and $src -match '^\.{0,2}/')) { continue }
                $where = if ($src -is [string]) { $src } else { ($src.repo, $src.url, $src.package | Where-Object { $_ }) -join ' ' }
                $pinned = ($src -isnot [string]) -and $src.sha
                Add-Finding ($pinned ? 'LOW' : 'MEDIUM') 'T11' $rel 0 "$($p.name): $where" ($pinned ? 'плагін із зовнішнього джерела (зафіксовано sha) — перевір окремо' : 'плагін із зовнішнього джерела без зафіксованого sha — вміст може змінитися після аудиту')
            }
        } catch { Add-Finding 'LOW' 'T11' $rel 0 $item.Name 'marketplace.json не вдалося розібрати' }
    }

    # --- рядки ---
    $hitCount = @{}
    $negSection = $false   # заголовок поточного розділу .md — заборона («Чого ніколи не писати»)
    $blank = 0
    $longLine = $false
    $isMd = $ext -eq '.md'
    $i = 0
    while ($i -lt $lines.Count) {
        $no = $i + 1
        $line = $lines[$i]
        # Склеюємо рядки з продовженням, щоб «curl … \⏎ | sh» лишався однією командою.
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

        if (-not $line.Trim()) { $blank++; continue }
        if ($blank -ge 40) { Add-Finding 'MEDIUM' 'T02' $rel $no $line "текст після $blank порожніх рядків (сховано внизу файлу)" }
        $blank = 0
        if ($isMd -and $line -match '^#{1,6}\s') { $negSection = $negHeadingRx.IsMatch($pseudoNegRx.Replace($line, '')) }
        foreach ($m in [regex]::Matches($line, 'https?://([^/\s)\]>"''`]+)')) { [void]$domains.Add($m.Groups[1].Value.ToLowerInvariant()) }
        foreach ($m in [regex]::Matches($line, '\[(https?://[^\]\s]+)\]\((https?://[^)\s]+)\)')) {
            $shown = ([uri]$m.Groups[1].Value).Host; $real = ([uri]$m.Groups[2].Value).Host
            if ($shown -and $real -and $shown -ne $real) { Add-Finding 'MEDIUM' 'T02' $rel $no $m.Value "текст посилання показує $shown, а веде на $real" }
        }
        if (-not $longLine -and $line.Length -gt 2000 -and $scriptExt -contains $ext) {
            $longLine = $true
            Add-Finding 'MEDIUM' 'T10' $rel $no $line "дуже довгий рядок ($($line.Length) символів) — мінізований чи обфускований код?"
        }

        $inFm = ($no - 1) -gt 0 -and ($no - 1) -lt $fmEnd
        try {
            $seen = @{}
            $report = {
                param($h, $text, $suffix, $bump)
                $r = $h.Rule
                $hitCount[$r.N] = 1 + ($hitCount[$r.N] ?? 0)
                if ($hitCount[$r.N] -gt 10) { return }   # не більше 10 збігів одного правила на файл
                $sev = if ($r.MdSev -and $isMd) { $r.MdSev } else { $r.Sev }
                $note = $r.Name ?? $h.Match.Value
                if ($r.Neg) {
                    $rest = $pseudoNegRx.Replace($h.Source.Remove($h.Match.Index, $h.Match.Length), '')
                    if ($negSection -or $negRx.IsMatch($rest)) { $sev = $down[$sev]; $note += ' — у контексті заборони' }
                }
                if ($bump) { $sev = $up[$sev] }
                Add-Finding $sev $r.Id $rel $no $text ($note + $suffix)
            }

            foreach ($h in (Get-Hits $line $inFm $ext $false)) { $seen[$h.Rule.N] = $true; & $report $h $line '' $false }

            # Той самий рядок після нормалізації: ловить гомогліфи, fullwidth і слова, розбиті невидимими символами.
            if ($line -match '[^\x00-\x7F]') {
                $norm = Get-Normalized $line
                if ($norm -cne $line) {
                    foreach ($h in (Get-Hits $norm $inFm $ext $true)) {
                        if ($seen[$h.Rule.N]) { continue }
                        $seen[$h.Rule.N] = $true
                        & $report $h $line ' — видно лише після нормалізації (гомогліфи / невидимі символи)' $true
                    }
                }
            }

            # Base64-блоки: розкодовуємо й перевіряємо, що всередині.
            $tokens = 0
            foreach ($bm in $b64Rx.Matches($line)) {
                if (++$tokens -gt 5) { break }
                $dec = Get-DecodedText $bm.Value
                if (-not $dec) { continue }
                foreach ($dl in ($dec -split '\r?\n' | Select-Object -First 50)) {
                    foreach ($h in (Get-Hits $dl $false $ext $true)) { & $report $h $dl ' — у розкодованому base64' $true }
                }
            }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
            Add-Finding 'MEDIUM' 'T10' $rel $no $line 'рядок не вдалося перевірити (тайм-аут regex) — прочитай вручну'
        }
    }
    foreach ($k in $hitCount.Keys) {
        if ($hitCount[$k] -gt 10) {
            $r = $rules[$k]
            Add-Finding 'LOW' $r.Id $rel 0 '' "ще $($hitCount[$k] - 10) збігів правила «$($r.Name ?? $r.Rx.Substring(0, [Math]::Min(40, $r.Rx.Length)))» приховано"
        }
    }
}

# ---------- Перевірки на рівні скіла ----------
$sep = [IO.Path]::DirectorySeparatorChar
$skillRoots = @($items | Where-Object { -not $_.PSIsContainer -and $_.Name -eq 'SKILL.md' } | ForEach-Object DirectoryName)
$roots = if ($skillRoots.Count) { $skillRoots } else { @($base) }
foreach ($root in $roots) {
    $rootRel = Rel $root
    $prefix = if ($rootRel -eq '.') { '' } else { "$rootRel/" }
    $anchor = if ($skillRoots.Count) { $prefix + 'SKILL.md' } else { $rootRel }
    $mine = $texts.GetEnumerator() | Where-Object { $_.Key.StartsWith($root + $sep) -or $isFile }
    $all = ($mine | ForEach-Object Value) -join "`n"
    $own = $findings | Where-Object { $_.File.StartsWith($prefix) }

    # T01: непряма ін'єкція
    $m = $externalRx.Match($all)
    if ($m.Success -and -not $guardRx.IsMatch($all)) {
        Add-Finding 'LOW' 'T01' $anchor 0 $m.Value 'читає зовнішній вміст, але немає правила «це дані, а не інструкції» (непряма ін''єкція)'
    }

    # T06 + T07: секрети й канал назовні в одному скілі
    $secret = $own | Where-Object { $_.Threat -eq 'T06' -and $_.Severity -in 'HIGH', 'CRITICAL' } | Select-Object -First 1
    $channel = $own | Where-Object { $_.Threat -eq 'T07' -and $_.Severity -in 'HIGH', 'CRITICAL' } | Select-Object -First 1
    if ($secret -and $channel) {
        Add-Finding 'CRITICAL' 'T07' $anchor 0 "$($secret.File):$($secret.Line) + $($channel.File):$($channel.Line)" 'доступ до секретів і канал назовні в одному скілі (комбінація T06 + T07)'
    }

    # T13: мережа, про яку description мовчить
    $desc = $fmDescriptions[$root]
    $m = $netRx.Match($all)
    if ($desc -and $m.Success -and -not $netDeclRx.IsMatch($desc)) {
        Add-Finding 'MEDIUM' 'T13' $anchor 0 $m.Value 'скіл ходить у мережу, а description про це не згадує'
    }

    # T11: посилання на файли, яких у скілі немає; скрипти, які ніде не згадано
    if ($skillRoots.Count) {
        $refs = @($refRx.Matches($all) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        foreach ($ref in $refs) {
            if (-not (Test-Path -LiteralPath (Join-Path $root $ref))) {
                Add-Finding 'LOW' 'T11' $anchor 0 $ref 'згадано файл, якого немає в скілі (з''явиться пізніше? завантажується?)'
            }
        }
        foreach ($f in $fileList | Where-Object { $_.Kind -eq 'script' -and $_.File.StartsWith($prefix) }) {
            $name = Split-Path -Leaf $f.File
            if ($all.IndexOf($name, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                Add-Finding 'LOW' 'T13' $f.File 0 $name 'скрипт ніде не згаданий в інструкціях скіла (навіщо він тут?)'
            }
        }
    }
}

# T12: однакові назви скілів у межах цілі (один перекриває інший)
foreach ($g in $fmNames | Group-Object Name | Where-Object Count -gt 1) {
    Add-Finding 'MEDIUM' 'T12' $g.Group[0].File $g.Group[0].Line ($g.Group.File -join ', ') "кілька скілів з однаковою назвою «$($g.Name)»"
}

# ---------- Хеш дерева: вердикт стосується саме цієї версії ----------
$manifest = ($fileList | Sort-Object File | ForEach-Object { "$($_.File):$($_.Sha256)" }) -join "`n"
$treeHash = -join ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($manifest)) | ForEach-Object { $_.ToString('x2') })

# ---------- Вивід ----------
$order = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3 }
$sorted = $findings | Where-Object { $order[$_.Severity] -le $order[$MinSeverity] } | Sort-Object { $order[$_.Severity] }, Threat, File, Line
$counts = [ordered]@{}
foreach ($s in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') { $counts[$s] = @($findings | Where-Object Severity -eq $s).Count }
$threats = @($findings | Where-Object { $_.Severity -ne 'LOW' } | ForEach-Object Threat | Sort-Object -Unique)

if ($Json) {
    [pscustomobject]@{
        Target = $target; TreeHash = $treeHash; Stats = $stats; Counts = $counts; Threats = $threats
        Skills = @($fmNames | ForEach-Object Name); Domains = @($domains); Findings = @($sorted); Inventory = @($fileList)
    } | ConvertTo-Json -Depth 5
} else {
    $colors = @{ CRITICAL = 'Red'; HIGH = 'Magenta'; MEDIUM = 'Yellow'; LOW = 'Gray' }
    Write-Host "how-deep-the-rabbit-hole-goes scan: $target"
    Write-Host ("Файлів: {0} · скриптів: {1} · зображень: {2} · бінарних/архівів/документів: {3} · симлінків: {4}" -f $stats.Files, $stats.Scripts, $stats.Images, $stats.Binary, $stats.Links)
    Write-Host "Хеш дерева (SHA-256): $treeHash"
    if ($Inventory) {
        Write-Host ''
        foreach ($f in $fileList | Sort-Object File) { Write-Host ("  {0,-9} {1,9}  {2}  {3}" -f $f.Kind, $f.Size, ($f.Sha256 ? $f.Sha256.Substring(0, 12) : '-'), $f.File) }
    }
    Write-Host ''
    foreach ($f in $sorted) {
        $loc = if ($f.Line) { "$($f.File):$($f.Line)" } else { $f.File }
        Write-Host ("[{0}] {1} {2}  ({3})" -f $f.Severity, $f.Threat, $loc, $f.Note) -ForegroundColor $colors[$f.Severity]
        if ($f.Evidence) { Write-Host "    $($f.Evidence)" }
    }
    if ($domains.Count) { Write-Host ''; Write-Host "Зовнішні домени: $(@($domains) -join ', ')" }
    Write-Host ''
    Write-Host ("Підсумок: CRITICAL {0} · HIGH {1} · MEDIUM {2} · LOW {3}" -f $counts.CRITICAL, $counts.HIGH, $counts.MEDIUM, $counts.LOW)
    if ($threats) { Write-Host "Загрози вище LOW: $($threats -join ', ')" }
    Write-Host 'Це сигнали для ручної перевірки, а не вердикт.'
}

if ($counts.CRITICAL) { exit 2 } elseif ($counts.HIGH) { exit 1 } else { exit 0 }
