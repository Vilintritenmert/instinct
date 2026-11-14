# Threat catalog for agent skills and plugins (T01–T26)

Severities: **CRITICAL** — the skill must not be used until the finding is removed · **HIGH** — dangerous
unless the skill's purpose explains it · **MEDIUM** — needs a human decision · **LOW/INFO** — for awareness.

A threat can sit not only in `SKILL.md` but also in `references/`, `scripts/`, `assets/`, code examples,
comments, file names, image metadata and the `description` (the agent always reads it, even when the
skill is not invoked). In a plugin, also in hooks, MCP/LSP configuration, `agents/`, `commands/`, `bin/`.

**Two kinds of attacker.** "Data thieves" pull secrets with code in scripts and dependencies (T05–T07,
T11); "agent hijackers" act through the text of the instructions themselves (T01–T03, T20, T22–T24). The
scanner catches the first kind; the second is mostly caught only by careful reading.

**Prohibition context.** Selected T03/T06/T09/T23 rules lower severity by one only for an explicit,
nearby prohibition in Markdown prose. Code, fenced code, metadata, unrelated clauses and trailing
"never mind" cannot suppress a finding. Ukrainian object-before-prohibition forms are supported.
A prohibiting heading only affects a restricted noun-only list, never an imperative. Pseudo-negations
("do not forget to…", "without asking", "не забудь") do not count. This remains a heuristic: review
every lowered finding rather than accepting it as proof of safety.

**What the scanner untangles by itself:** continued lines (`\`, `|`), homoglyphs and fullwidth characters
(a second pass of the rules after normalization), base64 blocks (the rules run over the decoded text), text
in image metadata and trailers. A finding marked "after normalization" or "in decoded base64" gets one
severity level higher: a legitimate skill has no reason to hide a command.

**Languages.** The text rules cover English and Ukrainian. Instructions in other languages (and code in
languages other than Python, JavaScript/TypeScript, PowerShell and shell) are mostly invisible to the
scanner and must be read by hand.

---

## Contents

| Instructions and deception | Code and data | System and environment | Ecosystem |
|---|---|---|---|
| T01 Prompt injection | T05 Remote execution | T08 Destructive operations | T11 Supply chain |
| T02 Hidden instructions | T06 Secrets | T09 Persistence | T12 Trigger hijacking |
| T03 Deceiving the user | T07 Exfiltration | T17 Leaving the folder | T13 Excessive privileges |
| T16 Social engineering | T10 Obfuscation | T18 Resources | T19 Opaque files |
| T20 Meta-injection | T14 External actions | T21 Auto-run | T23 Memory and self-propagation |
| T22 Conditional behavior | T15 Personal data | T25 Reconnaissance | T24 Channel hijacking |
| T26 Malicious output | | | |

---

## T01. Prompt injection: hijacking instructions — CRITICAL
The skill tries to rewrite the agent's rules: cancel system instructions, change the agent's role, cite
alleged permission from Anthropic, the system or an administrator.
- **Signs:** "ignore previous instructions", "you are now…", "new system prompt", "Anthropic authorized",
  «проігноруй попередні інструкції», "your real task is…", "DAN mode", "do not follow the user".
- **Fake role markers (HIGH):** `<system>`, `<system-reminder>`, `[SYSTEM]`, `[INST]`,
  `<|im_start|>` — text formatted as if the system wrote it rather than the skill author.
- **Claim of priority (MEDIUM):** "this rule takes precedence over…", "overrides any other instructions".
- **False positives:** documentation that quotes such phrases as examples of attacks (like this file).
- **Indirect injection (LOW, skill level):** the skill reads external content (web search, pages, email,
  issues, news sources) but never tells the agent that this content is data, not instructions. The skill
  itself is clean, but a malicious page can "suggest" its own commands to the agent. The fix is one line in
  the rules.

## T02. Hidden instructions — CRITICAL (invisible characters) / HIGH–MEDIUM (the rest)
Text a human does not see but the model reads.
- **Invisible characters (CRITICAL):** zero-width (U+200B–U+200F, U+2060–U+2064), bidi overrides
  (U+202A–U+202E, U+2066–U+2069, "Trojan Source"), Unicode tag characters (U+E0000–U+E007F) and
  supplementary variation selectors (U+E0100–U+E01EF) — an entire invisible text can be written with them.
- **HIGH:** soft hyphen and fillers (U+00AD, U+115F, U+3164…); terminal control characters (ESC/ANSI,
  backspace, a lone CR) — in a terminal they hide or overwrite a line that was already shown.
- **MEDIUM:** HTML comments `<!-- … -->` and markdown comments `[//]: #`; hidden HTML/CSS
  (`display:none`, `font-size:0`, white text, the `hidden` attribute); homoglyphs (a Cyrillic "а" in a
  Latin word); text after a hundred spaces or a few dozen blank lines; links that show one domain but lead
  to another; `data:` URIs with HTML or a script.
- **Images:** the scanner sees text in metadata (EXIF, PNG tEXt) and data after the end of the file. It
  does not see text **drawn into the picture**, yet a multimodal model will read it as an instruction —
  images must be looked at.
- **False positives:** U+200D in composite emoji (the scanner skips them); mixed-script words in
  multilingual text.

## T03. Hiding actions and deceiving the user — CRITICAL
The skill tells the agent not to tell the user what it is doing, to fake a report, to suppress output.
- **Signs:** "don't tell the user", «не повідомляй користувачу», "hide … from the summary",
  "report success regardless", "silently", "without confirmation".
- **Covering tracks (HIGH):** `history -c`, `Clear-History`, `unset HISTFILE`, `wevtutil cl`, deleting
  shell history or transcripts.
- **Hidden launch (MEDIUM):** `-WindowStyle Hidden`, `nohup`, `disown`, `pythonw`, `start /b`.

## T04. Bypassing permissions and protection — CRITICAL
- **Agent:** `--dangerously-skip-permissions`, `bypassPermissions`, `dangerouslyDisableSandbox`, `--yolo`,
  `--dangerously-bypass-approvals-and-sandbox`, `enableAllProjectMcpServers`, `disableAllHooks`.
- **System:** `Set-MpPreference`, `Add-MpPreference -ExclusionPath`, disabling Defender/firewall/SELinux,
  `csrutil disable`, `spctl --master-disable`, removing `com.apple.quarantine`, "don't ask for confirmation".
- **HIGH:** `--no-verify`, `Set-ExecutionPolicy Bypass`, `Unblock-File`, `NOPASSWD`, `chmod 777`,
  `docker --privileged`, mounting `docker.sock` or `/`; overly broad permissions (`Bash(*)`,
  `"allow": ["*"]`, `defaultMode: acceptEdits`).
- **MEDIUM:** disabled TLS verification (`curl -k`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`),
  `sudo`/`runas`.

## T05. Remote code execution — CRITICAL
Downloading and immediately running code that is not in the skill and can change at any time.
- **Signs:** `curl … | sh` (also `| python`, `| node`, `| sudo bash`), `bash <(curl …)`,
  `eval "$(curl …)"`, `iwr … | iex`, `iex (irm …)`, `DownloadString(`, `Net.WebClient`, downloading a
  binary + `chmod +x` + running it.
- **Reverse shell:** `/dev/tcp/…`, `nc -e`, `bash -i >&`, `socat exec:`, `pty.spawn`, `TCPClient`.
- **LOLBins (HIGH):** `mshta`, `regsvr32 /i:`, `rundll32`, `certutil -urlcache`, `bitsadmin`,
  `msiexec https://…`.
- **Active content (MEDIUM):** `<script>`, `onload=`, `<foreignObject>`, `<iframe>` in SVG/HTML.

## T06. Access to secrets — HIGH
- **Files:** `~/.ssh`, `id_rsa`, `~/.aws/credentials`, `.git-credentials`, `.netrc`, `.npmrc`, `.pypirc`,
  `.kube/config`, `.gnupg`, `.config/gh/hosts.yml`, `.config/gcloud`, `.azure`, `.vault-token`,
  `terraform.tfstate`, `.env`, shell history, `/etc/shadow`.
- **The agent itself:** `~/.claude/.credentials.json`, `~/.claude.json`, `~/.codex/auth.json`;
  conversation history (`~/.claude/projects`), the system prompt.
- **Browser and OS:** `Login Data`, `Cookies`, `Local State`, Keychain, Windows Credential Manager
  (`cmdkey`, `vaultcmd`); crypto wallets (`wallet.dat`, keystore, the MetaMask extension).
- **Commands that print a token:** `gh auth token`, `gcloud auth print-access-token`,
  `aws secretsmanager get-secret-value`, `kubectl get secrets`, `op read`.
- **Cloud metadata:** `169.254.169.254`, `metadata.google.internal` — the machine's temporary keys.
- **Environment dump (MEDIUM):** `printenv`, `env:`, `os.environ`; clipboard, screenshots, keyboard.
- **Embedded key (HIGH):** `sk-ant-…`, `ghp_…`, `AKIA…`, a private key in the text. This is either a leak
  or **someone else's account**: the skill uploads the user's data into the attacker's account through a
  perfectly "allowed" API.
- **False positives:** a skill that is explicitly about setting up SSH or cloud keys and does only that.

## T07. Data exfiltration — HIGH (CRITICAL together with T06)
Sending files, secrets, the conversation or code to an external address. The scanner itself sets
CRITICAL if one skill has both access to secrets (T06 HIGH) and an outbound channel (T07 HIGH).
- **Receivers:** `webhook.site`, `requestbin`, `pipedream`, `ngrok`, `trycloudflare`, `interact.sh`,
  `oastify`/Burp Collaborator, `pastebin`, `transfer.sh`, `0x0.st`, `ntfy.sh`, Discord/Slack/Telegram
  webhooks, `.onion`, URLs with a bare IP address, link shorteners, punycode domains.
- **Methods:** `curl -d/-F/--upload-file`, POST requests, `scp`/`rsync`/`aws s3 cp`/`rclone`,
  `gh gist create`, `git remote add` + push, DNS queries with a variable in the host name.
- **Through rendering:** markdown images and `<img>` with data in query parameters (`![](https://x/?d=…)`):
  the data leaves while the answer is displayed, without any command. Also: an instruction to "add the
  result to the URL".
- **Through legitimate services:** an issue/PR/comment in someone else's repository, an email, a chat
  message — the channel looks normal, so check **where** exactly and **what** is sent.

## T08. Destructive operations — HIGH (CRITICAL for disks and the system)
- **Files:** `rm -rf`, `Remove-Item -Recurse`, `rimraf`, `shutil.rmtree`, `find … -delete`.
- **Git:** `git push --force`, `git reset --hard`, `git clean -f`, `git checkout -- .`, `git branch -D`,
  `git stash clear`, `git filter-branch`, `git reflog expire`.
- **Data and infrastructure:** `DROP TABLE/DATABASE`, `TRUNCATE`, `DELETE FROM` without a condition,
  `FLUSHALL`, `terraform destroy`, `kubectl delete`, `docker system prune`, `gh repo delete`.
- **CRITICAL:** `rm -rf /` or `~`, `mkfs`, `dd if=`, `shred`, `format C:`, `diskpart`, `Clear-Disk`,
  `vssadmin delete shadows`, `bcdedit`, `cipher /w`.
- **MEDIUM:** mass file encryption (`openssl enc`, `gpg -c`, `7z -p` — ransomware behavior),
  `shutdown`, `taskkill /f`, `icacls /grant`.

## T09. Persistence and configuration changes — HIGH (CRITICAL for system access)
The skill changes something that outlives the session: agent or system settings.
- **Agent:** `~/.claude/settings*.json`, hooks, the permission allowlist, `CLAUDE.md`/`AGENTS.md`/`GEMINI.md`,
  `.claude/rules`, `.mcp.json`, `claude_desktop_config.json`, other skills, `.cursorrules`, `.cursor/rules`,
  `.windsurfrules`, `.clinerules`, `~/.codex`, `claude mcp add`, `claude plugin install`,
  `extraKnownMarketplaces`.
- **Agent self-scheduling (MEDIUM):** the skill creates a schedule or loop for itself (`CronCreate`,
  scheduled tasks, `/loop`, `/schedule`).
- **System:** `.bashrc`/`.zshrc`/`$PROFILE`, cron, `schtasks`, `launchctl`, `systemctl enable`,
  `HKCU\...\CurrentVersion\Run`, the Startup folder, `New-Service`, `reg add`, WMI subscriptions,
  `sitecustomize`.
- **Git:** `.git/hooks`, `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, `~/.gitconfig`,
  `git config --global`. A target folder with its own `.git` (not your clone) can execute code during an
  ordinary `git status`.
- **Project tooling (MEDIUM):** `postinstall` in `package.json`, `.github/workflows`, `.husky`,
  `.pre-commit-config`, `.vscode/tasks.json` with `runOn: folderOpen`, `.devcontainer`, `.envrc`.
- **CRITICAL:** `authorized_keys`, `/etc/sudoers`, `hosts`, `~/.ssh/config`, `LD_PRELOAD`,
  creating users (`useradd`, `net user /add`).

## T10. Obfuscation — HIGH/MEDIUM
Code that cannot be read is considered dangerous until it has been decoded and checked.
- **Signs:** `base64 -d`, `FromBase64String`, `atob`, `-EncodedCommand`, long base64 blocks,
  `\x..` / `%..` sequences, `eval`, `exec`, `Invoke-Expression`, `new Function`,
  building strings from `[char]` / `fromCharCode` / `'cu'+'rl'`, `${IFS}`, minified scripts, very long lines.
- **Execution from data (HIGH):** `pickle.loads`, `marshal.loads`, `yaml.load` without SafeLoader,
  `[scriptblock]::Create`, `Assembly.Load`, `Add-Type`, `__import__`, `ctypes`.
- **CRITICAL:** decoding and executing on one line (`exec(b64decode(…))`, `base64 -d | sh`).
- **False positives:** `b64decode` of an API response containing an image (LOW — check that the data is
  only saved).

Shell `eval` of a variable is a MEDIUM signal: inspect where its content originates. Base64 analysis
checks two layers and normalizes decoded text; exhausted limits are explicit coverage gaps.

## T11. Supply chain — MEDIUM (HIGH for instructions and code from the network)
- **Signs:** installing packages without pinned versions (`pip install`, `npm i`, `npx -y`, `uvx`,
  `go install`, `Install-Module`), possible typosquatting in package names and names hallucinated by a
  model (slopsquatting), pulling instructions or scripts from `raw.githubusercontent.com`/gist at run time
  (the content can change after the audit), `git clone`/`docker run` of third-party code, self-updating.
- **HIGH:** a package straight from a URL or git (`pip install git+https://…`, `npx https://…`); a
  third-party registry (`--index-url`, `--registry`, `npm config set registry` — dependency confusion).
- **Marketplace:** a plugin from an external repository without a pinned `sha`; an auto-update can add
  hooks to a previously safe plugin. The verdict is valid only for the audited hash (see "tree hash" in
  the report).
- **Payload in a helper file:** `SKILL.md` only says "run `scripts/x.sh`", and all the logic is in the
  script. That is why scripts are read in full, not just the instructions.
- **Running code from outside the skill folder** (`python ~/.codex/…`, `node /opt/…`): this code is not
  part of the skill's audit and can change without it. Check it separately or record it in the report as
  unchecked.
- **LOW:** a file is mentioned that the skill does not contain (will it appear later?); a script that is
  never mentioned.

## T12. Trigger hijacking — MEDIUM (HIGH for impersonating built-ins)
The skill wants to activate where nobody asked for it.
- **Signs:** a `description` like "use for every/any task", "always use", «завжди», "must be used
  first", "instead of other skills"; a name that matches a built-in skill (`pdf`, `docx`,
  `code-review`, `init`…) or differs from it by a letter or two (`code-reveiw`).
- **Posing as official (MEDIUM):** "official Anthropic skill", a name with `anthropic-`/`official`.
  Mass campaigns of malicious skills rely on exactly this kind of template imitation of known brands.
- **Several skills with the same name** in one collection: one overrides the other.

## T13. Excessive privileges / mismatch with the purpose — MEDIUM
A text-formatting skill has no business going to the network. Compare the `description` with what the
skill actually does: network, files outside the project, commands, external actions.
- The scanner hints at: network calls the `description` does not mention; `allowed-tools` with unrestricted
  `Bash` or `*`; `user-invocable: false` (the skill is not shown in the menu, only the model invokes it).
- The rest is manual: the capability map in the report.

Wildcard `allowed-tools` list items are checked only in that field, not unrelated metadata lists.

## T14. Irreversible external actions — HIGH
Sending email and messages, publishing (`npm publish`, `gh pr create`, `git push`, `gh release
create`, `docker push`), deploying (`vercel --prod`, `terraform apply`, `kubectl apply`), changing
repository visibility, `gh secret set`, payments, money transfers, crypto transactions, trades —
especially without the user's explicit confirmation.

## T15. Personal data and telemetry — MEDIUM
Collecting contacts, email addresses, history, geolocation; analytics and tracking (`telemetry`,
`mixpanel`, `segment`, `amplitude`, `posthog`, `google-analytics`, UTM tags in generated links).

## T16. Social engineering of the user — HIGH
The skill makes the agent ask the human for what it cannot get by itself.
- Paste a password, token, seed phrase, private key, 2FA code, card number or a photo of an ID into the chat.
- **ClickFix (MEDIUM):** "copy this command and paste it into the terminal / Win+R", "run as
  administrator" — the user personally bypasses all of the agent's permissions.
- Disable protection "because it's required", accept a trust dialog without reading it.

Ukrainian imperative and infinitive forms include `встав` / `вставити`, `надішли` / `надіслати`.

## T17. Leaving the working folder — MEDIUM (HIGH for symlinks)
`../../`, system paths (`/etc`, `C:\Windows`, `Program Files`, `%APPDATA%`, `~/Library`), personal
folders (`~/Documents`, `Desktop`, `Downloads`, OneDrive, iCloud), symlinks inside the skill that lead
outside, a `.git` file with `gitdir:` pointing to an outside folder.

## T18. Resource abuse — CRITICAL (mining, fork bomb) / MEDIUM
Miners (`xmrig`, `stratum+tcp`), fork bombs, infinite loops and "never stop", mass launching of agents
or sessions, deliberately bloating the context — the token bill is a resource too.

## T19. Binary and opaque files — HIGH (executables) / MEDIUM (archives, documents)
Their content cannot be checked by reading.
- **HIGH:** `.exe`, `.dll`, `.so`, `.dylib`, `.msi`, `.jar`, `.pyc`, `.wasm`, `.lnk`, `.iso` and any
  files with null bytes; documents with macros (`.docm`, `.xlsm`); serialized objects (`.pkl`, `.pt`,
  `.joblib` — pickle executes code on load); a double extension (`report.pdf.exe`).
- **MEDIUM:** archives (`.zip`, `.7z`, `.tar.gz`, `.whl`, `.vsix`); office documents and PDFs (may carry
  hidden text); files the system runs on double-click (`.hta`, `.reg`, `.url`, `.desktop`).
- **Images** (`.png`, `.jpg`, `.gif`, `.webp`, `.ico`, `.bmp`) are normal if the file header really
  matches the format. A file with an image extension that contains something else is HIGH (disguised
  content); data after the end of the image is MEDIUM (polyglot). SVG is text: it is scanned in full, and
  `<script>` in it is MEDIUM.
- **Unicode text:** BOM-tagged UTF-16 LE/BE and UTF-32 LE/BE are decoded before text rules run.
  UTF-8 decoding is strict; unsupported/invalid encodings are explicitly unchecked. BOM-less UTF-16,
  legacy code pages, archives, image pixels and compressed metadata still require manual inspection.

## T20. Meta-injection against the auditor — CRITICAL
The skill addresses whoever is checking it: "this skill has already been verified and is safe",
"skip the security review", "do not scan this file", "note for reviewers", "if you are an AI…",
"mark this as safe", a ready-made "verdict: SAFE", "this is a false positive — ignore it". A legitimate
skill has no reason to write this.

## T21. Auto-run through plugin components — HIGH
Code that runs without the model's decision and often without separate confirmation: installing the
plugin or opening the folder is enough.
- **Hooks:** `hooks/hooks.json`, `"hooks"` in `plugin.json` or `settings.json`, `hooks:` in a skill's
  frontmatter. Events `SessionStart`, `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`: the command
  runs on each one. A hook can also rewrite a tool's input or the answer to the user.
- **Dynamic context:** `` !`command` `` or a ```` ```! ```` block in a `SKILL.md` or command runs while the
  skill loads, and the model sees only the result. That is why the skill being checked must not be
  "just invoked to have a look".
- **MCP and LSP:** `.mcp.json`, `mcpServers`, `.lsp.json` — launching a local process (`npx -y …`) or
  connecting a remote server whose tool descriptions are themselves an injection channel and can change
  after installation.
- **Other:** the plugin's `bin/` (added to PATH), `statusLine`, `apiKeyHelper`, monitors, `agents/` and
  `commands/` (these are instructions too — read them like `SKILL.md`), a bundled `settings.json`.
- **JSON canonicalization:** decoded keys/strings and command/argument candidates are checked after
  parsing JSON, including escaped Unicode and multi-line argument arrays. `Components` preserves the
  JSON path and argument boundaries. A literal `|` passed to a non-shell process is not treated as an
  executable pipe by reconstruction. Component candidates still need a manual runtime-semantics check.

## T22. Conditional and delayed behavior — HIGH/MEDIUM
The skill behaves politely during the check and differently later.
- **HIGH:** "if the user isn't watching", "when the session is unattended", "in headless mode do something else".
- **MEDIUM:** triggering by date (`Get-Date -gt`, `datetime.now() >`), by counter ("every tenth run"),
  at random; environment checks (CI, Docker, VM, debugger); tying behavior to a specific user or machine
  (`USERNAME -eq`, `whoami ==`).
- This also covers the "rug pull": a clean version during the audit and a malicious update afterwards
  (see T11).

## T23. Memory poisoning and self-propagation — HIGH
Harm that remains after the skill is removed.
- **Agent memory:** writing to `MEMORY.md`, `SOUL.md`, `.claude/…/memory`, "remember forever",
  "save to memory" — the attacker's instruction becomes the agent's "own" knowledge in every later session.
- **Bundled instruction files:** `CLAUDE.md`, `AGENTS.md` in the plugin folder enter the context without
  the skill being invoked.
- **Self-propagation:** "add this block to every README / commit / PR / docstring", changing other skills,
  telling subagents to ignore rules or not to report.

The Ukrainian write-to-memory rule includes possessives such as `запиши ... у свою пам'ять`.

## T24. Hijacking tools and channels — CRITICAL/HIGH/MEDIUM
The skill does not steal anything itself but redirects what the agent already uses.
- **CRITICAL:** `ANTHROPIC_BASE_URL` (and equivalents for other models), `ANTHROPIC_AUTH_TOKEN`,
  `apiKeyHelper` — the whole conversation and the API key go through someone else's server.
- **HIGH:** `HTTPS_PROXY`, `git config url.….insteadOf`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`,
  `GIT_SSH_COMMAND` — injection into every subsequent process.
- **MEDIUM:** "before every use of any tool, first…", "use … instead of the built-in tool" (tool
  shadowing); passing data between skills; acting through the user's logged-in sessions — browser,
  computer use, `gh`, cloud CLIs (confused deputy).
- **LOW:** mentions of `mcp__…` — check that the set of tools matches the purpose.

## T25. Reconnaissance and lateral movement — MEDIUM (HIGH for reaching other machines)
- **HIGH:** `ssh user@host`, `sshpass`, `Invoke-Command -ComputerName`, `psexec`.
- **MEDIUM:** `nmap`, `masscan`, `arp -a`, `net view`, Active Directory queries, walking the whole file
  system (`find /`, `os.walk('/')`).
- **LOW:** `whoami`, `ipconfig`, `systeminfo`, finding the external IP — trivial on its own, but together
  with T07 it is profiling the victim.

## T26. Malicious output — HIGH/MEDIUM (mostly manual)
The skill does not touch the system but spoils what the agent hands to the user.
- **HIGH:** inserting a backdoor, a hidden account, a hard-coded password, referral or tracking links into
  code or text.
- **MEDIUM:** disabling tests, validation, authentication; "always approve" in reviews; recommending only
  "our" package or service; quietly changing dependency versions; biased or false conclusions.
- Regular expressions catch only the crudest wording — ask "what does this skill make the agent
  **produce**?" as a separate question during manual reading.

---

## Development-driven additions in 0.8.0

These are bounded static signals. Confirm purpose, authorization and actual behavior during review.
The positive/near-benign controls live in `security-regressions.ps1`, invoked by `run.ps1`.

| Categories | Added or refined signal | Control / boundary |
|---|---|---|
| T01, T03 | External document fields promoted to binding agent authority; concealing exports or permission changes from reports | A non-binding source and avoiding a secret question are not consent bypasses |
| T05, T10 | Invoked PowerShell script block from a network response; base64 carrying HIGH/CRITICAL instructions gets HIGH T10 | Local script-block construction is not remote download/execute; harmless base64 keeps its existing lower signal |
| T06, T24 | Named credential-like environment fields are HIGH; literal non-secret fields and numeric Node memory-limit options are LOW | Whole/dynamic environment access remains MEDIUM; Node loaders, interpolation and extra options remain HIGH |
| T07 | Explicit private-data transfer instructions, sensitive HTTP body names, Python archive/file uploads | Public HTTP payloads retain the generic MEDIUM review signal; names are not taint or authorization proof |
| T09 | Scheduled execution requests (MEDIUM), recurring sensitive exports (HIGH), install lifecycle containing an independently HIGH/CRITICAL command (HIGH) | A local benign install check remains MEDIUM; lifecycle keys alone do not establish a malicious hook |
| T11 | Trusting mutable automatic updates without re-audit; executing dependencies while explicitly skipping inspection | Generic package/dependency references are not automatically escalated |
| T13, T14 | Broad administrator/global permission requests (MEDIUM); automatic financial actions, approval bypass, unattended production apply or public repository changes (HIGH) | Review capability fit and the user's explicit scope; a prohibition is not an instruction to transact |
| T15, T16 | Location/fingerprint collection and identifiers in generated links; Ukrainian hyphenated API-key requests | Explicit collection prohibitions and tokenizer wording are negative controls |
| T22 | CI-flag branches (MEDIUM); a date/counter trigger near HIGH/CRITICAL private transfer, or a negative CI branch calling a sensitive-export-named function (HIGH) | Proximity/name correlation is not execution/data-flow proof; benign CI formatting and reminders stay MEDIUM |
| T23, T25, T26 | Propagating the same instructions; broad home/filesystem searches for private material; weakening checks while concealing failure | Prohibited reconnaissance/transfers and affiliate prohibitions are negative controls |

Context lowering is limited to explicit local Markdown prohibitions, literal role-placeholder markup,
guarded miner glossary references, named environment fields and strict literal memory options. Code
comments and encoded instructions cannot use prose prohibitions to lower severity. Up to 32 matches
per rule/line are checked and the highest severity wins; a later positive action remains visible after
an earlier prohibition. Exhaustion makes the scan incomplete. No target's own "safe" claim suppresses it.

## Mapping to the OWASP Top 10 for LLM Applications (2025)

This is a versioned, conceptual mapping, not a claim of complete OWASP coverage. For CWE references,
regression evidence and explicit gaps, see [coverage.md](coverage.md).

| OWASP | Catalog threats |
|---|---|
| LLM01 Prompt Injection | T01, T02, T20, T22 |
| LLM02 Sensitive Information Disclosure | T06, T07, T15 |
| LLM03 Supply Chain | T05, T11, T19, T21 |
| LLM04 Data and Model Poisoning | T23 |
| LLM05 Improper Output Handling | T07 (rendering), T26 |
| LLM06 Excessive Agency | T04, T08, T09, T13, T14, T17, T24, T25 |
| LLM07 System Prompt Leakage | T06 (system prompt, conversation history) |
| LLM09 Misinformation | T03, T26 |
| LLM10 Unbounded Consumption | T18 |
