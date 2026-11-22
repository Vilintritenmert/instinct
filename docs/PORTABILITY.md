# Agent and operating-system portability

instinct has one audit skill, a `security-check` command shortcut that loads it, one scanner
implementation and a `read-the-lips` request rewriter. Its instructions describe capabilities
(read files, search text, run a command) rather than one agent's tool API. The same skill folder is
used for Codex, Claude Code and other agents; host packaging and discovery paths are separate.

## What is portable

| Layer | Shared implementation | Requirements and boundaries |
|---|---|---|
| Audit instructions | `skills/how-deep-the-rabbit-hole-goes/SKILL.md` and `references/` | An agent that can read the target and follow the instructions; native skill discovery is optional |
| Command shortcut | `skills/security-check/SKILL.md` | Loads the audit skill from its sibling folder; the command form depends on the host (see [Run the audit as a command](#run-the-audit-as-a-command)) |
| Request rewriter | `skills/read-the-lips/SKILL.md` and `references/` | An agent that can follow the instructions; reading files is optional and only grounds names in the open project. No scripts or shell |
| Static scanner | `scripts/scan.ps1` inside the skill | PowerShell 7+ and permission to run a local command; no agent SDK or API key |
| Unix launcher | `scripts/scan.sh` inside the skill | POSIX `sh`; locates PowerShell and translates options without duplicating detection logic |
| Skill installer | Repository `scripts/install.py` | Python 3.10+, standard library only; copies the complete skill on Windows, macOS and Linux |
| Plugin package | Root `plugin.json` and fixed `skills/` layout | An [Agent Plugins 1.0](https://agent-plugins.org/) compatible client and its installation flow |
| Compatibility packaging | `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` | Clients that use those manifests; these describe the shared skill without duplicating it |

The plugin does not bundle hooks, an MCP server or a background service. Installing a skill copy
does not install an agent, register a marketplace, change an agent's permissions or install PowerShell.
The package format does not standardize every client's installation UI or invocation syntax.

## Install a complete skill

Run the following from a trusted checkout of this repository. Replace `python` with `py -3` on
Windows or `python3` on macOS/Linux if needed. Examples use ordinary quoted paths and work with
PowerShell, cmd, bash and zsh once the Python executable is selected.

```text
python scripts/install.py --agent codex --project-root "../my-project" --dry-run
python scripts/install.py --agent codex --project-root "../my-project"
python scripts/install.py --agent claude --scope user
```

Project scope is the default. Without `--project-root`, its root is the current working directory.
Use an absolute path to the installer when running it from another directory. User scope uses your
home directory and makes the skill available across local projects.

Use `--list` to list source skills without a destination, or `--skill <name>` to install a single
named skill. By default the installer includes every skill under the repository's `skills/` folder;
currently `how-deep-the-rabbit-hole-goes`, `read-the-lips` and `security-check`. `--skill security-check` also installs
`how-deep-the-rabbit-hole-goes`, which the shortcut loads from the sibling folder. `--scope` applies
only with `--agent`, and `--project-root` applies only to an agent's project scope.

| Preset | Project skill parent | User skill parent | Official reference |
|---|---|---|---|
| `codex` | `<project>/.agents/skills` | `~/.agents/skills` | [Codex local skills](https://developers.openai.com/codex/skills) |
| `claude` | `<project>/.claude/skills` | `~/.claude/skills` | [Claude Code skill locations](https://code.claude.com/docs/en/skills#choose-where-skills-load) |

`~` in this table means the home directory on the current OS, including the Windows user profile.
These are local discovery locations; a hosted/cloud agent cannot access your machine's installed
copy unless its own environment provides it. Reload skills or start a new session if the installed
skill does not appear. Avoid installing both a marketplace plugin and an ordinary copy of the same
skill unless you intend to manage both.

### Run the audit as a command

`security-check` runs the same audit when invoked by name with a target. It adds no checks of its own:
it reads `../how-deep-the-rabbit-hole-goes/SKILL.md` next to its own folder and follows it.

| Installation | Command |
|---|---|
| Claude Code, copied with `--agent claude` | `/security-check ../candidate-skill` |
| Claude Code plugin | `/instinct:security-check ../candidate-skill` (plugin skills are namespaced) |
| Codex, copied with `--agent codex` | Mention the skill: `$security-check ../candidate-skill` |
| Another agent | Its own syntax for invoking a skill by name, or ask for the audit in plain words |

The shortcut sets `disable-model-invocation: true`, so Claude Code offers it only as a command and
leaves plain-language requests to `how-deep-the-rabbit-hole-goes`. Hosts that ignore that field may
also choose the shortcut on their own; it leads to the same audit.

### Improve a request

`read-the-lips` is invoked the same way, with the request after the command: `/read-the-lips <request>`
for a copied Claude Code install, `/instinct:read-the-lips` from the plugin, `$read-the-lips` in Codex.
Agents may also choose it on their own when asked to improve or rewrite a prompt. It is self-contained:
it loads no other skill, has no scripts and needs no shell.

### Other agents and custom layouts

Choose the skill parent documented by the agent, then pass it explicitly:

```text
python scripts/install.py --destination "../other-agent-skills"
```

The helper creates `how-deep-the-rabbit-hole-goes`, `security-check` and `read-the-lips` beneath that
parent and includes their scripts and references. `--destination` is an alternative to `--agent`, not a path to `SKILL.md` itself. It also
supports legacy installations, including a Codex configuration that still uses `.codex/skills`.
Check the paths used by your installed host rather than assuming one preset covers every release.

Manual installation is equivalent: copy the whole
`skills/how-deep-the-rabbit-hole-goes` folder into the host's skill parent. Copying only `SKILL.md`
loses the scanner, threat catalog and coverage contract. For the command shortcut, also copy
`skills/security-check` into the same parent. The request rewriter is the whole `skills/read-the-lips`
folder, with its `references/`.

For an agent without native skill discovery, ask it to read the trusted `SKILL.md` directly and use
its own tools to follow the instructions. It must resolve supporting files relative to that loaded
file, and resolve the audit target against the user's working directory. An agent without file
access cannot audit a local tree. Without shell access or PowerShell, it can review available text
manually and must disclose that the automated scan did not run and identify any unchecked content.

## Update and remove

Update the trusted checkout, review your installed local edits if any, then repeat the original
installation command with `--update`:

```text
python scripts/install.py --agent codex --project-root "../my-project" --update
python scripts/install.py --destination "../other-agent-skills" --update
```

Without `--update`, an existing skill folder is not replaced. Updating replaces that skill's copy,
so preserve local customizations elsewhere first. The checkout and installed copy are independent:
`git pull` alone does not update a copied skill. To remove the copied skills, remove only their
`how-deep-the-rabbit-hole-goes`, `security-check` and `read-the-lips` directories from the selected
skill parent.

For Claude Code marketplace installs, continue using the Claude plugin update/uninstall commands
in the [README](../README.md#claude-code-plugin). The portable installer does not manage plugin
caches or marketplaces.

## Run on each OS

PowerShell 7 is the shared scanner runtime. Windows PowerShell 5.1 (`powershell.exe`) does not replace
it. From any supported shell, point to the scanner in the actual installed skill:

```text
pwsh -NoProfile -File "<installed-skill>/scripts/scan.ps1" -Path "<target>" -Json
```

On macOS/Linux the POSIX wrapper is also available:

```text
sh "<installed-skill>/scripts/scan.sh" --json "<target>"
```

These commands read the target as data. Never install or invoke an untrusted target merely to
inspect it. Scanner output and exit codes are signals for manual review; check `ScanComplete` and
`CoverageIssues` before interpreting the result. See the [scanner guide](SCANNER.md) for the full
contract and the skill's [coverage contract](../skills/how-deep-the-rabbit-hole-goes/references/coverage.md)
for limits.

The scanner hashes exact bytes. For a repository under audit, use
`git -c core.autocrlf=false clone --depth 1 <url> <new-empty-folder>` to avoid OS-dependent newline
conversion; acquiring an untrusted target still follows the skill's authorization rules. Link
representation and filesystem capabilities can differ across OSes and must be reported.

## Verification status

For 0.13.0, the full scanner regression suite passes on Windows 11 with PowerShell 7.6.9:
115/115 positive probes, 0/67 false positives and 17/17 robustness probes. Windows link probes skip
when privileges are unavailable, and Unix-only scanner probes skip there.

The 18 portability checks pass on Windows (two link privilege skips) and on an isolated Ubuntu 24.04
checkout with Python 3.12.3 and PowerShell 7.7.0 (no skips). They cover both agent presets, project and
user scopes, exact-byte copies, updates and recovery, Unicode paths, links and an installed scanner
running from another working directory. Windows and Linux scanner reports match after removing only
the absolute target path. Earlier scanner verification also covered Linux.

The CI matrix is configured for Windows, Linux and macOS. Execution on macOS and native discovery
inside each agent remain unverified. Report the OS, runtime versions, host version and any skipped
filesystem probes when validating a new environment.
