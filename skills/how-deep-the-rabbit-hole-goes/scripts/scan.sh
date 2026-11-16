#!/bin/sh
# Runs the how-deep-the-rabbit-hole-goes scanner (scan.ps1) on macOS, Linux and other Unix-like systems.
# The scanner itself is PowerShell 7+ code: this wrapper finds `pwsh`, accepts Unix-style options and
# passes the scanner's exit code through. Like the scanner, it only reads the target; nothing in it runs.
# POSIX sh: works with dash, bash, zsh, ksh and BusyBox; no execute bit is needed (`sh scan.sh ...`).

set -eu
# `zsh scan.sh` ignores the shebang; plain sh rules keep an unmatched glob from aborting the search.
if [ -n "${ZSH_VERSION:-}" ]; then emulate sh; fi

usage() {
    cat <<'EOF'
Usage: sh scan.sh [options] <target>
       sh scan.sh --list-rules

Statically scans a skill, plugin or marketplace folder, or a single file, for threats T01-T26.
Findings are signals for manual review, not a verdict.

Options:
  --json                 machine-readable output: findings, coverage, inventory and hashes
  --inventory            add the file inventory (types and SHA-256) to the text output
  --min-severity LEVEL   show findings at or above LOW (default), MEDIUM, HIGH or CRITICAL;
                         counts and the exit code do not change
  --list-rules           print the versioned rule catalog as JSON without scanning
  -h, --help             show this help
  --                     end of options, for a target whose name starts with '-'

The scanner's own spellings also work: -Path, -Json, -Inventory, -MinSeverity, -ListRules.

Environment:
  PWSH                   path to a specific pwsh executable

Exit codes:
  2  at least one CRITICAL signal      1  at least one HIGH signal
  0  no HIGH or CRITICAL signal        64 usage error
  127 PowerShell 7+ not found          other: the scan did not complete
EOF
}

die() {
    printf 'scan.sh: %s\n' "$1" >&2
    printf "Try 'sh scan.sh --help'.\n" >&2
    exit 64
}

# Locate pwsh: $PWSH, then PATH, then the usual install locations on macOS and Linux.
find_pwsh() {
    if [ -n "${PWSH:-}" ]; then
        if [ -f "$PWSH" ] && [ -x "$PWSH" ]; then
            printf '%s\n' "$PWSH"
            return 0
        fi
        printf 'scan.sh: PWSH is set but is not an executable file: %s\n' "$PWSH" >&2
        return 2
    fi
    if command -v pwsh >/dev/null 2>&1; then
        command -v pwsh
        return 0
    fi
    home=${HOME:-/nonexistent}
    for candidate in /usr/local/bin/pwsh /opt/homebrew/bin/pwsh /opt/microsoft/powershell/7/pwsh \
        /snap/bin/pwsh "$home/.dotnet/tools/pwsh" "$home/.local/bin/pwsh" "$home"/.local/opt/pwsh*/pwsh; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

missing_pwsh() {
    {
        echo 'scan.sh: PowerShell 7+ (pwsh) is required to run the scanner and was not found.'
        echo 'Install it, then run this script again (or set PWSH=/path/to/pwsh):'
        case $(uname -s 2>/dev/null || echo unknown) in
            Darwin)
                echo '  brew install --cask powershell' ;;
            Linux)
                echo "  Ubuntu, Debian, Fedora, RHEL: the 'powershell' package from Microsoft's repository"
                echo '  Snap: sudo snap install powershell --classic'
                echo '  Any distribution: the official powershell-<version>-linux-<arch>.tar.gz release;'
                echo '  check its SHA-256, extract it anywhere and set PWSH to the pwsh inside' ;;
            *)
                echo "  see Microsoft's PowerShell installation guide for your system" ;;
        esac
        echo 'Without PowerShell, do the manual first pass described in SKILL.md, step 2.'
    } >&2
    exit 127
}

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
scanner="$here/scan.ps1"
[ -f "$scanner" ] || { printf 'scan.sh: scan.ps1 not found next to this script (%s)\n' "$here" >&2; exit 70; }

severity() {
    level=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
    case $level in
        LOW|MEDIUM|HIGH|CRITICAL) printf '%s\n' "$level" ;;
        *) die "invalid severity '$1': use LOW, MEDIUM, HIGH or CRITICAL" ;;
    esac
}

# Translate the options. The original arguments are consumed from the front while the translated
# ones are appended at the end, so "$@" ends up holding only the scanner's arguments. Values use the
# -Name:value form, which PowerShell binds even when the value itself starts with '-'.
remaining=$#
targets=0
list_rules=0
while [ "$remaining" -gt 0 ]; do
    arg=$1
    shift
    remaining=$((remaining - 1))
    case $arg in
        -h|--help)
            usage
            exit 0 ;;
        --json|-[Jj][Ss][Oo][Nn])
            set -- "$@" -Json ;;
        --inventory|-[Ii][Nn][Vv][Ee][Nn][Tt][Oo][Rr][Yy])
            set -- "$@" -Inventory ;;
        --list-rules|-[Ll][Ii][Ss][Tt][Rr][Uu][Ll][Ee][Ss])
            list_rules=1
            set -- "$@" -ListRules ;;
        --min-severity=*)
            level=$(severity "${arg#*=}")
            set -- "$@" "-MinSeverity:$level" ;;
        --min-severity|-[Mm][Ii][Nn][Ss][Ee][Vv][Ee][Rr][Ii][Tt][Yy])
            [ "$remaining" -gt 0 ] || die "$arg needs a value: LOW, MEDIUM, HIGH or CRITICAL"
            level=$(severity "$1")
            shift
            remaining=$((remaining - 1))
            set -- "$@" "-MinSeverity:$level" ;;
        -[Pp][Aa][Tt][Hh])
            [ "$remaining" -gt 0 ] || die '-Path needs a value'
            targets=$((targets + 1))
            set -- "$@" "-Path:$1"
            shift
            remaining=$((remaining - 1)) ;;
        --)
            while [ "$remaining" -gt 0 ]; do
                targets=$((targets + 1))
                set -- "$@" "-Path:$1"
                shift
                remaining=$((remaining - 1))
            done ;;
        -?*)
            die "unknown option: $arg" ;;
        '')
            die 'the target is an empty string' ;;
        *)
            targets=$((targets + 1))
            set -- "$@" "-Path:$arg" ;;
    esac
done

if [ "$list_rules" -eq 1 ] && [ "$targets" -gt 0 ]; then die 'use either a target or --list-rules, not both'; fi
if [ "$list_rules" -eq 0 ] && [ "$targets" -eq 0 ]; then die 'no target given'; fi
[ "$targets" -le 1 ] || die 'give one target at a time'

if pwsh_bin=$(find_pwsh); then
    :
elif [ $? -eq 2 ]; then
    exit 127
else
    missing_pwsh
fi
exec "$pwsh_bin" -NoLogo -NoProfile -NonInteractive -File "$scanner" "$@"
