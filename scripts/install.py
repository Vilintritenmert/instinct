#!/usr/bin/env python3
"""Copy packaged skills into a host's discovery directory, without shell commands.

Python 3.10+, standard library only. Does not install runtimes, configure an agent,
or execute skill scripts. Paths are resolved on the machine doing the install.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
AGENT_DIRS = {"codex": ".agents", "claude": ".claude"}
# Skills that load another packaged skill from a sibling folder; --skill installs those too.
REQUIRES = {"security-check": ("how-deep-the-rabbit-hole-goes",)}


def is_link(path: Path) -> bool:
    """Include Windows junctions/reparse points without requiring Python 3.12."""
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def check_tree(path: Path) -> None:
    """Never follow packaged or installed links, pipes, devices or sockets."""
    if is_link(path):
        raise ValueError(f"Refusing linked path: {path}")
    if path.is_dir():
        for child in path.iterdir():
            check_tree(child)
    elif not path.is_file():
        raise ValueError(f"Refusing non-regular file: {path}")


def packaged_skills() -> dict[str, Path]:
    result = {}
    for source in sorted(SKILLS.iterdir()):
        if source.name.startswith("."):
            continue
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", source.name):
            raise ValueError(f"Invalid packaged skill name: {source.name}")
        check_tree(source)
        if not (source / "SKILL.md").is_file():
            raise ValueError(f"Packaged skill has no SKILL.md: {source}")
        result[source.name] = source
    if not result:
        raise ValueError(f"No skills found in {SKILLS}")
    return result


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    target = cli.add_mutually_exclusive_group()
    target.add_argument("--agent", choices=sorted(AGENT_DIRS), help="host discovery preset")
    target.add_argument(
        "--destination", type=Path,
        help="custom skills directory; each skill is copied into its own subfolder",
    )
    cli.add_argument("--scope", choices=("project", "user"), help="agent preset scope (default: project)")
    cli.add_argument("--project-root", type=Path, help="project directory (default: current directory)")
    cli.add_argument("--skill", help="install one packaged skill and the skills it needs (default: all)")
    cli.add_argument("--list", action="store_true", help="list packaged skills and exit")
    cli.add_argument("--update", action="store_true", help="replace an existing same-named skill folder")
    cli.add_argument("--dry-run", action="store_true", help="show the validated plan without writing files")
    return cli


def destination(args: argparse.Namespace, cli: argparse.ArgumentParser) -> Path:
    if not args.agent and args.destination is None:
        cli.error("choose --agent or --destination (or use --list)")
    if args.destination is not None:
        if args.scope or args.project_root is not None:
            cli.error("--scope and --project-root require --agent")
        return args.destination.expanduser().resolve()
    scope = args.scope or "project"
    if scope == "user":
        if args.project_root is not None:
            cli.error("--project-root cannot be used with --scope user")
        base = Path.home()
    else:
        base = (args.project_root or Path.cwd()).expanduser().resolve()
        if not base.is_dir():
            cli.error(f"project root is not an existing directory: {base}")
    return (base / AGENT_DIRS[args.agent] / "skills").resolve()


def check_target(target: Path, update: bool) -> None:
    # Project-local .agents/skills and .claude/skills inside this repo are fine;
    # overwriting the checkout or copying back into packaged skills is not.
    resolved = target.resolve()
    if ROOT.is_relative_to(resolved) or resolved.is_relative_to(SKILLS):
        raise ValueError(f"Destination overlaps the source checkout: {target}")
    if os.path.lexists(target):
        if is_link(target) or not target.is_dir():
            raise ValueError(f"Existing target is not an ordinary skill directory: {target}")
        if not update:
            raise ValueError(f"Already exists: {target}; use --update to replace this skill")
        check_tree(target)


def rename_directory(source: Path, target: Path) -> None:
    """Allow brief Windows sharing locks after copying files (for example, AV)."""
    delays = (0.05, 0.1, 0.2, 0.4)
    for attempt in range(len(delays) + 1):
        try:
            source.rename(target)
            return
        except PermissionError as error:
            if os.name != "nt" or error.winerror not in (5, 32, 33) or attempt == len(delays):
                raise
            time.sleep(delays[attempt])


def install(source: Path, target: Path) -> None:
    """Stage a complete copy before moving the old skill; restore on rename errors."""
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".instinct-install-", dir=target.parent))
    incoming = staging / "incoming"
    previous = staging / "previous"
    committed = False
    try:
        shutil.copytree(source, incoming)
        if target.exists():
            rename_directory(target, previous)
        try:
            rename_directory(incoming, target)
        except OSError:
            if previous.exists():
                try:
                    rename_directory(previous, target)
                except OSError as error:
                    raise OSError(f"Update failed; old skill retained at {previous}: {error}") from error
            raise
        committed = True
    finally:
        # Preserve the old folder for recovery if both commit and rollback failed.
        if committed or not previous.exists():
            if staging.resolve().parent != target.parent.resolve() or is_link(staging):
                raise ValueError(f"Refusing cleanup outside the installation directory: {staging}")
            shutil.rmtree(staging)


def main(argv: list[str] | None = None) -> int:
    # Redirected Windows terminals may use a legacy code page. Logging a valid
    # Unicode path must not turn a completed installation into an error.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    cli = parser()
    args = cli.parse_args(argv)
    try:
        skills = packaged_skills()
        if args.skill:
            if args.skill not in skills:
                cli.error(f"unknown skill {args.skill!r}; use --list")
            selected = (*REQUIRES.get(args.skill, ()), args.skill)
            skills = {name: skills[name] for name in selected}
        if args.list:
            for name in skills:
                print(name)
            return 0
        parent = destination(args, cli)
        if parent.exists() and not parent.is_dir():
            raise ValueError(f"Destination is not a directory: {parent}")
        # Validate every target before installing any skill.
        for name in skills:
            check_target(parent / name, args.update)
        for name, source in skills.items():
            target = parent / name
            if args.dry_run:
                print(f"Would {'replace' if target.exists() else 'install'} {name} -> {target}")
            else:
                install(source, target)
                print(f"Installed {name} -> {target}")
        if not args.dry_run:
            print("Reload skills or start a new agent session. Scanner execution requires PowerShell 7+ (pwsh).")
        return 0
    except (OSError, ValueError, shutil.Error) as error:
        print(f"install: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
