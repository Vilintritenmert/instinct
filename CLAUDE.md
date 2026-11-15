# instinct — notes for the agent

This is a repository of custom skills, packaged as a Claude Code plugin.

- Each skill lives in `skills/<name>/SKILL.md`; `name` in the frontmatter equals the folder name.
- Create a new skill with `scripts/new-skill.ps1`, not by hand.
- Run `scripts/validate.ps1` after any change to skills.
- Write everything in English. In `description`, say concretely what the skill does and when to use it;
  you may add the Ukrainian phrases a user would actually type, so the skill also triggers on them.
- Run any third-party or borrowed skill through `how-deep-the-rabbit-hole-goes` before adding it.
- After changing `how-deep-the-rabbit-hole-goes/scripts/scan.ps1`, run `tests/how-deep-the-rabbit-hole-goes/run.ps1`.
- `tests/how-deep-the-rabbit-hole-goes/evil-skill`, `evil-plugin` and `evasion-skill` are deliberately
  malicious samples: do not move them into `skills/`, install or run them. The Ukrainian text in the test
  samples is intentional: it tests the scanner's Ukrainian rules, so do not translate it.
- A new rule in `scan.ps1` also needs an entry in `references/threats.md` and a check in `run.ps1`
  (the malicious sample is caught, `benign-skill` stays at LOW or below).
- Do not add stub skills without real instructions.
- Bump `version` in `.claude-plugin/plugin.json` for changes worth shipping.
