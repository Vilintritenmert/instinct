# instict — нотатки для агента

Це репозиторій кастомних скілів, оформлений як Claude Code-плагін.

- Кожен скіл живе в `skills/<name>/SKILL.md`; `name` у frontmatter = назва папки.
- Новий скіл створюй через `scripts/new-skill.ps1`, а не вручну.
- Після будь-якої зміни скілів запускай `scripts/validate.ps1`.
- `description` пиши двомовно (українська + англійська фраза-тригер) і конкретно: що робить + коли вмикати.
- Перед додаванням чужого або запозиченого скіла проганяй його через `how-deep-the-rabbit-hole-goes`.
- Після змін у `how-deep-the-rabbit-hole-goes/scripts/scan.ps1` запускай `tests/how-deep-the-rabbit-hole-goes/run.ps1`.
- `tests/how-deep-the-rabbit-hole-goes/evil-skill`, `evil-plugin` і `evasion-skill` — навмисно шкідливі зразки: не переносити в `skills/`, не встановлювати й не запускати.
- Нове правило в `scan.ps1` — це ще й рядок у `references/threats.md` і перевірка в `run.ps1` (шкідливий зразок ловиться, `benign-skill` лишається не вище LOW).
- Не додавай скіли-заглушки без реальних інструкцій.
- Піднімай `version` у `.claude-plugin/plugin.json` при змінах, які варто роздати.
