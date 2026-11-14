# instict

Набір кастомних скілів для агентів (Claude Code та сумісних). Репозиторій оформлено як
Claude Code-плагін із власним маркетплейсом, тож усі скіли встановлюються однією командою.

## Скіли

| Скіл | Що робить |
|------|-----------|
| [how-deep-the-rabbit-hole-goes](skills/how-deep-the-rabbit-hole-goes/SKILL.md) | Аудит безпеки скілів і плагінів перед встановленням: 26 класів загроз ([каталог](skills/how-deep-the-rabbit-hole-goes/references/threats.md)), статичний сканер, вердикт SAFE / REVIEW / UNSAFE. |

## Структура

```
instict/
├── .claude-plugin/
│   ├── plugin.json        # маніфест плагіна
│   └── marketplace.json   # локальний маркетплейс (щоб можна було встановити плагін)
├── skills/                # кожен скіл — окрема папка з SKILL.md
│   └── <skill-name>/
│       ├── SKILL.md       # обовʼязково: frontmatter + інструкції
│       ├── references/    # необовʼязково: довідкові матеріали, які агент читає за потреби
│       ├── scripts/       # необовʼязково: скрипти, які скіл запускає
│       └── assets/        # необовʼязково: шаблони, зображення тощо
├── tests/                 # тестові зразки й регресійні тести скілів
├── templates/
│   └── SKILL.template.md  # шаблон нового скіла
└── scripts/
    ├── new-skill.ps1      # створити новий скіл із шаблону
    └── validate.ps1       # перевірити всі скіли
```

## Новий скіл

```powershell
./scripts/new-skill.ps1 -Name my-skill -Description "Що робить скіл і коли його вмикати."
```

Потім заповни `skills/my-skill/SKILL.md` і перевір:

```powershell
./scripts/validate.ps1
```

## Правила для скілів

- `name` — kebab-case, до 64 символів, збігається з назвою папки.
- `description` — до 1024 символів. Це головний тригер: опиши **що** робить скіл і **коли**
  його використовувати, з фразами, якими користувач реально про це просить
  (українською та англійською).
- Тіло `SKILL.md` — коротке й по суті; великі довідки винось у `references/`.

## Встановлення

```bash
claude plugin marketplace add <шлях-до-instict>
claude plugin install instict@instict
```

Після змін у скілах: `claude plugin marketplace update instict`.
