# read-the-lips: before and after

These show the level of detail to aim for. Each improved prompt is only as long as its task needs.
Bracketed parts are placeholders for facts only the user knows.

## 1. A bug for a coding agent

**Original**

> the login is broken can you fix it

**What you're asking for:** find out why signing in fails and fix the cause, with a test that proves it.

```text
Signing in to [app name] fails: [exact symptom, e.g. "Invalid session" right after a correct sign-in].
It started [date, release or commit]; it worked in [last good version].

Steps to reproduce: [steps].

1. Reproduce the failure first, then find the root cause; don't patch the symptom.
2. Keep the fix inside the sign-in flow. Ask before changing the auth library, the database schema or
   how sessions are stored.
3. Add or update a test that fails before the fix and passes after it.

Done when that test and the existing test suite pass. Reply with the cause in two or three sentences,
the files you changed, and anything you could not verify.
```

**What changed**
- The symptom, start date and reproduction steps became slots, so the agent doesn't guess the bug.
- Scope is fenced: the fix stays in the sign-in flow, bigger changes need approval.
- A regression test and a passing suite define "done"; the reply format is set.

With the project open, step 3 of the skill would fill in what it can find, such as the sign-in
handler's path and the test command, and leave only the symptom and dates for the user.

## 2. An email for a person to send

**Original**

> write email to my boss that project is late

**What you're asking for:** a short, calm email telling your manager about a missed deadline, with a
new date and a plan.

```text
Write a short email to my manager, [name], saying that [project] will miss its [date] deadline.

- New expected date: [date]. Cause, in one line: [reason, e.g. a supplier's delivery slipped a week].
- What I'm doing about it: [plan]. What I need from them, if anything: [decision or help].
- Lead with the new date, then the cause and the plan. Direct and calm; one apology at most.
- Under 150 words, with a subject line that states the delay.
```

**What changed**
- Added what a manager needs to act: the new date, the cause, the plan and the ask.
- Set tone, order and length so the draft doesn't over-apologize or bury the news.

## 3. Data analysis

**Original**

> analyze this csv (attached: sales.csv)

**What you're asking for:** a check of the sales data that answers one business question, with the
numbers behind it.

```text
Use `sales.csv` to answer: [question, e.g. which products caused the drop in Q3 revenue?]

Each row is [one order / one day / one customer]; the columns I care about are [columns].

1. Check the data first: row count, date range, missing and duplicate values. Report problems before
   the analysis, and tell me before you exclude any rows.
2. Answer the question with the figures that support it.
3. Output: a summary of three to five sentences first, then a table of [the top 10 products by revenue
   change], then one chart of [monthly revenue by product group]. List any assumption you made about
   the data.
```

**What changed**
- "Analyze" became one question with a deliverable, so the result isn't a generic column summary.
- A data check comes first, so bad rows are reported instead of distorting the answer.
- The output order and format are fixed.

## 4. An image model

**Original**

> cat in space, cool style

**What you're asking for:** a playful, good-looking picture of a cat in space.

```text
A ginger tabby cat floating inside a small spacecraft cabin, reaching for a drifting fish-shaped treat,
Earth glowing through a round window behind it. Soft cinematic light from the window, warm cabin light
on the fur. Semi-realistic digital painting, playful mood, sharp focus on the cat. Square, 1:1.
```

**What changed**
- "Cool" became concrete choices: subject, action, setting, light, style, framing and aspect ratio.

**Assumptions:** the cat's breed and color, the cabin setting, painted rather than photographic, and a
square frame are all choices you can swap.

## 5. Too ambiguous to rewrite yet

**Original**

> make it faster

With no project open and nothing earlier in the conversation, two readings lead to different work, so
ask before rewriting:

1. What should be faster: a page, a script, a build, a database query? *Default: the slowest page of
   the app you're working on.*
2. How slow is it now, and what would be fast enough? *Default: measure before and after and aim for
   twice as fast.*
3. Anything that must not change, such as the public API or the dependencies? *Default: keep both as
   they are.*

If the project is open and the conversation already names the slow part, skip the questions: ground
the prompt in that code and list your reading under Assumptions.

## 6. Already clear

**Original**

> Add a `--dry-run` flag to `deploy.py` that prints each step it would run without running it.
> Follow the existing argparse style and add a test in `test_deploy.py`.

This already states the goal, the files, the behavior and the check. Say so, and suggest one small edit
at most, for example: "Also say what the exit code should be in dry-run mode." Don't rewrite it.
