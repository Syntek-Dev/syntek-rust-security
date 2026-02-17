# Coding Principles

These principles govern all code written in this codebase. They are not
suggestions — they are the default mindset. Read them before writing anything.

---

## Rob Pike's 5 Rules of Programming

*Co-creator of Go. Derived from his programming philosophy and writings on
performance, simplicity, and engineering discipline.*

**Rule 1** — You can't tell where a program is going to spend its time.
Bottlenecks occur in surprising places, so don't try to second-guess and put in
a speed hack until you know that is where the bottleneck is.

**Rule 2** — Don't tune for speed until you've measured. And even then, don't
unless one part of the code overwhelms the rest.

**Rule 3** — Fancy algorithms are slow when N is small, and N is usually small.
Fancy algorithms have big constants. Until you know that N is frequently going
to be big, don't get fancy. Even if N does get big, use Rule 2 first.

**Rule 4** — Fancy algorithms are buggier and much harder to implement. Use
simple, reusable, easy-to-maintain algorithms as well as simple data structures.

**Rule 5** — Data dominates. If you have chosen the right data structures and
organised things well, the algorithms will almost always be self-evident. Data
structures are central to programming, not algorithms.

---

## Linus Torvalds' Coding Rules

*Creator of Linux. Derived from his coding style documentation, mailing list
contributions, and public talks on taste, clarity, and engineering discipline.*

**Rule 1 — Data structures over algorithms**
> "Show me your flowcharts and conceal your tables, and I shall continue to be
> mystified. Show me your tables, and I won't usually need your flowcharts;
> they'll be obvious."

Focus on how data is organised. A solid data model often eliminates the need for
complex, messy code. The logic will naturally follow from the structure.

**Rule 2 — "Good taste" in coding**
- Remove special cases: good code eliminates edge cases rather than creating `if`
  statements for them.
- Simplify logic: avoid tricky expressions or complex, nested control flows.
- Reduce branches: fewer conditional statements make code faster (CPU branch
  prediction) and easier to reason about.

**Rule 3 — Readability and maintainability**
- Short functions: do one thing, be short, fit on one or two screenfuls of text.
- Descriptive names: variables and functions should be descriptive but concise.
- Avoid excessive indentation: deep nesting makes code hard to read, especially
  after looking at it for 20 hours.

**Rule 4 — Code structure and style**
- Avoid multiple assignments on a single line.
- One operation, one line — keep it obvious.

**Rule 5 — Favour stability over complexity**
Don't do something cool at the expense of something that works and is
understood. Stability and predictability beat clever.

**Rule 6 — The bad code principle: make it work, then make it better**
- Don't over-optimise. Get it working first, then optimise where evidence
  demands it.
- All code should be maintainable by anyone, not just the original author.
  Write for the next person.
