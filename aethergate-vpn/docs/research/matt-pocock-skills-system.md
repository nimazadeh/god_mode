# Research Note: Matt Pocock's Engineering & Productivity Skills System (`mattpocock/skills@main`)

**Primary Source Repository:** [mattpocock/skills (`main` branch, commit `49dd158`)](https://github.com/mattpocock/skills/tree/main)
**Research Methodology:** Produced via [`/research`](https://github.com/mattpocock/skills/blob/main/skills/engineering/research/SKILL.md) — every claim below is traced directly to the primary source (`SKILL.md`, `docs/`, `GLOSSARY.md`, `CLAUDE.md`) that owns it.

---

## 1. Core Philosophy & The Four Failure Modes Solved

According to [`README.md`](https://github.com/mattpocock/skills/blob/main/README.md), the skill system exists to replace "vibe coding" and heavy process frameworks (like GSD, BMAD, Spec-Kit) with small, composable, model-agnostic engineering primitives that address four root failure modes:

1. **Misalignment ("The Agent Didn't Do What I Want")**: Fixed by relentless upfront interviewing via [`/grill-me`](https://github.com/mattpocock/skills/blob/main/skills/productivity/grill-me/SKILL.md) and [`/grill-with-docs`](https://github.com/mattpocock/skills/blob/main/skills/engineering/grill-with-docs/SKILL.md), driven by the [`/grilling`](https://github.com/mattpocock/skills/blob/main/skills/productivity/grilling/SKILL.md) primitive ([`README.md#1`](https://github.com/mattpocock/skills/blob/main/README.md)).
2. **Verbosity & Jargon Drift ("The Agent Is Way Too Verbose")**: Fixed by building a ubiquitous domain language in `GLOSSARY.md` and recording hard-to-reverse trade-offs in `docs/adr/` via [`/domain-modeling`](https://github.com/mattpocock/skills/blob/main/skills/engineering/domain-modeling/SKILL.md) ([`README.md#2`](https://github.com/mattpocock/skills/blob/main/README.md)).
3. **Broken Output ("The Code Doesn't Work")**: Fixed by tight, observable feedback loops: static types, headless browser verification, vertical-slice Red-Green-Refactor in [`/tdd`](https://github.com/mattpocock/skills/blob/main/skills/engineering/tdd/SKILL.md), and phase-gated bug reproduction in [`/diagnosing-bugs`](https://github.com/mattpocock/skills/blob/main/skills/engineering/diagnosing-bugs/SKILL.md) ([`README.md#3`](https://github.com/mattpocock/skills/blob/main/README.md)).
4. **Software Entropy ("We Built A Ball Of Mud")**: Fixed by designing deep modules (high leverage behind a small interface at a clean seam) using [`/codebase-design`](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/SKILL.md) and periodically surveying with [`/improve-codebase-architecture`](https://github.com/mattpocock/skills/blob/main/skills/engineering/improve-codebase-architecture/SKILL.md) ([`README.md#4`](https://github.com/mattpocock/skills/blob/main/README.md)).

---

## 2. Two-Axis Invocation Architecture: User-Invoked vs. Model-Invoked

Per [`CLAUDE.md`](https://github.com/mattpocock/skills/blob/main/CLAUDE.md) and [`.agents/invocation.md`](https://github.com/mattpocock/skills/blob/main/.agents/invocation.md), all promoted skills (`engineering/` and `productivity/`) split strictly on one axis:

- **User-Invoked Skills (`disable-model-invocation: true`)**: Orchestrators invoked explicitly by the human. A user-invoked skill may call model-invoked skills, **never** another user-invoked skill ([`README.md#reference`](https://github.com/mattpocock/skills/blob/main/README.md)).
- **Model-Invoked Skills**: Reusable engineering disciplines that the agent reaches for automatically whenever the task matches their trigger description ([`README.md#reference`](https://github.com/mattpocock/skills/blob/main/README.md)).

---

## 3. The Canonical Engineering Flow (`ask-matt`)

The router skill [`/ask-matt`](https://github.com/mattpocock/skills/blob/main/skills/engineering/ask-matt/SKILL.md) defines the complete operational map for how human and agent collaborate from idea to shipped code:

### A. The Main Flow (`Idea -> Ship`)
1. **Align & Model (`/grill-with-docs`)**: Calls [`/grilling`](https://github.com/mattpocock/skills/blob/main/skills/productivity/grilling/SKILL.md) + [`/domain-modeling`](https://github.com/mattpocock/skills/blob/main/skills/engineering/domain-modeling/SKILL.md). Interviews the user in **rounds** across the current **frontier** of the design tree (every question whose prerequisites are settled), offering a recommended default (`➡️`) for each question and looking up environment facts itself rather than asking the user ([`grilling/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/grilling/SKILL.md)). Updates `GLOSSARY.md` inline and creates ADRs only when a decision is (1) hard to reverse, (2) surprising without context, and (3) the result of a real trade-off ([`domain-modeling/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/domain-modeling/SKILL.md)).
2. **Prototype Detour (`/prototype`)**: When a question requires a runnable answer (state logic or visual UI), build a throwaway prototype — either a single HTML file for state/logic or 3–5 radically different visual variants (`?variant=B`, `?variant=C`) with a floating keyboard switcher (`←` / `→`) ([`prototype/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/prototype/SKILL.md), [`prototype/UI.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/prototype/UI.md)).
3. **Spec & Tracer-Bullet Tickets (`/to-spec` -> `/to-tickets`)**: Synthesize the agreed design into a spec ([`to-spec/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/to-spec/SKILL.md)) and break it into vertical tracer-bullet issues with explicit blocking edges ([`to-tickets/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/to-tickets/SKILL.md)). Keep steps 1–3 in **one unbroken context window** within the ~150k token **smart zone** ([`ask-matt/SKILL.md#context-hygiene`](https://github.com/mattpocock/skills/blob/main/skills/engineering/ask-matt/SKILL.md)).
4. **Build & Two-Axis Review (`/implement` or `/implement-spec`)**:
   - Drive [`/tdd`](https://github.com/mattpocock/skills/blob/main/skills/engineering/tdd/SKILL.md) one vertical slice (one test) at a time at clean module seams ([`implement/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/implement/SKILL.md)).
   - Close out with [`/code-review`](https://github.com/mattpocock/skills/blob/main/skills/engineering/code-review/SKILL.md), which runs two independent parallel reviews over the diff:
     1. **Standards Axis**: Repo coding standards + Martin Fowler's 12 code smells baseline (*Mysterious Name*, *Duplicated Code*, *Feature Envy*, *Data Clumps*, *Primitive Obsession*, *Repeated Switches*, *Shotgun Surgery*, *Divergent Change*, *Speculative Generality*, *Message Chains*, *Middle Man*, *Refused Bequest*).
     2. **Spec Axis**: Missing/partial requirements, unrequested scope creep, and faulty implementations against the originating spec/issue ([`code-review/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/code-review/SKILL.md)).
5. **Environment Retrospective (`/retro`)**: After a build or bug fix, inspect the session to upgrade the agent's **environment** (navigation pointers, deterministic automated checks for mechanical rules, `CODING_STANDARDS.md` for judgement calls, tool economy, and pruning no-ops) ([`retro/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/retro/SKILL.md)).

### B. Three On-Ramps onto the Main Flow
- **Hard Bugs (`/diagnosing-bugs`)**: Refuses to guess until it builds a **tight feedback loop** (one deterministic command that goes **red** on *this* bug), minimises the repro, instruments hypotheses, fixes, and locks in a regression test ([`diagnosing-bugs/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/diagnosing-bugs/SKILL.md)).
- **Huge, Foggy Efforts (`/wayfinder`)**: When a project is too big for one session and covered in **fog of war**, chart a `wayfinder:map` issue with child **decision tickets** (`wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, `wayfinder:task`), resolving one HITL decision ticket per session (and running AFK `research` tickets in parallel) until the route to the destination is clear ([`wayfinder/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/wayfinder/SKILL.md)).
- **Raw Incoming Backlog (`/triage`)**: State-machine triage for external issues not created by `/to-tickets` ([`triage/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/triage/SKILL.md)).

---

## 4. Deep-Module Vocabulary (`codebase-design`) & Agent Writing Rules (`writing-for-agents`)

### Deep Modules ([`codebase-design/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/SKILL.md))
- **Module**: Anything with an interface and an implementation (function, class, package).
- **Interface**: Everything a caller must know (signature, invariants, ordering constraints, error modes, performance).
- **Depth**: Leverage at the interface — how much behaviour a caller or test exercises per unit of interface learned.
- **Seam** *(Michael Feathers)*: Where a module's interface lives and where behaviour can be altered without editing in place.
- **Adapter**: A concrete implementation satisfying an interface at a seam.
- **The Deletion Test**: If deleting a module makes complexity vanish, it was a shallow pass-through; if complexity reappears across N callers, it was a deep module earning its keep.

### Writing for Agents ([`writing-for-agents/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/writing-for-agents/SKILL.md))
- **Context Pointers**: Front-load leading words and list one trigger per branch.
- **Progressive Disclosure & Co-location**: Keep steps at the top of the information hierarchy; push branch-specific reference behind pointers; co-locate a concept's definition, rules, and caveats under one heading.
- **Completion Criteria**: Every step needs a checkable, high-demand completion criterion to prevent premature completion.
- **Leading Words & Positive Framing**: Anchor agent behaviour with compact pretrained tokens (*tight*, *red*, *frontier*, *fog of war*, *tracer bullets*) and state positive targets rather than negations.

---

## 5. Complete Inventory of Promoted Skills (`mattpocock/skills@main`)

| Bucket | Skill | Invocation | Primary Source | Core Role |
| :--- | :--- | :--- | :--- | :--- |
| **Engineering** | `ask-matt` | User | [`ask-matt/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/ask-matt/SKILL.md) | Router over all flows, on-ramps, and phase boundaries ([`PHASE-BOUNDARIES.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/ask-matt/PHASE-BOUNDARIES.md)) |
| **Engineering** | `grill-with-docs` | User | [`grill-with-docs/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/grill-with-docs/SKILL.md) | Relentless design-tree interview + inline `GLOSSARY.md` & ADR updates |
| **Engineering** | `to-spec` | User | [`to-spec/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/to-spec/SKILL.md) | Synthesizes agreed conversation into a technical spec |
| **Engineering** | `to-tickets` | User | [`to-tickets/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/to-tickets/SKILL.md) | Splits spec into vertical tracer-bullet issues with blocking edges |
| **Engineering** | `implement` | User | [`implement/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/implement/SKILL.md) | Implements a ticket/spec using `/tdd` at seams + closes with `/code-review` |
| **Engineering** | `implement-spec` | User | [`implement-spec/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/implement-spec/SKILL.md) | Parallel subagent task-graph execution across the ready ticket frontier |
| **Engineering** | `wayfinder` | User | [`wayfinder/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/wayfinder/SKILL.md) | Multi-session map of decision tickets (`research`, `prototype`, `grilling`, `task`) |
| **Engineering** | `improve-codebase-architecture` | User | [`improve-codebase-architecture/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/improve-codebase-architecture/SKILL.md) | Surveys codebase for module-deepening candidates and renders visual HTML report |
| **Engineering** | `triage` | User | [`triage/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/triage/SKILL.md) | Moves raw incoming issues through triage state-machine roles |
| **Engineering** | `retro` | User | [`retro/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/retro/SKILL.md) | Post-session environment retrospective (checks, standards, navigation, no-ops) |
| **Engineering** | `setup-matt-pocock-skills` | User | [`setup-matt-pocock-skills/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/setup-matt-pocock-skills/SKILL.md) | One-time repo setup for issue tracker, triage labels, and doc paths |
| **Engineering** | `tdd` | Model | [`tdd/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/tdd/SKILL.md) | Vertical-slice Red -> Green -> Refactor loop at public module interfaces |
| **Engineering** | `diagnosing-bugs` | Model | [`diagnosing-bugs/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/diagnosing-bugs/SKILL.md) | Phase-gated bug diagnosis: tight red repro loop -> minimise -> instrument -> fix |
| **Engineering** | `prototype` | Model | [`prototype/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/prototype/SKILL.md) | Throwaway state/logic HTML or multi-variant (`←`/`→`) UI exploration |
| **Engineering** | `research` | Model | [`research/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/research/SKILL.md) | Primary-source investigation saved as a single cited Markdown file in the repo |
| **Engineering** | `domain-modeling` | Model | [`domain-modeling/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/domain-modeling/SKILL.md) | Ubiquitous language enforcement in `GLOSSARY.md` + strict 3-rule ADR gate |
| **Engineering** | `codebase-design` | Model | [`codebase-design/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/codebase-design/SKILL.md) | Deep-module vocabulary (Module, Interface, Depth, Seam, Adapter, Leverage, Locality) |
| **Engineering** | `code-review` | Model | [`code-review/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/code-review/SKILL.md) | Parallel two-axis review: **Standards** (repo + Fowler smells) & **Spec** |
| **Engineering** | `pr` | Model | [`pr/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/pr/SKILL.md) | Visual-first PR body: diagram/diff-sketch, Before/After evidence, One/Two-Way Door |
| **Engineering** | `wizard` | Model | [`wizard/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/engineering/wizard/SKILL.md) | Interactive terminal wizard (`template.sh`) for human-only setup/secret steps |
| **Productivity** | `grill-me` | User | [`grill-me/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/grill-me/SKILL.md) | Stateless design-tree interview when not inside a code repo |
| **Productivity** | `handoff` | User | [`handoff/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/handoff/SKILL.md) | Portable context handoff file for moving across harnesses or directories |
| **Productivity** | `teach` | User | [`teach/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/teach/SKILL.md) | Multi-session stateful teaching workspace |
| **Productivity** | `to-questionnaire` | User | [`to-questionnaire/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/to-questionnaire/SKILL.md) | Grills the *send* (recipient + gap) to produce an async discovery questionnaire |
| **Productivity** | `wait-what` | User | [`wait-what/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/wait-what/SKILL.md) | Instant plain-English (ASD-STE100) + `GLOSSARY.md` re-pitch when a message doesn't land |
| **Productivity** | `grilling` | Model | [`grilling/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/grilling/SKILL.md) | Core interview primitive: design tree, rounds, frontier, `❓ Q1` + `➡️` recommendation |
| **Productivity** | `writing-for-agents` | Model | [`writing-for-agents/SKILL.md`](https://github.com/mattpocock/skills/blob/main/skills/productivity/writing-for-agents/SKILL.md) | Context pointers, progressive disclosure, co-location, completion criteria, leading words |
