<a id="readme-top"></a>

<div align="center">

<img width="1672" height="941" alt="ctf-rat — route · verify · reuse" src="assets/banner.png" />

<br>

# CTF-Rat

### **route → verify → reuse**

Verify fast on a small context, and stop re-deriving what the cache already knows.

<p>
<img alt="focus" src="https://img.shields.io/badge/FOCUS-PWN%20%2F%20REV-e63946?style=for-the-badge">
<img alt="agents" src="https://img.shields.io/badge/AGENTS-CLAUDE%20%C2%B7%20CODEX-457b9d?style=for-the-badge">
<img alt="selfcontained" src="https://img.shields.io/badge/SELF--CONTAINED-YES-2a9d8f?style=for-the-badge">
<img alt="tests" src="https://img.shields.io/badge/REGRESSION-ALL%20GREEN-43aa8b?style=for-the-badge">
</p>

<p>
<img alt="python" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white">
<img alt="git" src="https://img.shields.io/badge/vcs-git-f05032?style=flat-square&logo=git&logoColor=white">
<img alt="angr" src="https://img.shields.io/badge/engine-angr-1d1d1d?style=flat-square">
<img alt="pwntools" src="https://img.shields.io/badge/exploit-pwntools-000000?style=flat-square">
<img alt="ghidra" src="https://img.shields.io/badge/rev-ghidra-6b8e23?style=flat-square">
</p>

</div>

<br>

A pwn/rev-focused, **environment-agnostic, self-contained CTF solving kit.** Tools, doctrine,
knowledge, and reference data all live in one repo — set it up **once** on any Linux environment
(native / VM / WSL2 / container) and Claude · Codex can start solving challenges right here.

<details open>
<summary><b>📑 Table of Contents</b></summary>

- [⚡ Quick Start](#-quick-start)
- [🔄 Flow](#-flow)
- [🧭 Entry Points & Rules](#-entry-points--rules)
- [📂 Layout](#-layout)
- [🛠️ Core Tools](#️-core-tools)
- [✅ Tests](#-tests-after-modifying-tools)
- [📐 Operating Principles](#-operating-principles)

</details>

## ⚡ Quick Start

```sh
# 0. One-time environment setup (venv+angr+pwntools, Ghidra, glibc-fetch)  →  SETUP.md
# 1. Lock the target engagement (allowlist / active lock)
ctfguard begin <challenge> [target]
# 2. Route — project evidence dimensions and bounded candidate probes
rat route <bin>
# 3. Run one bounded discriminator; use full recon/revq only when evidence says it is needed
rat query pwn <bin>              # example pwn capability query
rat query func <bin> <function>  # example rev function card
```

<div align="right"><a href="#readme-top">↑ back to top</a></div>

## 🔄 Flow

```mermaid
flowchart LR
    A["📥 newchal / ctfpull<br/>collect artifact"] --> B["🧭 rat route<br/>signals · dimensions · candidate probes"]
    B --> D["🎯 run one bounded discriminator<br/>recommend only on clear dominance"]
    B --> E["🔍 preserve coexisting leads and unresolved premises"]
    D --> F["🧪 rat-verify / concrete-verify"]
    E --> F
    F --> G{"PASS?"}
    G -->|no, DEEP condition| H["🔬 lazy-load doctrine<br/>inherit STATE · cache · current evidence"]
    H -->|next discriminator| D
    G -->|yes| I["📦 pkshare → HANDOFF.md<br/>knowledge/learned/"]

    style A fill:#264653,color:#fff
    style B fill:#2a9d8f,color:#fff
    style D fill:#e76f51,color:#fff
    style E fill:#e76f51,color:#fff
    style F fill:#e9c46a,color:#111
    style H fill:#6d597a,color:#fff
    style I fill:#43aa8b,color:#fff
```

<div align="right"><a href="#readme-top">↑ back to top</a></div>

## 🧭 Entry Points & Rules

| Doc                                                              | Role                                                                                                                                                                 |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **[SETUP.md](SETUP.md)**                                         | Environment-agnostic one-time setup                                                                                                                                  |
| **[CLAUDE.md](CLAUDE.md)** (= `AGENTS.md`)                       | Agent entry point. Auto-loads the FAST hot-path (7-rule ROE · tool map) every session; full doctrine is lazy-loaded **only on DEEP escalation** (M1 slim entrypoint) |
| **operator skill**                                               | `skills/<route>/SKILL.md` — load exactly **one** per route. SIGNALS / FIRST ACTION / PIVOT / ESCALATE / VERIFY                                                       |
| **[knowledge/GROUNDING_INDEX.md](knowledge/GROUNDING_INDEX.md)** | Knowledge router → `knowledge/ctf-skills/`                                                                                                                           |

> [!NOTE]
> **DEEP-only doctrine** — [SOLVING](doctrine/SOLVING.md) (FAST evidence handoff + bounded convergence loop) · [SOLVABILITY](doctrine/SOLVABILITY.md) · [PRIMITIVE_GATE](doctrine/PRIMITIVE_GATE.md) · [FINALS](doctrine/FINALS.md)
>
> Benchmark corpus, ablations, and design-review docs live on the `dev` branch. `main` ships only the operational tools needed to actually solve and verify challenges.

<div align="right"><a href="#readme-top">↑ back to top</a></div>

## 📂 Layout

```
CLAUDE.md / AGENTS.md      agent entry point (symlink)
SETUP.md                   environment-agnostic initial setup
doctrine/                  SOLVING · SOLVABILITY · PRIMITIVE_GATE · REFUSAL · FINALS
docs/                       calibration (오염 상수 포함 — doctrine 밖)
knowledge/                 vendored pwn/rev knowledge + repo-owned learned/ + writeup pipeline
reference/                 libc-offsets/ · glibc/(list · SOURCES · glibc-fetch)
bin/                       all tools (+ghidra_scripts/)
solve/_template/rev/       symsolve · vmlift
kernel/                    kernel pwn extensions
tests/                     e2e_mock.py(ctfpull) · e2e_rev.sh(rev loop)
```

<div align="right"><a href="#readme-top">↑ back to top</a></div>

## 🛠️ Core Tools

<details open>
<summary><code>rat</code> — the single front-door dispatcher</summary>
<br>

`rat route <bin>` projects observations into independent dimensions and returns evidence-linked bounded candidate probes (a thin composition of rat-doctor + rat-profile + revq,
no new analysis). Static routing leaves `skill=null`; after an active derived/direct STATE observation confirms the method, `rat route <bin> --skill <name> --skill-evidence <obs_id> --skill-reason <reason>` records the committed Skill in the existing route-assessment note. It emits a recommendation only when one probe clearly dominates the alternatives on deterministic evidence/cost criteria, and `rat query {graph,func,oracle,pwn,pattern,slice}` · `rat dyn|verify` · `rat state compact` ·
`rat cache stats` expose everything through one entry point. Existing CLIs (revq / recon / etc.)
still work standalone.

`rat query pattern <bin>` returns at most three source-bound hypothesis aids for
coexisting Router v2 leads. `rat dyn session` optionally keeps one local GDB
process for sequential observations; see [GDB session usage](docs/GDB_SESSION.md).

</details>

<details>
<summary><code>ctfpull</code> — pull CTFd challenges into a <code>newchal</code> scaffold</summary>
<br>

Never auto-submits flags (ToS + honest-mode).

```sh
ctfpull ctfd --list [--category pwn]
ctfpull ctfd --id 42 [--dest DIR]        # download → extract → detect ELF → run.json → newchal
```

기본 수집 경로는 `solve/<name>/artifact/`이며, 생성된 풀이 파일과 제공 원본이
`solve/<name>/` 한 곳에 모인다. `--dest DIR`을 명시하면 기존처럼 `DIR/<name>/`에
스테이징한다.

Config precedence: CLI > env vars (`CTFD_URL` / `CTFD_TOKEN`) > dotenv (`--env`, default `./.ctfd.env`).

</details>

<details open>
<summary>🔍 <b>rev loop</b></summary>
<br>

```sh
revq <bin>                     # summary + INTERESTING (check-routine candidates) + EVASION (anti-debug/packing)
revq <bin> --func <name>       # single-function neighborhood card (saves context before decompiling)
decomp <bin> <func>             # Bash executable: Ghidra headless decompile cache
mod2solve system.json           # solve matrix @ x = target modulo 2**bits; verify against original inputs
symsolve.py <bin> --find-str Correct --stdin 16 --printable   # recover input, re-run the real binary to verify
vmlift.py --disasm|--run|--solve [blob]                       # custom VM lifter
```

> [!TIP]
> `revq` addresses = angr's load base (PIE `0x400000`) → feed them straight into `symsolve --find <addr>`.

`decomp` is a Bash script: invoke `bin/decomp <bin> <func>` directly or with
`bash bin/decomp <bin> <func>`. Python tools such as `revq` accept
`python3 bin/revq ...`; `python3 bin/decomp ...` does not. Bad-instruction output
from a cached function is marked `partial` with a bounded `objdump` diagnostic;
compare revq's mapped address with the ELF VMA before disassembly.

For Linux boot images, `newchal` skips generic ELF recon and `rat route` reports
the kernel identity and the prerequisite to extract ELF `vmlinux` using Linux
`scripts/extract-vmlinux`. Symbol-bearing kernels use bounded ELF metadata in
`revq` (including executable NOTYPE symbols), without a whole-kernel CFG.
This establishes artifact identity only; boot environment and primitives still
require evidence. Ghidra imports of kernels or files at least 16 MiB require
`decomp --allow-full-analysis --timeout SEC BIN [FUNC]`; cached function reads
remain available. Initial import analyzes and exports the whole program.

`rat-adapt --root` names the artifact store, normally `<challenge>/.rat`.
Omitting it uses `./.rat`. A challenge root containing `.rat` is rejected before
execution with the corrected store path, so evidence cannot silently land in a
different store from STATE.

`mod2solve` is a Python executable with no solver dependency. Its JSON input is
`{"bits":8,"matrix":[[3,2],[0,1]],"target":[19,5]}`. Run
`python3 bin/mod2solve system.json`; it returns a solution vector, `solution_hex`
for byte-sized moduli, the original inputs and file digest, and an independent
`matrix @ solution` check. Status distinguishes `unique`, `multiple`, and
`inconsistent`; exit codes are 0 for a solution, 1 for no solution, and 2 for
invalid input. Even pivots and rectangular systems are supported (up to 256
rows/columns and 64 modulus bits). For a non-unique system, one representative
is returned; byte/printable constraints are not imposed. This verifies the
equation only: validate the recovered input with the challenge's concrete
verifier before recording solve evidence.

</details>

<details>
<summary>🎯 <b>pwn</b></summary>
<br>

`pwnkit` / `pwnstage` / `primitives` · `pwncalc` / `pwnleak` / `pwnpayload` / `pwnropcheck` / `pwncrash` / `pwnscope` / `pwnclean` / `pkflag`

`pkflag` checks **format only**; `REAL` is not proof of executable-oracle success.
By default `pkflag` uses `solve/<active-challenge>/FLAG_FORMAT` (from `ctfguard`'s `ACTIVE.json`, or the current `solve/<challenge>` directory). A stale repository-global `FLAG_FORMAT` is **not** used implicitly. With no challenge format, a generic `NAME{...}` heuristic applies.

```sh
ctfguard begin example
pkflag --set 'DH\{[A-Za-z0-9_]+\}' # set this challenge's format
pkflag --show                          # show this challenge's format
pkflag 'DH{example_candidate}'         # format-only check
pkflag --global --show                 # explicitly inspect legacy global format
```

Use `--chal example` to select a challenge explicitly. `--global --set` is available only for deliberate legacy-global configuration; `pkselftest` no longer writes the repository setting.

</details>

<details>
<summary>➕ <b>and more</b></summary>
<br>

- **Environment / execution plan** — `rat-doctor <bin> --format json` shows which paths (native/GDB/angr/Ghidra/QEMU/Qiling/Wine) actually work for this artifact and why others are blocked. Regression testing is handled separately by `pkselftest`.
- **Reproducible scenarios** — `rat-scenario init|validate|show` normalizes the input/argv/env/oracle shared by `rat-dyn` / `rat-runtime` / `rat-verify`. Binary stdin is preserved via `--stdin-file`.
- **State bus** — `state` (record confirmed / ruled-out / next) · **kernel** — `k_*` (kernel/).
- **Internal schema test helper** — `ratlib.schema_docs` extracts validator field contracts for `tests/test_schema_docs.py`; it is not part of runtime STATE validation.
- **Handoff & knowledge** — `pkshare` → `HANDOFF.md`; `writeupcheck` quality gate → reviewed lessons land in `knowledge/learned/`. Typed STATE v2 takes precedence; legacy PASS entries are shown only as candidates. Completion docs require an operator attestation linked to an evidence digest.

</details>

<div align="right"><a href="#readme-top">↑ back to top</a></div>

## ✅ Tests (after modifying tools)

```sh
python3 bin/revq selftest
python3 bin/rat selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 bin/ctfpull selftest && python3 tests/e2e_mock.py
python3 -m unittest tests.test_writeup_pipeline
bash tests/e2e_rev.sh        # real crackme e2e if angr is installed, selftest only otherwise
bash tests/e2e_rev.sh --require-engine  # release/CI gate: missing native angr is failure
```

Release verification requires `--require-engine` and `ALL GREEN ✅`; the optional
selftest-only run is reported as partial coverage.

<div align="right"><a href="#readme-top">↑ back to top</a></div>

## 📐 Operating Principles

> [!IMPORTANT]
> One active challenge at a time · fan-out only **inside** a challenge · delegate large reads to a subagent and pull back **conclusions only** · typed `.rat/events/STATE.v2.jsonl` is the canonical state stream (`STATE.jsonl` is legacy inspection/import only) · **no reinventing** what an existing tool already does.

<div align="right"><a href="#readme-top">↑ back to top</a></div>

<div align="center">

---

Made for the CTF grind · <b>route → verify → reuse</b>

</div>
