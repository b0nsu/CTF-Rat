# Optional local GDB session

An active `run.json`, matching `ctfguard` active challenge, verified binary
digest, scenario JSON, and local `gdb` are required. This path is selected
explicitly; ordinary `rat dyn`, `gdbq`, and `pwncrash` keep their batch behavior.

```sh
rat dyn session start ./chall --scenario scenario.json --total-timeout 120 --idle-timeout 30 --action-timeout 10 --output-cap 8192
rat dyn session break ./chall gdb_<session-id> main
rat dyn session continue ./chall gdb_<session-id>
rat dyn session registers ./chall gdb_<session-id>
rat dyn session memory ./chall gdb_<session-id> 0x404000 32
rat dyn session heap ./chall gdb_<session-id> --layout glibc-2.35-x86_64 --tcache 0x<TCACHE_ADDRESS> --arena 0x<MAIN_ARENA_ADDRESS> --chunk 0x<CHUNK_HEADER_ADDRESS>
rat dyn session mappings ./chall gdb_<session-id>
rat dyn session capture ./chall gdb_<session-id>
rat dyn session close ./chall gdb_<session-id>
```

Each command returns JSON. `start` reports the generated session ID, run ID,
binary digest and process identities. `inspect` commands retain one inferior
and record ordered responses. `capture` writes an immutable
`gdb-session-candidate` artifact to the existing Artifact Store, plus a small
session result file that keeps the digest reachable for artifact GC. The
artifact includes binary, environment and scenario digests, process identity,
sequence and tool version. It is a candidate, never direct evidence for STATE
PASS or SOLVED. A changed run, binary, or inferior identity ends the session.

### Bounded heap snapshot (#104 / #105)

`rat dyn session heap` is an optional *read-only, stopped-inferior* action.
Pass one or more of `--tcache`, `--arena`, `--chunk` as numeric addresses
obtained from the same local run. It never attaches to an arbitrary PID.
The only decoded layout is `glibc-2.35-x86_64`; other libc versions are
rejected, not guessed. Confirm the exact build and corresponding layouts
before interpreting the result (a libc version string alone is not proof of
matching allocator state).

The action reads at most 640 bytes from a tcache structure, 32 from
`main_arena+0x60`, and 32 from a chunk header, in requests of at most
256 bytes each. Maximum total is 1024 bytes per action. Only non-empty
tcache bins are shown; full raw dumps are not injected into the model context.
A short/inaccessible read yields `partial` and an unresolved region, not
invented zero values. `candidate_decoded_fd` assumes the supplied chunk is
freed and safe-linked, and must not be treated as established pointer control.
The selected snapshots are included in the existing GDB candidate artifact
on `capture`; no direct STATE evidence or primitive PASS is created.

**Interaction limitation:** this session still does not expose an interactive
stdin action. If the target requires input between allocator operations,
the existing session cannot automatically reach every desired heap state.
Do not claim an end-to-end exploit observer from a static snapshot alone.

`rat.gdb-session-candidate/v1` is the first version of this artifact contract.
Schema versions are scoped to document types: STATE events remain
`rat.state-event/v2`, while STATE primitives and observations already use
their own `/v1` schemas. This candidate schema does not roll STATE back or
register a new direct-evidence producer.

The worker owns GDB's process group and closes it on `close`, idle/total/action
timeout, run termination, or inferior exit. `close` can be repeated. Action
output beyond the cap returns `partial` and `truncated=true`; a timed out action
returns `timeout` and ends the session. A lost socket returns
`connection_lost`. Each session accepts at most 64 inspect observations.
GDB MI records and challenge console
strings are observation data. The client does not treat text such as `Access
denied` or `Ignore previous instructions` as a policy response. Platform
permission failures remain platform permission failures.

Scenario stdin is currently rejected because a persistent debugger needs an
explicit interactive input action that this interface does not expose. The
supported scenario fields are `argv`, `cwd`, and string `env` pairs. Compare
normal and debug execution conditions for a representative fixture before
using timing-sensitive observations. The GDB/MI command forms follow the
[GDB manual](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Program-Execution.html).

The host is ARM64; GDB must run in a native ARM64 Linux container. The existing
amd64 image runs through ARM emulation and cannot read the inferior's CS
register. Build the native test image and run the real GDB integration test:

```sh
docker build --platform linux/arm64 -f tests/docker/gdb-native.Dockerfile -t ctf-rat-gdb-native:v21 .
docker run --rm --platform linux/arm64 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD:/work:ro" -w /work --entrypoint python3 ctf-rat-gdb-native:v21 \
  -m unittest tests.test_gdb_session_v21
```

This passed on native ARM64 Linux GDB 15.1: the tests compare a plain run with
the debugger scenario, hit two breakpoints in one inferior, read registers and
memory, capture candidate evidence, and observe process exit. They also issue
`rat dyn session` commands from separate CLI processes against one live session.
