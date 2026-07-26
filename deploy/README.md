# Privileged deployment

Install the broker code at `/opt/ctf-rat` (root-owned, read-only to agents),
create the `ratbroker` system user and a 0600 receipt key, then install the
`rat-broker.service` unit. The daemon owns its socket directly; do not enable
the optional socket-activation template at the same time. `/etc/ratbroker/environment` must define `CTF_HOME`,
`RAT_AGENT_UID`, `RAT_BROKER_KEY_PATH`, `RAT_RUNTIME_DIR`, `RAT_SHARED_STORE=1`, and
`RAT_BROKER_REQUIRE_SOCKET=1`.

Keep code root-owned, but provision `/opt/ctf-rat/solve` as the shared,
setgid challenge-state directory for the agent and broker group (including
existing challenge subdirectories and their `.rat` stores). Provision
`RAT_RUNTIME_DIR` (normally `/var/lib/ratbroker/runtime`) as `root:ratbroker`
mode `2770`; `ctfguard`, `state`, and the broker read the same
`RAT_RUNTIME_DIR/ACTIVE.json`. This keeps the target lock mutable without
making the installed code tree writable. Its parent `/var/lib/ratbroker` must
be `0710 root:ratbroker` so agents can traverse only to this shared child;
keep the receipt key itself `0600 ratbroker:ratbroker`.

The unit intentionally does not set `NoNewPrivileges=true`: the broker runs
Bubblewrap's reviewed setuid helper to create the sandbox namespace. If that
transition is prohibited, execution fails closed rather than falling back to
the host.

For target-filtered networking, install `rat-netns-root` as
`/usr/local/libexec/rat-netns-root` (root:root, 0755) and the supplied sudoers
file. Set `RAT_BROKER_NETWORK_RUNNER=/opt/ctf-rat/bin/rat-netns-runner` only
after an administrator has reviewed the helper. It creates a per-invocation
network namespace, pins the target's resolved IPv4 addresses, and permits only
TCP to the requested port. Hostname targets additionally need a pinned hosts
file injected into Bubblewrap before enabling production use.
