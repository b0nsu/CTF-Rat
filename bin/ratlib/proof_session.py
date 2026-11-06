"""Bounded leak-to-payload strategy for local GDB proof runs.

The payload depends only on inferior output, never debugger symbol addresses.
The debugger separately observes the resulting transfer. No user Python or
shell command is accepted in a strategy.
"""
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid

# Upper bound on the inferior stdout we will capture and re-verify per run.
# This is NOT a limit on normal program output: a benign binary may legitimately
# print many kilobytes before the success oracle (e.g. a menu, a dump, progress
# chatter), and an earlier 64 KiB cap enforced with RLIMIT_FSIZE silently killed
# such binaries with SIGXFSZ -> non-zero exit -> rejected proof.  The cap exists
# only to bound forgery/DoS surface, so it is sized for realistic chatty output
# while still being finite.  Every read/size check below uses this one constant;
# reads request OUTPUT_CAP+1 bytes so an overflow is detectable rather than
# silently truncated.  proof_session.py is content-addressed (its digest is
# bound into the invocation and re-checked at verify time), so this value is
# pinned to whatever bytes verified the run.
OUTPUT_CAP = 4 * 1024 * 1024  # 4 MiB

# Wall-clock the leak feeder waits for the inferior's first-line leak.  The feeder
# MUST poll from Session construction, not from `run`: `run` blocks inside GDB
# until the inferior stops at the breakpoint, and the inferior itself blocks on
# read() for the feeder's leak-derived payload, so a feeder that waited for `run`
# to return would deadlock.  An earlier hardcoded 5s rejected valid same-session
# proofs whenever GDB startup plus the inferior's time-to-first-leak exceeded 5s
# (loaded host, emulation, block-buffered stdout).
#
# This is a FIXED cap, defaulting to 60s (matching rat-adapt/execute()'s default
# --timeout), not something auto-derived from the outer --timeout: the Session runs
# inside GDB and has no channel to that value.  So a proof run with --timeout > 60
# would otherwise be cut short HERE by this inner feeder deadline.  To let the inner
# window track a larger external budget, the operator sets RAT_PROOF_LEAK_WAIT (the
# environment is inherited by the gdbq subprocess and thus by this feeder).
try:
    LEAK_WAIT_SECONDS = float(os.environ.get("RAT_PROOF_LEAK_WAIT") or 60.0)
    if LEAK_WAIT_SECONDS <= 0:
        LEAK_WAIT_SECONDS = 60.0
except (TypeError, ValueError):
    LEAK_WAIT_SECONDS = 60.0


def _read_capped(path):
    """Read a session output file, rejecting anything over the cap.

    Returns the bytes (<= OUTPUT_CAP).  A file larger than the cap raises, so a
    runaway or forged capture cannot be silently truncated into a false match.
    """
    with open(path, "rb") as stream:
        data = stream.read(OUTPUT_CAP + 1)
    if len(data) > OUTPUT_CAP:
        raise ValueError("session output exceeds cap")
    return data


def load_strategy(path):
    with open(path, "rb") as stream:
        raw = stream.read(8193)
    return decode_strategy(raw)


def decode_strategy(raw):
    if len(raw) > 8192:
        raise ValueError("session strategy exceeds 8192 bytes")
    obj = json.loads(raw)
    fields = {"schema", "leak_prefix", "prefix_hex", "suffix_hex", "offset",
              "control_offset", "expect"}
    if not isinstance(obj, dict) or set(obj) != fields or obj["schema"] != "rat.proof-session/v1":
        raise ValueError("invalid session strategy fields")
    for key in ("leak_prefix", "expect"):
        if not isinstance(obj[key], str) or not 1 <= len(obj[key].encode()) <= 128 or "\n" in obj[key]:
            raise ValueError("invalid session " + key)
    for key in ("prefix_hex", "suffix_hex"):
        if not isinstance(obj[key], str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,64}", obj[key]):
            raise ValueError("invalid session payload bytes")
    for key in ("offset", "control_offset"):
        if type(obj[key]) is not int or not -(2**31) <= obj[key] < 2**31:
            raise ValueError("invalid session offset")
    if obj["offset"] == obj["control_offset"]:
        raise ValueError("session primary and control offsets must differ")
    return obj


def payload_for(strategy, leak, control=False):
    target = leak + strategy["control_offset" if control else "offset"]
    if not 0 < target < 2**64:
        raise ValueError("session target outside uint64")
    return (bytes.fromhex(strategy["prefix_hex"]) + target.to_bytes(8, "little")
            + bytes.fromhex(strategy["suffix_hex"]))


class Session:
    """Used only by generated GDB commands, one instance per inferior run."""
    def __init__(self, strategy, label):
        import gdb
        # The capture is bounded on the READ side only: _read_capped and
        # parse_sessions reject anything over OUTPUT_CAP, so a runaway or forged
        # capture can never be truncated into a false match.  An earlier
        # RLIMIT_FSIZE here was process-wide and inherited by the inferior, so a
        # target writing >OUTPUT_CAP to any unrelated scratch file (not just the
        # stdout capture) was killed with SIGXFSZ -> non-zero exit -> the proof
        # was rejected despite a valid leak and oracle.  Bounding the capture does
        # not require constraining every file the inferior writes, so no process
        # resource limit is imposed here.
        self.strategy, self.label = strategy, label
        self.directory = tempfile.TemporaryDirectory(prefix="rat-proof-session-")
        self.fifo = os.path.join(self.directory.name, "stdin")
        self.output = os.path.join(self.directory.name, "stdout")
        os.mkfifo(self.fifo, 0o600)
        open(self.output, "wb").close()
        self.fd = os.open(self.fifo, os.O_RDWR | os.O_NONBLOCK)
        self.record = {"session_id": uuid.uuid4().hex, "label": label, "pid": None,
                       "exit_code": None, "error": None}
        self.thread = threading.Thread(target=self._feed, daemon=True)
        self.exit_handler = lambda event: self.record.update(exit_code=getattr(event, "exit_code", None))
        gdb.events.exited.connect(self.exit_handler)
        self.thread.start()

    def command(self):
        import shlex
        return "run < " + shlex.quote(self.fifo) + " > " + shlex.quote(self.output) + " 2>&1"

    def _feed(self):
        try:
            # Poll from construction (see LEAK_WAIT_SECONDS): the window is sized to
            # the external proof --timeout instead of a tighter hardcoded 5s.
            deadline = time.monotonic() + LEAK_WAIT_SECONDS
            while time.monotonic() < deadline:
                data = _read_capped(self.output)
                if b"\n" in data:
                    line = data.split(b"\n", 1)[0]
                    prefix = self.strategy["leak_prefix"].encode()
                    if not line.startswith(prefix) or not re.fullmatch(rb"0x[0-9a-fA-F]{1,16}", line[len(prefix):]):
                        raise ValueError("session has no valid first-line leak")
                    leak = int(line[len(prefix):], 16)
                    payload = payload_for(self.strategy, leak)
                    os.write(self.fd, payload)
                    self.record.update(leak=leak, leak_line_hex=line.hex(), payload_hex=payload.hex())
                    return
                time.sleep(0.005)
            raise ValueError("session leak timeout")
        except Exception as exc:
            self.record["error"] = str(exc)
        finally:
            os.close(self.fd)

    def note_pid(self):
        import gdb
        self.record["pid"] = gdb.selected_inferior().pid
        # A benign target can print more than OUTPUT_CAP before the breakpoint;
        # that is an oversized-capture rejection, not a reason to abort the whole
        # gdbq run with an uncaught ValueError here (finish() handles the same case
        # gracefully).  Record the error and the capped bytes so parse_sessions
        # fails closed instead.
        try:
            self.record["pre_transfer_stdout_hex"] = _read_capped(self.output).hex()
        except ValueError:
            with open(self.output, "rb") as stream:
                self.record["pre_transfer_stdout_hex"] = stream.read(OUTPUT_CAP).hex()
            self.record["error"] = "incomplete or oversized session"

    def finish(self):
        import gdb
        # By the time `continue` has returned (inferior exited) the feeder has long
        # since consumed the leak and returned, so this join is near-instant on the
        # happy path.  It stays short so finish() always prints its record well
        # inside the external proof --timeout; if the feeder is somehow still alive
        # (no leak was ever produced) the is_alive() check below fails the proof
        # closed without this call having to block for the whole leak window.
        self.thread.join(timeout=6)
        gdb.events.exited.disconnect(self.exit_handler)
        try:
            data = _read_capped(self.output)
        except ValueError:
            # Over-cap output is a rejected capture, not a crash: record the
            # error and emit whatever fits so parse_sessions fails closed.
            with open(self.output, "rb") as stream:
                data = stream.read(OUTPUT_CAP)
            self.record["error"] = "incomplete or oversized session"
        self.record["stdout_hex"] = data.hex()
        if self.thread.is_alive():
            self.record["error"] = "incomplete or oversized session"
        print("RAT_SESSION_" + self.label + "=" + json.dumps(self.record, sort_keys=True))
        self.directory.cleanup()


def parse_sessions(text, strategies, labels):
    """Re-verify each per-run capture against the strategy bound to its label.

    `strategies` is either one strategy applied to every label, or a
    {label: strategy} map so each run's payload is checked against the very
    strategy file whose bytes drove it (the control run uses the control file).
    """
    # A single strategy is itself a dict carrying "schema"; a per-label map is
    # keyed by labels, so distinguish on that key rather than the type.
    per_label = "schema" not in strategies
    records = []
    for label in labels:
        strategy = strategies[label] if per_label else strategies
        matches = re.findall(r"(?m)^RAT_SESSION_" + label + r"=(\{[^\n]+\})$", text)
        if len(matches) != 1:
            raise ValueError("missing or repeated session capture")
        record = json.loads(matches[0])
        if (record.get("label") != label or record.get("error") is not None
                or type(record.get("pid")) is not int or record["pid"] <= 0
                or record.get("exit_code") != 0
                or not re.fullmatch(r"[0-9a-f]{32}", record.get("session_id", ""))):
            raise ValueError("session did not complete normally")
        data = bytes.fromhex(record["stdout_hex"])
        if len(data) > OUTPUT_CAP:
            raise ValueError("oversized session capture")
        first = data.split(b"\n", 1)[0]
        prefix = strategy["leak_prefix"].encode()
        if (first.hex() != record["leak_line_hex"] or not first.startswith(prefix)
                or not re.fullmatch(rb"0x[0-9a-fA-F]{1,16}", first[len(prefix):])):
            raise ValueError("session leak differs from inferior output")
        leak = int(first[len(prefix):], 16)
        expected = payload_for(strategy, leak)
        if leak != record["leak"] or record["payload_hex"] != expected.hex():
            raise ValueError("session payload is not derived from its own leak")
        before = bytes.fromhex(record["pre_transfer_stdout_hex"])
        if not data.startswith(before) or strategy["expect"].encode() not in data[len(before):]:
            raise ValueError("session oracle failed")
        records.append(record)
    if len({r["session_id"] for r in records}) != len(records):
        raise ValueError("session capture reused across runs")
    return records
