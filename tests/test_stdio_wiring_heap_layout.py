"""Regression for issue #106: child stdio wiring shifts the heap layout.

The reported symptom was a SIGSEGV in ``tcache_get`` that reproduced only when
the target's stdout/stderr were inherited (pwntools' default ``process()``,
which attaches a PTY) and vanished with ``stderr=DEVNULL``. The mechanism is not
a heap bug: when stdout is a TTY, glibc makes it line-buffered and allocates a
differently sized stdio buffer from the heap than when stdout is a pipe/file
(fully-buffered). That buffer preempts heap space, so *subsequent* chunk
addresses move -- even with ASLR disabled. ``stderr`` itself is unbuffered and
does not move the heap, so it was never the real variable.

These tests pin the mechanism deterministically without asserting any exact
buffer size (buffer sizing depends on glibc/device ``st_blksize`` and is not a
portable constant -- we only require that the difference exists and that stderr
does not move the heap).
"""
import os
import pty
import shutil
import subprocess
import sys
import tempfile
import unittest


# A program that allocates a chunk, forces one stdout write (which triggers the
# stdio buffer allocation iff stdout is buffered), allocates a second chunk, and
# reports both chunk addresses plus isatty(1) on stderr. The B-A gap grows by
# the stdio buffer chunk size when stdout is buffered.
PROBE_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    void *a = malloc(0x30);
    printf(" ");            /* first stdout I/O: may allocate the stdio buffer */
    fflush(stdout);
    void *b = malloc(0x30);
    fprintf(stderr, "A=%p B=%p GAP=%ld ISATTY1=%d\n",
            a, b, (long)((char *)b - (char *)a), isatty(1));
    return 0;
}
"""

# A program that only writes to stderr, then reports the first-chunk address.
# stderr is unbuffered, so the chunk address must not depend on stderr wiring.
STDERR_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    fprintf(stderr, "noise\n");
    fflush(stderr);
    void *p = malloc(0x30);
    fprintf(stderr, "P=%p ISATTY2=%d\n", p, isatty(2));
    return 0;
}
"""


def _compile(c_source, out_path):
    src = out_path + ".c"
    with open(src, "w", encoding="utf-8") as f:
        f.write(c_source)
    subprocess.run(["gcc", "-O0", src, "-o", out_path], check=True, capture_output=True)


def _argv(binary):
    # ASLR off so the only variable is stdio wiring, matching the issue report.
    setarch = shutil.which("setarch")
    return ([setarch, "-R", binary] if setarch else [binary])


def _parse(stderr_text):
    # The probe's result line starts with "A=" or "P="; ignore any other noise.
    for line in stderr_text.splitlines():
        if line.startswith(("A=", "P=")):
            return dict(
                tok.split("=", 1) for tok in line.split() if "=" in tok)
    raise AssertionError("probe produced no result line: %r" % stderr_text)


def _run_stdout_pipe(binary):
    """Run with stdout as a pipe (fully-buffered); capture stderr."""
    proc = subprocess.run(
        _argv(binary), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=30)
    return _parse(proc.stderr)


def _run_stdout_pty(binary):
    """Run with stdout on a pseudo-terminal (line-buffered); capture stderr."""
    err_r, err_w = os.pipe()
    pid, master = pty.fork()
    if pid == 0:  # child: stdout is the pty slave (a TTY); stderr -> our pipe
        try:
            os.close(err_r)
            os.dup2(err_w, 2)
            os.close(err_w)
            devnull = os.open(os.devnull, os.O_RDONLY)
            os.dup2(devnull, 0)
            os.execvp(_argv(binary)[0], _argv(binary))
        finally:
            os._exit(127)
    os.close(err_w)
    chunks = []
    while True:
        try:
            data = os.read(err_r, 4096)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    os.close(err_r)
    # Drain the pty master so the child is not blocked on a full buffer.
    try:
        while True:
            if not os.read(master, 4096):
                break
    except OSError:
        pass
    os.close(master)
    os.waitpid(pid, 0)
    return _parse(b"".join(chunks).decode(errors="replace"))


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux glibc stdio behavior")
@unittest.skipUnless(shutil.which("gcc"), "requires gcc")
class StdioWiringHeapLayout(unittest.TestCase):
    def test_stdout_tty_vs_pipe_shifts_subsequent_heap_chunks(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "probe")
            _compile(PROBE_SRC, binary)
            pipe = _run_stdout_pipe(binary)
            tty = _run_stdout_pty(binary)

            # Sanity: the two runs really had different stdout tty-ness.
            self.assertEqual(pipe["ISATTY1"], "0", pipe)
            self.assertEqual(tty["ISATTY1"], "1", tty)

            gap_pipe = int(pipe["GAP"])
            gap_tty = int(tty["GAP"])
            # Each path allocates a stdio buffer between A and B, so both gaps are
            # nonzero; the point is that they differ because the buffer size
            # differs with tty-ness. We assert the *existence* of the shift, not
            # any specific size (buffer sizing is not a portable constant).
            self.assertGreater(gap_pipe, 0, pipe)
            self.assertGreater(gap_tty, 0, tty)
            self.assertNotEqual(
                gap_pipe, gap_tty,
                "stdout tty-ness did not change the heap chunk spacing; the "
                "#106 mechanism (stdio buffer preempting heap) is not reproduced")

    def test_stderr_wiring_does_not_move_the_heap(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "eprobe")
            _compile(STDERR_SRC, binary)
            # stderr -> pipe vs stderr -> /dev/null: the first user chunk address
            # (relative layout) must be identical because stderr is unbuffered.
            pipe = subprocess.run(
                _argv(binary), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, timeout=30)
            # Re-run with stderr pointed at a regular file (a different non-tty
            # sink) to confirm the chunk address does not depend on it.
            tmp = os.path.join(d, "err.txt")
            with open(tmp, "w") as errf:
                subprocess.run(
                    _argv(binary), stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=errf, timeout=30)
            with open(tmp, encoding="utf-8") as f:
                file_run = _parse(f.read())
            pipe_run = _parse(pipe.stderr)
            # Neither run has stderr on a tty; both are non-tty, and the chunk
            # address must match regardless of which non-tty sink stderr uses.
            self.assertEqual(pipe_run["ISATTY2"], "0", pipe_run)
            self.assertEqual(file_run["ISATTY2"], "0", file_run)
            self.assertEqual(
                pipe_run["P"], file_run["P"],
                "stderr sink changed the heap layout; stderr is unbuffered and "
                "must not move the heap (see #106)")


if __name__ == "__main__":
    unittest.main()
