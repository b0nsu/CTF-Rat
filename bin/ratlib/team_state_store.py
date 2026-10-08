"""Shared team STATE v2 snapshot closure and repository coordination checks."""
from __future__ import annotations
import contextlib
import fcntl
import hashlib, json, os, re, subprocess
from dataclasses import dataclass

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_LOCK_DEPTH = {"repo": 0, "author": 0}


def require_plain_under(root, path, label):
    root_abs = os.path.abspath(root)
    path_abs = os.path.abspath(path)
    try:
        rel = os.path.relpath(path_abs, root_abs)
    except ValueError as exc:
        raise ValueError("%s escapes root: %s" % (label, path)) from exc
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        raise ValueError("%s escapes root: %s" % (label, path))
    cur = root_abs
    for part in [] if rel == "." else rel.split(os.sep):
        cur = os.path.join(cur, part)
        if os.path.lexists(cur) and os.path.islink(cur):
            raise ValueError("%s must not be a symlink: %s" % (label, cur))
    real_root = os.path.realpath(root_abs)
    real_path = os.path.realpath(path_abs)
    if os.path.commonpath((real_root, real_path)) != real_root:
        raise ValueError("%s escapes root: %s" % (label, path))


def require_plain_dir_under(root, path, label, *, required=True):
    require_plain_under(root, path, label)
    if required and not os.path.isdir(path):
        raise ValueError("%s is not a directory: %s" % (label, path))


def _ensure_lock_file(root, path, label):
    require_plain_under(root, path, label)
    if os.path.lexists(path) and os.path.islink(path):
        raise ValueError("%s must not be a symlink: %s" % (label, path))
    return path


def _lock_base(repo):
    # Assumes .git is a plain directory (a normal checkout), not a file pointing
    # elsewhere -- require_plain_dir_under below will raise on git worktrees /
    # submodules, where .git is a file. Acceptable for this repo's usage model
    # (one shared team checkout), but not a general-purpose git assumption.
    git_dir = os.path.join(repo, ".git")
    require_plain_dir_under(repo, git_dir, ".git")
    base = os.path.join(git_dir, "teamsync-locks")
    require_plain_under(git_dir, base, "teamsync lock dir")
    os.makedirs(base, mode=0o700, exist_ok=True)
    require_plain_dir_under(git_dir, base, "teamsync lock dir")
    return base


@contextlib.contextmanager
def repo_lock(repo):
    """Serialize all mutations of the shared team Git checkout.

    Contract: callers acquire this repository lock before any author lock.
    """
    if _LOCK_DEPTH["author"]:
        raise RuntimeError("repository lock must be acquired before author lock")
    path = _ensure_lock_file(os.path.join(repo, ".git"), os.path.join(_lock_base(repo), "git.lock"), "repository lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            _LOCK_DEPTH["repo"] += 1
            try:
                yield
            finally:
                _LOCK_DEPTH["repo"] -= 1
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    finally:
        pass


@contextlib.contextmanager
def author_lock(repo, chal, author):
    """Serialize one author's CURRENT/snapshot publication under repo_lock."""
    if not _LOCK_DEPTH["repo"]:
        raise RuntimeError("author lock requires repository lock")
    name = "%s.%s.lock" % (chal, author)
    path = _ensure_lock_file(os.path.join(repo, ".git"), os.path.join(_lock_base(repo), name), "author lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            _LOCK_DEPTH["author"] += 1
            try:
                yield
            finally:
                _LOCK_DEPTH["author"] -= 1
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    finally:
        pass


def require_repo_lock():
    if not _LOCK_DEPTH["repo"]:
        raise RuntimeError("repository lock is required for team Git operations")


@dataclass(frozen=True)
class GitOutcome:
    state: str
    step: str = ""
    returncode: int = 0
    stderr: str = ""


def _relpaths(repo, paths):
    rels = []
    for path in paths:
        require_plain_under(repo, path if os.path.isabs(path) else os.path.join(repo, path), "git path")
        rels.append(os.path.relpath(path if os.path.isabs(path) else os.path.join(repo, path), repo))
    return sorted(set(rels))


def publication_manifest_state(repo, snapshot_root):
    path = os.path.join(snapshot_root, "PUBLICATION.json")
    require_plain_under(repo, snapshot_root, "snapshot")
    if os.path.lexists(path):
        require_plain_under(repo, path, "PUBLICATION")
        if not os.path.isfile(path):
            raise ValueError("PUBLICATION.json is not a regular file: %s" % path)
        return path
    return None


def publication_paths(repo, snapshot_root, current_path, digests, *, require_manifest=True):
    """Return the exact files that make one selected team publication."""
    paths = [
        current_path,
        os.path.join(snapshot_root, ".rat", "events", "STATE.v2.jsonl"),
    ]
    manifest = publication_manifest_state(repo, snapshot_root)
    if manifest:
        paths.append(manifest)
    elif require_manifest:
        raise ValueError("missing PUBLICATION.json for %s" % snapshot_root)
    for digest in sorted(digests):
        paths.extend(artifact_paths(os.path.join(snapshot_root, ".rat"), digest))
    for path in paths:
        require_plain_under(repo, path, "publication closure")
        if not os.path.isfile(path):
            raise ValueError("missing publication closure file: %s" % path)
    return sorted(set(paths))


def validate_publication_lineage(supersedes, reason, *, stream_id, seq):
    """Validate immutable manifest lineage against its selected cursor."""
    if reason not in (None, "explicit replace-lineage"):
        raise ValueError("PUBLICATION.json replacement reason mismatch")
    if supersedes is None:
        if reason is not None:
            raise ValueError("PUBLICATION.json replacement requires prior cursor")
        return
    if not isinstance(supersedes, dict) or set(supersedes) != {"stream_id", "seq", "snapshot"}:
        raise ValueError("PUBLICATION.json supersedes cursor mismatch")
    previous_stream = supersedes.get("stream_id")
    previous_seq = supersedes.get("seq")
    if (not isinstance(previous_stream, str) or not previous_stream or
            not isinstance(previous_seq, int) or previous_seq < 1 or
            supersedes.get("snapshot") != "%s-%d" % (previous_stream, previous_seq)):
        raise ValueError("PUBLICATION.json supersedes cursor mismatch")
    if reason == "explicit replace-lineage":
        if previous_stream == stream_id:
            raise ValueError("PUBLICATION.json replacement must change stream")
    elif previous_stream != stream_id or previous_seq >= seq:
        raise ValueError("PUBLICATION.json advancement lineage mismatch")


def _git_blob_bytes(repo, treeish, rel):
    spec = ("%s:%s" % (treeish, rel)) if treeish else (":" + rel)
    command = ["git", "-C", repo, "show", spec]
    return subprocess.run(command, timeout=30, capture_output=True)


def verify_git_tree_matches(repo, paths, *, treeish="HEAD", timeout=30):
    """Fail unless every selected path is tracked in treeish and byte-identical."""
    rels = _relpaths(repo, paths)
    if treeish == "HEAD":
        head = run_git(repo, ["rev-parse", "--verify", "HEAD"], timeout=timeout, capture=True)
        if head.returncode:
            raise ValueError("HEAD is missing selected publication paths")
    for rel in rels:
        blob = _git_blob_bytes(repo, treeish if treeish != "INDEX" else "", rel)
        if blob.returncode:
            raise ValueError("%s missing selected publication path: %s" % (treeish, rel))
        local = read_bytes_under(repo, os.path.join(repo, rel), "selected publication")
        if blob.stdout != local:
            raise ValueError("%s selected publication path differs from working tree: %s" % (treeish, rel))


def selection_parent_current(repo, current_path, snapshot, *, timeout=30):
    """Return the cursor selected immediately before HEAD first selected snapshot.

    The newest transition to ``snapshot`` is the immutable publication event;
    later manifest-only commits must not be able to rewrite its predecessor.
    """
    rel = _relpaths(repo, [current_path])[0]
    history = run_git(repo, ["log", "--format=%H", "HEAD", "--", rel], timeout=timeout, capture=True)
    if history.returncode:
        raise ValueError("cannot read CURRENT history")
    for commit in history.stdout.splitlines():
        selected = run_git(repo, ["show", "%s:%s" % (commit, rel)], timeout=timeout, capture=True)
        if selected.returncode or selected.stdout.strip() != snapshot:
            continue
        parent = run_git(repo, ["rev-parse", commit + "^"], timeout=timeout, capture=True)
        if parent.returncode:
            return None
        previous = run_git(repo, ["show", "%s:%s" % (parent.stdout.strip(), rel)], timeout=timeout, capture=True)
        return previous.stdout.strip() if previous.returncode == 0 else None
    raise ValueError("HEAD never selected snapshot %s" % snapshot)


def verify_publication_predecessor(repo, snapshots_root, cursor):
    """Prove a manifest's immediate predecessor exists in the committed tree."""
    snapshot = os.path.join(snapshots_root, cursor["snapshot"])
    event_path = os.path.join(snapshot, ".rat", "events", "STATE.v2.jsonl")
    require_plain_under(repo, snapshot, "publication predecessor")
    if not os.path.isfile(event_path):
        raise ValueError("PUBLICATION.json predecessor snapshot is missing")
    data = read_bytes_under(repo, event_path, "publication predecessor stream")
    events = parse_state_events(data, allow_partial_tail=False)
    last = events[-1]
    if last["stream_id"] != cursor["stream_id"] or last["seq"] != cursor["seq"]:
        raise ValueError("PUBLICATION.json predecessor cursor mismatch")
    verify_git_tree_matches(repo, [event_path], treeish="HEAD")


def run_git(repo, args, *, timeout=30, capture=False):
    io = {"capture_output": True} if capture else {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    command = ["git", "-C", repo, *args]
    try:
        return subprocess.run(command, timeout=timeout, text=True, **io)
    except subprocess.TimeoutExpired as exc:
        stderr = "git %s timed out after %ss" % (args[0] if args else "command", timeout)
        return subprocess.CompletedProcess(command, 124, stdout=exc.stdout or "", stderr=stderr)


def conflict_state(repo, *, timeout=30):
    """Return a GitOutcome when the worktree/index is in a merge/rebase conflict."""
    git_dir = run_git(repo, ["rev-parse", "--git-dir"], timeout=timeout, capture=True)
    git_path = os.path.join(repo, ".git")
    if git_dir.returncode == 0:
        value = git_dir.stdout.strip()
        git_path = value if os.path.isabs(value) else os.path.join(repo, value)
    try:
        require_plain_dir_under(repo, git_path, ".git")
        for marker in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"):
            marker_path = os.path.join(git_path, marker)
            if os.path.lexists(marker_path):
                return GitOutcome("conflict", marker.lower(), 1, "repository has unresolved %s" % marker)
        for marker in ("rebase-merge", "rebase-apply"):
            marker_path = os.path.join(git_path, marker)
            if os.path.lexists(marker_path):
                return GitOutcome("conflict", marker, 1, "repository has unresolved %s" % marker)
    except ValueError as exc:
        return GitOutcome("conflict", "git-dir", 1, str(exc))
    unmerged = run_git(repo, ["ls-files", "-u"], timeout=timeout, capture=True)
    if unmerged.returncode:
        return GitOutcome("conflict", "ls-files", unmerged.returncode, unmerged.stderr)
    if unmerged.stdout.strip():
        return GitOutcome("conflict", "unmerged", 1, unmerged.stdout)
    return None


def abort_in_progress_rebase(repo, *, timeout=30):
    """Abort a rebase left in progress by a failed pull.

    Without this, a conflicted ``pull --rebase`` leaves .git/rebase-merge (or
    rebase-apply) in place, and conflict_state() then makes EVERY subsequent sync for
    EVERY author return "conflict" until a human runs ``git rebase --abort`` -- a shared
    availability wedge. The local commit is already durable on the branch, so aborting
    only means this round did not integrate remote changes; the next sync retries from a
    clean tree. Returns True if a rebase was aborted.
    """
    git_dir = run_git(repo, ["rev-parse", "--git-dir"], timeout=timeout, capture=True)
    git_path = os.path.join(repo, ".git")
    if git_dir.returncode == 0:
        value = git_dir.stdout.strip()
        git_path = value if os.path.isabs(value) else os.path.join(repo, value)
    if any(os.path.lexists(os.path.join(git_path, m)) for m in ("rebase-merge", "rebase-apply")):
        run_git(repo, ["rebase", "--abort"], timeout=timeout, capture=True)
        return True
    return False


def sync_paths(repo, paths, message, *, push=True, timeout=30):
    """Stage path-scoped changes, commit them, then optionally pull/rebase and push.

    Must run while repo_lock is held. Outcomes are intentionally coarse and
    stable for CLI diagnostics: unchanged, committed, local-only, remote-synced,
    or failed.
    """
    require_repo_lock()
    conflict = conflict_state(repo, timeout=timeout)
    if conflict:
        return conflict
    rels = _relpaths(repo, paths)
    if not rels:
        return GitOutcome("unchanged")
    added = run_git(repo, ["add", "-f", "--", *rels], timeout=timeout, capture=True)
    if added.returncode:
        return GitOutcome("failed", "add", added.returncode, added.stderr)
    try:
        verify_git_tree_matches(repo, rels, treeish="INDEX", timeout=timeout)
    except ValueError as exc:
        return GitOutcome("failed", "verify-index", 1, str(exc))
    diff = run_git(repo, ["diff", "--cached", "--quiet", "--", *rels], timeout=timeout, capture=True)
    if diff.returncode not in (0, 1):
        return GitOutcome("failed", "diff", diff.returncode, diff.stderr)
    committed = False
    if diff.returncode == 1:
        commit = run_git(repo, ["commit", "-q", "-m", message, "--", *rels], timeout=timeout, capture=True)
        if commit.returncode:
            return GitOutcome("local-only", "commit", commit.returncode, commit.stderr)
        committed = True
    try:
        verify_git_tree_matches(repo, rels, treeish="HEAD", timeout=timeout)
    except ValueError as exc:
        return GitOutcome("local-only", "verify-head", 1, str(exc))
    remote = run_git(repo, ["remote"], timeout=timeout, capture=True)
    if remote.returncode:
        return GitOutcome("failed", "remote", remote.returncode, remote.stderr)
    if not push or not remote.stdout.strip():
        return GitOutcome("committed" if committed else "unchanged")
    # Pull-then-push, retried a bounded number of times so a push rejected by a remote
    # that advanced mid-sync self-heals instead of silently staying local-only.
    attempts = 3
    for attempt in range(attempts):
        pull = run_git(repo, ["pull", "-q", "--rebase"], timeout=timeout, capture=True)
        if pull.returncode:
            # Abort a conflicted rebase before returning so it cannot wedge the shared
            # repo for other authors. The local commit remains; this round is local-only.
            if abort_in_progress_rebase(repo, timeout=timeout):
                return GitOutcome("local-only", "pull-rebase-aborted", pull.returncode, pull.stderr)
            conflict = conflict_state(repo, timeout=timeout)
            if conflict:
                return conflict
            # First publish of this branch: with no upstream, `pull --rebase` fails with
            # "no tracking information" and the branch could otherwise never be pushed.
            # Create the remote branch and set tracking with an initial push -u.
            if "no tracking information" in (pull.stderr or "").lower():
                first = run_git(repo, ["push", "-q", "-u", "origin", "HEAD"], timeout=timeout, capture=True)
                if first.returncode:
                    return GitOutcome("local-only", "push", first.returncode, first.stderr)
                break
            return GitOutcome("local-stale", "pull", pull.returncode, pull.stderr)
        try:
            verify_git_tree_matches(repo, rels, treeish="HEAD", timeout=timeout)
        except ValueError as exc:
            return GitOutcome("local-stale", "verify-head", 1, str(exc))
        push_result = run_git(repo, ["push", "-q"], timeout=timeout, capture=True)
        if push_result.returncode == 0:
            break
        if attempt == attempts - 1:
            return GitOutcome("local-only", "push", push_result.returncode, push_result.stderr)
    upstream = run_git(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], timeout=timeout, capture=True)
    if upstream.returncode:
        return GitOutcome("local-only", "upstream", upstream.returncode, upstream.stderr)
    ahead = run_git(repo, ["rev-list", "--count", "%s..HEAD" % upstream.stdout.strip(), "--", *rels], timeout=timeout, capture=True)
    if ahead.returncode or int(ahead.stdout.strip() or "0"):
        return GitOutcome("local-only", "verify-push", ahead.returncode or 1, ahead.stderr)
    return GitOutcome("remote-synced")


def remote_trust(repo, paths, *, timeout=30, refresh=True):
    """Return local/remote freshness for selected publication paths.

    NOT read-only despite the name when ``refresh=True`` (the default, kept for
    existing callers that already hold repo_lock and expect the old behavior):
    it runs `git pull --rebase` to compare against the remote, mutating the
    working tree. Safe only because callers hold repo_lock and a wedged rebase
    is auto-aborted (mirrors sync_paths' wedge guard).

    Pass ``refresh=False`` for a genuine read-only freshness check: it compares
    HEAD against the existing remote-tracking ref (whatever the last fetch/pull
    left it at) without running `git pull`. The reported state can be stale if
    nobody has fetched recently -- callers that need a guaranteed-fresh view
    must still opt into ``refresh=True``.
    """
    require_repo_lock()
    conflict = conflict_state(repo, timeout=timeout)
    if conflict:
        return conflict
    rels = _relpaths(repo, paths)
    dirty = run_git(repo, ["status", "--porcelain", "--", *rels], timeout=timeout, capture=True)
    if dirty.returncode:
        return GitOutcome("local-stale", "status", dirty.returncode, dirty.stderr)
    if dirty.stdout.strip():
        return GitOutcome("local-only", "dirty", 1, dirty.stdout)
    remote = run_git(repo, ["remote"], timeout=timeout, capture=True)
    if remote.returncode:
        return GitOutcome("local-stale", "remote", remote.returncode, remote.stderr)
    if not remote.stdout.strip():
        return GitOutcome("local")
    if not refresh:
        upstream = run_git(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], timeout=timeout, capture=True)
        if upstream.returncode:
            return GitOutcome("local-stale", "upstream", upstream.returncode, upstream.stderr)
        ahead = run_git(repo, ["rev-list", "--count", "%s..HEAD" % upstream.stdout.strip(), "--", *rels], timeout=timeout, capture=True)
        behind = run_git(repo, ["rev-list", "--count", "HEAD..%s" % upstream.stdout.strip(), "--", *rels], timeout=timeout, capture=True)
        if ahead.returncode or behind.returncode:
            return GitOutcome("local-stale", "ahead", ahead.returncode or behind.returncode, ahead.stderr or behind.stderr)
        try:
            n_behind = int(behind.stdout.strip() or "0")
        except ValueError:
            n_behind = 1
        if n_behind:
            return GitOutcome("local-stale", "unrefreshed", n_behind, "local view is %d commit(s) behind the last-known remote (no pull run)" % n_behind)
        try:
            n_ahead = int(ahead.stdout.strip() or "0")
        except ValueError:
            n_ahead = 1
        return GitOutcome("local-only" if n_ahead else "remote-synced", "ahead" if n_ahead else "", n_ahead)
    pull = run_git(repo, ["pull", "-q", "--rebase"], timeout=timeout, capture=True)
    if pull.returncode:
        # Same wedge guard as sync_paths: never leave a conflicted rebase behind.
        if abort_in_progress_rebase(repo, timeout=timeout):
            return GitOutcome("local-stale", "pull-rebase-aborted", pull.returncode, pull.stderr)
        conflict = conflict_state(repo, timeout=timeout)
        if conflict:
            return conflict
        return GitOutcome("local-stale", "pull", pull.returncode, pull.stderr)
    dirty = run_git(repo, ["status", "--porcelain", "--", *rels], timeout=timeout, capture=True)
    if dirty.returncode:
        return GitOutcome("local-stale", "status", dirty.returncode, dirty.stderr)
    if dirty.stdout.strip():
        return GitOutcome("conflict", "dirty", 1, dirty.stdout)
    upstream = run_git(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], timeout=timeout, capture=True)
    if upstream.returncode:
        return GitOutcome("local-stale", "upstream", upstream.returncode, upstream.stderr)
    ahead = run_git(repo, ["rev-list", "--count", "%s..HEAD" % upstream.stdout.strip(), "--", *rels], timeout=timeout, capture=True)
    if ahead.returncode:
        return GitOutcome("local-stale", "ahead", ahead.returncode, ahead.stderr)
    try:
        count = int(ahead.stdout.strip() or "0")
    except ValueError:
        count = 1
    return GitOutcome("local-only" if count else "remote-synced", "ahead" if count else "", count)


def read_bytes_under(root, path, label):
    require_plain_under(root, path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("%s cannot be safely read: %s" % (label, exc)) from exc
    with os.fdopen(fd, "rb") as source:
        return source.read()


def parse_state_events(data, *, allow_partial_tail):
    events = []
    stream_id = None
    lines = data.splitlines(keepends=True)
    for n, line in enumerate(lines, 1):
        if n == len(lines) and not line.endswith(b"\n"):
            if allow_partial_tail:
                break
            raise ValueError("unterminated immutable snapshot event at line %d" % n)
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid state event at line %d: %s" % (n, exc)) from exc
        required = {"schema", "stream_id", "seq", "event_id", "at", "actor", "task_id", "type", "payload", "caused_by"}
        if set(event) != required or event["schema"] != "rat.state-event/v2":
            raise ValueError("invalid v2 event shape at line %d" % n)
        if stream_id is None:
            stream_id = event["stream_id"]
        if event["stream_id"] != stream_id or event["seq"] != len(events) + 1:
            raise ValueError("non-monotonic v2 stream at line %d" % n)
        events.append(event)
    if not events:
        raise ValueError("STATE v2 stream has no complete events")
    return events


def collect_event_digests(events):
    digests = set()
    for event in events:
        payload = event.get("payload", {})
        if event.get("type") == "observation.recorded":
            digests.update(d for d in payload.get("evidence", []) if isinstance(d, str))
        elif event.get("type") == "checkpoint.created":
            for key in ("context_artifact", "overflow_artifact"):
                if isinstance(payload.get(key), str):
                    digests.add(payload[key])
        elif event.get("type") == "migration.diagnostic" and isinstance(payload.get("raw_artifact"), str):
            digests.add(payload["raw_artifact"])
    for digest in digests:
        if DIGEST_RE.fullmatch(digest) is None:
            raise ValueError("invalid artifact digest in stream: %s" % digest)
    return sorted(digests)


def artifact_paths(root, digest):
    if DIGEST_RE.fullmatch(digest or "") is None:
        raise ValueError("invalid artifact digest: %s" % digest)
    h = digest[7:]
    return (
        os.path.join(root, "objects", "sha256", h[:2], h[2:]),
        os.path.join(root, "metadata", "sha256", h[:2], h[2:] + ".json"),
    )


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _listed_digests(root, containment, base, suffix):
    path = os.path.join(root, base, "sha256")
    if not os.path.exists(path):
        return set()
    require_plain_dir_under(containment, path, base)
    out = set()
    for bucket in os.scandir(path):
        if bucket.is_symlink():
            raise ValueError("%s bucket must not be a symlink: %s" % (base, bucket.path))
        if not bucket.is_dir():
            raise ValueError("unexpected %s store entry: %s" % (base, bucket.path))
        if not re.fullmatch(r"[0-9a-f]{2}", bucket.name):
            raise ValueError("unexpected %s bucket: %s" % (base, bucket.path))
        for entry in os.scandir(bucket.path):
            if entry.is_symlink():
                raise ValueError("%s entry must not be a symlink: %s" % (base, entry.path))
            if not entry.is_file():
                raise ValueError("unexpected %s store entry: %s" % (base, entry.path))
            name = entry.name
            if suffix:
                if not name.endswith(suffix):
                    raise ValueError("unexpected %s entry: %s" % (base, entry.path))
                name = name[:-len(suffix)]
            if not re.fullmatch(r"[0-9a-f]{62}", name):
                raise ValueError("unexpected %s entry: %s" % (base, entry.path))
            out.add("sha256:" + bucket.name + name)
    return out


def _nested_digests(data):
    """Artifact digests a rat.tool-result/v1 envelope's own bytes cite.

    An observation's ``evidence`` list names an envelope digest, not the
    measurement/stdout/stderr bytes behind it -- those live in the envelope's
    own ``artifacts[]``. A closure that stops at the envelope digest can look
    complete while the actual measurement bytes it vouches for are missing, so
    every envelope found during closure verification must have its nested
    artifacts pulled into the same closure.
    """
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return set()
    if not isinstance(doc, dict) or doc.get("schema") != "rat.tool-result/v1":
        return set()
    artifacts = doc.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("malformed nested artifact list")
    out = set()
    for art in artifacts:
        if not isinstance(art, dict):
            raise ValueError("malformed nested artifact reference")
        digest = art.get("digest")
        if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
            raise ValueError("malformed nested artifact digest: %s" % digest)
        out.add(digest)
    return out


def _discover_closure(root, containment, digests, object_digests, metadata_digests, label):
    """Expand ``digests`` with every artifact a present, readable envelope cites.

    A digest that turns out to be missing or unreadable is left out here rather
    than raised: this pass only exists to compute the *expected* full closure
    so the aggregate object/metadata-closure and dangling-artifact checks in
    ``verify_artifact_closure`` can report it with their existing framing. The
    per-digest presence/corruption raise still happens, unconditionally, in
    that function's final verification loop.
    """
    required = set(digests); pending = set(required); discovered = set()
    while pending:
        digest = pending.pop()
        if digest in discovered: continue
        discovered.add(digest)
        if digest not in object_digests:
            continue
        # Expansion only needs the object bytes (read below), not the metadata
        # sidecar. Gating on metadata presence too would let a missing metadata
        # file silently truncate discovery -- undercounting `required` and
        # surfacing a spurious "object closure mismatch" for the envelope's
        # nested digests instead of the real "metadata closure mismatch" for
        # the digest whose sidecar is actually missing.
        obj, _ = artifact_paths(root, digest)
        try:
            data = read_bytes_under(containment, obj, "%s artifact object" % label)
        except ValueError:
            continue
        new = _nested_digests(data) - required
        if new:
            required |= new
            pending |= new
    return required


def verify_artifact_closure(root, digests, *, containment_root=None, label="artifact", exact=False):
    containment = os.path.abspath(containment_root or (os.path.dirname(root) if os.path.basename(os.path.abspath(root)) == ".rat" else root))
    root = os.path.abspath(root)
    require_plain_dir_under(containment, root, "%s .rat" % label)
    object_digests = _listed_digests(root, containment, "objects", "")
    metadata_digests = _listed_digests(root, containment, "metadata", ".json")
    # required is the full transitive closure (event-cited digests plus every
    # artifact those envelopes cite, e.g. SELF-measurement bytes) -- the same
    # ordering as before (object exact, then metadata exact, then dangling) is
    # preserved so callers keep getting the aggregate mismatch they expect
    # instead of a per-digest error on the first missing artifact.
    required = _discover_closure(root, containment, digests, object_digests, metadata_digests, label)
    if exact and object_digests != required:
        extra = sorted(object_digests - required)
        missing = sorted(required - object_digests)
        raise ValueError("%s object closure mismatch extra=%s missing=%s" % (label, extra, missing))
    if exact and metadata_digests != required:
        extra = sorted(metadata_digests - required)
        missing = sorted(required - metadata_digests)
        raise ValueError("%s metadata closure mismatch extra=%s missing=%s" % (label, extra, missing))
    if object_digests != metadata_digests:
        raise ValueError("%s dangling artifact object/metadata object_only=%s metadata_only=%s" % (
            label, sorted(object_digests - metadata_digests), sorted(metadata_digests - object_digests)))
    closure = {}
    for digest in sorted(required):
        obj, meta_path = artifact_paths(root, digest)
        if digest not in object_digests or digest not in metadata_digests:
            raise ValueError("missing %s artifact closure for %s" % (label, digest))
        data = read_bytes_under(containment, obj, "%s artifact object" % label)
        if "sha256:" + _sha(data) != digest:
            raise ValueError("corrupt %s artifact object for %s" % (label, digest))
        meta_bytes = read_bytes_under(containment, meta_path, "%s artifact metadata" % label)
        try:
            meta = json.loads(meta_bytes)
        except json.JSONDecodeError as exc:
            raise ValueError("corrupt %s artifact metadata for %s" % (label, digest)) from exc
        if not isinstance(meta, dict):
            raise ValueError("corrupt %s artifact metadata for %s" % (label, digest))
        if meta.get("schema") != "rat.artifact/v1" or meta.get("digest") != digest:
            raise ValueError("corrupt %s artifact metadata for %s" % (label, digest))
        closure[digest] = (_sha(data), _sha(meta_bytes))
    return closure
