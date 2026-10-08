"""Field-level contract extracted from ratlib/schema.py — the single source.

``schemas/*.json`` are reference docs surfaced by ``state schema``; the
authoritative runtime contract lives in the imperative validators in
``ratlib/schema.py``. Those validators encode cross-field rules JSON Schema
cannot express, so they stay canonical and the JSON is NOT generated wholesale
(that would strip the hand-authored enums/patterns). Instead this module reads,
by AST, the *field-level* contract each validator enforces — the ``_need(...)``
required tuple and the ``_strict(...)`` allowed set — so a test can assert every
JSON reference doc agrees with the validator and can never silently drift.

Pure stdlib (ast). No third-party dependency, honoring schema.py's design.
"""
from __future__ import annotations
import ast, os
from functools import lru_cache

_SCHEMA_PY = os.path.join(os.path.dirname(os.path.realpath(__file__)), "schema.py")


def _literal_strs(node: ast.AST) -> list[str] | None:
    """Return the string members of a tuple/set/list literal, or None."""
    if not isinstance(node, (ast.Tuple, ast.Set, ast.List)):
        return None
    out = []
    for elt in node.elts:
        if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
            return None
        out.append(elt.value)
    return out


def _extract_from_function(fn: ast.FunctionDef) -> tuple[list[str] | None, set[str] | None]:
    """(required, allowed) for one validator: first _need tuple, first _strict set."""
    required = allowed = None
    for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
        name = getattr(call.func, "id", None)
        if name == "_need" and required is None and len(call.args) == 2:
            required = _literal_strs(call.args[1])
        elif name == "_strict" and allowed is None and len(call.args) == 2:
            members = _literal_strs(call.args[1])
            allowed = set(members) if members is not None else None
    return required, allowed


@lru_cache(maxsize=1)
def _parse() -> tuple[dict[str, str], dict[str, ast.FunctionDef]]:
    with open(_SCHEMA_PY, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    dispatch: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                    and k.value.startswith("rat.") and isinstance(v, ast.Name)):
                dispatch.setdefault(k.value, v.id)
    return dispatch, funcs


def dispatched_schemas() -> list[str]:
    """Every schema id ratlib.schema.validate() knows how to check."""
    return sorted(_parse()[0])


def contract(schema_id: str) -> tuple[set[str], set[str] | None]:
    """(required, allowed) field-name sets for a schema id.

    ``allowed`` is None when the validator imposes no closed field set
    (``additionalProperties`` is effectively open); otherwise it is the exact
    set of permitted top-level keys.
    """
    dispatch, funcs = _parse()
    fn_name = dispatch[schema_id]
    required, allowed = _extract_from_function(funcs[fn_name])
    if required is None:
        raise ValueError("no _need(...) literal found for %s" % schema_id)
    return set(required), allowed


def json_filename(schema_id: str) -> str:
    """rat.observation/v1 -> rat.observation.v1.json"""
    return schema_id.replace("/", ".") + ".json"
