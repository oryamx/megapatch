"""Patch proposal for one Bandit B602 finding (subprocess with shell=True, CWE-78) of a scanned repository.

A proposal is statically reviewed only: it is NEVER run, and nothing from the project is run either. It is
shown as "statically reviewed, not tested in the application", never as an accepted patch.

  1. prepare(): finds the function that contains the flagged line (Python's ast module), checks that the shell
     command is a simple command (literal words and whole-word values joined with + or an f-string; no pipe,
     redirection, wildcard, variable, quote or other shell syntax that an argument list would change), and
     builds the exact text that would be sent: that one function, Bandit's message and the rules. Nothing else
     from the repository: no other code, no .env, no .git, no virtual environment. If the text looks like it
     holds a credential, it is blocked. The text is bound to the exact file it came from (file_sha256, the
     sha256 of the bytes read).
  2. propose(): only with explicit consent, and only if the file is still that exact version, sends that text to
     NVIDIA Nemotron on Nebius Token Factory (llm.py) and puts the returned function into a disposable copy of
     that one file, outside the project. If the file changed while the answer was awaited, the answer is
     recorded without a review or a diff (status file_changed).
  3. Static review of the copy: the file parses; only the target function changed (same name, arguments and
     decorators; nothing else in the file); Bandit no longer reports B602 in it and reports nothing new of
     medium or high severity; no subprocess call in it uses shell=True; the argument list holds the original
     command's words in the same order, each value as its own element.
     The argument list may be written in the call or in a local name assigned once, before the call, to a list
     literal and used nowhere else (so it cannot be changed or aliased). Every call the function makes must be
     a recognized form (process_audit: an allow-list; an import inside the function, an alias, a name imported
     from os, a dynamic call or a module-level function fails the check, with the reason), and it may not start
     more processes than before. With an allowed folder, each condition of the contract is a check of its own.
     Observations (not checks) note what a reader should see: removed comments, error responses without a
     status code.
  4. decide(): a person approves or rejects a proposal that passed the review. Only an approval exports the diff
     (analysis/<project>/patches/<proposal id>.diff), and only while the file is still the version the proposal
     was made from. The decision is saved first, then the diff is put in place; neither ever replaces a file. An
     approval whose diff is not in place is "pending", never shown as finished; retry_export() reconciles it.
     The project itself is never modified.

Removing shell=True stops the shell, but a value that names a file can still point anywhere, or be read as an
option. When the person declares an allowed folder (a name the file already defines at module level, such as
BACKUP_SOURCE), the request also asks for the confinement rule of confined_path() (empty, absolute and "-..."
values rejected; the path resolved, which follows symbolic links, and kept inside the folder; an existing file;
passed after "--"), and the review checks each condition on its own (contract_checks): the argument list has
"--" before the value and passes a value other than the raw one, and the function has the rule's structure
(resolve, is_relative_to, is_file, the rejections). A rejection counts only when the structure proves it is
unconditional and comes first: an `if` that is a statement of the function itself, before the first statement
that holds a process call, whose branch ends with return or raise. A return nested under another condition, a
guard inside another if, a loop, a try or a nested function, or after the command, does not count.
The rule itself is tested on confined_path(); a proposal is only checked statically to follow its structure.

Records: analysis/<project>/proposals/<id>/proposal.json and decision.json, each written once, complete or not
at all, and never replaced (publish(): a temporary file put in place with a hard link, so the file system must
support hard links; without them nothing is sent, decided or exported). A record that cannot be read is skipped
and listed, never changed. They hold the text that was sent, so they stay on this machine (analysis/ is ignored by
Git).

  python propose_patch.py PATH/TO/REPO --project P --finding FINDING_ID [--allowed NAME]    show what would be sent
  python propose_patch.py PATH/TO/REPO --project P --finding FINDING_ID [--allowed NAME] --send --i-consent
  python propose_patch.py PATH/TO/REPO --project P --rereview PROPOSAL_ID   review a recorded answer again (no request)
"""
import argparse
import ast
import contextlib
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tokenize
from collections import Counter
from pathlib import Path, PureWindowsPath

import repo_scan

TEST_ID, CWE = "B602", "CWE-78"
PURPOSE = "propose_patch:CWE-78"
MAX_TOKENS = 6000  # reasoning tokens count against this budget, as for the practice app's patches
SUBPROCESS_CALLS = {"call", "run", "check_call", "check_output", "Popen"}
# The allow-list of the process audit (process_audit): anything a function calls must be one of these forms.
SAFE_BUILTINS = {"str", "len", "int", "float", "bool", "isinstance", "repr", "list", "tuple", "dict", "set",
                 "frozenset", "min", "max", "any", "all", "range", "enumerate", "zip", "sorted", "reversed", "abs",
                 "round", "print"}
SAFE_MODULES = {"flask", "pathlib", "json", "re", "typing"}  # names imported from these may be called and used
SAFE_DUNDERS = {"__file__", "__name__"}
PATH_TYPES = {"Path", "PurePath", "PurePosixPath", "PureWindowsPath"}
# Methods a call may use (process_audit), the ones this case needs. By name only: the review does not know types.
VALUE_METHODS = {"startswith", "resolve", "is_relative_to", "is_file", "is_absolute"}  # on a local or computed value
CONSTANT_METHODS = {"resolve", "route"}  # on a module-level constant built only from SAFE_MODULES (a Path, a Flask app)
IMPORTED_CHAINS = {("flask", "request"): {("args", "get"), ("form", "get"), ("values", "get")}}
# The only forms a rejection of the confinement contract may take (contract_checks); anything else fails closed.
# Where: the test of an `if` that is a statement of the function itself, before the first statement that holds a
# process call, whose branch ends with return or raise (the test: one term, or terms joined by `or`).
# {v}: the value; {c}: the checked path, a name bound once to (<folder> / {v}).resolve(); {r}: <folder>.resolve()
# or a name bound once to it. Each name in a term: {v}, {c} and {r} bound exactly once, before it; all others never.
GUARD_TERMS = {
    "empty": ("not {v}", "{v} == ''", "len({v}) == 0"),
    "dash": ("{v}.startswith('-')",),
    "absolute": tuple(f"{t}({{v}}).is_absolute()" for t in sorted(PATH_TYPES)) + ("os.path.isabs({v})",),
    "inside": ("not {c}.is_relative_to({r})",),
    "is_file": ("not {c}.is_file()",),
}
# Characters that give a shell command a meaning an argument list would lose or change (POSIX sh and cmd.exe):
# pipes, redirections, separators, substitutions, variables, wildcards, quotes, escapes, comments, history.
SHELL_SYNTAX = set("|&;<>`$()*?[]{}~!#'\"\\^%\n\r\t")
NOT_TESTED = "statically reviewed, not tested in the application"
SYSTEM = ("You are a senior application security engineer. You fix vulnerabilities with the smallest safe change, "
          "and you change nothing else.")
USER_TEMPLATE = """Bandit reports {test_id} ({cwe}) at line {line} of `{file}`, in the function `{function}`:
"{message}"

The function (it is the only code you get from this project):
```python
{source}
```

{fix}
Return ONLY the complete fixed function, in ONE ```python block, and nothing else."""
PLAIN_FIX = """Fix it: replace the shell command string with an argument list (the same words, in the same order, each
interpolated value as its own element), and remove shell=True. Keep everything else in the function exactly as
it is: same name, arguments, decorators, return value and other statements. Add no import outside the function."""
CONFINED_FIX = """Fix it in two parts.
1. Replace the shell command string with an argument list (the same words, in the same order) and remove
   shell=True. Put a "--" element right before the value, so that it can never be read as an option.
2. The value `{value}` comes from the request and names a file. The module already defines `{allowed}` (a
   pathlib.Path; `Path` is imported): the only folder that file may come from. Before running the command,
   reject the request (return an error response and do not run the command) when the value is empty, starts
   with "-", or is an absolute path. Otherwise resolve `{allowed} / {value}` with .resolve(), which follows
   symbolic links, and reject it unless it is inside `{allowed}.resolve()` (check it with Path.is_relative_to)
   and is an existing file. Pass that resolved path to the command instead of the raw value.
Keep everything else in the function as it is: same name, arguments, decorators and return value. Add no import
outside the function."""
SENSITIVE = {
    "an assignment of a password, token, secret or key": re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\w*\s*[:=]\s*[rbuf]?['\"][^'\"]{4,}['\"]"),
    "a known token prefix": re.compile(r"\b(sk-|sk-ant-|ghp_|gho_|github_pat_|xox[abp]-|AKIA|AIza|tvly-|nvapi-|hf_)"
                                       r"[A-Za-z0-9_\-]{8,}"),
    "a private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "a URL with a user or password": re.compile(r"://[^/\s@'\"]+:[^/\s@'\"]*@"),
    "a long opaque string": re.compile(r"['\"][A-Za-z0-9+/=_\-]{32,}['\"]"),
}
MESSAGES = {
    "not_b602": "only Bandit B602 findings (subprocess with shell=True) can get a proposal",
    "not_found": "{file} is not in the folder, or is left out of the scan",
    "stale": "the file changed since the scan: Bandit no longer reports B602 at line {line}",
    "no_function": "line {line} is not inside a function",
    "no_call": "no subprocess call with shell=True found at line {line}",
    "not_simple": "not a simple command: {why}",
    "sensitive": "the text to send looks like it holds {kinds} (line {lines} of the function): nothing is sent",
    "no_consent": "nothing is sent without explicit consent",
    "no_key": "NEBIUS_API_KEY is not set in .env",
    "not_reviewable": "only a proposal that passed the static review can be approved",
    "decided": "this proposal already has a decision",
    "allowed_name": "the allowed folder must be a Python name, such as BACKUP_SOURCE",
    "allowed_missing": "{name} is not defined at module level in {file}",
    "allowed_one_value": "an allowed folder needs a command with exactly one value; this one has {count}",
    "rereview_original": "only a proposal that came from a request can be reviewed again ({id} is itself a re-review)",
    "rereview_changed": "the file, the scan or the request text changed since proposal {id}: it cannot be reviewed "
                        "again as the same request",
    "file_changed": "{file} changed since the text to send was prepared: nothing was sent and no diff was made; "
                    "prepare it again",
    "export_changed": "{file} in that folder is not the exact version proposal {id} was made from (it changed, cannot "
                      "be read, or the proposal does not record its version): nothing was exported or decided",
    "exported_exists": "a diff of proposal {id} already exists ({path}): nothing was exported or decided",
    "export_pending": "the approval of proposal {id} is saved, but its diff could not be put in place ({why}): the "
                      "export is pending, not finished; retry it",
    "export_conflict": "another file is already at {path}: it is not replaced, so the approval of proposal {id} is "
                       "not exported; a person must check that file",
    "not_pending": "proposal {id} has no approval to export",
    "decision_not_saved": "the decision on proposal {id} could not be saved ({why}): nothing was decided or exported",
    "export_stale": "{file} changed after proposal {id} was approved: the approval is obsolete (stale) and its diff is "
                    "never exported; make a new proposal for the current file",
    "record_not_saved": "the record of proposal {id} could not be saved ({why}): nothing was recorded. If a request "
                        "was made, logs/usage.jsonl has it",
    "no_hard_links": "this file system does not support hard links (analysis/{project}/), which MegaPatch needs to "
                     "write each record complete and never replace one: nothing was sent or recorded",
}


class ProposalError(Exception):
    """A reason not to go on; `key` and `values` let the dashboard say it in its language."""

    def __init__(self, key, **values):
        self.key, self.values = key, values
        super().__init__(MESSAGES[key].format(**values))


# ---------- the flagged call ----------

def enclosing_function(tree, line):
    """The innermost function or method whose lines contain `line`."""
    found = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= node.end_lineno:
            if found is None or node.lineno >= found.lineno:
                found = node
    return found


def is_subprocess_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in SUBPROCESS_CALLS
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess")


def shell_keyword(call):
    return next((k for k in call.keywords if k.arg == "shell"), None)


def uses_shell(call):
    """shell= present with anything but a literal False."""
    keyword = shell_keyword(call)
    return keyword is not None and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False)


def flagged_call(function, line):
    """The subprocess call with shell=True that covers `line` (Bandit reports the line where the call starts)."""
    for node in ast.walk(function):
        if is_subprocess_call(node) and node.lineno <= line <= node.end_lineno:
            keyword = shell_keyword(node)
            if keyword is not None and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return node
    return None


def command_words(call):
    """The argument list a simple shell command stands for, or raises ProposalError('not_simple').
    Each item is ('word', text) or ('value', ast dump of the expression)."""
    if not call.args:
        raise ProposalError("not_simple", why="the command is not the first argument")
    parts = []

    def flatten(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            flatten(node.left)
            flatten(node.right)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(("text", node.value))
        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(("text", value.value))
                elif value.conversion == -1 and value.format_spec is None:
                    parts.append(("value", value.value))
                else:
                    raise ProposalError("not_simple", why="an f-string value with a format or conversion")
        elif isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
            parts.append(("value", node))
        else:
            raise ProposalError("not_simple", why="the command is built in a way this version does not analyze")

    flatten(call.args[0])
    if not any(kind == "text" for kind, _ in parts):
        raise ProposalError("not_simple", why="the whole command comes from one expression (a variable, a call or str.format)")
    for kind, text in parts:
        if kind == "text":
            bad = sorted(set(text) & SHELL_SYNTAX) + (["NUL"] if "\x00" in text else [])
            if bad:
                raise ProposalError("not_simple", why="shell syntax in the command: " + " ".join(repr(c) for c in bad))
    # Each value stands in the text as a marker; after splitting on spaces, a value must be a whole word.
    template = "".join(item if kind == "text" else f"\x00{i}\x00" for i, (kind, item) in enumerate(parts))
    words = []
    for token in template.split(" "):
        marker = re.fullmatch(r"\x00(\d+)\x00", token)
        if marker:
            words.append(("value", ast.dump(parts[int(marker.group(1))][1])))
        elif "\x00" in token:
            raise ProposalError("not_simple", why="a value glued to other text in the same word")
        elif token:
            words.append(("word", token))
    if not words or words[0][0] != "word":
        raise ProposalError("not_simple", why="the program name comes from a value")
    if "=" in words[0][1]:
        raise ProposalError("not_simple", why="a variable assignment before the program")
    return words


def value_sources(call):
    """The source text of each value of a simple command, in order (command_words has accepted it)."""
    def walk(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return walk(node.left) + walk(node.right)
        if isinstance(node, ast.JoinedStr):
            return [ast.unparse(v.value) for v in node.values if isinstance(v, ast.FormattedValue)]
        return [] if isinstance(node, ast.Constant) else [ast.unparse(node)]

    return walk(call.args[0])


def confined_path(base, name):
    """The confinement rule a proposal is asked to follow when a value names a file inside an allowed folder.
    Returns the resolved file, or None when the name must be rejected: empty, starting with "-" (it would be read
    as an option), absolute (POSIX or Windows), outside the folder once resolved (".." or a link that leaves it:
    resolve() follows symbolic links and Windows junctions), or not an existing file. check_patch_proposal.py
    tests this reference; a proposal is only checked statically to follow its structure."""
    if not isinstance(name, str) or not name or name.startswith("-") or "\x00" in name:
        return None
    if Path(name).is_absolute() or PureWindowsPath(name).is_absolute() or PureWindowsPath(name).drive:
        return None
    root = Path(base).resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return target


# ---------- what would be sent ----------

def sensitive_kinds(text):
    """[(kind, line)] for every credential-looking piece of `text`; the values themselves are never returned."""
    found = []
    for kind, pattern in SENSITIVE.items():
        for match in pattern.finditer(text):
            found.append((kind, text.count("\n", 0, match.start()) + 1))
    return found


def bandit_on(path, runner=subprocess.run):
    """Bandit's results for one file (it parses the file, it does not run it)."""
    proc = repo_scan.run_tool(runner, "bandit", [str(path), "-f", "json", "-q"])
    return repo_scan.json_output(proc, "Bandit").get("results", [])


def read_version(path):
    """The text of a file (as read_text gives it) and the sha256 of its exact bytes, from one single read."""
    data = Path(path).read_bytes()
    return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8").read(), hashlib.sha256(data).hexdigest()


def same_version(path, sha256):
    """The text of the file if it is still exactly the version with this sha256; None if it changed, is gone or
    cannot be read, or if no version is given."""
    try:
        text, version = read_version(path)
    except (OSError, UnicodeDecodeError):
        return None
    return text if sha256 and version == sha256 else None


def prepare(repo, scan, finding_id, allowed=None, runner=subprocess.run, installed=None):
    """Everything a person needs to decide whether to send: the target, the exact messages, an estimate.
    `allowed`: the name of the folder the value must stay in (defined at module level in that file), or None.
    Reads one file of the repository; writes nothing."""
    finding = next((f for f in scan["findings"]["code"] if f["id"] == finding_id), None)
    if finding is None or finding["test_id"] != TEST_ID:
        raise ProposalError("not_b602")
    repo_scan.check_scanners(repo_scan.installed_scanners() if installed is None else installed, {"bandit"})
    repo = Path(repo).expanduser().resolve()
    rel = finding["file"]
    path = (repo / rel).resolve()
    left_out = [e["path"] for e in scan["meta"]["excluded"]]
    if (not path.is_file() or not path.is_relative_to(repo)
            or any(rel.startswith(e) if e.endswith("/") else rel == e for e in left_out)
            or any(part.startswith(".env") or part in repo_scan.VCS_DIRS | repo_scan.VENV_DIRS
                   for part in Path(rel).parts)):
        raise ProposalError("not_found", file=rel)
    text, file_sha256 = read_version(path)
    with tempfile.TemporaryDirectory() as tmp:  # Bandit reads a copy of the file, so the check is fresh
        copy = Path(tmp) / Path(rel).name
        copy.write_text(text, encoding="utf-8")
        current = bandit_on(copy, runner)
    if not any(r["test_id"] == TEST_ID and r["line_number"] == finding["line"] for r in current):
        raise ProposalError("stale", line=finding["line"])
    tree = ast.parse(text)
    function = enclosing_function(tree, finding["line"])
    if function is None:
        raise ProposalError("no_function", line=finding["line"])
    call = flagged_call(function, finding["line"])
    if call is None:
        raise ProposalError("no_call", line=finding["line"])
    words = command_words(call)
    values = value_sources(call)
    allowed = (allowed or "").strip() or None
    if allowed:
        if not allowed.isidentifier():
            raise ProposalError("allowed_name")
        defined = {t.id for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
                   for t in (node.targets if isinstance(node, ast.Assign) else [node.target]) if isinstance(t, ast.Name)}
        if allowed not in defined:
            raise ProposalError("allowed_missing", name=allowed, file=rel)
        if len(values) != 1:
            raise ProposalError("allowed_one_value", count=len(values))
    first = min([function.lineno] + [d.lineno for d in function.decorator_list])
    lines = text.splitlines(keepends=True)
    source = textwrap.dedent("".join(lines[first - 1:function.end_lineno])).rstrip("\n")
    fix = CONFINED_FIX.format(value=values[0], allowed=allowed) if allowed else PLAIN_FIX
    user = USER_TEMPLATE.format(test_id=TEST_ID, cwe=CWE, line=finding["line"], file=rel, function=function.name,
                                message=finding["message"], source=source, fix=fix)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    sensitive = sensitive_kinds(source)
    return {
        "file": rel, "file_sha256": file_sha256, "line": finding["line"], "finding_id": finding_id,
        "function": function.name, "function_lines": [first, function.end_lineno], "words": words, "values": values,
        "allowed": allowed,
        "messages": messages,
        "sent_text": SYSTEM + "\n\n" + user, "sent_sha256": hashlib.sha256((SYSTEM + "\n\n" + user).encode()).hexdigest(),
        "sensitive": sensitive, "estimate": estimate(SYSTEM + user),
    }


def estimate(text):
    """A rough cost estimate (not a bill): about 4 characters per input token, the typical output of earlier
    CWE-78 patch calls in logs/usage.jsonl (or 1,000 tokens), and at most MAX_TOKENS of output."""
    import llm  # only here: it loads .env and the model client, which the public dashboard does not need

    earlier = sorted(r["completion_tokens"] for r in llm.usage_lines() if r.get("purpose", "").startswith(
        ("generate_patch:CWE-78", PURPOSE)))
    typical = earlier[len(earlier) // 2] if earlier else 1000
    tokens_in = max(1, len(text) // 4)
    price = lambda out: round((tokens_in * llm.PRICE_IN_PER_M + out * llm.PRICE_OUT_PER_M) / 1_000_000, 5)  # noqa: E731
    return {"input_tokens": tokens_in, "typical_output_tokens": typical, "max_output_tokens": MAX_TOKENS,
            "typical_usd": price(typical), "max_usd": price(MAX_TOKENS), "based_on_calls": len(earlier),
            "price_in_per_m": llm.PRICE_IN_PER_M, "price_out_per_m": llm.PRICE_OUT_PER_M}


def has_api_key():
    import llm  # noqa: F401  (loads .env when python-dotenv is installed)

    return bool(os.getenv("NEBIUS_API_KEY"))


def nemotron(messages, max_tokens=MAX_TOKENS):
    """The real call (llm.py logs tokens, latency and estimated cost). Returns (text, usage). `max_tokens` caps the
    output (reasoning included), which caps the cost."""
    import llm

    response = llm.chat(PURPOSE, messages, temperature=0.2, max_tokens=min(max_tokens, MAX_TOKENS))
    usage = response.usage
    return response.choices[0].message.content or "", {
        "model": response.model, "prompt_tokens": usage.prompt_tokens, "completion_tokens": usage.completion_tokens}


# ---------- the proposal and its static review ----------

def extract_function(text):
    match = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.S)
    return textwrap.dedent(match.group(1) if match else text).strip("\n") + "\n"


def process_calls(function):
    """Every call in the function that starts a process: subprocess.* and os.system / os.popen / os.exec* /
    os.spawn* (the os ones take a command string)."""
    found = []
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module, name = node.func.value.id, node.func.attr
            if (module == "subprocess" and name in SUBPROCESS_CALLS) or (
                    module == "os" and (name in ("system", "popen") or name.startswith(("exec", "spawn")))):
                found.append(node)
    return found


def argv_node(call, function):
    """The list the call runs: written in the call, or a local name assigned exactly once, before the call, to a
    list or tuple literal, and used nowhere else but as the first argument of process calls. Any other use
    (reassignment, append, item assignment, del, aliasing, passing it to another function, a parameter or a
    global of the same name) could change the list after it was checked, so it is not accepted."""
    first = call.args[0] if call.args else None
    if isinstance(first, (ast.List, ast.Tuple)):
        return first
    if not isinstance(first, ast.Name) or function is None:
        return None
    name = first.id
    assigns = [n for n in ast.walk(function) if isinstance(n, ast.Assign) and len(n.targets) == 1
               and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    if len(assigns) != 1 or not isinstance(assigns[0].value, (ast.List, ast.Tuple)) or assigns[0].lineno >= call.lineno:
        return None
    allowed_uses = {id(assigns[0].targets[0])} | {id(c.args[0]) for c in process_calls(function) if c.args}
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and node.id == name and id(node) not in allowed_uses:
            return None
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return None
        if isinstance(node, ast.arg) and node.arg == name:
            return None
    return assigns[0].value


def argv_matches(call, words, confined=False, function=None):
    """True when the list the call runs holds the expected words and values, in order (see argv_node for where
    that list may be written). `confined`: the literal words must be the same, in the same order, with one
    non-literal element where each value was; the "--" element and what follows it are checked by
    contract_checks."""
    node = argv_node(call, function)
    if node is None:
        return False
    got = [("word", e.value) if isinstance(e, ast.Constant) and isinstance(e.value, str) else ("value", ast.dump(e))
           for e in node.elts]
    expected = [tuple(w) for w in words]
    if not confined:
        return got == expected
    got = [g for g in got if g != ("word", "--")]
    return len(got) == len(expected) and all(g == e if e[0] == "word" else g[0] == "value"
                                             for g, e in zip(got, expected))


def module_bindings(tree):
    """What each module-level name is bound to: ("import", module, unaliased), ("from", module, name),
    ("assign", value) or ("def",)."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                out[bound] = ("import", alias.name, alias.asname is None)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                out[alias.asname or alias.name] = ("from", node.module or "", alias.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(target, ast.Name):
                    out[target.id] = ("assign", node.value)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = ("def",)
    return out


def safe_name(name, bindings, seen=()):
    """A module-level name the function may use: a safe builtin, __file__/__name__, something imported from a
    module in SAFE_MODULES, or a constant built only from those (one module-level assignment)."""
    if name in SAFE_BUILTINS or name in SAFE_DUNDERS:
        return True
    bound = bindings.get(name)
    if not bound or name in seen:
        return False
    if bound[0] == "from":
        return bound[1].split(".")[0] in SAFE_MODULES
    if bound[0] == "import":
        return bound[1].split(".")[0] in SAFE_MODULES and bound[2]
    if bound[0] == "assign":
        return all(safe_name(n.id, bindings, seen + (name,)) for n in ast.walk(bound[1])
                   if isinstance(n, ast.Name))
    return False


def attribute_chain(node):
    chain = []
    while isinstance(node, ast.Attribute):
        chain.insert(0, node.attr)
        node = node.value
    return node, chain


def process_audit(function, module_tree):
    """Recognize every call the function makes against an allow-list of call forms. Returns (the number of
    subprocess calls, the reasons the review cannot tell what something runs). Recognized: subprocess.call/run/
    check_call/check_output/Popen on `import subprocess` (no alias); os.path.* and os.fspath on `import os`;
    SAFE_BUILTINS; names imported from SAFE_MODULES and constants built only from them; and methods only from
    explicit lists: VALUE_METHODS on a local name or a computed value (one level), CONSTANT_METHODS on a
    module-level constant, IMPORTED_CHAINS on flask's request. Anything else fails safe: an import or a global
    statement inside the function, an alias, a name imported from os or another module, a module-level
    function, a call through a local name, a dynamic call, any other method (runner.run(...),
    request.args.get(...).run(...)). Methods are matched by name, not by type: an object of an unexpected type
    whose listed method (say resolve) does something else is not detected."""
    bindings = module_bindings(module_tree)
    params = {a.arg for a in ast.walk(function.args) if isinstance(a, ast.arg)}
    local = params | {n.id for n in ast.walk(function) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    is_module = lambda name, module: (name == module and name not in local  # noqa: E731
                                      and bindings.get(name) == ("import", module, True))
    reasons, count, roots = [], 0, set()
    for node in ast.walk(function):
        where = f"line {getattr(node, 'lineno', '?')}"
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            reasons.append(f"{where}: an import inside the function (it could bring a process function under another name)")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            reasons.append(f"{where}: a global or nonlocal statement (it could rebind a module-level name)")
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            roots.add(id(func))
            if func.id in local:
                reasons.append(f"{where}: calls {func.id}, a local name: what it runs is decided at run time")
            elif bindings.get(func.id, ("",))[0] == "def":
                reasons.append(f"{where}: calls {func.id}, a module-level function the review cannot follow")
            elif not safe_name(func.id, bindings):
                origin = bindings.get(func.id)
                reasons.append(f"{where}: calls {func.id}" + (f", imported from {origin[1]}" if origin and origin[0] == "from"
                                                              else "") + ": not on the list of recognized forms")
        elif isinstance(func, ast.Attribute):
            root, chain = attribute_chain(func)
            shown = (root.id if isinstance(root, ast.Name) else f"({ast.unparse(root)[:50]})") + "." + ".".join(chain)
            if not isinstance(root, ast.Name):  # a method of a computed value; its inner calls are checked on their own
                if not (len(chain) == 1 and chain[0] in VALUE_METHODS):
                    reasons.append(f"{where}: calls {shown}(...): {chain[-1]} on a computed value is not on the list "
                                   "of recognized methods")
                continue
            roots.add(id(root))
            if is_module(root.id, "subprocess"):
                if chain[0] in SUBPROCESS_CALLS and len(chain) == 1:
                    count += 1
                else:
                    reasons.append(f"{where}: subprocess.{'.'.join(chain)} is not on the list of recognized forms")
            elif is_module(root.id, "os"):
                if not (chain[0] == "path" or chain == ["fspath"]):
                    reasons.append(f"{where}: os.{'.'.join(chain)} could start a process")
            elif root.id in local:
                if not (len(chain) == 1 and chain[0] in VALUE_METHODS):
                    reasons.append(f"{where}: calls {shown}(...): {'.'.join(chain)} on the local name {root.id} is not "
                                   "on the list of recognized methods")
            elif not safe_name(root.id, bindings):
                reasons.append(f"{where}: calls {shown}(...): {root.id} is not on the list of recognized forms (an alias "
                               "or an unknown module)")
            else:
                bound = bindings.get(root.id, ("builtin",))
                allowed = (bound[0] == "from" and tuple(chain) in IMPORTED_CHAINS.get((bound[1].split(".")[0], bound[2]),
                                                                                      set())) or (
                    bound[0] == "assign" and len(chain) == 1 and chain[0] in CONSTANT_METHODS)
                if not allowed:
                    reasons.append(f"{where}: calls {shown}(...): not on the list of recognized methods")
        else:
            reasons.append(f"{where}: a dynamic call: what it runs is decided at run time")
    for node in ast.walk(function):  # any other use of a module-level name that is not recognized
        if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and id(node) not in roots
                and node.id not in local and not safe_name(node.id, bindings)):
            reasons.append(f"line {node.lineno}: uses {node.id} outside a recognized call (it could be passed along "
                           "or aliased)")
    return count, list(dict.fromkeys(reasons))


def binding_counts(function):
    """How many times each name is bound or unbound anywhere in the function, nested scopes included: assignment
    targets, loop and with variables, :=, +=, del, parameters, imports, except ... as, match captures, nested def
    and class names, and global / nonlocal declarations."""
    counts = Counter()
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            counts[node.id] += 1
        elif isinstance(node, ast.arg):
            counts[node.arg] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not function:
            counts[node.name] += 1
        elif isinstance(node, ast.alias):
            counts[(node.asname or node.name).split(".")[0]] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            counts[node.name] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            counts.update(node.names)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            counts[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            counts[node.rest] += 1
    return counts


def contract_checks(function, prepared, argv):
    """With an allowed folder: each condition of the contract (confined_path's rule) as a check of its own,
    read from the code, never run. `argv`: the elements of the list the command runs (or None).
    Only the bounded forms of GUARD_TERMS count, in a rejection whose structure proves it is unconditional and
    first (see GUARD_TERMS); a name a form relies on must be bound exactly once (a local) or never (a module
    name) in the whole function. Anything else fails closed: the condition's check fails."""
    allowed = prepared["allowed"]
    value = prepared["values"][0]
    raw = ast.dump(ast.parse(value, mode="eval").body)
    counts = binding_counts(function)
    # A local a form may rely on: bound once in the whole function, by a statement of the function itself.
    top = {}
    for index, node in enumerate(function.body):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            top.setdefault(node.targets[0].id, []).append((index, node.value))
    single = lambda name: (top[name][0][1] if len(top.get(name, [])) == 1 and counts[name] == 1  # noqa: E731
                           else None)
    is_raw = lambda node: ast.dump(node) == raw  # noqa: E731
    resolve_of = lambda node: (node.func.value if isinstance(node, ast.Call) and not node.args  # noqa: E731
                               and isinstance(node.func, ast.Attribute) and node.func.attr == "resolve" else None)
    folder = lambda node: isinstance(node, ast.Name) and node.id == allowed and counts[allowed] == 0  # noqa: E731

    def folder_resolved(node):
        """Follow local aliases without recursing; model output may contain cycles or very long chains."""
        seen = set()
        while isinstance(node, ast.Name):
            if node.id in seen:
                return False
            seen.add(node.id)
            node = single(node.id)
            if node is None:
                return False
        base = resolve_of(node)
        return base is not None and folder(base)

    folder_base = lambda node: (folder(node) or folder_resolved(node) or (  # noqa: E731
        isinstance(node, ast.Name) and single(node.id) is not None and folder(single(node.id))))
    aliases = {name for name in top if single(name) is not None
               and (folder(single(name)) or folder_resolved(single(name)))}
    found = []
    for name in top:
        bound = single(name)
        resolved = resolve_of(bound) is not None if bound is not None else False
        joined = resolve_of(bound) if resolved else bound
        if (isinstance(joined, ast.BinOp) and isinstance(joined.op, ast.Div) and folder_base(joined.left)
                and is_raw(joined.right)):
            found.append((name, resolved))
    checked, resolved = found[0] if len(found) == 1 else (None, False)
    locals_once = aliases | ({checked} if checked else set()) | ({value} if value.isidentifier() else set())
    params = {a.arg for a in function.args.posonlyargs + function.args.args + function.args.kwonlyargs}
    bound_at = {name: top[name][0][0] if name in top else -1 for name in locals_once if name in top or name in params}
    # A form holds only if each name in it is bound as expected: the value, the checked path and the folder's
    # names once (by a statement of the function itself, before that one, or as a parameter); every other name
    # (Path, os, len, the folder...) never.
    stable = lambda node, at: all(  # noqa: E731
        (counts[n.id] == 1 and n.id in bound_at and bound_at[n.id] < at) if n.id in locals_once
        else counts[n.id] == 0 for n in ast.walk(node) if isinstance(n, ast.Name))
    if checked and not stable(single(checked), bound_at[checked]):
        checked, resolved = None, False
    # The rejections: an `if` that is a statement of the function itself, before the first statement that holds
    # a process call, whose branch ENDS with return or raise; each part of its test (one term, or terms joined by
    # `or`). Nothing nested counts: not inside another if, a loop, a try, a with, a match or a nested function.
    runs = [i for i, statement in enumerate(function.body) if any(is_subprocess_call(n) for n in ast.walk(statement))]
    terms = []
    for index, statement in enumerate(function.body[:runs[0] if runs else len(function.body)]):
        if isinstance(statement, ast.If) and isinstance(statement.body[-1], (ast.Return, ast.Raise)):
            test = statement.test
            terms += [(index, t) for t in (test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or)
                                           else [test])]
    form = lambda source: ast.dump(ast.parse(source, mode="eval").body)  # noqa: E731
    has = lambda kind, **names: any(  # noqa: E731
        ast.dump(t) in {form(f.format(**names)) for f in GUARD_TERMS[kind]} and stable(t, at) for at, t in terms)
    rejects = {kind: value.isidentifier() and counts[value] == 1 and has(kind, v=value)
               for kind in ("empty", "dash", "absolute")}
    missing = [what for what, kind in (("empty", "empty"), ('starting with "-"', "dash"), ("absolute", "absolute"))
               if not rejects[kind]]
    unknown = (f"the checked path could not be identified (a name assigned once from {allowed} / {value}, "
               "resolved or not, whose names are not bound again)")
    folders = [f"{allowed}.resolve()"] + sorted(a for a in aliases if folder_resolved(ast.Name(id=a)))
    inside = checked is not None and any(has("inside", c=checked, r=r) for r in folders)
    is_file = checked is not None and has("is_file", c=checked)
    dashes = [i for i, e in enumerate(argv or []) if isinstance(e, ast.Constant) and e.value == "--"]
    after = None
    if checked and len(dashes) == 1 and dashes[0] + 1 < len(argv):
        e = argv[dashes[0] + 1]
        after = ast.dump(e) in {form(src) for src in (checked, f"str({checked})", f"os.fspath({checked})")}
        after = after and stable(e, len(function.body)) and not any(is_raw(x) for x in argv)
        words_before = next(i for i, w in enumerate(prepared["words"]) if w[0] == "value")
        after = after and dashes[0] == words_before
    return [
        ("rejects_input", not missing, "rejects empty, \"-...\" and absolute values before the command runs"
         if not missing else "does not reject these values before the command runs (or not in a form the review "
                             "can prove): " + ", ".join(missing)),
        ("resolves", resolved, f"resolves {allowed} / {value} with .resolve() (links followed) into {checked}"
         if resolved else (unknown if checked is None else f"{checked} is {allowed} / {value} without .resolve()")),
        ("inside", inside, f"rejects {checked} unless it is inside {allowed}.resolve() (is_relative_to)" if inside
         else (unknown if checked is None else f"no rejection the review can prove when {checked} is not inside "
                                                f"{allowed}.resolve()")),
        ("is_file", is_file, f"rejects {checked} unless it is an existing file" if is_file
         else (unknown if checked is None else f"no rejection the review can prove when {checked} is not an "
                                                "existing file")),
        ("after_dashdash", bool(after), f"passes {checked} right after \"--\", and never the raw value" if after
         else (unknown if checked is None else f"the list does not pass {checked} right after one \"--\" (or it "
                                                "passes the raw value)")),
    ]


def comments(source):
    try:
        return [t.string for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type == tokenize.COMMENT]
    except (tokenize.TokenError, SyntaxError):
        return []


def observations(original_source, proposed_function):
    """Notes for the person, not checks: what the static review does not judge but a reader should see."""
    notes = []
    lost = [c for c in comments(original_source) if c not in comments(proposed_function)]
    if lost:
        notes.append("removed comment(s): " + "; ".join(lost))
    try:
        tree = ast.parse(proposed_function)
    except SyntaxError:
        return notes
    bare = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)
            and any(isinstance(k, ast.Constant) and k.value == "error" for k in n.value.keys)]
    if bare:
        notes.append("returns its error response without a status code, so with HTTP 200 (line "
                     + ", ".join(str(n) for n in bare) + " of the proposed function)")
    return notes


def function_source(text, prepared):
    first, last = prepared["function_lines"]
    return textwrap.dedent("".join(text.splitlines(keepends=True)[first - 1:last])).rstrip("\n")


def review(original_text, prepared, proposed_function, runner=subprocess.run):
    """Put the proposed function into a disposable copy of the file and review it statically."""
    checks = []
    first, last = prepared["function_lines"]
    lines = original_text.splitlines(keepends=True)
    indent = re.match(r"\s*", lines[first - 1]).group(0)
    newline = "\r\n" if lines[first - 1].endswith("\r\n") else "\n"
    new_block = "".join((indent + ln if ln.strip() else ln) + newline for ln in proposed_function.splitlines())
    patched = "".join(lines[:first - 1]) + new_block + "".join(lines[last:])

    try:
        snippet = ast.parse(proposed_function)
        tree = ast.parse(patched)
        checks.append(("syntax", True, "the patched file is valid Python"))
    except SyntaxError as exc:
        checks.append(("syntax", False, f"not valid Python: line {exc.lineno}"))
        return patched, checks
    original = enclosing_function(ast.parse(original_text), prepared["line"])
    same = (len(snippet.body) == 1 and isinstance(snippet.body[0], type(original))
            and snippet.body[0].name == original.name
            and ast.dump(snippet.body[0].args) == ast.dump(original.args)
            and [ast.dump(d) for d in snippet.body[0].decorator_list] == [ast.dump(d) for d in original.decorator_list])
    checks.append(("only_function", same, "only the target function changed (same name, arguments and decorators)"
                   if same else "the proposal changes more than the target function, or its name, arguments or "
                                "decorators"))
    function = next((n for n in ast.walk(tree) if isinstance(n, type(original)) and n.name == original.name
                     and n.lineno >= first), None)
    calls = [n for n in ast.walk(function) if is_subprocess_call(n)] if function else []
    no_shell = bool(calls) and not any(uses_shell(c) for c in calls)
    checks.append(("no_shell", no_shell, "no subprocess call in the function uses shell=True" if no_shell
                   else "a subprocess call in the function still uses shell=True (or shell is not False)"))
    count, reasons = process_audit(function, tree) if function else (0, ["the function was not found"])
    before = len(process_calls(original))
    one = not reasons and count <= before
    checks.append(("one_process", one, f"every call is a recognized form, and it starts no more processes than before "
                   f"({count})" if one else ("the review cannot tell what every call runs: " + "; ".join(reasons)
                                             if reasons else f"it starts more processes than before ({count} > {before})")))
    confined = bool(prepared.get("allowed"))
    matches = any(argv_matches(c, prepared["words"], confined, function) for c in calls)
    checks.append(("same_words", matches, (
        "the argument list holds the original command's words in the same order, with one element where the value "
        "was (the \"--\" and that element are checked on their own below)" if confined else
        "the argument list holds the original command's words in the same order, each value as its own element")
        if matches else ("the argument list does not hold the original command's words in the same order, with one "
                         "element where the value was" if confined else
                         "the argument list does not hold the original command's words, in the same order")))
    if confined:
        argv = next((node.elts for c in calls if (node := argv_node(c, function)) is not None), None)
        checks += contract_checks(function, prepared, argv) if function else [
            (name, False, "the function was not found") for name in ("rejects_input", "resolves", "inside", "is_file",
                                                                     "after_dashdash")]

    end = function.end_lineno if function else first
    with tempfile.TemporaryDirectory() as tmp:  # the disposable copy: this one file, outside the project
        before, after = Path(tmp) / "before.py", Path(tmp) / "after.py"
        before.write_text(original_text, encoding="utf-8")
        after.write_text(patched, encoding="utf-8")
        old = [r for r in bandit_on(before, runner) if first <= r["line_number"] <= last]
        new = [r for r in bandit_on(after, runner) if first <= r["line_number"] <= end]
    gone = not any(r["test_id"] == TEST_ID for r in new)
    checks.append(("b602_gone", gone, "Bandit no longer reports B602 in the function" if gone
                   else "Bandit still reports B602 in the function"))
    old_ids = {r["test_id"] for r in old}
    added = sorted({(r["test_id"], r["issue_severity"]) for r in new if r["test_id"] not in old_ids})
    serious = [a for a in added if a[1] in ("MEDIUM", "HIGH")]
    checks.append(("no_new_serious", not serious, "Bandit reports nothing new of medium or high severity"
                   + (f" (new low-severity notes: {', '.join(t for t, _ in added)})" if added else "")
                   if not serious else f"Bandit reports new findings: {', '.join(f'{t} {s}' for t, s in serious)}"))
    return patched, checks


def diff_text(rel, original_text, patched):
    return "".join(difflib.unified_diff(original_text.splitlines(keepends=True), patched.splitlines(keepends=True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def proposals_dir(project, root=None):
    return repo_scan.project_dir(project, root) / "proposals"


def propose(repo, scan, prepared, consent, model=None, runner=subprocess.run, root=None):
    """Send the prepared text (only with consent), review the answer statically and record the proposal."""
    if consent is not True:
        raise ProposalError("no_consent")
    if prepared["sensitive"]:
        raise ProposalError("sensitive", kinds=", ".join(sorted({k for k, _ in prepared["sensitive"]})),
                            lines=", ".join(str(n) for _, n in prepared["sensitive"]))
    repo = Path(repo).expanduser().resolve()
    original_text = same_version(repo / prepared["file"], prepared.get("file_sha256"))
    if original_text is None:
        raise ProposalError("file_changed", file=prepared["file"])
    if not links_supported(proposals_dir(scan["meta"]["project"], root)):  # before the request, not after
        raise ProposalError("no_hard_links", project=scan["meta"]["project"])
    answer, usage = (model or nemotron)(prepared["messages"])
    proposed = extract_function(answer)
    if same_version(repo / prepared["file"], prepared["file_sha256"]) is None:
        # The request was made, so the answer is kept; but no review and no diff for a file that is not this version.
        patched, checks, status = None, [], "file_changed"
    else:
        patched, checks = review(original_text, prepared, proposed, runner)
        status = "statically_reviewed" if all(ok for _, ok, _ in checks) else "failed_static_review"
    record = {
        "id": repo_scan.new_id(), "project": scan["meta"]["project"], "scan_id": scan["meta"]["id"],
        "finding_id": prepared["finding_id"], "file": prepared["file"], "file_sha256": prepared["file_sha256"],
        "line": prepared["line"], "function": prepared["function"], "test_id": TEST_ID, "cwe": CWE,
        "created_at": repo_scan.now(), "allowed_folder": prepared.get("allowed"),
        "sent_to": "Nebius Token Factory (NVIDIA Nemotron)", "sent_text": prepared["sent_text"],
        "sent_sha256": prepared["sent_sha256"], "consent": True, "usage": usage, "answer": answer,
        "proposed_function": proposed,
        "diff": diff_text(prepared["file"], original_text, patched) if patched is not None else None,
        "checks": [{"check": c, "passed": ok, "detail": d} for c, ok, d in checks],
        "observations": observations(function_source(original_text, prepared), proposed),
        "status": status, "verified_in_application": False, "label": NOT_TESTED, "requests_made": 1,
        "review_of": None,
    }
    return write_record(record, root)


def write_record(record, root=None):
    """Write a proposal record once, complete or not at all (publish): an interruption never leaves a cut-off
    proposal.json, and no record is ever replaced. On failure nothing is left but what was there before."""
    folder = proposals_dir(record["project"], root) / record["id"]
    created = False
    try:
        folder.mkdir(parents=True, exist_ok=False)
        created = True
        publish(folder / "proposal.json", json.dumps(record, indent=2))
    except OSError as exc:
        if created:
            with contextlib.suppress(OSError):
                folder.rmdir()  # empty: this call made it
        raise ProposalError("record_not_saved", id=record["id"], why=exc.strerror or type(exc).__name__) from None
    return record


def links_supported(folder):
    """Whether this file system lets publish() put a file in place with a hard link: a probe with a temporary
    file, removed afterwards. FAT32, exFAT and some network shares do not."""
    folder.mkdir(parents=True, exist_ok=True)
    fd, probe = tempfile.mkstemp(prefix=".link-probe.", suffix=".partial", dir=folder)
    os.close(fd)
    linked = Path(probe + ".link")
    try:
        os.link(probe, linked)
        return True
    except OSError:
        return False
    finally:
        linked.unlink(missing_ok=True)
        Path(probe).unlink(missing_ok=True)


def rereview(repo, project, proposal_id, runner=subprocess.run, root=None, installed=None):
    """Review a recorded answer again with the current checks, into a NEW record. No request is sent, and the
    original record (the text sent and the answer received) is not changed: the new one points to it by id and
    by hash. The file must still be what was sent (same request text)."""
    original = json.loads((proposals_dir(project, root) / proposal_id / "proposal.json").read_text(encoding="utf-8"))
    if original.get("review_of"):
        raise ProposalError("rereview_original", id=proposal_id)
    scans = {scan_id: folder for scan_id, folder, done in repo_scan.list_scans(project, root) if done}
    if original["scan_id"] not in scans:
        raise ProposalError("rereview_changed", id=proposal_id)
    scan = repo_scan.load_scan(scans[original["scan_id"]])
    prepared = prepare(repo, scan, original["finding_id"], allowed=original.get("allowed_folder"), runner=runner,
                       installed=installed)
    if prepared["sent_sha256"] != original["sent_sha256"]:
        raise ProposalError("rereview_changed", id=proposal_id)
    original_text = same_version(Path(repo).expanduser().resolve() / prepared["file"], prepared["file_sha256"])
    if original_text is None:
        raise ProposalError("file_changed", file=prepared["file"])
    proposed = original["proposed_function"]
    patched, checks = review(original_text, prepared, proposed, runner)
    passed = all(ok for _, ok, _ in checks)
    record = {key: original[key] for key in ("project", "scan_id", "finding_id", "file", "line", "function", "test_id",
                                             "cwe", "allowed_folder", "sent_to", "sent_sha256")}
    record.update({
        "id": repo_scan.new_id(), "created_at": repo_scan.now(), "file_sha256": prepared["file_sha256"],
        "review_of": proposal_id, "requests_made": 0,
        "answer_sha256": hashlib.sha256(original["answer"].encode()).hexdigest(), "usage": None,
        "proposed_function": proposed, "diff": diff_text(prepared["file"], original_text, patched),
        "checks": [{"check": c, "passed": ok, "detail": d} for c, ok, d in checks],
        "observations": observations(function_source(original_text, prepared), proposed),
        "status": "statically_reviewed" if passed else "failed_static_review",
        "verified_in_application": False, "label": NOT_TESTED,
    })
    return write_record(record, root)


def publish(path, text):
    """Create `path` holding `text`, complete or not at all, and only if nothing is there yet. The text is written
    to a temporary file next to it and put in place with a hard link, which never replaces an existing file on
    any platform (FileExistsError). Needs a file system with hard links (NTFS, ext4, APFS...). A process killed
    on the way can leave the temporary file (".<name>.*.partial"), never a partial `path`."""
    fd, partial = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.link(partial, path)
    finally:
        Path(partial).unlink(missing_ok=True)


def export_path(project, proposal_id, root=None):
    return repo_scan.project_dir(project, root) / "patches" / f"{proposal_id}.diff"


def source_version(record, repo):
    """The source file in `repo` against the version the proposal was made from: "same", "changed" (another
    version: the proposal is obsolete for it) or "missing" (not readable there, or no folder given)."""
    if not repo or not str(repo).strip() or not record.get("file_sha256"):
        return "missing"
    try:
        data = (Path(repo).expanduser().resolve() / record["file"]).read_bytes()
    except OSError:
        return "missing"
    return "same" if hashlib.sha256(data).hexdigest() == record["file_sha256"] else "changed"


def export_state(project, proposal_id, decision, root=None, record=None, repo=None):
    """Where an approval stands: None (no approval); "exported" (the diff is in place with exactly the approved
    text: the only finished export); "conflict" (another file is at the diff's name; it is never replaced);
    "stale" (the diff is not in place and the source file in `repo` is no longer the approved version: terminal,
    it is never exported; with `record` and `repo` only); "pending" (the diff is not in place yet: retry_export()
    finishes it, once the source file can be checked to be the approved version)."""
    if not decision or decision["decision"] != "approved":
        return None
    target = export_path(project, proposal_id, root)
    if not target.exists():
        return "stale" if record is not None and source_version(record, repo) == "changed" else "pending"
    try:
        text = read_version(target)[0]
    except (OSError, UnicodeDecodeError):
        return "conflict"
    return "exported" if hashlib.sha256(text.encode()).hexdigest() == decision.get("diff_sha256") else "conflict"


def export_diff(project, record, root=None):
    """Put the approved diff in place (publish). After the decision is saved, so a failure leaves it pending."""
    target = export_path(project, record["id"], root)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        publish(target, record["diff"])
    except FileExistsError:
        raise ProposalError("export_conflict", id=record["id"], path=f"patches/{target.name}") from None
    except OSError as exc:
        raise ProposalError("export_pending", id=record["id"], why=exc.strerror or type(exc).__name__) from None


def check_version(record, repo):
    if repo is None or same_version(Path(repo).expanduser().resolve() / record["file"],
                                    record.get("file_sha256")) is None:
        raise ProposalError("export_changed", file=record["file"], id=record["id"])


def decide(project, proposal_id, approve, repo=None, root=None):
    """Record a person's decision once. Only an approved, statically reviewed proposal exports its diff, and only
    while the file in `repo` is still the exact version the proposal was made from (its file_sha256).
    The decision is saved first (complete or not at all, never replaced), holding the sha256 of the approved diff;
    then the diff is put in place, never replacing a file. If that second step does not happen (an error, or a
    process stopped in between), the approval is "pending", not exported: export_state() tells, the dashboard does
    not show it as a finished approval, and retry_export() finishes it."""
    folder = proposals_dir(project, root) / proposal_id
    record = json.loads((folder / "proposal.json").read_text(encoding="utf-8"))
    if (folder / "decision.json").exists():
        raise ProposalError("decided")
    if approve and record["status"] != "statically_reviewed":
        raise ProposalError("not_reviewable")
    if approve:
        check_version(record, repo)
        if export_path(project, proposal_id, root).exists():
            raise ProposalError("exported_exists", id=proposal_id, path=f"patches/{proposal_id}.diff")
    decision = {"proposal_id": proposal_id, "decision": "approved" if approve else "rejected",
                "decided_at": repo_scan.now(), "decided_by": "a person at this machine", "label": NOT_TESTED,
                "verified_in_application": False,
                "export_target": f"patches/{proposal_id}.diff" if approve else None,
                "diff_sha256": hashlib.sha256(record["diff"].encode()).hexdigest() if approve else None}
    try:
        publish(folder / "decision.json", json.dumps(decision, indent=2))
    except FileExistsError:
        raise ProposalError("decided") from None
    except OSError as exc:
        raise ProposalError("decision_not_saved", id=proposal_id, why=exc.strerror or type(exc).__name__) from None
    if approve:
        export_diff(project, record, root)
    return decision


def retry_export(project, proposal_id, repo, root=None):
    """Reconcile an approval: finish a pending export (the file must still be the exact version, as on approval;
    nothing is replaced), or confirm one that is already in place. A stale approval (the source file changed) is
    never exported. Leftover temporary files of this proposal are removed. Returns "exported" when it is done."""
    folder = proposals_dir(project, root) / proposal_id
    record = json.loads((folder / "proposal.json").read_text(encoding="utf-8"))
    decision_path = folder / "decision.json"
    decision = json.loads(decision_path.read_text(encoding="utf-8")) if decision_path.exists() else None
    state = export_state(project, proposal_id, decision, root, record=record, repo=repo)
    if state is None:
        raise ProposalError("not_pending", id=proposal_id)
    patches = export_path(project, proposal_id, root).parent
    for leftover in [*folder.glob(".decision.json.*.partial"), *patches.glob(f".{proposal_id}.diff.*.partial")]:
        leftover.unlink(missing_ok=True)
    if state == "conflict":
        raise ProposalError("export_conflict", id=proposal_id, path=decision["export_target"])
    if state == "stale":
        raise ProposalError("export_stale", file=record["file"], id=proposal_id)
    if state == "pending":
        check_version(record, repo)
        export_diff(project, record, root)
    return export_state(project, proposal_id, decision, root, record=record, repo=repo)


def read_json(path):
    """The JSON in `path`, or None if it cannot be read as JSON (cut off or damaged). Never changes the file."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def load_proposals(project, root=None):
    """(record, decision or None) for every readable proposal of a project, newest first. A proposal whose
    proposal.json or decision.json cannot be read (cut off by an interruption under an older version, or damaged)
    is skipped, so it can never break the dashboard; damaged_records() lists it, and it is left untouched."""
    folder = proposals_dir(project, root)
    out = []
    for path in sorted(folder.glob("*/proposal.json"), reverse=True) if folder.is_dir() else []:
        decision_path = path.parent / "decision.json"
        record, decision = read_json(path), read_json(decision_path) if decision_path.exists() else None
        if isinstance(record, dict) and (isinstance(decision, dict) or not decision_path.exists()):
            out.append((record, decision))
    return out


def damaged_records(project, root=None):
    """The proposal.json and decision.json files of a project that cannot be read, relative to the project's
    folder (for example proposals/<id>/proposal.json). They are never changed, replaced or removed."""
    folder = proposals_dir(project, root)
    found = [p for name in ("proposal.json", "decision.json") for p in (folder.glob(f"*/{name}") if folder.is_dir()
                                                                         else [])
             if not isinstance(read_json(p), dict)]
    return sorted(p.relative_to(folder.parent).as_posix() for p in found)


# ---------- command line ----------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Propose a patch for one B602 finding (see the module docstring).")
    parser.add_argument("repo", help="folder of the scanned repository")
    parser.add_argument("--project", required=True)
    parser.add_argument("--scan", help="scan id (default: the newest complete scan)")
    parser.add_argument("--finding", help="finding id, e.g. bandit:B602:app/archive.py:12")
    parser.add_argument("--rereview", metavar="PROPOSAL_ID", help="review a recorded answer again (no request)")
    parser.add_argument("--allowed", help="the folder the value must stay in: a name the file defines at module level")
    parser.add_argument("--send", action="store_true", help="send the text to Nemotron (needs --i-consent)")
    parser.add_argument("--i-consent", action="store_true", help="I agree to send exactly the text shown")
    args = parser.parse_args(argv)
    if not args.finding and not args.rereview:
        parser.error("give --finding (a new proposal) or --rereview PROPOSAL_ID")
    try:
        if args.rereview:
            record = rereview(args.repo, args.project, args.rereview)
            print(f"Re-review {record['id']} of {args.rereview} (no request was sent): {record['status']} ({NOT_TESTED})")
            for c in record["checks"]:
                print(f"[{'PASS' if c['passed'] else 'FAIL'}] {c['detail']}")
            for note in record["observations"]:
                print(f"Observation: {note}")
            return
        scans = [s for s in repo_scan.list_scans(args.project) if s[2] and (not args.scan or s[0] == args.scan)]
        if not scans:
            raise repo_scan.ScanError("no_project", project=args.project)
        scan = repo_scan.load_scan(scans[0][1])
        prepared = prepare(args.repo, scan, args.finding, allowed=args.allowed)
        print("=== exactly what would be sent to Nebius Token Factory (NVIDIA Nemotron) ===")
        print(prepared["sent_text"])
        e = prepared["estimate"]
        print(f"\n=== {len(prepared['sent_text'])} characters; estimate (not a bill): about {e['input_tokens']} input "
              f"tokens; typical output {e['typical_output_tokens']} tokens -> about ${e['typical_usd']}; at most "
              f"{e['max_output_tokens']} output tokens -> at most ${e['max_usd']} (prices in llm.py: "
              f"${e['price_in_per_m']}/M in, ${e['price_out_per_m']}/M out; {e['based_on_calls']} earlier calls) ===")
        if prepared["sensitive"]:
            print("Blocked: " + str(ProposalError("sensitive", kinds=", ".join(sorted({k for k, _ in prepared["sensitive"]})),
                                                  lines=", ".join(str(n) for _, n in prepared["sensitive"]))))
            return
        if not args.send:
            print("Nothing was sent. Add --send --i-consent to send exactly this text.")
            return
        record = propose(args.repo, scan, prepared, consent=args.i_consent)
        print(record["diff"])
        for c in record["checks"]:
            print(f"[{'PASS' if c['passed'] else 'FAIL'}] {c['detail']}")
        print(f"\nProposal {record['id']}: {record['status']} ({NOT_TESTED}). Decide in the dashboard.")
    except (ProposalError, repo_scan.ScanError) as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
