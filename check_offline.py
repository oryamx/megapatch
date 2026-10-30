"""Focused check: what MegaPatch may reach, and what it may run. No network, no model, no sandbox, no credentials.

  1. The detector the checks use (no_network) refuses, in this process, any host other than this machine before
     anything is sent (name lookups, TCP and UDP connections, UDP datagrams), records it, and leaves this machine
     reachable. It is a detector with known gaps (child processes, references taken before it was installed, C
     code: see no_network.py), not a barrier; the checks also replace every service with a mock.
  2. Model-written code is never run (execution_policy.py): the switch is off, no flag or environment variable can
     turn it on, and nothing outside it sets it. The pipeline's patch loop, with the sandbox label and with
     --local alike, never hands the candidate to the judge, asks nothing, accepts and exports nothing.
     rejudge.py and sandbox_spike.py refuse before any sandbox call.
  3. The PoCs reach the practice app only in-process (Flask's test client): no network module, no URL, no IP
     address. The scan and the patch proposal never call a PoC.
  4. A local scan is local by default: no dependency check and no threat data unless asked for, in the code and in
     the dashboard's form; the commit is read without running git.
  5. A limited inventory, not a proof: a text search of MegaPatch's own top-level .py modules (not its checks,
     not third-party packages, not the tools it starts, such as Bandit, pip-audit or git) for six call patterns
     (urlopen(, OpenAI(, ContreeSync(, create_connection(, requests.get( or requests.post(, httpx.) finds them
     only in the modules listed in NETWORK_MODULES. It cannot see network code written any other way (another
     library, an indirect or dynamic call, code inside a dependency), and it says nothing about whether the
     system is isolated. Tavily is used only when asked for with --enrich (a TAVILY_API_KEY alone does nothing),
     and isolation_check.py, which opens a connection from the sandbox to pypi.org on purpose, is run by no
     routine check.
None of this tests the isolation of the system: no part of it runs at the level of the operating system.

Read-only: the repository is only read; the one patch-loop case writes a fake candidate (text, never run) to a
temporary folder. Usage: python check_offline.py   (judge_check.py runs it too)
"""
import ast
import builtins
import inspect
import os
import re
import socket
import sys
import tempfile
import urllib.request
from pathlib import Path

import no_network

HERE = Path(__file__).resolve().parent
results = []
NETWORK_MODULES = {  # where the text search below expects its call patterns, and what each module reaches
    "fetch_threat_data.py": "CISA KEV, FIRST EPSS, NVD (only for a scan's --threat-data / the dashboard box)",
    "enrich.py": "Tavily (the pipeline's enrichment step)",
    "llm.py": "Nebius Token Factory (Nemotron)",
    "sandbox_judge.py": "Nebius Sandboxes (the PoC on the practice app)",
    "sandbox_spike.py": "Nebius Sandboxes (gate script)",
    "isolation_check.py": "Nebius Sandboxes (gate script)",
    "no_network.py": "nothing: it refuses connections for the checks",
}
NETWORK_CALL = re.compile(r"urlopen\(|OpenAI\(|ContreeSync\(|create_connection\(|requests\.(get|post)\(|httpx\.")
POCS = ("poc_sqli.py", "poc_cmdi.py", "poc_path.py")


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def source(name):
    return (HERE / name).read_text(encoding="utf-8")


def project_modules():
    """MegaPatch's own modules: not its checks, not third-party code, not anything a scan analyzes."""
    return sorted(p.name for p in HERE.glob("*.py") if not p.name.startswith("check_") and p.name != "judge_check.py")


def refuses_first(path, function, calls):
    """In `function` of `path`: a `if not policy.candidates_may_run(): raise ...` comes before any call in `calls`."""
    tree = ast.parse(source(path))
    body = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function).body
    for statement in body:
        text = ast.unparse(statement)
        if isinstance(statement, ast.If) and "policy.candidates_may_run()" in ast.unparse(statement.test) and any(
                isinstance(n, ast.Raise) for n in statement.body):
            return True
        if any(f"{c}(" in text for c in calls):
            return False
    return False


def main():
    no_network.install()

    # 1. The tripwire.
    refused = []
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for label, attempt in (("a TCP connection to 192.0.2.1 (a documentation-only address)",
                            lambda: socket.create_connection(("192.0.2.1", 9), timeout=1)),
                           ("a name lookup of example.invalid (a reserved name)",
                            lambda: socket.getaddrinfo("example.invalid", 443)),
                           ("gethostbyname of example.invalid", lambda: socket.gethostbyname("example.invalid")),
                           ("a UDP datagram to 192.0.2.1", lambda: udp.sendto(b"x", ("192.0.2.1", 9))),
                           ("an HTTP request through urllib (no proxy: the request itself must be refused)",
                            lambda: urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                                "https://example.invalid/", timeout=1))):
        try:
            attempt()
            refused.append((label, False))
        except Exception as exc:  # urllib wraps the refusal in a URLError
            refused.append((label, isinstance(exc, no_network.NetworkBlocked)
                            or isinstance(getattr(exc, "reason", None), no_network.NetworkBlocked)))
    local_ok = bool(socket.getaddrinfo("localhost", 0)) and bool(socket.getaddrinfo("127.0.0.1", 0))
    sent_locally = udp.sendto(b"x", ("127.0.0.1", 9)) == 1  # this machine stays reachable (a datagram to itself)
    udp.close()
    tried = list(no_network.ATTEMPTS)
    no_network.ATTEMPTS.clear()
    gaps = all(x in no_network.__doc__ for x in ("not a network barrier", "does NOT cover", "child processes",
                                                  "_socket", "ConnectEx", "operating system"))
    check("the checks' detector refuses any other host in this process before sending anything (lookups, TCP, UDP), "
          "records it, leaves this machine reachable, and documents what it does not cover",
          all(ok for _, ok in refused) and len(tried) == 5 and local_ok and sent_locally and gaps,
          f"({refused}, {tried})")

    # 2. Model-written code is never run.
    import execution_policy as policy
    policy_src = source("execution_policy.py")
    setters = []
    for name in project_modules():
        for node in ast.walk(ast.parse(source(name))):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    if "CANDIDATES_MAY_RUN" in ast.unparse(target):
                        setters.append(name)
    check("execution policy: running model-written code is off, no flag or environment variable can turn it on, and "
          "only execution_policy.py sets it",
          policy.CANDIDATES_MAY_RUN is False and policy.candidates_may_run() is False
          and not any(x in policy_src for x in ("os.environ", "getenv", "sys.argv", "argparse"))
          and setters == ["execution_policy.py"], f"({setters})")

    import run_patch_loop as loop

    class Judge:
        def __init__(self):
            self.calls = []

        def __call__(self, app_dir, poc, run_tests=True):
            self.calls.append(str(app_dir))
            raise AssertionError("the judge was handed a candidate")

    asked = []
    real_input = builtins.input
    builtins.input = lambda question="": asked.append(question) or "y"
    outcomes = {}
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            real_candidates = loop.CANDIDATES
            loop.CANDIDATES = tmp / "candidates"
            try:
                (loop.CANDIDATES / "CWE-89").mkdir(parents=True)
                practice_app = (HERE / "target_app" / "app.py").read_text(encoding="utf-8")
                (loop.CANDIDATES / "CWE-89" / "app.py").write_text(  # text only: it is never run
                    practice_app + "\n# a candidate\n", encoding="utf-8")
                for label, where, auto_yes in (("sandbox", "the Nebius sandbox", True),
                                               ("--local, with the question", loop.LOCAL_LABEL, False),
                                               ("--local --yes", loop.LOCAL_LABEL, True)):
                    judge = Judge()
                    result = loop.patch_cycle(judge, where, "CWE-89", "evidence", auto_yes=auto_yes, generate=False,
                                              export_dir=tmp / "out" / label)
                    outcomes[label] = (judge.calls, result["executed"], result["accepted"], result["exported"],
                                       "candidate" in result["diff"], (tmp / "out").exists())
            finally:
                loop.CANDIDATES = real_candidates
    finally:
        builtins.input = real_input
    check("pipeline patch loop: in the sandbox and with --local (with or without the question), the candidate is never "
          "handed to the judge; nothing is asked, accepted or exported; the diff is still shown",
          outcomes == {k: ([], False, False, False, True, False) for k in outcomes} and len(outcomes) == 3
          and not asked, f"({outcomes}, asked={asked})")
    check("rejudge.py and sandbox_spike.py refuse to run model-written code before any sandbox call",
          refuses_first("rejudge.py", "main", ("warm_up", "rejudge_patch", "describe_environment", "judge_in_sandbox"))
          and source("sandbox_spike.py").count("policy.candidates_may_run()") == 2)

    # 3. The PoCs.
    findings = {}
    for name in POCS:
        tree = ast.parse(source(name))
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {
            n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        constants = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        findings[name] = (sorted(imported), "test_client()" in source(name),
                          [c for c in constants if "://" in c or re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", c)])
    harness_tree = ast.parse(source("harness.py"))
    harness_imports = {a.name.split(".")[0] for n in ast.walk(harness_tree) if isinstance(n, ast.Import)
                       for a in n.names} | {n.module.split(".")[0] for n in ast.walk(harness_tree)
                                            if isinstance(n, ast.ImportFrom) and n.module}
    callers = [m for m in ("repo_scan.py", "scan_view.py", "propose_patch.py")
               if re.search(r"poc_|\[\"poc\"\]", source(m))]
    check("PoCs: they reach the practice app only in-process (Flask's test client): no network module, no URL, no IP "
          "address; the scan and the patch proposal never call one",
          all(imports == ["harness", "sys"] and client and not targets
              for imports, client, targets in findings.values())
          and not harness_imports & {"socket", "urllib", "requests", "http", "subprocess", "httpx"} and not callers,
          f"({findings}, {callers})")

    # 4. The local scan's defaults.
    import repo_scan
    params = inspect.signature(repo_scan.scan).parameters
    view = source("scan_view.py")
    check("local scan: no dependency check and no threat data unless asked for (the function's defaults and the "
          "dashboard's two boxes, unticked); git is not run on the analyzed folder",
          params["audit_dependencies"].default is False and params["threat_data"].default is False
          and 'st.checkbox(t("rp_audit"), value=False' in view and 'st.checkbox(t("rp_threat"), value=False' in view
          and "rev-parse" not in source("repo_scan.py") and '["git"' not in source("repo_scan.py"))

    # 5. A limited inventory: where six call patterns appear in MegaPatch's own top-level modules (a text search).
    found = sorted(name for name in project_modules() if NETWORK_CALL.search(source(name)))
    check("inventory (a text search, not a proof of isolation): the six network call patterns appear only in the "
          "listed modules of MegaPatch's own code", set(found) <= set(NETWORK_MODULES), f"({found})")
    import enrich
    with_key = dict(os.environ, TAVILY_API_KEY="placeholder-not-a-key")
    real_environ = os.environ
    os.environ = with_key
    try:
        unasked = enrich.enrich_finding({"cve": "CVE-2023-4863", "id": "x"})
    finally:
        os.environ = real_environ
    pipeline = source("megapatch.py")
    check("Tavily: only when asked for with --enrich; a TAVILY_API_KEY alone sends nothing",
          unasked == {"skipped": "not requested (run megapatch.py with --enrich)"} and not no_network.ATTEMPTS
          and 'parser.add_argument("--enrich", action="store_true"' in pipeline and "args.enrich" in pipeline
          and pipeline.count("requested=True") == 1, f"({unasked})")
    routine = [name for name in sorted(p.name for p in HERE.glob("check_*.py")) + ["judge_check.py"]
               if name != "check_offline.py" and re.search(r"isolation_check\.py|import isolation_check|"
                                                             r"from isolation_check", source(name))]
    check("isolation_check.py (a connection from the sandbox to pypi.org, on purpose) is run by no routine check",
          not routine, f"({routine})")
    check("this check did not try to reach another host", not no_network.ATTEMPTS, f"({no_network.ATTEMPTS})")

    print("\nCHECK-OFFLINE:", "ALL PASSED" if results and all(results) else "FAILED")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()
