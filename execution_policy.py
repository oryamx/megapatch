"""Whether code written by a model may be run, anywhere: in the Nebius sandbox or on this machine (--local).

It may not, for now. A candidate patch is shown as a proposal, "not executed, not verified": the exploit and the
tests never run against it, so it is never "accepted by the judge" and never exported by the pipeline.

Why: the code a model writes could reach any site, and nothing here can prove it would not.
  - Documented default: the Nebius sandbox gives the guest a network unless the operation asks otherwise: the
    REST field networking.enabled defaults to true (docs.tokenfactory.nebius.com, "Configure networking and
    secrets"). The SDK this project uses, contree-sdk 0.3.6, has no parameter for it, so no run so far asked
    for it to be off. That is what the documentation says, not a verification of each run's network access.
  - Observed once: on 2026-10-10, isolation_check.py saw one outbound TCP connection from the sandbox to
    pypi.org:443 succeed, which does not establish the full extent of its network access.
  - --local would run it on this machine, with this machine's network.
  - A sandbox that accepts no incoming connection says nothing about outgoing ones, and a static filter of the
    candidate can reduce risk but proves nothing about the environment.

What would allow it: an operation started with networking.enabled = false (dependencies prepared beforehand, in an
operation that runs no candidate, since a saved image does not keep the network setting), and a check from inside
that same operation that /sys/class/net holds no interface but the loopback, before the candidate runs. Until that
is implemented and shown, CANDIDATES_MAY_RUN stays False. Changing it is a code change on purpose: no command-line
flag or environment variable can turn it on.

What still runs: the PoCs against the bundled practice app (target_app/, written by hand, through Flask's test
client), never against the repository a person scans, and never against a URL or an IP address.
"""
CANDIDATES_MAY_RUN = False
REASON = ("running model-written code is disabled: no environment here is proven to block outbound network "
          "(the sandbox's guest network is on by default, and --local would use this machine's)")
NOT_RUN = "proposal, not executed and not verified"


class CandidateExecutionDisabled(RuntimeError):
    """Raised by a tool whose only job is to run model-written code (rejudge.py)."""


def candidates_may_run():
    return CANDIDATES_MAY_RUN


def refuse(where):
    raise CandidateExecutionDisabled(f"{where}: {REASON}")
