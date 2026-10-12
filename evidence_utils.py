"""Small helpers shared by rejudge.py, judge_check.py and dashboard.py.

Kept out of judge.py on purpose: judge.py is part of the judge fingerprint, and a helper
that only reads evidence files must not change what counts as "the judge".
"""
import hashlib


def lf_sha(data):
    """SHA-256 of text or bytes with CRLF normalized to LF, so Windows and Linux agree."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def describe_export(patch):
    """What happened to one patch's export, read from the record itself: (kind, text).

    Records written by interactive.py carry `export_status` ("exported", "pending", "failed",
    "declined", "not_applicable") and that field alone decides. `exported: false` is never read as
    a refusal by a person: it is also exactly what "pending" and "failed" look like.

    Older records (the CLI runs) have no `export_status`. There, the CLI wrote exported=false for
    an accepted patch only when the person's answer was not "y", so the text says the person did
    not approve it, and says the record is old; it does not say the person "declined".
    """
    approval = str(patch.get("approval") or "not recorded")
    exported = bool(patch.get("exported"))
    status = patch.get("export_status")

    if not patch.get("accepted"):
        if status in ("pending", "failed", "exported") or exported:
            return "inconsistent", (
                f"the record is inconsistent: not accepted by the judge, but export_status={status!r} "
                f"and exported={exported}"
            )
        return "not_accepted", "no export (the judge did not accept it)"

    if status is None:  # older record: no export_status
        if approval.startswith("auto"):
            if exported:
                return "auto_exported", "exported automatically (--yes); no person approved it"
            return "inconsistent", "the record says automatic approval (--yes) but not exported"
        if approval.startswith("human"):
            if exported:
                return "exported", "export approved by a person"
            return "not_approved", (
                "not exported: the person was asked and did not approve it (older record, no export_status)"
            )
        return "unrecorded", "export approval not recorded"

    if status == "exported":
        if not exported:
            return "inconsistent", "the record is inconsistent: export_status='exported' but exported=false"
        return "exported", "export approved by a person" if approval.startswith("human") else (
            "exported (export_status='exported')"
        )
    if status in ("pending", "failed", "declined", "not_applicable") and exported:
        return "inconsistent", f"the record is inconsistent: export_status={status!r} but exported=true"
    if status == "pending":
        return "pending", (
            "export pending: the person approved it, but the export was never confirmed "
            "(the session stopped before finishing; the diff may or may not exist)"
        )
    if status == "failed":
        error = patch.get("export_error")
        return "failed", "export failed: the diff could not be written" + (f" (`{error}`)" if error else "")
    if status == "declined":
        return "declined", "the person declined to export it"
    if status == "not_applicable":
        return "inconsistent", "the record is inconsistent: export_status='not_applicable' on an accepted patch"
    return "unknown", f"export status not recognized: {status!r}"
