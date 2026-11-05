"""Tests for the user/AI custom-command store: it must accept well-formed commands and refuse
destructive ones, and loading must skip anything invalid."""

import os

from dogpark import custom


def test_add_and_load_roundtrip(tmp_path):
    path = os.path.join(tmp_path, "custom_actions.json")
    entry = {
        "label": "Quiet UDP sweep",
        "phase": 1,
        "risk": "quiet",
        "template": "nmap -sU --top-ports 50 -T2 {target} -oA {output}/udp_{target}",
        "needs": ["target", "output"],
        "description": "Quiet UDP sweep of the 50 most common ports.",
    }
    ok, _ = custom.add_custom_action(entry, path)
    assert ok
    actions = custom.load_custom_actions(path)
    assert len(actions) == 1
    a = actions[0]
    assert a.id.startswith("custom.")
    assert a.risk == "quiet"
    assert a.needs == ("target", "output")
    # the rendered command fills in cleanly
    assert "{" not in a.build_command({"target": "192.168.1.5", "output": "/tmp"})


def test_destructive_templates_refused(tmp_path):
    path = os.path.join(tmp_path, "c.json")
    for bad in (
        "nmap --script dos {target}",
        "hping3 --flood {target}",
        "rm -rf / ",
        ":(){ :|:& };:",
    ):
        ok, msg = custom.add_custom_action(
            {"label": "x", "template": bad, "needs": [], "phase": 1}, path
        )
        assert not ok, f"should refuse: {bad}"
        assert "refused" in msg


def test_missing_fields_refused(tmp_path):
    path = os.path.join(tmp_path, "c.json")
    ok, _ = custom.add_custom_action({"label": "", "template": "nmap {target}"}, path)
    assert not ok
    ok, _ = custom.add_custom_action({"label": "x", "template": ""}, path)
    assert not ok


def test_load_missing_file_is_empty():
    assert custom.load_custom_actions("/nonexistent/path/x.json") == ()


def test_load_skips_invalid_entries(tmp_path):
    import json

    path = os.path.join(tmp_path, "c.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(
            {"actions": [
                {"label": "good", "template": "nmap -sV {target}", "needs": ["target"], "phase": 1},
                {"label": "bad-destructive", "template": "hping3 --flood {target}", "phase": 1},
                {"nolabel": True},
            ]},
            fh,
        )
    actions = custom.load_custom_actions(path)
    assert len(actions) == 1
    assert actions[0].label == "good"
