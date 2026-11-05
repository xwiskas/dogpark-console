"""Template-rendering unit tests for the tool/action registry — no live tools invoked."""

from dogpark.tools import Action, all_tools, find_action, tools_for_phase


def test_registry_is_nonempty_and_has_no_destructive_actions():
    banned_terms = ("dos", "flood", "--max-rate 0", "hping3", "slowloris")
    for tool in all_tools():
        assert tool.actions, f"{tool.name} has no actions"
        for action in tool.actions:
            blob = f"{action.template} {action.description}".lower()
            for term in banned_terms:
                assert term not in blob, f"{tool.name}/{action.id} looks destructive: {term}"


def test_find_action_roundtrip():
    tool, action = find_action("nmap.quiet_top_ports")
    assert tool.name == "nmap"
    assert action.risk == "quiet"


def test_find_action_missing_returns_none():
    assert find_action("does.not.exist") is None


def test_tools_for_phase_filters():
    phase1_tools = tools_for_phase(1)
    assert any(t.category == "discovery" for t in phase1_tools)
    phase6_tools = tools_for_phase(6)
    assert any(t.category == "pivot" for t in phase6_tools)


def test_build_command_fills_placeholders():
    action = Action(
        id="test.action",
        label="Test",
        phase=1,
        description="test",
        risk="quiet",
        template="nmap -sn {target} -oA {output}/x",
        needs=("target", "output"),
    )
    cmd = action.build_command({"target": "192.168.1.5", "output": "/tmp/dogpark"})
    assert cmd == "nmap -sn 192.168.1.5 -oA /tmp/dogpark/x"


def test_build_command_missing_value_renders_blank_not_error():
    action = Action(
        id="test.action2",
        label="Test2",
        phase=1,
        description="test",
        risk="quiet",
        template="tool {target} {missing}",
        needs=("target", "missing"),
    )
    cmd = action.build_command({"target": "192.168.1.5"})
    assert cmd == "tool 192.168.1.5 "


def test_every_action_template_renders_without_crashing():
    for tool in all_tools():
        for action in tool.actions:
            values = {need: f"<{need}>" for need in action.needs}
            rendered = action.build_command(values)
            assert isinstance(rendered, str)
            assert rendered  # non-empty
