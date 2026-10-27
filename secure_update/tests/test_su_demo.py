"""演示脚本的冒烟测试（不写任何文件）。这是工具测试，不映射到威胁，所以不在 traceability_secure_update.csv 里。"""
import csv
import io

from secure_update import demo


def test_demo_cli_runs_every_scenario_and_reports_success():
    out = io.StringIO()
    assert demo.main([], out=out) == 0
    text = out.getvalue()
    assert "全部检查通过" in text
    for test_id, _, _ in demo.ATTACKS:
        assert test_id in text
    buffer = io.StringIO()
    demo.write_rows(buffer, demo.run_attacks(), demo.ATTACK_FIELDS)
    rows = list(csv.DictReader(io.StringIO(buffer.getvalue())))
    assert len(rows) == len(demo.ATTACKS) and all(r["ecu_unchanged"] == "Y" and r["error"] for r in rows)
