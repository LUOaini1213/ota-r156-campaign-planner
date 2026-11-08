"""Golden 测试：已提交的 data/、out/ 和 README 里的数字都能从代码逐字节重现。

改了 ota_plan.py 的逻辑或活动配置却没有重新生成输出、或者没有同步 README，这里会失败。
"""
from datetime import date
from pathlib import Path

import pytest

import ota_plan as op
from tools import check_results as cr

ROOT = Path(__file__).resolve().parents[1]


def test_fleet_regenerates_byte_identical(tmp_path):
    rows = op.generate_synthetic_fleet(op.DEFAULT_FLEET_SIZE, 2026, date(2026, 10, 27))
    op.write_csv(tmp_path / "fleet.csv", rows, op.FLEET_COLUMNS)
    assert (tmp_path / "fleet.csv").read_bytes() == (ROOT / cr.FLEET).read_bytes()


@pytest.mark.parametrize("name", cr.CAMPAIGNS)
def test_campaign_outputs_byte_identical(tmp_path, name):
    c = op.load_campaign(ROOT / "campaigns" / f"campaign_{name}.json")
    as_of = date.fromisoformat(c["as_of"])
    res = op.run_campaign(op.load_fleet(ROOT / cr.FLEET), c, 7, as_of)
    op.write_outputs(res, c, tmp_path, 7, as_of)
    changed = [f for f in cr.OUT_FILES if (tmp_path / f).read_bytes() != (ROOT / "out" / name / f).read_bytes()]
    assert changed == []


def test_secure_update_headline_counts():
    from secure_update import demo

    attacks, sweep = demo.run_attacks(), demo.run_power_sweeps()
    assert len(attacks) == 14 and all(r["ecu_unchanged"] == "Y" and r["error"] for r in attacks)
    assert len(sweep) == 249 and not any(r["problems"] for r in sweep)


def test_readme_numbers_match_committed_artifacts():
    assert cr.check_readme_numbers(ROOT) == []
