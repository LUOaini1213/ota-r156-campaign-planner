"""ota_plan.py 的测试：资格规则、先决条件、发布闸门、分批计算、闸门（叫停）逻辑、端到端。"""
import copy
import csv
import json
from datetime import date
from pathlib import Path

import pytest

import ota_plan as op

ROOT = Path(__file__).resolve().parents[1]
AS_OF = date(2026, 10, 27)


def campaign(name="campaign_baseline.json"):
    return json.loads((ROOT / "campaigns" / name).read_text(encoding="utf-8"))


def vehicle(**overrides):
    v = {
        "vehicle_id": "T-0001", "model": "MODEL_A", "powertrain": "ICE", "market": "MY",
        "region": "MY-CENTRAL", "sw_version": "1.4.2", "hw_variant": "A-H1", "rxswin": "A-RX-06",
        "soc_pct": 80.0, "gear": "P", "ignition": "OFF", "network": "GOOD",
        "last_seen": date(2026, 10, 25), "critical_dtc": 0, "data_source": op.SYNTHETIC_LABEL,
    }
    v.update(overrides)
    return v


# ------------------------------------------------------------ 资格（服务端）
def test_reference_vehicle_is_eligible_and_ready():
    c = campaign()
    assert op.check_eligibility(vehicle(), c, AS_OF) == []
    assert op.check_preconditions(vehicle(), c) == []


@pytest.mark.parametrize("overrides, reason", [
    ({"model": "MODEL_X"}, "MODEL_NOT_TARGETED"),
    ({"market": "TH"}, "MARKET_NOT_TARGETED"),
    ({"hw_variant": "A-H0"}, "HW_INCOMPATIBLE"),
    ({"sw_version": "1.3.9", "rxswin": "A-RX-05"}, "VERSION_NOT_IN_PATH"),
    ({"sw_version": "1.6.0", "rxswin": "A-RX-07"}, "ALREADY_ON_TARGET"),
    ({"rxswin": "A-RX-04"}, "RXSWIN_MISMATCH"),
    ({"last_seen": date(2026, 9, 26)}, "STALE_CONFIG"),  # 31 天
    ({"critical_dtc": 1}, "CRITICAL_DTC"),
])
def test_each_eligibility_rule_gives_its_own_reason(overrides, reason):
    assert op.check_eligibility(vehicle(**overrides), campaign(), AS_OF) == [reason]


def test_last_seen_exactly_at_limit_is_still_eligible():
    assert op.check_eligibility(vehicle(last_seen=date(2026, 9, 27)), campaign(), AS_OF) == []  # 30 天


def test_reasons_accumulate():
    reasons = op.check_eligibility(vehicle(hw_variant="A-H0", critical_dtc=1), campaign(), AS_OF)
    assert reasons == ["HW_INCOMPATIBLE", "CRITICAL_DTC"]


def test_market_approval_pending_only_matters_for_type_approval_relevant_update():
    c = campaign()
    c["target"]["markets"]["MY"]["approval_ready"] = False
    assert op.check_eligibility(vehicle(), c, AS_OF) == ["MARKET_APPROVAL_PENDING"]
    c["target"]["type_approval_relevant"] = False
    assert op.check_eligibility(vehicle(), c, AS_OF) == []


# ------------------------------------------------------------ 先决条件（车端）
@pytest.mark.parametrize("overrides, expected", [
    ({"powertrain": "ICE", "soc_pct": 59.9}, ["LOW_SOC"]),
    ({"powertrain": "ICE", "soc_pct": 60.0}, []),
    ({"powertrain": "BEV", "model": "MODEL_C", "soc_pct": 29.0}, ["LOW_SOC"]),
    ({"powertrain": "BEV", "model": "MODEL_C", "soc_pct": 30.0}, []),
    ({"gear": "D"}, ["NOT_PARKED"]),
    ({"ignition": "ON"}, ["IGNITION_NOT_OFF"]),
    ({"network": "NONE"}, ["NO_NETWORK"]),
    ({"network": "WEAK"}, []),
    ({"gear": "N", "ignition": "ACC", "soc_pct": 10.0}, ["LOW_SOC", "NOT_PARKED", "IGNITION_NOT_OFF"]),
])
def test_preconditions(overrides, expected):
    assert op.check_preconditions(vehicle(**overrides), campaign()) == expected


# ------------------------------------------------------------ 发布闸门
def test_baseline_release_gate_passes():
    assert op.check_release_gate(campaign()) == []


@pytest.mark.parametrize("mutate, keyword", [
    (lambda c: c["release_gate"].update(signature_verified=False), "签名"),
    (lambda c: c["release_gate"].update(vv_passed=False), "V&V"),
    (lambda c: c["release_gate"].update(requires_skilled_action=True), "专业操作"),
    (lambda c: c["release_gate"].update(install_while_driving=True), "行驶中"),
    (lambda c: c["notification"].update(expected_duration_min=""), "expected_duration_min"),
    (lambda c: c["target"]["rxswin_after"].pop("MODEL_B"), "RXSWIN"),
    (lambda c: c["target"]["rxswin_register"].pop("MODEL_C|1.5.0"), "登记册"),
])
def test_release_gate_blocks_planning(mutate, keyword):
    c = campaign()
    mutate(c)
    problems = op.check_release_gate(c)
    assert any(keyword in p for p in problems)
    with pytest.raises(op.ReleaseGateError):
        op.run_campaign([vehicle()], c, seed=1, as_of=AS_OF)


# ------------------------------------------------------------ 分批计算
def test_min_attempts_to_detect():
    assert op.min_attempts_to_detect(0.02, 0.95) == 149
    assert op.min_attempts_to_detect(0.01, 0.95) == 299
    assert op.min_attempts_to_detect(0.05, 0.90) == 45
    with pytest.raises(ValueError):
        op.min_attempts_to_detect(0, 0.95)


def test_wave_targets_pilot_driven_by_detection_power():
    targets, info = op.wave_targets(4000, campaign()["waves"])
    assert info == {"min_attempts": 149, "pilot_by_power": 271}  # ceil(149 / 0.55)
    assert targets == [271, 400, 1600, 4000]


def test_wave_targets_fraction_wins_for_large_fleet():
    targets, _ = op.wave_targets(50000, campaign()["waves"])
    assert targets == [1000, 5000, 20000, 50000]  # 2% = 1000 > 271


def test_wave_targets_small_fleet_puts_everyone_in_pilot():
    targets, _ = op.wave_targets(200, campaign()["waves"])
    assert targets == [200, 200, 200, 200]


def test_wave_targets_rejects_bad_fractions():
    w = copy.deepcopy(campaign()["waves"])
    w["cumulative_fractions"] = [0.1, 0.1, 1.0]
    with pytest.raises(ValueError):
        op.wave_targets(100, w)


def test_allocate_is_proportional_capped_and_exact():
    sizes = {"a": 50, "b": 30, "c": 20}
    assert op.allocate(10, sizes) == {"a": 5, "b": 3, "c": 2}
    assert sum(op.allocate(7, sizes).values()) == 7
    assert op.allocate(500, sizes) == sizes  # 不会超过分层内车辆数


def test_allocate_min_one_covers_every_stratum():
    sizes = {"big": 97, "tiny1": 1, "tiny2": 2}
    alloc = op.allocate(5, sizes, min_one=True)
    assert all(alloc[k] >= 1 for k in sizes) and sum(alloc.values()) == 5


def test_plan_waves_assigns_each_vehicle_once_and_is_reproducible():
    fleet = op.generate_synthetic_fleet(1500, seed=3, as_of=AS_OF)
    for v in fleet:
        v["last_seen"] = date.fromisoformat(v["last_seen"])
    c = campaign()
    eligible = [v for v in fleet if not op.check_eligibility(v, c, AS_OF)]
    plan = op.plan_waves(eligible, c["waves"], seed=11)
    ids = [v["vehicle_id"] for wave in plan for v in wave]
    assert sorted(ids) == sorted(v["vehicle_id"] for v in eligible)  # 不重不漏
    targets, _ = op.wave_targets(len(eligible), c["waves"])
    assert [len(w) for w in plan] == [b - a for a, b in zip([0] + targets[:-1], targets)]
    strata = {op.stratum_key(v) for v in eligible}
    assert {op.stratum_key(v) for v in plan[0]} == strata  # 试点覆盖所有分层
    again = op.plan_waves(eligible, c["waves"], seed=11)
    assert [v["vehicle_id"] for v in again[0]] == [v["vehicle_id"] for v in plan[0]]
    other = op.plan_waves(eligible, c["waves"], seed=12)
    assert [v["vehicle_id"] for v in other[0]] != [v["vehicle_id"] for v in plan[0]]


# ------------------------------------------------------------ 闸门（叫停逻辑）
def stats(attempted, rolled_back=0, safe_state=0, complaints=0):
    return {"attempted": attempted, "rolled_back": rolled_back, "safe_state": safe_state,
            "failed": rolled_back + safe_state, "complaints": complaints}


def test_wilson_interval_known_value():
    low, high = op.wilson_interval(5, 100)
    assert low == pytest.approx(0.0215, abs=1e-3)
    assert high == pytest.approx(0.1118, abs=1e-3)
    assert op.wilson_interval(0, 0) == (0.0, 1.0)


def test_gate_pass():
    assert op.gate_decision(stats(200, rolled_back=1, complaints=1), campaign()["gates"]) == ("PASS", [])


def test_gate_halt_on_any_safe_state():
    decision, reasons = op.gate_decision(stats(500, safe_state=1), campaign()["gates"])
    assert decision == "HALT" and "safe_state" in reasons[0]


def test_gate_halt_when_lower_bound_exceeds_threshold():
    decision, _ = op.gate_decision(stats(200, rolled_back=12), campaign()["gates"])  # 6%，下界约 3.5%
    assert decision == "HALT"


def test_gate_hold_when_only_point_estimate_exceeds_threshold():
    decision, reasons = op.gate_decision(stats(200, rolled_back=5), campaign()["gates"])  # 2.5%，下界约 1.1%
    assert decision == "HOLD" and "rollback_rate" in reasons[0]


def test_gate_hold_on_insufficient_sample():
    decision, reasons = op.gate_decision(stats(10), campaign()["gates"])
    assert decision == "HOLD" and "样本不足" in reasons[0]


def test_gate_halts_even_small_sample_when_evidence_is_clear():
    decision, _ = op.gate_decision(stats(20, rolled_back=8), campaign()["gates"])  # 40%，下界约 22%
    assert decision == "HALT"


def test_gate_complaint_rate_alone_can_halt():
    decision, reasons = op.gate_decision(stats(400, complaints=20), campaign()["gates"])  # 5%
    assert decision == "HALT" and "complaint_rate" in reasons[0]


def test_pilot_gate_requires_detection_power_sample():
    g = campaign()["gates"]
    assert op.gate_decision(stats(140), g)[0] == "PASS"  # 普通批次：140 ≥ 30
    decision, reasons = op.gate_decision(stats(140), g, min_attempted=149)  # 试点：要 149 次
    assert decision == "HOLD" and "140<149" in reasons[0]


def test_small_fleet_skips_empty_waves_instead_of_holding():
    fleet = op.generate_synthetic_fleet(300, seed=8, as_of=AS_OF)
    for r in fleet:
        r["last_seen"] = date.fromisoformat(r["last_seen"])
    res = op.run_campaign(fleet, campaign(), seed=7, as_of=AS_OF)
    assert [w["decision"] for w in res.waves[1:]] == ["SKIPPED_EMPTY"] * 3  # 合格车不到 271 辆，全在试点


# ------------------------------------------------------------ 端到端
@pytest.fixture(scope="module")
def demo_fleet():
    rows = op.generate_synthetic_fleet(op.DEFAULT_FLEET_SIZE, seed=2026, as_of=AS_OF)
    for r in rows:
        r["last_seen"] = date.fromisoformat(r["last_seen"])
    return rows


def test_generator_is_labelled_synthetic_and_reproducible(demo_fleet):
    assert op.DEFAULT_FLEET_SIZE == 5287
    assert len(demo_fleet) == 5287
    assert {r["data_source"] for r in demo_fleet} == {"SYNTHETIC_DEMO"}
    again = op.generate_synthetic_fleet(50, seed=2026, as_of=AS_OF)
    assert [r["vehicle_id"] for r in again] == [r["vehicle_id"] for r in demo_fleet[:50]]
    assert again[0]["soc_pct"] == demo_fleet[0]["soc_pct"]


def test_baseline_campaign_completes(demo_fleet):
    res = op.run_campaign(demo_fleet, campaign(), seed=7, as_of=AS_OF)
    assert res.status == "COMPLETED_ALL_WAVES"
    assert [w["decision"] for w in res.waves] == ["PASS"] * 4
    assert res.waves[0]["attempted"] >= res.sizing["min_attempts"]  # 试点实际安装数够检出能力
    installed = [o for o in res.outcomes if o["outcome"] == "INSTALLED"]
    assert installed and all(o["sw_version_after"] == "1.6.0" for o in installed)
    assert all(o["rxswin_after"].endswith("-RX-07") for o in installed)  # 型式批准相关升级后 RXSWIN 更新
    kept = [o for o in res.outcomes if o["outcome"] != "INSTALLED"]
    assert all(o["rxswin_after"] == o["rxswin_before"] for o in kept)


def test_faulty_variant_stops_after_pilot_and_points_to_bad_hardware(demo_fleet):
    res = op.run_campaign(demo_fleet, campaign("campaign_faulty_variant.json"), seed=7, as_of=AS_OF)
    assert res.status.endswith("_AFTER_pilot") and res.waves[0]["decision"] in ("HOLD", "HALT")
    assert [w["decision"] for w in res.waves[1:]] == ["NOT_EXECUTED"] * 3
    later = [o for o in res.outcomes if o["wave_no"] > 1]
    assert later and {o["outcome"] for o in later} == {"NOT_EXECUTED"}
    pilot = [s for s in res.segments if s["wave_no"] == 1 and s["attempted"]]
    worst = max(pilot, key=lambda s: s["failure_rate"])
    assert worst["hw_variant"] == "B-H2"


def test_cli_writes_outputs_and_blocks_bad_release(tmp_path):
    fleet = tmp_path / "fleet.csv"
    assert op.main(["generate", "--n", "800", "--seed", "5", "--out", str(fleet)]) == 0
    out = tmp_path / "out"
    assert op.main(["run", "--fleet", str(fleet), "--campaign",
                    str(ROOT / "campaigns" / "campaign_baseline.json"), "--out", str(out)]) == 0
    for name in ("eligibility.csv", "wave_plan.csv", "outcomes.csv", "wave_summary.csv",
                 "segment_summary.csv", "campaign_record.json"):
        assert (out / name).exists()
    with open(out / "wave_summary.csv", encoding="utf-8") as fh:
        assert next(csv.reader(fh)) == op.WAVE_FIELDS
    record = json.loads((out / "campaign_record.json").read_text(encoding="utf-8"))
    assert record["final_status"] and "SYNTHETIC" in record["data_note"]

    bad = campaign()
    bad["release_gate"]["signature_verified"] = False
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
    assert op.main(["run", "--fleet", str(fleet), "--campaign", str(bad_path),
                    "--out", str(tmp_path / "bad_out")]) == 2
