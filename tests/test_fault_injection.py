"""故障注入、防回滚和 TARA 表的测试。

每类故障都要落到“安全且有记录”的终态：
  NEW_VERSION_VERIFIED / OLD_VERSION_INTACT / OLD_VERSION_RESTORED / SAFE_STATE_NEEDS_SERVICE
"""
import copy
import csv
import json
import random
from datetime import date
from pathlib import Path

import pytest

import ota_plan as op

ROOT = Path(__file__).resolve().parents[1]
AS_OF = date(2026, 10, 27)


def campaign(name="campaign_baseline.json"):
    return json.loads((ROOT / "campaigns" / name).read_text(encoding="utf-8"))


def ready_vehicle(**overrides):
    v = {
        "vehicle_id": "T-0001", "model": "MODEL_A", "powertrain": "ICE", "market": "MY",
        "region": "MY-CENTRAL", "sw_version": "1.4.2", "hw_variant": "A-H1", "rxswin": "A-RX-06",
        "soc_pct": 80.0, "gear": "P", "ignition": "OFF", "network": "GOOD",
        "last_seen": date(2026, 10, 25), "critical_dtc": 0, "data_source": op.SYNTHETIC_LABEL,
    }
    v.update(overrides)
    return v


def forced(rollback_ok=1.0, install_fail=0.0, **faults):
    """其他环节都必然成功，只让指定的故障发生，结果确定。"""
    c = campaign()
    c["simulation"].update(p_consent=1.0, p_download_ok={"GOOD": 1.0, "WEAK": 1.0},
                           p_install_fail=install_fail, p_rollback_ok=rollback_ok,
                           p_complaint_success=0.0, p_complaint_failure=0.0)
    c["faults"] = faults
    return c


def simulate(c, wave_no=1, **vehicle):
    return op.simulate_vehicle(ready_vehicle(**vehicle), c, random.Random(0), wave_no=wave_no)


def unchanged(r):
    return (r["sw_version_after"], r["rxswin_after"]) == (r["sw_version_before"], r["rxswin_before"])


@pytest.fixture(scope="module")
def demo_fleet():
    rows = op.generate_synthetic_fleet(op.DEFAULT_FLEET_SIZE, seed=2026, as_of=AS_OF)
    for r in rows:
        r["last_seen"] = date.fromisoformat(r["last_seen"])
    return rows


# ------------------------------------------------------------ 单车：每类故障的处理和终态
def test_no_fault_installs_and_updates_rxswin():
    r = simulate(forced())
    assert (r["outcome"], r["final_state"], r["faults"]) == ("INSTALLED", "NEW_VERSION_VERIFIED", "")
    assert (r["sw_version_after"], r["rxswin_after"]) == ("1.6.0", "A-RX-07")


def test_download_interruption_resumes_after_reauthentication():
    r = simulate(forced(p_download_interrupt=1.0, p_resume_ok=1.0))
    assert r["faults"] == "DOWNLOAD_INTERRUPTED:RESUMED"
    assert (r["outcome"], r["final_state"]) == ("INSTALLED", "NEW_VERSION_VERIFIED")


def test_download_interruption_abandoned_keeps_old_version():
    r = simulate(forced(p_download_interrupt=1.0, p_resume_ok=0.0))
    assert (r["outcome"], r["final_state"]) == ("DOWNLOAD_FAILED", "OLD_VERSION_INTACT")
    assert unchanged(r)


def test_hash_mismatch_is_fixed_by_redownload():
    r = simulate(forced(p_hash_mismatch=1.0, p_redownload_ok=1.0))
    assert r["faults"] == "HASH_MISMATCH:REDOWNLOADED" and r["outcome"] == "INSTALLED"


def test_persistent_hash_mismatch_refuses_install():
    r = simulate(forced(p_hash_mismatch=1.0, p_redownload_ok=0.0))
    assert (r["outcome"], r["final_state"]) == ("REJECTED_INTEGRITY", "OLD_VERSION_INTACT")
    assert unchanged(r)
    assert op.summarize([r])["attempted"] == 0  # 拒装不算一次安装


def test_invalid_signature_refuses_install():
    r = simulate(forced(p_signature_invalid=1.0))
    assert (r["outcome"], r["final_state"], r["faults"]) == (
        "REJECTED_SIGNATURE", "OLD_VERSION_INTACT", "SIGNATURE_INVALID:REFUSED")
    assert unchanged(r)


def test_battery_drop_mid_install_rolls_back():
    r = simulate(forced(p_battery_drop=1.0))
    assert r["faults"] == "BATTERY_LOW_MID_INSTALL:ROLLED_BACK"
    assert (r["outcome"], r["final_state"]) == ("ROLLED_BACK", "OLD_VERSION_RESTORED")
    assert unchanged(r)


def test_failed_rollback_ends_in_safe_state_needing_service():
    r = simulate(forced(rollback_ok=0.0, p_battery_drop=1.0))
    assert (r["outcome"], r["final_state"]) == ("SAFE_STATE", "SAFE_STATE_NEEDS_SERVICE")
    assert (r["sw_version_after"], r["rxswin_after"]) == ("UNVERIFIED", "UNVERIFIED")


def test_ecu_flash_failure_rolls_back_automatically():
    r = simulate(forced(install_fail=1.0))
    assert r["faults"] == "FLASH_FAILURE:ROLLED_BACK"
    assert (r["outcome"], r["final_state"]) == ("ROLLED_BACK", "OLD_VERSION_RESTORED")
    assert unchanged(r)


def test_rxswin_mismatch_after_install_rolls_back():
    r = simulate(forced(p_post_verify_mismatch=1.0))
    assert r["faults"] == "RXSWIN_MISMATCH_POST_INSTALL:ROLLED_BACK"
    assert r["outcome"] == "ROLLED_BACK" and r["rxswin_after"] == r["rxswin_before"] == "A-RX-06"


def test_network_outage_keeps_old_version():
    r = simulate(forced(p_network_outage=1.0))
    assert (r["outcome"], r["final_state"], r["faults"]) == (
        "NETWORK_OUTAGE", "OLD_VERSION_INTACT", "NETWORK_OUTAGE")


def test_wave_override_applies_only_to_its_wave():
    c = forced(wave_overrides={"2": {"p_signature_invalid": 1.0}})
    assert simulate(c, wave_no=1)["outcome"] == "INSTALLED"
    assert simulate(c, wave_no=2)["outcome"] == "REJECTED_SIGNATURE"


# ------------------------------------------------------------ 活动层面
def test_signature_failure_halts_campaign(demo_fleet):
    c = campaign()
    c["faults"] = {"wave_overrides": {"1": {"p_signature_invalid": 1.0}}}
    res = op.run_campaign(demo_fleet, c, seed=7, as_of=AS_OF)
    assert res.status == "HALT_AFTER_pilot"
    assert "signature_failures" in res.waves[0]["decision_reasons"]
    assert [w["decision"] for w in res.waves[1:]] == ["NOT_EXECUTED"] * 3
    assert op.check_final_states(res, c) == []


def test_network_outage_wave_holds_instead_of_expanding(demo_fleet):
    c = campaign()
    c["faults"] = {"wave_overrides": {"1": {"p_network_outage": 1.0}}}
    res = op.run_campaign(demo_fleet, c, seed=7, as_of=AS_OF)
    pilot = res.waves[0]
    assert pilot["attempted"] == 0 and pilot["network_outage"] > 0
    assert res.status == "HOLD_AFTER_pilot" and "样本不足" in pilot["decision_reasons"]
    assert op.check_final_states(res, c) == []


def test_wave_crossing_rollback_threshold_stops_later_waves(demo_fleet):
    c = campaign()
    c["faults"] = {"wave_overrides": {"2": {"p_install_fail": 0.5}}}
    res = op.run_campaign(demo_fleet, c, seed=7, as_of=AS_OF)
    assert [w["decision"] for w in res.waves] == ["PASS", "HALT", "NOT_EXECUTED", "NOT_EXECUTED"]
    later = [o for o in res.outcomes if o["wave_no"] > 2]
    assert later and {(o["outcome"], o["final_state"]) for o in later} == {("NOT_EXECUTED", "OLD_VERSION_INTACT")}
    assert op.check_final_states(res, c) == []


def test_zero_fault_rates_reproduce_baseline_exactly(demo_fleet):
    base = op.run_campaign(demo_fleet, campaign(), seed=7, as_of=AS_OF)
    c = campaign()
    c["faults"] = {k: 0.0 for k in op.FAULT_KEYS}
    same = op.run_campaign(demo_fleet, c, seed=7, as_of=AS_OF)
    key = lambda res: [(o["vehicle_id"], o["outcome"], o["complaint"]) for o in res.outcomes]  # noqa: E731
    assert key(same) == key(base)


def test_fault_injection_demo_every_fault_ends_safe_and_recorded(demo_fleet):
    c = campaign("campaign_fault_injection.json")
    res = op.run_campaign(demo_fleet, c, seed=7, as_of=AS_OF)
    assert res.status == "COMPLETED_ALL_WAVES"
    summary = {(f["fault"], f["detail"]): f for f in op.fault_summary(res)}
    expected = {("NETWORK_OUTAGE", ""), ("DOWNLOAD_INTERRUPTED", "RESUMED"), ("DOWNLOAD_INTERRUPTED", "ABANDONED"),
                ("HASH_MISMATCH", "REDOWNLOADED"), ("HASH_MISMATCH", "REFUSED"),
                ("BATTERY_LOW_MID_INSTALL", "ROLLED_BACK"), ("FLASH_FAILURE", "ROLLED_BACK"),
                ("RXSWIN_MISMATCH_POST_INSTALL", "ROLLED_BACK")}
    assert expected <= set(summary)
    assert all(f["all_safe_and_recorded"] == "Y" for f in summary.values())
    assert all(e["response"] and e["basis"] and e["final_state"] in op.SAFE_FINAL_STATES for e in res.fault_events)
    assert op.check_final_states(res, c) == []


def test_fault_halt_demo_refuses_tampered_packages_and_stops(demo_fleet):
    c = campaign("campaign_fault_halt.json")
    res = op.run_campaign(demo_fleet, c, seed=7, as_of=AS_OF)
    assert res.status == "HALT_AFTER_expand-1"
    assert [w["decision"] for w in res.waves] == ["PASS", "HALT", "NOT_EXECUTED", "NOT_EXECUTED"]
    rejected = [o for o in res.outcomes if o["outcome"] == "REJECTED_SIGNATURE"]
    assert rejected and all(o["final_state"] == "OLD_VERSION_INTACT" and unchanged(o) for o in rejected)


def test_check_final_states_catches_unpaired_version():
    res = op.run_campaign([ready_vehicle()], forced(), seed=1, as_of=AS_OF)
    assert op.check_final_states(res, forced()) == []
    res.outcomes[0]["rxswin_after"] = "A-RX-06"  # 新软件配旧 RXSWIN：必须被查出来
    assert op.check_final_states(res, forced())


def test_release_gate_blocks_downgrade():
    c = campaign()
    c["target"]["to_version"] = "1.4.0"
    assert any("防回滚" in p for p in op.check_release_gate(c))
    c["release_gate"]["authorized_downgrade"] = True
    assert not any("防回滚" in p for p in op.check_release_gate(c))


# ------------------------------------------------------------ TARA 表复算
R155_THREATS = (
    {"1.1", "1.2", "1.3", "2.1", "3.1", "3.2", "3.3", "3.4", "3.5", "4.1", "4.2", "5.1", "5.2", "5.3", "5.4",
     "5.5", "6.1", "6.2", "6.3", "7.1", "7.2", "8.1", "8.2", "9.1", "10.1", "11.1", "11.2", "11.3", "11.4",
     "12.1", "12.2", "12.3", "12.4", "13.1", "15.1", "15.2", "16.1", "16.2", "16.3", "17.1", "18.1", "18.2",
     "18.3", "19.1", "19.2", "19.3", "20.1", "20.2", "20.3", "20.4", "20.5", "21.1", "22.2", "23.1", "24.1",
     "25.1", "25.2", "26.1", "26.2", "26.3", "27.1", "28.1", "28.2", "29.1", "29.2", "31.1", "32.1"}
)  # R155 附件5 表A1 的全部编号（S4）
LEVELS = ["Negligible", "Moderate", "Major", "Severe"]
RISK = {"Severe": [2, 3, 4, 5], "Major": [1, 2, 3, 4], "Moderate": [1, 2, 2, 3], "Negligible": [1, 1, 1, 1]}
FEAS = ["VeryLow", "Low", "Medium", "High"]


def feasibility(ap_sum):
    return "High" if ap_sum <= 9 else "Medium" if ap_sum <= 13 else "Low" if ap_sum <= 19 else "VeryLow"


def test_tara_csv_is_internally_consistent():
    rows = list(csv.DictReader(open(ROOT / "03_tara.csv", encoding="utf-8-sig")))
    controls = {r["control_id"] for r in csv.DictReader(open(ROOT / "02_traceability_matrix.csv",
                                                             encoding="utf-8-sig"))}
    assert len(rows) == 8
    for r in rows:
        impact = max((r[f"impact_{k}"] for k in "SFOP"), key=LEVELS.index)
        assert r["impact_used"] == impact
        for stage in ("init", "res"):
            factors = [int(r[f"{stage}_{k}"]) for k in
                       ("elapsed_time", "expertise", "knowledge", "window", "equipment")]
            assert int(r[f"{stage}_ap_sum"]) == sum(factors)
            assert r[f"{stage}_feasibility"] == feasibility(sum(factors))
            assert int(r[f"{stage}_risk"]) == RISK[impact][FEAS.index(r[f"{stage}_feasibility"])]
        assert int(r["res_risk"]) <= int(r["init_risk"]) and int(r["res_risk"]) <= 2
        if int(r["init_risk"]) >= 3:
            assert "降低" in r["treatment"]
        assert set(r["r155_annex5_threats"].split(";")) <= R155_THREATS
        assert set(r["controls"].split(";")) <= controls
        assert all(m.startswith("M") and 1 <= int(m[1:]) <= 24 for m in r["r155_mitigations"].split(";"))
