"""python tools/check_results.py --check：核对已提交的结果文件和 README 里的数字。

三步，任何一步不一致就以退出码 1 结束：
1. 重放：按 README 的命令在临时目录里重新生成合成车队和四个活动的输出，逐字节和 data/、out/ 比对。
2. README 数字：从已提交的 CSV / JSON 重新算出 README 首屏和结果表里的每个数字，确认 README 里写的就是这些数。
3. 测试数量：用 pytest --collect-only 数用例，和 README 里写的数量比对。

只用标准库（第 3 步需要已安装 pytest；secure_update 的计数需要 cryptography）。
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CAMPAIGNS = ["baseline", "faulty_variant", "fault_injection", "fault_halt"]
OUT_FILES = ["campaign_record.json", "eligibility.csv", "fault_events.csv", "fault_summary.csv", "outcomes.csv",
             "segment_summary.csv", "wave_plan.csv", "wave_summary.csv"]
FLEET = Path("data") / "fleet_synthetic_MY.csv"
FAULT_LABELS = {  # README 结果表里 fault_injection 一行的写法 → fault_summary.csv 的 (fault, detail)
    "断网": ("NETWORK_OUTAGE", ""),
    "续传": ("DOWNLOAD_INTERRUPTED", "RESUMED"),
    "放弃": ("DOWNLOAD_INTERRUPTED", "ABANDONED"),
    "哈希重下": ("HASH_MISMATCH", "REDOWNLOADED"),
    "拒装": ("HASH_MISMATCH", "REFUSED"),
    "刷写失败": ("FLASH_FAILURE", "ROLLED_BACK"),
    "电量跌落": ("BATTERY_LOW_MID_INSTALL", "ROLLED_BACK"),
    "RXSWIN 回读不一致": ("RXSWIN_MISMATCH_POST_INSTALL", "ROLLED_BACK"),
}


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def record(root: Path, campaign: str) -> dict:
    return json.loads((root / "out" / campaign / "campaign_record.json").read_text(encoding="utf-8"))


# ---------- 1. 重放 ----------

def replay(root: Path = ROOT) -> list[str]:
    """在临时目录重新生成全部输出，返回和已提交文件不一致的路径。"""
    import ota_plan as op
    from datetime import date

    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        fleet_path = tmp_path / FLEET
        fleet_path.parent.mkdir(parents=True)
        rows = op.generate_synthetic_fleet(op.DEFAULT_FLEET_SIZE, 2026, date(2026, 10, 27))
        op.write_csv(fleet_path, rows, op.FLEET_COLUMNS)
        if fleet_path.read_bytes() != (root / FLEET).read_bytes():
            problems.append(FLEET.as_posix())
        fleet = op.load_fleet(root / FLEET)
        for name in CAMPAIGNS:
            c = op.load_campaign(root / "campaigns" / f"campaign_{name}.json")
            as_of = date.fromisoformat(c["as_of"])
            res = op.run_campaign(fleet, c, 7, as_of)
            op.write_outputs(res, c, tmp_path / "out" / name, 7, as_of)
            for f in OUT_FILES:
                if (tmp_path / "out" / name / f).read_bytes() != (root / "out" / name / f).read_bytes():
                    problems.append(f"out/{name}/{f}")
    return problems


# ---------- 2. README 数字 ----------

def pct(num: int, den: int, digits: int) -> str:
    return f"{100 * num / den:.{digits}f}%"


def expected_readme_facts(root: Path = ROOT) -> dict[str, list[str]]:
    """{README 路径: [必须原样出现的片段]}，片段里的每个数字都从已提交的文件算出来。"""
    import ota_plan as op

    fleet = read_csv(root / FLEET)
    base = record(root, "baseline")
    sizing = base["wave_sizing"]
    base_waves = read_csv(root / "out/baseline/wave_summary.csv")
    attempted = sum(int(w["attempted"]) for w in base_waves)
    installed = sum(int(w["installed"]) for w in base_waves)
    base_safe = sum(int(w["safe_state"]) for w in base_waves)
    assert base_safe == 0 and all(w["decision"] == "PASS" for w in base_waves), "baseline 不再是四批 PASS、零安全状态"

    fv = read_csv(root / "out/faulty_variant/wave_summary.csv")[0]
    assert fv["decision"] == "HALT", "faulty_variant 试点不再 HALT"
    seg = [s for s in read_csv(root / "out/faulty_variant/segment_summary.csv")
           if s["wave_no"] == "1" and s["hw_variant"] == "B-H2"][0]

    fi_waves = read_csv(root / "out/fault_injection/wave_summary.csv")
    assert all(w["decision"] == "PASS" for w in fi_waves), "fault_injection 不再四批 PASS"
    fs = {(r["fault"], r["detail"]): r for r in read_csv(root / "out/fault_injection/fault_summary.csv")}
    assert all(r["all_safe_and_recorded"] == "Y" for r in fs.values()), "fault_injection 有故障没落到安全终态"
    total_events = sum(int(r["events"]) for r in fs.values())
    fault_parts = [f"{label} {fs[key]['events']}" for label, key in FAULT_LABELS.items()]
    w3 = fi_waves[2]
    min_attempted = json.loads((root / "campaigns/campaign_fault_injection.json").read_text(encoding="utf-8"))["gates"]["min_attempted"]
    assert w3["decision"] == "PASS" and int(w3["attempted"]) >= min_attempted

    fh = read_csv(root / "out/fault_halt/wave_summary.csv")
    halt_wave = [w for w in fh if w["decision"] == "HALT"][0]
    not_executed = [w["wave_no"] for w in fh if w["decision"] == "NOT_EXECUTED"]
    assert halt_wave["wave_no"] == "2" and not_executed == ["3", "4"], "fault_halt 不再在第2批叫停"

    for name in CAMPAIGNS:
        rec = record(root, name)
        assert rec["final_state_violations"] == [], f"{name} 有终态违规"
        assert sum(rec["final_state_counts"].values()) == sizing["eligible"], f"{name} 终态车辆数不等于合格数"

    n_req = len(read_csv(root / "01_requirements_checklist.csv"))
    n_ctrl = len(read_csv(root / "02_traceability_matrix.csv"))
    n_ts = len(read_csv(root / "03_tara.csv"))
    n_su = len(read_csv(root / "secure_update/traceability_secure_update.csv"))
    assert op.DEFAULT_FLEET_SIZE == len(fleet)

    readme = [
        f"{n_req} 条要求", f"{n_ctrl} 个控制点", f"{n_ts} 个威胁场景",
        f"取 {len(fleet):,} 辆",
        f"合格车辆 {sizing['eligible']:,} / {len(fleet):,}",
        f"试点推送 {sizing['pilot_by_power']} 辆，覆盖全部 {sizing['pilot_strata_covered']} 个分层",
        f"{attempted:,} 次安装，成功率 {pct(installed, attempted, 2)}",
        f"试点回滚 {fv['rolled_back']}/{fv['attempted']}（{pct(int(fv['rolled_back']), int(fv['attempted']), 1)}，"
        f"Wilson 下界 {100 * float(fv['rollback_wilson_low']):.1f}% > 2%）",
        f"B-H2（{seg['failed']}/{seg['attempted']}）",
        f"{total_events} 次故障事件全部落在安全终态",
        *fault_parts,
        f"少于 {min_attempted} 次", f"第3批有 {w3['network_outage']} 辆车断网，但仍有 {w3['attempted']} 次安装",
        f"第{halt_wave['wave_no']}批 {halt_wave['rejected_signature']} 辆车签名无效",
        f"{sizing['eligible']:,} 辆车全部处于安全且有记录的终态",
        f"`traceability_secure_update.csv`（{n_su} 行）",
        # 英文摘要
        f"{n_req} requirements", f"{n_ctrl} controls", f"{n_ts}-threat TARA",
        f"{len(fleet):,}-vehicle synthetic fleet",
        f"{attempted:,} installs at {pct(installed, attempted, 2)}",
        f"{fv['rolled_back']}/{fv['attempted']} pilot rollbacks",
        f"{total_events} injected fault events",
        f"wave {halt_wave['wave_no']}",
    ]
    return {"README.md": readme}


def expected_secure_update_facts() -> dict[str, list[str]]:
    from secure_update import demo
    from secure_update.testbed import write_steps, UpdateBed

    attacks = demo.run_attacks()
    sweep = demo.run_power_sweeps()
    assert all(r["error"] and r["ecu_unchanged"] == "Y" for r in attacks), "有攻击没被拒或改了 ECU"
    assert not any(r["problems"] for r in sweep), "断电扫描有不变量违反"
    bed = UpdateBed()
    demo._new(bed)
    writes = len(write_steps(bed)[1])
    common = [f"{len(attacks)} 种攻击场景", f"共 {len(sweep)} 种情况", f"{writes} 次持久化写入",
              f"{len(attacks)} attacks", f"{len(sweep)} power-cut cases"]
    return {"README.md": common, "secure_update/README.md": [f"{len(attacks)} 个攻击", f"共 {writes} 次持久化写入"]}


def check_readme_numbers(root: Path = ROOT, with_secure_update: bool = True) -> list[str]:
    facts = expected_readme_facts(root)
    if with_secure_update:
        for path, items in expected_secure_update_facts().items():
            facts.setdefault(path, []).extend(items)
    missing = []
    for path, items in facts.items():
        text = (root / path).read_text(encoding="utf-8")
        missing += [f"{path}: 找不到「{item}」" for item in items if item not in text]
    return missing


# ---------- 3. 测试数量 ----------

def collected_counts(root: Path = ROOT) -> Counter:
    proc = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
                          cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
    counts = Counter()
    for line in proc.stdout.splitlines():
        if "::" in line:
            counts[line.split("::")[0]] += 1
    return counts


def check_test_counts(root: Path = ROOT) -> list[str]:
    counts = collected_counts(root)
    main = {f: n for f, n in counts.items() if f.startswith("tests/")}
    su = sum(n for f, n in counts.items() if f.startswith("secure_update/"))
    total = sum(counts.values())
    text = (root / "README.md").read_text(encoding="utf-8")
    su_text = (root / "secure_update/README.md").read_text(encoding="utf-8")
    want = [(text, f"当前 {total} passed（主项目 {sum(main.values())} + secure_update {su}）", "README.md"),
            (text, f"{sum(main.values())} 个 pytest 用例", "README.md"),
            (text, f"{su} 个测试用例", "README.md"),
            (su_text, f"# {total} passed（主项目 {sum(main.values())} 个 + 本目录 {su} 个）", "secure_update/README.md")]
    for f, n in main.items():
        want.append((text, f"`{Path(f).name}` {n} 个", "README.md"))
    return [f"{path}: 找不到「{s}」（按 pytest --collect-only 计数）" for t, s, path in want if s not in t]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="执行全部核对（默认行为，保留这个开关方便 CI 写法统一）")
    ap.add_argument("--skip-test-count", action="store_true")
    args = ap.parse_args(argv)
    problems = [f"重放结果和已提交文件不一致：{p}" for p in replay()]
    problems += check_readme_numbers()
    if not args.skip_test_count:
        problems += check_test_counts()
    for p in problems:
        print("FAIL", p)
    print("全部一致" if not problems else f"{len(problems)} 处不一致")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
