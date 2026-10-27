#!/usr/bin/env python3
"""ota_plan.py：海外市场 OTA 升级活动规划演示工具（作品集项目，不是生产代码）。

子命令
  generate  生成合成（SYNTHETIC）演示车队 CSV。每行 data_source=SYNTHETIC_DEMO，不是真实车辆数据。
  run       读取车队 CSV 和活动配置 JSON，依次执行：
              1. 发布闸门：签名、V&V、告知内容、RXSWIN 配置齐全才允许排计划
              2. 资格筛选（服务端）：车型 / 市场 / 硬件 / 版本路径 / RXSWIN 一致性 / 数据新鲜度 / 故障码
              3. 分层分批：试点 → 扩量 → 全量，试点样本量按检出能力计算
              4. 逐批模拟（固定随机种子）：车端先决条件 → 用户确认 → 下载 → 安装 → 失败回滚
              5. 每批过闸：PASS 继续 / HOLD 暂停扩量 / HALT 叫停
            结果写成 CSV 和 JSON，并在终端打印摘要。

只用 Python 3.10+ 标准库。每条规则对应的法规条款见 02_traceability_matrix.csv。
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

SYNTHETIC_LABEL = "SYNTHETIC_DEMO"
# 规模参照：调用方提供的马来西亚 JPJ 登记汇总中 Chery 2025-01—2026-08 约 52,872 辆，按 1:10 缩放。
# 只用来定车队规模，车队内容全部是合成的。
DEFAULT_FLEET_SIZE = round(52_872 / 10)

FLEET_COLUMNS = [
    "vehicle_id", "model", "powertrain", "market", "region", "sw_version", "hw_variant",
    "rxswin", "soc_pct", "gear", "ignition", "network", "last_seen", "critical_dtc", "data_source",
]

# 资格（服务端，排计划前）不通过的原因码
ELIGIBILITY_TEXT = {
    "MODEL_NOT_TARGETED": "车型不在本次活动范围",
    "MARKET_NOT_TARGETED": "市场不在本次活动范围",
    "MARKET_APPROVAL_PENDING": "该市场的型式批准扩展未就绪",
    "HW_INCOMPATIBLE": "硬件变体与升级包不兼容",
    "ALREADY_ON_TARGET": "已经是目标版本",
    "VERSION_NOT_IN_PATH": "当前版本不在允许的升级路径",
    "RXSWIN_MISMATCH": "车上 RXSWIN 与版本登记册不一致",
    "STALE_CONFIG": "最后已知配置过旧（last_seen 超期）",
    "CRITICAL_DTC": "存在严重故障码",
}
# 先决条件（车端，安装开始前）不满足的原因码
PRECONDITION_TEXT = {
    "LOW_SOC": "电量低于阈值",
    "NOT_PARKED": "不在 P 挡",
    "IGNITION_NOT_OFF": "点火未关闭",
    "NO_NETWORK": "无网络",
}
# R156 7.2.2.2 (a)-(e) / GB 44496 5.2.1 要求升级前告知的内容
NOTIFICATION_FIELDS = ("purpose", "changes", "expected_duration_min", "unavailable_functions", "instructions")
ATTEMPTED = ("INSTALLED", "ROLLED_BACK", "SAFE_STATE")  # 实际开始安装的结局
# 闸门检查的比率指标：(指标名, 分子字段, 配置里的阈值键)，分母都是实际安装数。
# 成功率 = 1 - 回滚率 - 安全状态率；安全状态零容忍、回滚率设阈值，就等于给成功率设了下限，
# 所以不再单独给成功率设闸门，免得同一件事被判两次。
RATE_GATES = (
    ("rollback_rate", "rolled_back", "max_rollback_rate"),
    ("complaint_rate", "complaints", "max_complaint_rate"),
)

# 故障注入：故障 → (谁发现, 怎么处理, 依据)。控制点 C19–C27 来自 03_TARA_OTA.md
FAULT_INFO = {
    "NETWORK_OUTAGE": ("连接中断", "不下载；已下载的车安装前联网确认不了就不装", "C07；C23"),
    "DOWNLOAD_INTERRUPTED": ("车端下载管理", "重新认证服务器后断点续传，续传后照常校验；续传失败则放弃",
                             "GB 44495 7.3(3)；C21"),
    "SIGNATURE_INVALID": ("车端校验：升级清单签名", "拒装，上报安全事件；活动零容忍，出现即叫停",
                          "R156 7.2.1.1、7.1.3.1；R155 M16；C12"),
    "HASH_MISMATCH": ("车端校验：镜像哈希对比已签名清单", "丢弃并重新下载；仍不一致就拒装",
                      "R156 7.2.1.1；GB 44496 5.1.1；R155 M16；C19"),
    "BATTERY_LOW_MID_INSTALL": ("车端电源监控", "中止安装并回滚（先决条件已预留回滚所需电量）",
                                "R156 7.2.2.1.1、7.2.2.1.2；GB 44496 5.2.4、5.2.9；C08、C10"),
    "FLASH_FAILURE": ("ECU 刷写结果", "自动回滚到旧版本", "R156 7.2.2.1.1；GB 44496 5.2.9；C10"),
    "RXSWIN_MISMATCH_POST_INSTALL": ("安装后回读校验", "判为失败并回滚，保证软件版本和 RXSWIN 成对一致",
                                     "R156 7.1.1.4、7.2.1.2.1；C17"),
}
# 每辆车的终态。四种都算“安全且有记录”：要么在已核实的版本上，要么在安全状态等待服务
FINAL_STATE = {"INSTALLED": "NEW_VERSION_VERIFIED", "ROLLED_BACK": "OLD_VERSION_RESTORED",
               "SAFE_STATE": "SAFE_STATE_NEEDS_SERVICE"}  # 其他结局 = OLD_VERSION_INTACT（没开始安装）
SAFE_FINAL_STATES = ("NEW_VERSION_VERIFIED", "OLD_VERSION_INTACT", "OLD_VERSION_RESTORED",
                     "SAFE_STATE_NEEDS_SERVICE")


def version_tuple(v: str) -> tuple:
    """'1.4.2' → (1, 4, 2)，用来比较版本高低（防回滚检查）。"""
    return tuple(int(x) for x in v.split("."))


class ReleaseGateError(Exception):
    """发布闸门没过：不允许排推送计划。"""


# ---------------------------------------------------------------- 读入
def load_fleet(path: str | Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in FLEET_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"车队 CSV 缺列：{missing}")
        rows = []
        for r in reader:
            r = dict(r)
            r["soc_pct"] = float(r["soc_pct"])
            r["critical_dtc"] = int(r["critical_dtc"])
            r["last_seen"] = date.fromisoformat(r["last_seen"])
            rows.append(r)
    return rows


def load_campaign(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- 1. 发布闸门
def check_release_gate(c: dict) -> list[str]:
    """返回问题清单；空清单 = 允许排计划。"""
    problems = []
    rg, t = c["release_gate"], c["target"]
    if not rg.get("signature_verified"):
        problems.append("升级包签名未验证（R156 7.2.1.1、7.1.3.1；GB 44496 5.1.1）")
    if not rg.get("vv_passed"):
        problems.append("未确认通过验证与确认 V&V（R156 7.1.2.5 (i)）")
    if rg.get("requires_skilled_action"):
        problems.append("需要专业操作（如重新标定传感器），改为到店由技术人员完成，不进入面向用户的 OTA 推送（R156 7.1.4.2）")
    if rg.get("install_while_driving"):
        problems.append("本设计不允许行驶中安装（R156 7.1.4.1、7.2.2.3；GB 44496 5.2.6）")
    note = c.get("notification", {})
    missing = [k for k in NOTIFICATION_FIELDS if not str(note.get(k, "")).strip()]
    if missing:
        problems.append(f"用户告知内容缺字段 {missing}（R156 7.2.2.2；GB 44496 5.2.1）")
    for model in t["models"]:
        for ver in t["from_versions"]:
            if f"{model}|{ver}" not in t["rxswin_register"]:
                problems.append(f"版本登记册缺 {model}|{ver}，无法核对 RXSWIN（R156 7.1.1.4、7.1.2.3）")
    if t.get("type_approval_relevant"):
        no_rx = [m for m in t["models"] if m not in t.get("rxswin_after", {})]
        if no_rx:
            problems.append(f"升级涉及型式批准相关软件，但未给出升级后 RXSWIN：{no_rx}（R156 7.2.1.2.1；01 系列 7.1.4）")
    lower = [f for f in t["from_versions"] if version_tuple(t["to_version"]) <= version_tuple(f)]
    if lower and not rg.get("authorized_downgrade"):
        problems.append(f"目标版本 {t['to_version']} 不高于当前版本 {lower}：疑似降级，需要单独审批"
                        "（防回滚 C22；R155 附件5 威胁 6.3）")
    return problems


# ---------------------------------------------------------------- 2. 资格（服务端）
def check_eligibility(v: dict, c: dict, as_of: date) -> list[str]:
    """服务端资格筛选，返回不通过的原因码；空清单 = 合格。"""
    t = c["target"]
    reasons = []
    if v["model"] not in t["models"]:
        reasons.append("MODEL_NOT_TARGETED")
    market = t["markets"].get(v["market"])
    if market is None:
        reasons.append("MARKET_NOT_TARGETED")
    elif t.get("type_approval_relevant") and not market.get("approval_ready"):
        reasons.append("MARKET_APPROVAL_PENDING")
    if v["hw_variant"] not in t["compatible_hw"]:
        reasons.append("HW_INCOMPATIBLE")
    if v["sw_version"] == t["to_version"]:
        reasons.append("ALREADY_ON_TARGET")
    elif v["sw_version"] not in t["from_versions"]:
        reasons.append("VERSION_NOT_IN_PATH")
    expected = t["rxswin_register"].get(f"{v['model']}|{v['sw_version']}")
    if expected is not None and v["rxswin"] != expected:
        reasons.append("RXSWIN_MISMATCH")
    if (as_of - v["last_seen"]).days > t["max_last_seen_days"]:
        reasons.append("STALE_CONFIG")
    if v["critical_dtc"]:
        reasons.append("CRITICAL_DTC")
    return reasons


# ---------------------------------------------------------------- 先决条件（车端）
def check_preconditions(v: dict, c: dict) -> list[str]:
    """车端在安装开始前检查，返回不满足的原因码；空清单 = 可以开始安装。

    要求联网是设计选择：安装前向服务器确认活动仍有效（叫停后已下载的车也不会再装），并能回传结果。
    """
    p = c["preconditions"]
    reasons = []
    if v["soc_pct"] < p["min_soc_pct"][v["powertrain"]]:
        reasons.append("LOW_SOC")
    if v["gear"] != p["required_gear"]:
        reasons.append("NOT_PARKED")
    if v["ignition"] != p["required_ignition"]:
        reasons.append("IGNITION_NOT_OFF")
    if v["network"] not in p["allowed_network"]:
        reasons.append("NO_NETWORK")
    return reasons


# ---------------------------------------------------------------- 3. 分批
def min_attempts_to_detect(rate: float, confidence: float) -> int:
    """真实失败率为 rate 时，想以 confidence 的概率至少看到 1 次失败，需要多少次实际安装。

    1 - (1 - rate)^n >= confidence  =>  n >= ln(1 - confidence) / ln(1 - rate)
    例：rate=2%、confidence=95% 时 n=149。
    """
    if not (0 < rate < 1 and 0 < confidence < 1):
        raise ValueError("rate 和 confidence 都必须在 0 和 1 之间")
    return math.ceil(math.log(1 - confidence) / math.log(1 - rate))


def wave_targets(n: int, w: dict) -> tuple[list[int], dict]:
    """返回每批结束时的累计车辆数，以及试点样本量的计算过程。"""
    fracs = w["cumulative_fractions"]
    if any(b <= a for a, b in zip(fracs, fracs[1:])) or abs(fracs[-1] - 1.0) > 1e-9:
        raise ValueError("cumulative_fractions 必须严格递增，且最后一个是 1.0")
    if len(w["names"]) != len(fracs):
        raise ValueError("names 和 cumulative_fractions 的个数必须相同")
    need = min_attempts_to_detect(w["pilot_detect_rate"], w["pilot_confidence"])
    pilot_by_power = math.ceil(need / w["expected_attempt_ratio"])  # 推送车辆数 ≠ 实际安装数
    targets, prev = [], 0
    for i, f in enumerate(fracs):
        t = math.ceil(f * n)
        if i == 0:
            t = max(t, pilot_by_power)
        t = min(max(t, prev), n)
        targets.append(t)
        prev = t
    targets[-1] = n
    return targets, {"min_attempts": need, "pilot_by_power": pilot_by_power}


def allocate(total: int, sizes: dict, min_one: bool = False) -> dict:
    """把 total 辆车按比例分到各分层（最大余数法，整数运算，结果可复现）。

    min_one=True 时先给每个非空分层 1 辆，保证试点覆盖每个 车型×硬件×地区 组合。
    """
    keys = sorted(k for k, s in sizes.items() if s > 0)
    alloc = {k: 0 for k in keys}
    cap = {k: sizes[k] for k in keys}
    total = max(0, min(total, sum(cap.values())))
    if min_one and keys and total >= len(keys):
        for k in keys:
            alloc[k], cap[k] = 1, cap[k] - 1
        total -= len(keys)
    pool = sum(cap.values())
    if total == 0 or pool == 0:
        return alloc
    floors = {k: (total * cap[k]) // pool for k in keys}
    remainder = {k: (total * cap[k]) % pool for k in keys}
    rest = total - sum(floors.values())
    for k in sorted(keys, key=lambda k: (-remainder[k], k))[:rest]:
        floors[k] += 1
    for k in keys:
        alloc[k] += floors[k]
    return alloc


def stratum_key(v: dict) -> str:
    return f"{v['model']}|{v['hw_variant']}|{v['region']}"


def plan_waves(eligible: list[dict], w: dict, seed: int) -> list[list[dict]]:
    """分层随机分批：每批在各分层里按剩余车辆数比例抽取。"""
    rng = random.Random(seed)
    strata = defaultdict(list)
    for v in sorted(eligible, key=lambda r: r["vehicle_id"]):
        strata[stratum_key(v)].append(v)
    for k in sorted(strata):
        rng.shuffle(strata[k])
    targets, _ = wave_targets(len(eligible), w)
    plan, assigned = [], 0
    for i, cum in enumerate(targets):
        alloc = allocate(cum - assigned, {k: len(lst) for k, lst in strata.items()}, min_one=(i == 0))
        wave = []
        for k in sorted(alloc):
            wave.extend(strata[k][:alloc[k]])
            strata[k] = strata[k][alloc[k]:]
        plan.append(wave)
        assigned += len(wave)
    return plan


# ---------------------------------------------------------------- 4. 模拟
FAULT_KEYS = ("p_network_outage", "p_download_interrupt", "p_resume_ok", "p_signature_invalid",
              "p_hash_mismatch", "p_redownload_ok", "p_battery_drop", "p_post_verify_mismatch")


def wave_params(c: dict, wave_no: int) -> dict:
    """本批次的模拟参数 = simulation + faults，再叠加 faults.wave_overrides 里该批次的覆盖值。"""
    faults = c.get("faults", {})
    p = dict(c["simulation"])
    p.update({k: faults.get(k, 0.0) for k in FAULT_KEYS})
    p.update(faults.get("wave_overrides", {}).get(str(wave_no), {}))
    return p


def simulate_vehicle(v: dict, c: dict, rng: random.Random, wave_no: int = 1) -> dict:
    """模拟一辆车在本批中的结局（含故障注入）。概率参数都来自配置，是演示用的假设值。

    实车流程一般是 下载并校验 → 告知并确认 → 安装前检查先决条件 → 安装 → 回读校验。
    这里用一份车辆快照，先判先决条件和用户确认，再判网络、下载、校验和安装；各环节相互独立，
    顺序只影响没装上的车归到哪一类，实际安装样本的统计性质不变。
    故障概率为 0 时不抽随机数，所以不注入故障时结果和不带故障模块时完全一样。
    """
    p, t = wave_params(c, wave_no), c["target"]
    row = {
        "vehicle_id": v["vehicle_id"], "model": v["model"], "hw_variant": v["hw_variant"],
        "region": v["region"], "sw_version_before": v["sw_version"], "rxswin_before": v["rxswin"],
        "precondition_failures": "", "faults": "", "outcome": "", "complaint": 0,
        "sw_version_after": v["sw_version"], "rxswin_after": v["rxswin"], "user_message": "",
        "final_state": "OLD_VERSION_INTACT",
    }
    events = []

    def chance(key: str) -> bool:  # 只在概率 > 0 时抽随机数
        return p.get(key, 0.0) > 0 and rng.random() < p[key]

    def stop(outcome: str, message: str) -> dict:
        row.update(outcome=outcome, user_message=message, faults=";".join(events))
        return row

    fails = check_preconditions(v, c)
    if fails:  # 车端拒绝开始安装，不算失败，留待重试
        row["precondition_failures"] = ";".join(fails)
        return stop("NOT_READY", "NONE")
    if rng.random() >= p["p_consent"]:
        return stop("USER_DEFERRED", "PRE_INFO")
    if chance("p_network_outage"):
        events.append("NETWORK_OUTAGE")
        return stop("NETWORK_OUTAGE", "NONE")
    if rng.random() >= p["p_download_ok"].get(v["network"], 0.0):
        return stop("DOWNLOAD_FAILED", "PRE_INFO")
    if chance("p_download_interrupt"):
        if rng.random() < p["p_resume_ok"]:
            events.append("DOWNLOAD_INTERRUPTED:RESUMED")
        else:
            events.append("DOWNLOAD_INTERRUPTED:ABANDONED")
            return stop("DOWNLOAD_FAILED", "PRE_INFO")
    if chance("p_signature_invalid"):
        events.append("SIGNATURE_INVALID:REFUSED")
        return stop("REJECTED_SIGNATURE", "NONE")
    if chance("p_hash_mismatch"):
        if rng.random() < p["p_redownload_ok"]:
            events.append("HASH_MISMATCH:REDOWNLOADED")
        else:
            events.append("HASH_MISMATCH:REFUSED")
            return stop("REJECTED_INTEGRITY", "NONE")

    failure = None
    p_flash = min(1.0, p["p_install_fail"] * p.get("segment_risk", {}).get(v["hw_variant"], 1.0))
    if chance("p_battery_drop"):
        failure = "BATTERY_LOW_MID_INSTALL"
    elif rng.random() < p_flash:
        failure = "FLASH_FAILURE"
    elif chance("p_post_verify_mismatch"):
        failure = "RXSWIN_MISMATCH_POST_INSTALL"
    if failure:
        restored = rng.random() < p["p_rollback_ok"]
        events.append(f"{failure}:{'ROLLED_BACK' if restored else 'SAFE_STATE'}")
        outcome = "ROLLED_BACK" if restored else "SAFE_STATE"
    else:
        outcome = "INSTALLED"
    p_complaint = p["p_complaint_success"] if outcome == "INSTALLED" else p["p_complaint_failure"]
    row["complaint"] = int(rng.random() < p_complaint)
    row["final_state"] = FINAL_STATE[outcome]
    if outcome == "INSTALLED":
        row["sw_version_after"] = t["to_version"]
        if t.get("type_approval_relevant"):
            row["rxswin_after"] = t["rxswin_after"][v["model"]]
        return stop(outcome, "POST_SUCCESS")  # 告知结果、变更内容、说明书更新
    if outcome == "ROLLED_BACK":
        return stop(outcome, "POST_FAILED_RESTORED")  # 告知失败、已恢复旧版本、处理建议
    row["sw_version_after"] = row["rxswin_after"] = "UNVERIFIED"  # 到店后重新读取并核实
    return stop(outcome, "POST_FAILED_SAFE_STATE")  # 告知失败、车辆在安全状态、联系经销商


def summarize(rows: list[dict]) -> dict:
    cnt = Counter(r["outcome"] for r in rows)
    return {
        "targeted": len(rows),
        "not_ready": cnt["NOT_READY"],
        "user_deferred": cnt["USER_DEFERRED"],
        "network_outage": cnt["NETWORK_OUTAGE"],
        "download_failed": cnt["DOWNLOAD_FAILED"],
        "rejected_signature": cnt["REJECTED_SIGNATURE"],
        "rejected_integrity": cnt["REJECTED_INTEGRITY"],
        "attempted": sum(cnt[o] for o in ATTEMPTED),
        "installed": cnt["INSTALLED"],
        "rolled_back": cnt["ROLLED_BACK"],
        "safe_state": cnt["SAFE_STATE"],
        "failed": cnt["ROLLED_BACK"] + cnt["SAFE_STATE"],
        "complaints": sum(r["complaint"] for r in rows),
    }


# ---------------------------------------------------------------- 5. 闸门
def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """比例 k/n 的 Wilson 置信区间。小样本时比"点估计 ± 误差"稳。"""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom)


def gate_decision(stats: dict, g: dict, min_attempted: int | None = None) -> tuple[str, list[str]]:
    """每批结束后的闸门。

    HALT：安全状态车辆或签名校验失败超过上限（默认都是 0），或某比率的 Wilson 下界也超过阈值（证据确凿）。
    HOLD：点估计超过阈值但证据还不够，或实际安装数太少，先不扩量。
    PASS：继续下一批。
    min_attempted 不传时用配置里的值；试点批次传入检出能力要求的安装数。
    """
    halt, hold = [], []
    n = stats["attempted"]
    need = g["min_attempted"] if min_attempted is None else min_attempted
    if stats["safe_state"] > g["max_safe_state"]:
        halt.append(f"safe_state={stats['safe_state']}>{g['max_safe_state']}")
    sig_limit = g.get("max_signature_failures", 0)  # 签名失败可能是攻击，零容忍，交安全团队研判
    if stats.get("rejected_signature", 0) > sig_limit:
        halt.append(f"signature_failures={stats['rejected_signature']}>{sig_limit}")
    if n > 0:
        for name, key, limit_key in RATE_GATES:
            k, limit = stats[key], g[limit_key]
            low, _ = wilson_interval(k, n, g["z"])
            if low > limit:
                halt.append(f"{name}={k}/{n}={k / n:.2%}, Wilson下界{low:.2%}>{limit:.2%}")
            elif k / n > limit:
                hold.append(f"{name}={k}/{n}={k / n:.2%}>{limit:.2%}（下界{low:.2%}未超）")
    if n < need:
        hold.append(f"实际安装数{n}<{need}，样本不足")
    if halt:
        return "HALT", halt + hold
    if hold:
        return "HOLD", hold
    return "PASS", []


# ---------------------------------------------------------------- 主流程
@dataclass
class CampaignResult:
    eligibility: list
    plan: list
    outcomes: list
    waves: list
    segments: list
    status: str
    sizing: dict
    fault_events: list = field(default_factory=list)


def run_campaign(fleet: list[dict], c: dict, seed: int, as_of: date) -> CampaignResult:
    problems = check_release_gate(c)
    if problems:
        raise ReleaseGateError(problems)

    eligibility, eligible = [], []
    for v in fleet:
        reasons = check_eligibility(v, c, as_of)
        eligibility.append({
            "vehicle_id": v["vehicle_id"], "model": v["model"], "market": v["market"],
            "region": v["region"], "hw_variant": v["hw_variant"], "sw_version": v["sw_version"],
            "rxswin": v["rxswin"], "eligible": "N" if reasons else "Y", "reasons": ";".join(reasons),
        })
        if not reasons:
            eligible.append(v)

    w = c["waves"]
    targets, sizing = wave_targets(len(eligible), w)
    plan = plan_waves(eligible, w, seed)
    sizing.update(eligible=len(eligible), cumulative_targets=targets,
                  strata=len({stratum_key(v) for v in eligible}),
                  pilot_strata_covered=len({stratum_key(v) for v in plan[0]}) if plan else 0)

    plan_rows, outcomes, waves, segments, fault_events = [], [], [], [], []
    rng = random.Random(seed + 1)  # 模拟用独立的随机数流，分批结果不受影响
    status = "COMPLETED_ALL_WAVES"
    stopped = False
    for i, (name, wave) in enumerate(zip(w["names"], plan), start=1):
        for v in wave:
            plan_rows.append({"vehicle_id": v["vehicle_id"], "wave_no": i, "wave_name": name,
                              "stratum": stratum_key(v)})
        if stopped:  # 活动已停止：后面批次的车不推送，留在旧版本
            for v in wave:
                outcomes.append({"vehicle_id": v["vehicle_id"], "wave_no": i, "wave_name": name,
                                 "model": v["model"], "hw_variant": v["hw_variant"], "region": v["region"],
                                 "sw_version_before": v["sw_version"], "rxswin_before": v["rxswin"],
                                 "precondition_failures": "", "faults": "", "outcome": "NOT_EXECUTED",
                                 "complaint": 0, "sw_version_after": v["sw_version"],
                                 "rxswin_after": v["rxswin"], "user_message": "NONE",
                                 "final_state": "OLD_VERSION_INTACT"})
            waves.append({"wave_no": i, "wave_name": name, "targeted": len(wave), "decision": "NOT_EXECUTED"})
            continue
        if not wave:  # 小车队时后面的批次可能是空的，跳过，不过闸
            waves.append({"wave_no": i, "wave_name": name, "targeted": 0, "decision": "SKIPPED_EMPTY"})
            continue
        rows = []
        for v in wave:
            r = simulate_vehicle(v, c, rng, wave_no=i)
            r.update(wave_no=i, wave_name=name)
            rows.append(r)
            for ev in filter(None, r["faults"].split(";")):
                code, _, detail = ev.partition(":")
                found_by, response, basis = FAULT_INFO[code]
                fault_events.append({
                    "vehicle_id": r["vehicle_id"], "wave_no": i, "wave_name": name, "fault": code,
                    "detail": detail, "detected_by": found_by, "response": response, "basis": basis,
                    "outcome": r["outcome"], "final_state": r["final_state"],
                    "sw_version_after": r["sw_version_after"], "rxswin_after": r["rxswin_after"],
                })
        outcomes.extend(rows)
        st = summarize(rows)
        # 试点要达到分批时算的检出能力（例如 149 次实际安装），不够就 HOLD、延长试点
        need = max(c["gates"]["min_attempted"], sizing["min_attempts"]) if i == 1 else None
        decision, reasons = gate_decision(st, c["gates"], need)
        n, z = st["attempted"], c["gates"]["z"]
        st.update(
            wave_no=i, wave_name=name, decision=decision, decision_reasons=" | ".join(reasons),
            success_rate=round(st["installed"] / n, 4) if n else "",
            rollback_rate=round(st["rolled_back"] / n, 4) if n else "",
            rollback_wilson_low=round(wilson_interval(st["rolled_back"], n, z)[0], 4) if n else "",
            complaint_rate=round(st["complaints"] / n, 4) if n else "",
            complaint_wilson_low=round(wilson_interval(st["complaints"], n, z)[0], 4) if n else "",
        )
        waves.append(st)
        seg = defaultdict(Counter)  # 按 车型×硬件 汇总，叫停时用来定位问题集中在哪
        for r in rows:
            seg[(r["model"], r["hw_variant"])][r["outcome"]] += 1
        for (model, hw), cnt in sorted(seg.items()):
            att = sum(cnt[o] for o in ATTEMPTED)
            failed = cnt["ROLLED_BACK"] + cnt["SAFE_STATE"]
            segments.append({"wave_no": i, "wave_name": name, "model": model, "hw_variant": hw,
                             "attempted": att, "failed": failed,
                             "failure_rate": round(failed / att, 4) if att else ""})
        if decision != "PASS":
            status, stopped = f"{decision}_AFTER_{name}", True
    return CampaignResult(eligibility, plan_rows, outcomes, waves, segments, status, sizing, fault_events)


def check_final_states(res: CampaignResult, c: dict) -> list[str]:
    """检查每辆车是否落在安全且有记录的终态，且软件版本和 RXSWIN 成对一致。返回违规清单。"""
    t, bad = c["target"], []
    for o in res.outcomes:
        state = o.get("final_state", "")
        if state not in SAFE_FINAL_STATES:
            bad.append(f"{o['vehicle_id']}: 终态 {state!r} 不在安全终态清单里")
        elif state == "NEW_VERSION_VERIFIED":
            rx = t["rxswin_after"][o["model"]] if t.get("type_approval_relevant") else o["rxswin_before"]
            if (o["sw_version_after"], o["rxswin_after"]) != (t["to_version"], rx):
                bad.append(f"{o['vehicle_id']}: 新版本与 RXSWIN 不成对")
        elif state == "SAFE_STATE_NEEDS_SERVICE":
            if (o["sw_version_after"], o["rxswin_after"]) != ("UNVERIFIED", "UNVERIFIED"):
                bad.append(f"{o['vehicle_id']}: 安全状态车辆的版本应标为待核实")
        elif (o["sw_version_after"], o["rxswin_after"]) != (o["sw_version_before"], o["rxswin_before"]):
            bad.append(f"{o['vehicle_id']}: 旧版本与 RXSWIN 不成对")
    return bad


def fault_summary(res: CampaignResult) -> list[dict]:
    """按 故障 × 处理结果 汇总终态分布，用来证明每类故障都落在安全且有记录的终态。"""
    groups = defaultdict(Counter)
    for e in res.fault_events:
        groups[(e["fault"], e["detail"])][e["final_state"]] += 1
    rows = []
    for (code, detail), cnt in sorted(groups.items()):
        row = {"fault": code, "detail": detail, "events": sum(cnt.values())}
        row.update({s: cnt[s] for s in SAFE_FINAL_STATES})
        row["all_safe_and_recorded"] = "Y" if sum(cnt[s] for s in SAFE_FINAL_STATES) == row["events"] else "N"
        rows.append(row)
    return rows


# ---------------------------------------------------------------- 输出
WAVE_FIELDS = ["wave_no", "wave_name", "targeted", "not_ready", "user_deferred", "network_outage",
               "download_failed", "rejected_signature", "rejected_integrity",
               "attempted", "installed", "rolled_back", "safe_state", "failed", "complaints",
               "success_rate", "rollback_rate", "rollback_wilson_low", "complaint_rate",
               "complaint_wilson_low", "decision", "decision_reasons"]
OUTCOME_FIELDS = ["vehicle_id", "wave_no", "wave_name", "model", "hw_variant", "region",
                  "sw_version_before", "rxswin_before", "precondition_failures", "faults", "outcome",
                  "complaint", "sw_version_after", "rxswin_after", "user_message", "final_state"]
FAULT_EVENT_FIELDS = ["vehicle_id", "wave_no", "wave_name", "fault", "detail", "detected_by", "response",
                      "basis", "outcome", "final_state", "sw_version_after", "rxswin_after"]
FAULT_SUMMARY_FIELDS = ["fault", "detail", "events", *SAFE_FINAL_STATES, "all_safe_and_recorded"]


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        wr.writeheader()
        wr.writerows(rows)


def write_outputs(res: CampaignResult, c: dict, out_dir: str | Path, seed: int, as_of: date) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "eligibility.csv", res.eligibility,
              ["vehicle_id", "model", "market", "region", "hw_variant", "sw_version", "rxswin",
               "eligible", "reasons"])
    write_csv(out / "wave_plan.csv", res.plan, ["vehicle_id", "wave_no", "wave_name", "stratum"])
    write_csv(out / "outcomes.csv", res.outcomes, OUTCOME_FIELDS)
    write_csv(out / "wave_summary.csv", res.waves, WAVE_FIELDS)
    write_csv(out / "segment_summary.csv", res.segments,
              ["wave_no", "wave_name", "model", "hw_variant", "attempted", "failed", "failure_rate"])
    write_csv(out / "fault_events.csv", res.fault_events, FAULT_EVENT_FIELDS)
    write_csv(out / "fault_summary.csv", fault_summary(res), FAULT_SUMMARY_FIELDS)
    reason_counts = Counter(r for e in res.eligibility for r in e["reasons"].split(";") if r)
    violations = check_final_states(res, c)
    record = {  # 一次升级活动的记录样例，对应 R156 7.1.2 的记录项
        "campaign_id": c["campaign_id"], "as_of": as_of.isoformat(), "seed": seed,
        "data_note": "车队为合成数据（SYNTHETIC_DEMO），结果只用于演示规划逻辑",
        "purpose_and_changes": {k: c["notification"][k] for k in NOTIFICATION_FIELDS},
        "from_versions": c["target"]["from_versions"], "to_version": c["target"]["to_version"],
        "type_approval_relevant": c["target"].get("type_approval_relevant", False),
        "rxswin_after": c["target"].get("rxswin_after", {}),
        "markets": c["target"]["markets"], "release_gate": c["release_gate"],
        "eligible_vehicles": res.sizing["eligible"], "ineligible_reason_counts": dict(reason_counts),
        "wave_sizing": res.sizing, "waves": res.waves, "final_status": res.status,
        "final_state_counts": dict(Counter(o["final_state"] for o in res.outcomes)),
        "final_state_violations": violations, "fault_summary": fault_summary(res),
    }
    with open(out / "campaign_record.json", "w", encoding="utf-8") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=2)


def print_summary(res: CampaignResult, c: dict) -> None:
    s = res.sizing
    print(f"活动 {c['campaign_id']}：车队 {len(res.eligibility)} 辆，合格 {s['eligible']} 辆")
    reason_counts = Counter(r for e in res.eligibility for r in e["reasons"].split(";") if r)
    for code, k in reason_counts.most_common():
        print(f"  不合格 {code:<24}{k:>6}  {ELIGIBILITY_TEXT[code]}")
    print(f"试点样本量：至少 {s['min_attempts']} 次实际安装 → 推送 {s['pilot_by_power']} 辆；"
          f"分层 {s['strata']} 个，试点覆盖 {s['pilot_strata_covered']} 个")
    print(f"累计推送目标：{s['cumulative_targets']}")
    skipped = {"NOT_EXECUTED": "未执行（活动已停止）", "SKIPPED_EMPTY": "空批次，跳过"}
    for wv in res.waves:
        if wv["decision"] in skipped:
            print(f"  第{wv['wave_no']}批 {wv['wave_name']:<9} 推送 {wv['targeted']:>5}  {skipped[wv['decision']]}")
            continue
        rate = f"{wv['success_rate']:.2%}" if wv["attempted"] else "—"
        print(f"  第{wv['wave_no']}批 {wv['wave_name']:<9} 推送 {wv['targeted']:>5}  未就绪 {wv['not_ready']:>4}  "
              f"未确认 {wv['user_deferred']:>4}  下载失败 {wv['download_failed']:>3}  安装 {wv['attempted']:>5}  "
              f"成功率 {rate}  回滚 {wv['rolled_back']}  安全状态 {wv['safe_state']}  "
              f"投诉 {wv['complaints']}  → {wv['decision']}")
        extra = {"断网": wv["network_outage"], "签名拒装": wv["rejected_signature"],
                 "哈希拒装": wv["rejected_integrity"]}
        if any(extra.values()):
            print("      " + "  ".join(f"{k} {n}" for k, n in extra.items()))
        if wv["decision_reasons"]:
            print(f"      原因：{wv['decision_reasons']}")
    pre = Counter(x for o in res.outcomes for x in o["precondition_failures"].split(";") if x)
    if pre:
        print("  未就绪原因（可叠加）：" + "，".join(f"{PRECONDITION_TEXT[k]} {n}" for k, n in pre.most_common()))
    last = max((wv["wave_no"] for wv in res.waves if wv["decision"] not in skipped), default=0)
    if res.status != "COMPLETED_ALL_WAVES":
        print("  停止批次按 车型×硬件 的失败分布：")
        for sg in res.segments:
            if sg["wave_no"] == last and sg["attempted"]:
                print(f"    {sg['model']} {sg['hw_variant']:<5} 安装 {sg['attempted']:>4}  失败 {sg['failed']:>3}  "
                      f"失败率 {sg['failure_rate']:.1%}")
    faults = fault_summary(res)
    if faults:
        print("  故障事件的处理结果（事件数 → 终态）：")
        for f in faults:
            label = f"{f['fault']}:{f['detail']}" if f["detail"] else f["fault"]
            states = "，".join(f"{s} {f[s]}" for s in SAFE_FINAL_STATES if f[s])
            print(f"    {label:<42}{f['events']:>5} → {states}")
    bad = check_final_states(res, c)
    print(f"终态检查：{len(res.outcomes)} 辆车，"
          + ("全部处于安全且有记录的终态，版本与 RXSWIN 成对一致" if not bad else f"{len(bad)} 处违规：{bad[:3]}"))
    print(f"最终状态：{res.status}")


# ---------------------------------------------------------------- 合成车队
SYN_MODELS = {  # 车型：(占比, 动力类型, {硬件变体: 占比})。车型和硬件代号都是虚构的
    "MODEL_A": (0.45, "ICE", {"A-H1": 0.55, "A-H2": 0.40, "A-H0": 0.05}),
    "MODEL_B": (0.35, "PHEV", {"B-H2": 0.70, "B-H3": 0.30}),
    "MODEL_C": (0.20, "BEV", {"C-H3": 1.00}),
}
SYN_REGIONS = {  # 地区占比是假设值，不来自 JPJ 数据
    "MY-CENTRAL": 0.45, "MY-SOUTH": 0.20, "MY-NORTH": 0.18, "MY-EAST-COAST": 0.07, "MY-EAST-MY": 0.10,
}
SYN_VERSIONS = {"1.4.2": 0.58, "1.5.0": 0.36, "1.3.9": 0.05, "1.6.0": 0.01}
# RXSWIN 格式由车企自定（R156 2.2）。1.5.0 没改型式批准相关软件，所以 RXSWIN 和 1.4.2 一样
SYN_RXSWIN = {"1.3.9": "05", "1.4.2": "06", "1.5.0": "06", "1.6.0": "07"}


def _pick(rng: random.Random, weights: dict) -> str:
    keys = list(weights)
    return rng.choices(keys, weights=[weights[k] for k in keys])[0]


def generate_synthetic_fleet(n: int, seed: int, as_of: date) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for i in range(1, n + 1):
        model = _pick(rng, {m: v[0] for m, v in SYN_MODELS.items()})
        _, powertrain, hw_mix = SYN_MODELS[model]
        ver = _pick(rng, SYN_VERSIONS)
        rx = f"{model[-1]}-RX-{SYN_RXSWIN[ver]}"
        if rng.random() < 0.004:  # 少量登记册不一致（例如线下刷写后记录没同步）
            rx = f"{model[-1]}-RX-04"
        if powertrain == "ICE":  # ICE 用 12V 蓄电池 SOC，电动车用动力电池 SOC
            soc = min(100.0, max(20.0, rng.gauss(80, 9)))
        else:
            soc = rng.triangular(5, 95, 65)
        days = rng.uniform(31, 120) if rng.random() < 0.05 else rng.expovariate(1 / 4)
        rows.append({
            "vehicle_id": f"SYN-{i:06d}", "model": model, "powertrain": powertrain, "market": "MY",
            "region": _pick(rng, SYN_REGIONS), "sw_version": ver, "hw_variant": _pick(rng, hw_mix),
            "rxswin": rx, "soc_pct": round(soc, 1),
            "gear": _pick(rng, {"P": 0.93, "N": 0.02, "D": 0.04, "R": 0.01}),
            "ignition": _pick(rng, {"OFF": 0.90, "ACC": 0.05, "ON": 0.05}),
            "network": _pick(rng, {"GOOD": 0.86, "WEAK": 0.10, "NONE": 0.04}),
            "last_seen": (as_of - timedelta(days=int(days))).isoformat(),
            "critical_dtc": int(rng.random() < 0.01), "data_source": SYNTHETIC_LABEL,
        })
    return rows


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="海外市场 OTA 升级活动规划演示工具（合成数据）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="生成合成演示车队（SYNTHETIC）")
    g.add_argument("--n", type=int, default=DEFAULT_FLEET_SIZE)
    g.add_argument("--seed", type=int, default=2026)
    g.add_argument("--as-of", default="2026-10-27")
    g.add_argument("--out", default="data/fleet_synthetic_MY.csv")
    r = sub.add_parser("run", help="资格筛选 + 分批 + 模拟 + 闸门")
    r.add_argument("--fleet", required=True)
    r.add_argument("--campaign", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--seed", type=int, default=7)
    r.add_argument("--as-of", default=None, help="默认用活动配置里的 as_of")
    args = ap.parse_args(argv)

    if args.cmd == "generate":
        rows = generate_synthetic_fleet(args.n, args.seed, date.fromisoformat(args.as_of))
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        write_csv(Path(args.out), rows, FLEET_COLUMNS)
        print(f"已生成 {len(rows)} 辆合成车辆（{SYNTHETIC_LABEL}）→ {args.out}")
        return 0

    c = load_campaign(args.campaign)
    as_of = date.fromisoformat(args.as_of or c["as_of"])
    try:
        res = run_campaign(load_fleet(args.fleet), c, args.seed, as_of)
    except ReleaseGateError as e:
        print("发布闸门未通过，不排计划：")
        for p in e.args[0]:
            print(f"  - {p}")
        return 2
    write_outputs(res, c, args.out, args.seed, as_of)
    print_summary(res, c)
    return 0


if __name__ == "__main__":
    sys.exit(main())
