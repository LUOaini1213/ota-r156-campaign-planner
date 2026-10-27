"""python -m secure_update.demo：在终端演示一次正常升级、攻击用例、设备故障和断电扫描。

可选 --out 目录：把攻击结果和断电扫描写成 CSV（证据文件）。全部数据是合成的，密钥运行时生成。
完整断言在 secure_update/tests 里；这里的编号与 traceability_secure_update.csv 的 test_id 对应。
"""
from __future__ import annotations

import argparse
import csv
import sys
from datetime import timedelta
from pathlib import Path
from typing import Callable, TextIO

from .canonical import sha256_hex
from .ecu import MAX_TRIAL_BOOTS
from .errors import SecureUpdateError
from .repository import verify_version_report
from .testbed import ECU_ID, HW_ID, NEW, OTHER_HW_ID, PAIRS, Release, UpdateBed, power_cut_sweep, write_steps


def _capped(prefix: Callable[[int], bytes]) -> Callable[[int], object]:
    """合法内容之后不停追加垃圾数据；如果客户端一直读，256 KB 后报错，演示不会卡死。"""
    def stream(offset: int = 0):
        head = prefix(offset)
        if head:
            yield head
        for _ in range(1000):
            yield b"\0" * 256
        raise RuntimeError("客户端没有停止读取")
    return stream


def _new(bed: UpdateBed, **kwargs) -> None:
    bed.release(NEW, **kwargs)
    bed.assign(NEW)


def _freeze(bed: UpdateBed) -> None:
    bed.client.update()
    bed.mirror.overrides[("director", "timestamp.json")] = bed.director.files["timestamp.json"]
    _new(bed)
    bed.advance(days=1)


def _rollback(bed: UpdateBed) -> None:
    recorded = bed.director.files["timestamp.json"]
    bed.client.update()
    bed.advance(hours=1)
    bed.client.update()
    bed.mirror.overrides[("director", "timestamp.json")] = recorded


def _mix_and_match(bed: UpdateBed) -> None:
    old_targets = bed.image_repo.files["targets.json"]
    _new(bed)
    bed.mirror.overrides[("image", "targets.json")] = old_targets


def _expired(bed: UpdateBed) -> None:
    bed.image_repo.expiry["targets"] = timedelta(days=2)
    _new(bed)
    bed.advance(days=3, refresh=False)
    bed.director.publish()
    bed.image_repo.publish(resign_targets=False)


def _metadata_endless(bed: UpdateBed) -> None:
    bed.mirror.overrides[("director", "timestamp.json")] = lambda: _capped(lambda _: b"")()


def _tampered(bed: UpdateBed) -> None:
    _new(bed)
    evil = bytearray(NEW.payload())
    evil[100] ^= 0xFF
    bed.mirror.image_overrides[NEW.filename] = bytes(evil)


def _image_endless(bed: UpdateBed) -> None:
    _new(bed)
    payload = NEW.payload()
    bed.mirror.image_overrides[NEW.filename] = _capped(lambda offset: payload[offset:])


def _wrong_hw(bed: UpdateBed) -> None:
    other = Release("1.6.0", secure_version=3, release_counter=6, rxswin="A-RX-07", hardware_identifiers=(OTHER_HW_ID,))
    bed.release(other)
    bed.assign(other)


def _below_threshold(bed: UpdateBed) -> None:
    _new(bed, targets_signers=[bed.image_repo.keys["targets"][0]])


def _revoked(bed: UpdateBed) -> None:
    revoked = bed.image_repo.rotate("targets")
    _new(bed, targets_signers=revoked)


def _director_compromise(bed: UpdateBed) -> None:
    evil = b"\xee" * 2048
    bed.director.set_target_entry("evil.bin", {
        "length": len(evil), "hashes": {"sha256": sha256_hex(evil)},
        "custom": {"ecu_identifier": ECU_ID, "hardware_identifier": HW_ID, "release_counter": 99, "rxswin": "A-RX-07"}})
    bed.director.publish()
    bed.mirror.image_overrides["evil.bin"] = evil


def _old_secure_version(bed: UpdateBed) -> None:
    _new(bed)
    bed.client.update()
    old = Release("1.5.0", secure_version=2, release_counter=7, rxswin="A-RX-06")
    bed.release(old)
    bed.assign(old)


def _release_counter(bed: UpdateBed) -> None:
    older = Release("1.4.9", secure_version=2, release_counter=4, rxswin="A-RX-06")
    bed.release(older)
    bed.assign(older)


def _rxswin_mismatch(bed: UpdateBed) -> None:
    bed.release(NEW)
    bed.assign(NEW, rxswin="A-RX-08")


ATTACKS = [
    ("SU-M01", "freeze：旧 timestamp 一直被重放，直到过期", _freeze),
    ("SU-M02", "rollback：重放旧版本 timestamp", _rollback),
    ("SU-M03", "mix-and-match：新 snapshot 配旧 targets", _mix_and_match),
    ("SU-M05", "过期：Image 仓库 targets 过期", _expired),
    ("SU-M06", "endless data：timestamp 读不完", _metadata_endless),
    ("SU-I01", "arbitrary software：镜像被篡改", _tampered),
    ("SU-I03", "endless data：镜像后面追加垃圾数据", _image_endless),
    ("SU-I05", "wrong ECU：硬件标识不符", _wrong_hw),
    ("SU-K01", "门限不足：只有 1 把 targets 密钥签名", _below_threshold),
    ("SU-K04", "已撤销密钥：轮换后用旧 targets 密钥签", _revoked),
    ("SU-K08", "Director 密钥被盗：指派不在 Image 仓库的镜像", _director_compromise),
    ("SU-A02", "防回滚：正式重发的旧代码 secure_version 太低", _old_secure_version),
    ("SU-A04", "防回滚：Director 指回旧发布（release counter 更低）", _release_counter),
    ("SU-R03", "RXSWIN 与发布记录不一致", _rxswin_mismatch),
]


def run_attacks() -> list[dict]:
    rows = []
    for test_id, title, stage in ATTACKS:
        bed = UpdateBed()
        stage(bed)
        before = bed.ecu_state()
        served = bed.mirror.image_bytes_served
        try:
            outcome, error = bed.client.update(), ""
        except SecureUpdateError as exc:
            outcome, error = exc.attack, type(exc).__name__
        rows.append({"test_id": test_id, "attack": title, "detected_as": outcome, "error": error,
                     "ecu_unchanged": "Y" if bed.ecu_state() == before else "N",
                     "image_bytes_downloaded": bed.mirror.image_bytes_served - served})
    return rows


def run_power_sweeps() -> list[dict]:
    rows = []
    for health, expected in (("OK", "COMMITTED"), ("FAIL", "ROLLED_BACK")):
        bed = UpdateBed(health_check=lambda header, verdict=health: verdict)
        _new(bed)
        for torn in (True, False):
            for row in power_cut_sweep(bed, torn=torn):
                rows.append({**row, "health_check": health, "expected": expected, "second_cut": "",
                             "problems": "；".join(row["problems"])})
    bed = UpdateBed()
    _new(bed)
    for row in power_cut_sweep(bed, torn=True, second_cut=True):
        rows.append({**row, "health_check": "OK", "expected": "COMMITTED", "problems": "；".join(row["problems"])})
    return rows


def run_device_faults() -> list[tuple[str, str, str]]:
    fail = UpdateBed(health_check=lambda header: "FAIL")
    _new(fail)
    crashes = []
    crash = UpdateBed(health_check=lambda header: crashes.append(1) or "CRASH")
    _new(crash)
    fail_result, crash_result = fail.client.update(), crash.client.update()
    return [("SU-D04", "健康检查失败", f"{fail_result}，软件标识仍为 {_pair(fail)}"),
            ("SU-D06", "新镜像每次都崩溃", f"{crash_result}，试启动 {len(crashes)} 次（上限 {MAX_TRIAL_BOOTS}）后自动回滚，"
                                         f"软件标识仍为 {_pair(crash)}")]


def _pair(bed: UpdateBed) -> str:
    return " / ".join(bed.committed_pair())


def happy_path(out: TextIO) -> bool:
    bed = UpdateBed()
    _new(bed)
    result, steps = write_steps(bed)
    print("== 1. 正常升级（SU-D01）：1.5.0 / A-RX-06 → 1.6.0 / A-RX-07 ==", file=out)
    print(f"一次会话共 {len(steps)} 次持久化写入，每一次都是断电扫描里的一个断点：", file=out)
    for number, step in enumerate(steps, start=1):
        print(f"  {number:2d}. {step}", file=out)
    before = _pair(bed)
    outcome = bed.client.update()
    report = verify_version_report(bed.ecu.version_report("demo-nonce", bed.now), bed.ecu_key.public, "demo-nonce")
    print(f"结果 {outcome}：软件标识 {before} → {_pair(bed)}，防回滚计数器 = {bed.ecu.counter()}，"
          f"签名版本报告里的 RXSWIN = {report['custom']['rxswin']}", file=out)
    return result == outcome == "COMMITTED" and bed.committed_pair() == (NEW.sw_version, NEW.rxswin)


def write_rows(handle: TextIO, rows: list[dict], fields: list[str]) -> None:
    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


ATTACK_FIELDS = ["test_id", "attack", "detected_as", "error", "ecu_unchanged", "image_bytes_downloaded"]
SWEEP_FIELDS = ["health_check", "torn", "write_no", "step", "second_cut", "expected", "final", "final_pair", "problems"]


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m secure_update.demo", description="车端安全升级演示（合成数据）")
    parser.add_argument("--out", type=Path, help="可选：把攻击结果和断电扫描写成 CSV 的目录")
    args = parser.parse_args(argv)
    if out is None:
        out = sys.stdout
        if hasattr(out, "reconfigure"):
            out.reconfigure(errors="replace")
    print("secure_update 演示：Uptane-inspired 元数据校验 + A/B 槽位更新客户端（合成数据，不是符合性实现）\n", file=out)
    ok = happy_path(out)

    attacks = run_attacks()
    print("\n== 2. 攻击用例：全部被拒，ECU 状态不变 ==", file=out)
    for row in attacks:
        print(f"  {row['test_id']}  {row['attack']}\n          → 识别为 {row['detected_as']}（{row['error']}），"
              f"ECU 不变 = {row['ecu_unchanged']}，镜像下载 {row['image_bytes_downloaded']} 字节", file=out)
    ok &= all(row["error"] and row["ecu_unchanged"] == "Y" for row in attacks)

    print("\n== 3. 设备故障 ==", file=out)
    for test_id, title, text in run_device_faults():
        print(f"  {test_id}  {title} → {text}", file=out)

    sweep = run_power_sweeps()
    print("\n== 4. 断电扫描（SU-D02 / SU-D03）：每一次持久化写入处断电，重新上电后检查 ==", file=out)
    groups: dict[tuple, list[dict]] = {}
    for row in sweep:
        key = (row["health_check"], "撕裂写入" if row["torn"] else "干净断电", "两次断电" if row["second_cut"] else "一次断电")
        groups.setdefault(key, []).append(row)
    for (health, torn, cuts), rows in groups.items():
        finals = sorted({row["final"] for row in rows})
        bad = sum(1 for row in rows if row["problems"])
        print(f"  健康检查 {health:4s} | {torn} | {cuts} | 断电组合 {len(rows):3d} | 最终结局 {finals} | 不变量违反 {bad}", file=out)
        ok &= bad == 0 and finals == [rows[0]["expected"]]
    ok &= all(row["final_pair"] in PAIRS for row in sweep)

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        sweep_rows = [{**row, "final_pair": " / ".join(row["final_pair"])} for row in sweep]
        for name, rows, fields in (("attack_results.csv", attacks, ATTACK_FIELDS),
                                   ("power_cut_sweep.csv", sweep_rows, SWEEP_FIELDS)):
            with open(args.out / name, "w", encoding="utf-8-sig", newline="") as handle:
                write_rows(handle, rows, fields)
        print(f"\n证据文件已写到 {args.out}", file=out)
    print("\n全部检查通过" if ok else "\n有检查没有通过", file=out)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
