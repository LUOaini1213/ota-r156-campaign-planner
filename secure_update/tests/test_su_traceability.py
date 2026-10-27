"""追溯表与仓库卫生自检。

1. traceability_secure_update.csv 的每个 ID 都能在 P3 的文件或官方文本里找到；每个测试函数都有一行映射，反之亦然。
2. secure_update/ 里没有私钥、没有绝对路径。
"""
import ast
import csv
import re
from pathlib import Path

SU = Path(__file__).resolve().parents[1]
P3 = SU.parent
MAPPED_TEST_FILES = ("test_su_metadata_attacks.py", "test_su_image_key_attacks.py", "test_su_ecu_client.py")
CATEGORIES = {"基础", "元数据攻击", "镜像攻击", "密钥攻击", "设备故障", "防回滚", "活动控制", "RXSWIN 记录"}

# UN R155 附件5（ECE/TRANS/WP.29/2020/79，2020-04-02）：本套测试引用的威胁编号（表 A1）→ Part B 表中对应的缓解措施。
# 原表有合并单元格：6.2 与 6.3 共用 M10（表 B1）；12.1–12.3 共用 M16（表 B2）；26.1–26.3 共用 M23（表 B6）。
R155_ANNEX5 = {
    "5.1": {"M10", "M6"},    # 表 B1
    "6.2": {"M10"},           # 表 B1
    "6.3": {"M10"},           # 表 B1
    "8.1": {"M13"},           # 表 B1
    "12.1": {"M16"},          # 表 B2
    "12.3": {"M16"},          # 表 B2
    "12.4": {"M11"},          # 表 B2
    "13.1": {"M3"},           # 表 B2
    "19.3": {"M11"},          # 表 B5
    "26.2": {"M23"},          # 表 B6
}
# Uptane Standard 2.1.0（uptane.org/docs/latest/standard/uptane-standard）中本项目引用并核对过的小节
UPTANE_SECTIONS = {"3.3", "3.4", "4.3.2", "4.3.3", "4.3.4", "5.1", "5.2", "5.2.1", "5.2.2", "5.2.3.1", "5.2.3.1.1",
                   "5.2.4", "5.2.5", "5.2.7", "5.3.1", "5.3.2", "5.4", "5.4.1", "5.4.2.1.2", "5.4.3.3", "5.4.3.4",
                   "5.4.3.5", "5.4.3.6", "5.4.4", "5.4.4.1", "5.4.4.2", "5.4.4.3", "5.4.4.4", "5.4.4.5", "5.4.4.6"}


def read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def ids(cell: str) -> set[str]:
    return set() if cell.strip() in ("", "—") else {part.strip() for part in cell.split(";")}


def test_traceability_csv_covers_every_test_and_ids_exist():
    rows = read_csv(SU / "traceability_secure_update.csv")
    req_ids = {r["req_id"] for r in read_csv(P3 / "01_requirements_checklist.csv")}
    controls = {r["control_id"] for r in read_csv(P3 / "02_traceability_matrix.csv")}
    tara = read_csv(P3 / "03_tara.csv")
    tara_ids = ({r["ts_id"] for r in tara} | {d for r in tara for d in r["damage_scenarios"].split(";")}
                | {re.match(r"CG\d+", r["cybersecurity_goal"]).group() for r in tara})
    assert len(rows) == len({r["test_id"] for r in rows}) == len({r["pytest_node"] for r in rows})
    for row in rows:
        tid = row["test_id"]
        path, _, func = row["pytest_node"].partition("::")
        assert (P3 / path).is_file() and func.startswith("test_"), tid
        assert row["category"] in CATEGORIES and row["scenario_cn"] and row["expected_cn"], tid
        assert ids(row["p3_req_ids"]) and ids(row["p3_req_ids"]) <= req_ids, tid
        assert ids(row["p3_controls"]) <= controls, tid
        assert ids(row["p3_tara"]) <= tara_ids, tid
        threats = ids(row["r155_annex5_threats"])
        assert threats <= set(R155_ANNEX5), tid
        assert ids(row["r155_annex5_mitigations"]) == set().union(*(R155_ANNEX5[t] for t in threats)), tid
        for ref in ids(row["uptane_2_1_0_ref"]):
            assert re.match(r"\d+(\.\d+)*", ref).group() in UPTANE_SECTIONS, (tid, ref)
    defined = set()
    for name in MAPPED_TEST_FILES:
        tree = ast.parse((SU / "tests" / name).read_text(encoding="utf-8"))
        defined |= {f"secure_update/tests/{name}::{node.name}" for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}
    assert {r["pytest_node"] for r in rows} == defined


def test_no_private_keys_or_absolute_paths_committed():
    marker = "PRIVATE" + " KEY"                      # 拼起来写，免得本文件自己命中
    drive_path = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]+[\w一-鿿]")
    home_path = re.compile(r"[\\/](Users|home)[\\/]")
    checked = 0
    for path in SU.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix not in {".py", ".md", ".csv", ".json", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8-sig")
        assert marker not in text, path.name
        assert not drive_path.search(text), (path.name, drive_path.search(text))
        assert not home_path.search(text), path.name
        checked += 1
    assert checked >= 10
