"""元数据层：确定性序列化、Ed25519 签名，以及元数据攻击（freeze、rollback、mix-and-match、过期、endless data）。

每个测试函数在 traceability_secure_update.csv 里有一行：测试 → Uptane 2.1.0 条款 → R155 附件5 → P3 的 TARA / 控制点 / 需求。
攻击被拒之后统一检查：抛出指明攻击类型的异常；安全日志有记录；ECU 的 active 槽、软件标识、计数器都不变。
"""
from datetime import timedelta

import pytest

from secure_update.canonical import canonical_bytes, strict_loads
from secure_update.crypto import SigningKey, keyid_of, verify_signature
from secure_update.errors import (EndlessDataError, ExpiredMetadataError, MetadataFormatError, MixAndMatchError,
                                  RollbackAttackError)
from secure_update.testbed import NEW, craft_snapshot, craft_timestamp
from secure_update.verifier import MAX_BYTES

from ._helpers import assert_rejected


# ---------------------------------------------------------------- 基础
def test_canonical_serialization_is_deterministic_and_strict():
    a = {"b": 1, "a": [True, None, "x"], "中": "文"}
    b = {"中": "文", "a": [True, None, "x"], "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b) == '{"a":[true,null,"x"],"b":1,"中":"文"}'.encode("utf-8")
    for bad in ({"v": 1.0}, {"s": "é"}, {1: "x"}, {"set": {1, 2}}):   # 浮点、非 NFC、非字符串键、不支持的类型
        with pytest.raises(MetadataFormatError):
            canonical_bytes(bad)
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.5}', b"\xff\xfe", b'{"a":'):  # 重复键、NaN、浮点、非 UTF-8、截断
        with pytest.raises(MetadataFormatError):
            strict_loads(raw)


def test_ed25519_signatures_via_cryptography_detect_tampering():
    key = SigningKey()
    data = canonical_bytes({"_type": "targets", "version": 1})
    sig = key.sign(data)
    assert verify_signature(key.public, sig, data)
    assert not verify_signature(key.public, sig, canonical_bytes({"_type": "targets", "version": 2}))  # 内容改了
    assert not verify_signature(SigningKey().public, sig, data)                                          # 换了公钥
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    assert not verify_signature(key.public, flipped, data)                                               # 签名改了
    assert not verify_signature(key.public, "not-hex", data)
    assert key.keyid == keyid_of(key.public) and len(key.keyid) == 64
    assert repr(key) == f"SigningKey(keyid={key.keyid[:8]}…)"                                            # 不会打印私钥


# ---------------------------------------------------------------- freeze
def test_freeze_attack_stale_timestamp_detected_after_expiry(bed):
    assert bed.client.update() == "NO_UPDATE"                       # ECU 先同步到最新元数据
    stale = bed.director.files["timestamp.json"]
    bed.mirror.overrides[("director", "timestamp.json")] = stale    # 攻击者从此只给这份旧 timestamp
    bed.release(NEW)
    bed.assign(NEW)                                                 # OEM 发布了修复版并指派给这台车
    before = bed.ecu_state()
    bed.advance(hours=12)                                           # 仓库照常重签，车只看得到旧 timestamp
    assert bed.client.update() == "NO_UPDATE"                       # 有效期内看不出冻结，但最长只能冻到过期
    bed.advance(hours=12)                                           # 旧 timestamp 到期（有效期 1 天）
    with pytest.raises(ExpiredMetadataError) as exc:
        bed.client.update()
    assert (exc.value.repo, exc.value.role, exc.value.attack) == ("director", "timestamp", "FREEZE")
    assert_rejected(bed, before, "FREEZE")
    del bed.mirror.overrides[("director", "timestamp.json")]        # 通道恢复后正常安装
    assert bed.client.update() == "COMMITTED"


# ---------------------------------------------------------------- rollback
@pytest.mark.parametrize("replayed", ["timestamp", "snapshot", "targets"])
def test_rollback_attack_older_metadata_versions_rejected(bed, replayed):
    recorded = dict(bed.director.files)                             # 攻击者录下的旧元数据（签名都有效）
    assert bed.client.update() == "NO_UPDATE"
    bed.advance(hours=1)                                            # 仓库发布新版本，ECU 跟上
    assert bed.client.update() == "NO_UPDATE"
    before = bed.ecu_state()
    d, served = bed.director, bed.mirror.overrides
    if replayed == "timestamp":                                     # 直接重放旧 timestamp
        served[("director", "timestamp.json")] = recorded["timestamp.json"]
    elif replayed == "snapshot":                                    # 偷到在线 timestamp 密钥：新 timestamp 指向旧 snapshot
        served[("director", "timestamp.json")] = craft_timestamp(d, recorded["snapshot.json"],
                                                                 version=d.versions["timestamp"] + 1)
        served[("director", "snapshot.json")] = recorded["snapshot.json"]
    else:                                                           # 偷到 timestamp + snapshot 密钥：新 snapshot 列出旧 targets
        snapshot = craft_snapshot(d, targets_version=d.versions["targets"] - 1, version=d.versions["snapshot"] + 1)
        served[("director", "snapshot.json")] = snapshot
        served[("director", "timestamp.json")] = craft_timestamp(d, snapshot, version=d.versions["timestamp"] + 1)
        served[("director", "targets.json")] = recorded["targets.json"]
    with pytest.raises(RollbackAttackError) as exc:
        bed.client.update()
    assert exc.value.role == {"timestamp": "timestamp", "snapshot": "snapshot", "targets": "snapshot"}[replayed]
    assert_rejected(bed, before, "ROLLBACK")


# ---------------------------------------------------------------- mix-and-match
@pytest.mark.parametrize("variant", ["targets-not-in-snapshot", "snapshot-not-in-timestamp"])
def test_mix_and_match_inconsistent_snapshot_rejected(bed, variant):
    old_image_files = dict(bed.image_repo.files)                    # 发布 NEW 之前的 Image 仓库元数据
    bed.release(NEW)
    bed.assign(NEW)
    before = bed.ecu_state()
    if variant == "targets-not-in-snapshot":                        # 新 snapshot（列出 targets v2）配旧 targets v1
        bed.mirror.overrides[("image", "targets.json")] = old_image_files["targets.json"]
    else:                                                           # 新 timestamp 配旧 snapshot
        bed.mirror.overrides[("image", "snapshot.json")] = old_image_files["snapshot.json"]
    with pytest.raises(MixAndMatchError) as exc:
        bed.client.update()
    assert (exc.value.repo, exc.value.role) == ("image", "targets" if variant == "targets-not-in-snapshot" else "snapshot")
    assert_rejected(bed, before, "MIX_AND_MATCH")
    assert bed.mirror.image_bytes_served == 0


def test_director_image_metadata_mismatch_rejected(bed):
    bed.release(NEW)
    entry = bed.director_entry(NEW)
    entry["hashes"] = {"sha256": "0" * 64}                          # Director 写的哈希与 Image 仓库签名的不一样
    bed.director.set_target_entry(NEW.filename, entry)
    bed.director.publish()
    before = bed.ecu_state()
    with pytest.raises(MixAndMatchError) as exc:
        bed.client.update()
    assert "长度或哈希不一致" in str(exc.value)
    assert_rejected(bed, before, "MIX_AND_MATCH")
    assert bed.mirror.image_bytes_served == 0


# ---------------------------------------------------------------- 过期
@pytest.mark.parametrize("which", ["image-targets", "director-targets-not-redownloaded", "director-root"])
def test_expired_metadata_rejected(bed, which):
    if which == "image-targets":
        bed.image_repo.expiry["targets"] = timedelta(days=2)
        bed.release(NEW)                                            # Image 仓库的 targets 只签了 2 天
        bed.assign(NEW)
        bed.advance(days=3, refresh=False)
        bed.director.publish()
        bed.image_repo.publish(resign_targets=False)                # 在线角色照常重签，离线 targets 没人重签
        expected = ("image", "targets")
    elif which == "director-targets-not-redownloaded":
        bed.director.expiry["targets"] = timedelta(days=2)
        bed.director.publish()
        assert bed.client.update() == "NO_UPDATE"                   # ECU 已信任这份 2 天后过期的 targets
        bed.advance(days=3, refresh=False)
        bed.director.publish_timestamp()                            # 只有 timestamp 在更新，snapshot 没变，不会重新下载 targets
        expected = ("director", "targets")
    else:
        bed.director.expiry["root"] = timedelta(days=2)
        bed.director.publish_root()                                 # root v2 只签了 2 天
        assert bed.client.update() == "NO_UPDATE"                   # ECU 跟上 root v2
        bed.advance(days=3)
        expected = ("director", "root")
    before = bed.ecu_state()
    with pytest.raises(ExpiredMetadataError) as exc:
        bed.client.update()
    assert (exc.value.repo, exc.value.role) == expected
    assert_rejected(bed, before, "FREEZE")
    if which == "director-root":                                    # OEM 签发新 root 后恢复
        bed.director.expiry["root"] = timedelta(days=365)
        bed.director.publish_root()
        assert bed.client.update() == "NO_UPDATE"


# ---------------------------------------------------------------- endless data（元数据）
def test_metadata_endless_data_stops_reading(bed):
    def endless():
        for _ in range(1000):                                       # 防护失效时最多给 256 KB 就报错，不会把测试拖死
            yield b" " * 256
        raise AssertionError("客户端一直在读，没有在上限处停下")

    bed.mirror.overrides[("director", "timestamp.json")] = endless
    before = bed.ecu_state()
    with pytest.raises(EndlessDataError) as exc:
        bed.client.update()
    assert "timestamp.json" in str(exc.value)
    assert bed.mirror.bytes_served <= MAX_BYTES["timestamp"] + 256  # 超过上限后立刻停止读取
    assert_rejected(bed, before, "ENDLESS_DATA")
