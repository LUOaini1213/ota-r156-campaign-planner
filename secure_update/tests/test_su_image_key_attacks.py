"""镜像攻击（arbitrary software、endless data、wrong ECU）和密钥攻击（门限不足、撤销 / 轮换、root 链、Director 密钥被盗）。

攻击者模型：控制分发通道（可以替换、丢弃、无限灌数据），并且在部分用例里拿到了某些密钥。
每个测试函数在 traceability_secure_update.csv 里有一行。
"""
import pytest

from secure_update.canonical import sha256_hex
from secure_update.crypto import SigningKey
from secure_update.errors import (ArbitrarySoftwareError, EndlessDataError, RollbackAttackError, RootRotationError,
                                  SignatureThresholdError, WrongEcuError)
from secure_update.metadata import encode, sign
from secure_update.testbed import (ECU_ID, HW_ID, NEW, OTHER_HW_ID, SLOT_CAPACITY, Release, craft_root,
                                   craft_timestamp, tamper_signed)

from ._helpers import assert_rejected


# ================================================================ 镜像攻击
def test_arbitrary_software_tampered_image_rejected_after_redownload(bed):
    bed.release(NEW)
    bed.assign(NEW)
    evil = bytearray(NEW.payload())
    evil[100] ^= 0xFF                                               # 长度不变，内容被篡改
    bed.mirror.image_overrides[NEW.filename] = bytes(evil)
    before = bed.ecu_state()
    with pytest.raises(ArbitrarySoftwareError):
        bed.client.update()
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")
    assert "更新日志：读回哈希不符，重新下载" in bed.nv.trace      # 先重新下载一次（可能只是传输损坏）
    assert bed.ecu.journal.read()["result"] == "REJECTED_ARBITRARY_SOFTWARE"
    assert bed.ecu.headers["B"].read() == {"valid": False}          # 非活动槽从未被标记为有效
    assert bed.mirror.image_bytes_served == 2 * NEW.size


def test_arbitrary_software_modified_metadata_fails_signature(bed):
    bed.release(NEW)
    bed.assign(NEW)
    evil = bytes(b ^ 0x5A for b in NEW.payload())

    def point_to_evil(signed):
        signed["targets"][NEW.filename]["hashes"]["sha256"] = sha256_hex(evil)

    # 攻击者没有离线 targets 密钥，只能改内容、保留原签名
    bed.mirror.overrides[("image", "targets.json")] = tamper_signed(bed.image_repo.files["targets.json"], point_to_evil)
    bed.mirror.image_overrides[NEW.filename] = evil
    before = bed.ecu_state()
    with pytest.raises(SignatureThresholdError) as exc:
        bed.client.update()
    assert (exc.value.repo, exc.value.role) == ("image", "targets")
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")
    assert bed.mirror.image_bytes_served == 0


def test_endless_data_image_stream_capped_at_signed_length(bed):
    bed.release(NEW)
    bed.assign(NEW)
    payload = NEW.payload()

    def endless(offset):
        yield from (payload[i:i + 256] for i in range(offset, len(payload), 256))
        for _ in range(1000):                                       # 合法内容之后不停的垃圾数据（防护失效时 256 KB 后报错）
            yield b"\0" * 256
        raise AssertionError("客户端一直在读，没有在签名长度处停下")

    bed.mirror.image_overrides[NEW.filename] = endless
    before = bed.ecu_state()
    with pytest.raises(EndlessDataError):
        bed.client.update()
    assert_rejected(bed, before, "ENDLESS_DATA")
    assert bed.mirror.image_bytes_served <= NEW.size + 256          # 只多读了一块就停
    assert len(bed.ecu.read_image("B", SLOT_CAPACITY)) <= NEW.size  # 写进槽的数据不超过签名长度
    assert bed.ecu.headers["B"].read() == {"valid": False}


def test_oversized_target_rejected_before_download(bed):
    huge = Release("1.6.0", secure_version=3, release_counter=6, rxswin="A-RX-07", size=SLOT_CAPACITY + 1)
    bed.release(huge)
    bed.assign(huge)
    before = bed.ecu_state()
    with pytest.raises(EndlessDataError) as exc:
        bed.client.update()
    assert "超过槽位容量" in str(exc.value)
    assert_rejected(bed, before, "ENDLESS_DATA")
    assert bed.mirror.image_bytes_served == 0


@pytest.mark.parametrize("director_claims", [OTHER_HW_ID, HW_ID], ids=["honest-other-hw", "director-lies-about-hw"])
def test_wrong_ecu_hardware_id_rejected(bed, director_claims):
    other_hw = Release("1.6.0", secure_version=3, release_counter=6, rxswin="A-RX-07",
                       hardware_identifiers=(OTHER_HW_ID,))           # 这个镜像只兼容 A-H2
    bed.release(other_hw)
    bed.assign(other_hw, hardware_identifier=director_claims)
    before = bed.ecu_state()
    with pytest.raises(WrongEcuError) as exc:
        bed.client.update()
    # 如实写 A-H2：车端比对自己的硬件标识时拒绝；谎称 A-H1：与 Image 仓库的兼容列表对不上
    assert exc.value.repo == ("" if director_claims == OTHER_HW_ID else "director")
    assert_rejected(bed, before, "WRONG_ECU")
    assert bed.mirror.image_bytes_served == 0


@pytest.mark.parametrize("variant", ["unknown-ecu", "duplicate-ecu"])
def test_director_lists_unknown_or_duplicate_ecu_rejected(bed, variant):
    bed.release(NEW)
    if variant == "unknown-ecu":
        bed.assign(NEW, ecu_id="ECU-NOT-IN-THIS-VEHICLE")
    else:
        patch = Release("1.6.1", secure_version=3, release_counter=7, rxswin="A-RX-07")
        bed.release(patch)
        for rel in (NEW, patch):                                    # 同一个 ECU 被指派了两个镜像
            bed.director.set_target_entry(rel.filename, bed.director_entry(rel))
        bed.director.publish()
    before = bed.ecu_state()
    with pytest.raises(WrongEcuError) as exc:
        bed.client.update()
    assert (exc.value.repo, exc.value.role) == ("director", "targets")
    assert_rejected(bed, before, "WRONG_ECU")


# ================================================================ 密钥攻击
def test_below_threshold_signatures_rejected(bed):
    # 攻击者攻破了 Image 仓库服务器（在线 snapshot / timestamp 密钥），离线 targets 密钥只偷到 1 把（门限 2）
    stolen = bed.image_repo.keys["targets"][0]
    bed.release(NEW, targets_signers=[stolen])
    bed.assign(NEW)
    before = bed.ecu_state()
    with pytest.raises(SignatureThresholdError) as exc:
        bed.client.update()
    assert (exc.value.repo, exc.value.role) == ("image", "targets")
    assert "有效签名 1 个，门限 2" in str(exc.value)
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")


def test_duplicate_signatures_do_not_reach_threshold(bed):
    stolen = bed.image_repo.keys["targets"][0]
    bed.release(NEW, targets_signers=[stolen, stolen, stolen])      # 同一把密钥的签名复制三份
    bed.assign(NEW)
    before = bed.ecu_state()
    with pytest.raises(SignatureThresholdError) as exc:
        bed.client.update()
    assert "有效签名 1 个，门限 2" in str(exc.value)
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")


def test_signature_from_other_role_key_not_counted(bed):
    stolen = bed.image_repo.keys["targets"][0]
    timestamp_key = bed.image_repo.keys["timestamp"][0]             # 本仓库的合法密钥，但没被授权签 targets
    bed.release(NEW, targets_signers=[stolen, timestamp_key])
    bed.assign(NEW)
    before = bed.ecu_state()
    with pytest.raises(SignatureThresholdError) as exc:
        bed.client.update()
    assert "有效签名 1 个，门限 2" in str(exc.value)
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")


def test_root_rotation_revokes_old_targets_key(bed):
    revoked = bed.image_repo.rotate("targets")                      # root v2：换掉全部 targets 密钥
    bed.release(NEW, targets_signers=revoked)                       # 攻击者用偷来的旧密钥签
    bed.assign(NEW)
    before = bed.ecu_state()
    with pytest.raises(SignatureThresholdError):
        bed.client.update()
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")
    assert bed.ecu.trust.read()["image"]["root"]["version"] == 2    # 车端已经跟上 root v2
    bed.image_repo.publish()                                        # OEM 用新密钥重签
    assert bed.client.update() == "COMMITTED"


@pytest.mark.parametrize("signed_by", ["new-keys-only", "old-keys-only"])
def test_root_rotation_requires_old_and_new_thresholds(bed, signed_by):
    old_keys = bed.director.keys["root"]
    new_keys = [SigningKey() for _ in range(3)]
    signers = new_keys if signed_by == "new-keys-only" else old_keys
    bed.mirror.overrides[("director", "2.root.json")] = craft_root(bed.director, version=2, root_keys=new_keys,
                                                                   signers=signers)
    before = bed.ecu_state()
    with pytest.raises(SignatureThresholdError) as exc:
        bed.client.update()
    assert ("旧 root 门限" if signed_by == "new-keys-only" else "新 root 门限") in str(exc.value)
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")
    assert bed.ecu.trust.read()["director"]["root"]["version"] == 1


@pytest.mark.parametrize("variant", ["replay-v1-as-v2", "skip-to-v3"])
def test_root_replay_and_version_skip_rejected(bed, variant):
    if variant == "replay-v1-as-v2":                                # 把 1.root.json 冒充成 2.root.json
        bed.mirror.overrides[("director", "2.root.json")] = bed.director.files["1.root.json"]
        expected, attack = RollbackAttackError, "ROLLBACK"
    else:                                                           # 签名合法，但版本号跳过了 2
        bed.mirror.overrides[("director", "2.root.json")] = encode(sign(bed.director.root_signed(3),
                                                                        bed.director.keys["root"]))
        expected, attack = RootRotationError, "INVALID_ROOT_CHAIN"
    before = bed.ecu_state()
    with pytest.raises(expected):
        bed.client.update()
    assert_rejected(bed, before, attack)
    assert bed.ecu.trust.read()["director"]["root"]["version"] == 1


def test_timestamp_key_rotation_discards_fast_forwarded_timestamp(bed):
    d = bed.director
    # 攻击者偷到在线 timestamp 密钥，签了一个版本号极大的 timestamp；签名有效，ECU 接受并记住了它
    bed.mirror.overrides[("director", "timestamp.json")] = craft_timestamp(d, d.files["snapshot.json"], version=10**6)
    assert bed.client.update() == "NO_UPDATE"
    del bed.mirror.overrides[("director", "timestamp.json")]
    d.publish()
    with pytest.raises(RollbackAttackError):                        # 合法 timestamp 的版本号更小，被当成回滚
        bed.client.update()
    d.rotate("timestamp")                                           # OEM 轮换 timestamp 密钥（root v2）
    d.publish()
    assert bed.client.update() == "NO_UPDATE"                       # 轮换后删掉旧 timestamp，恢复正常
    assert bed.ecu.trust.read()["director"]["timestamp"]["version"] == d.versions["timestamp"]
    bed.release(NEW)
    bed.assign(NEW)
    assert bed.client.update() == "COMMITTED"


def test_director_key_compromise_cannot_install_unlisted_image(bed):
    evil = b"\xee" * 2048
    entry = {"length": len(evil), "hashes": {"sha256": sha256_hex(evil)},
             "custom": {"ecu_identifier": ECU_ID, "hardware_identifier": HW_ID, "release_counter": 99,
                        "rxswin": "A-RX-07"}}
    bed.director.set_target_entry("evil.bin", entry)                # 攻击者用被盗的 Director 在线密钥签发指派
    bed.director.publish()
    bed.mirror.image_overrides["evil.bin"] = evil
    before = bed.ecu_state()
    with pytest.raises(ArbitrarySoftwareError) as exc:
        bed.client.update()
    assert exc.value.repo == "image" and "不在 Image 仓库" in str(exc.value)
    assert_rejected(bed, before, "ARBITRARY_SOFTWARE")
    assert bed.mirror.image_bytes_served == 0
