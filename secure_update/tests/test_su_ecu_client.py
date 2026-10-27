"""ECU 更新客户端：A/B 槽位、每一步断电、健康检查与试启动计数、防回滚计数器、活动叫停与续传、软件标识 / RXSWIN 记录。

每个测试函数在 traceability_secure_update.csv 里有一行。
"""
import pytest

from secure_update.canonical import sha256_hex
from secure_update.ecu import MAX_TRIAL_BOOTS
from secure_update.errors import AntiRollbackError, ArbitrarySoftwareError, MixAndMatchError, RollbackAttackError, \
    SignatureThresholdError
from secure_update.repository import verify_version_report
from secure_update.testbed import (FACTORY, NEW, PAIRS, Release, UpdateBed, check_invariants, power_cut_sweep,
                                   tamper_signed, write_steps)

from ._helpers import assert_rejected, last_attack

OLD_PAIR = (FACTORY.sw_version, FACTORY.rxswin)     # ("1.5.0", "A-RX-06")
NEW_PAIR = (NEW.sw_version, NEW.rxswin)             # ("1.6.0", "A-RX-07")


def bed_with_new(**kwargs) -> UpdateBed:
    bed = UpdateBed(**kwargs)
    bed.release(NEW)
    bed.assign(NEW)
    return bed


# ---------------------------------------------------------------- 正常流程
def test_happy_path_commits_and_updates_rxswin_atomically(bed):
    bed.release(NEW)
    bed.assign(NEW)
    assert bed.committed_pair() == OLD_PAIR
    assert bed.client.update() == "COMMITTED"
    swid = bed.ecu.read_software_identification()
    assert swid["trial"] is None
    assert (swid["committed"]["sw_version"], swid["committed"]["rxswin"], swid["committed"]["image_sha256"]) == (
        "1.6.0", "A-RX-07", sha256_hex(NEW.payload()))
    assert bed.ecu_state()["active"] == bed.ecu.running == "B"
    assert bed.ecu.counter() == NEW.secure_version
    assert check_invariants(bed, PAIRS) == []
    assert bed.client.update() == "NO_UPDATE"                       # 已经装上，不重复安装


# ---------------------------------------------------------------- 断电
@pytest.mark.parametrize("torn", [True, False], ids=["torn-write", "clean-cut"])
@pytest.mark.parametrize("health, expected", [("OK", "COMMITTED"), ("FAIL", "ROLLED_BACK")])
def test_power_loss_at_every_write_never_bricks(torn, health, expected):
    bed = bed_with_new(health_check=lambda header: health)
    result, steps = write_steps(bed)
    assert result == expected
    rows = power_cut_sweep(bed, torn=torn)
    assert len(rows) == len(steps) >= 17                            # 每一次持久化写入都断过一次电
    assert [r for r in rows if r["problems"]] == []
    assert {r["final"] for r in rows} == {expected}                 # 恢复后结局与不断电时相同
    assert {r["final_pair"] for r in rows} == {NEW_PAIR if expected == "COMMITTED" else OLD_PAIR}
    activation = "提交" if expected == "COMMITTED" else "健康检查失败"
    for keyword in ("持久化已信任元数据", "写第", "已校验的槽头", "pending", "bootloader", activation, "结束"):
        assert any(keyword in step for step in steps), keyword


def test_double_power_loss_during_recovery_never_bricks():
    rows = power_cut_sweep(bed_with_new(), torn=True, second_cut=True)
    assert len(rows) > 100                                          # 第一次断电 × 恢复途中第二次断电的全部组合
    assert [r for r in rows if r["problems"]] == []
    assert {r["final"] for r in rows} == {"COMMITTED"}


# ---------------------------------------------------------------- 健康检查与试启动计数
def test_failed_health_check_rolls_back_to_previous_slot():
    bed = bed_with_new(health_check=lambda header: "FAIL" if header["sw_version"] == "1.6.0" else "OK")
    before = bed.ecu_state()
    assert bed.client.update() == "ROLLED_BACK"
    assert bed.ecu_state() == before                                # active、软件标识 / RXSWIN、计数器都没变
    assert bed.ecu.running == "A"
    assert bed.ecu.bootctl.read()["last_result"]["reason"] == "HEALTH_CHECK_FAILED"
    assert bed.client.update() == "SKIPPED_PREVIOUSLY_ROLLED_BACK"  # 同一个镜像不自动重试


def test_bootloader_refuses_corrupted_pending_slot():
    missing = ["LOW_SOC"]
    bed = bed_with_new(preconditions=lambda: list(missing))
    assert bed.client.update() == "DEFERRED_PRECONDITIONS:LOW_SOC"  # 镜像已校验、槽头有效，只差激活
    slot = bed.ecu.journal.read()["slot"]
    chunk = bed.nv.read(f"slot{slot}.chunk00001")
    bed.nv.write(f"slot{slot}.chunk00001", bytes([chunk[0] ^ 0xFF]) + chunk[1:], "测试：校验之后槽内容被改写")
    missing.clear()
    before = bed.ecu_state()
    assert bed.client.update() == "ROLLED_BACK"                     # bootloader 重算哈希，拒绝启动 pending 槽
    assert bed.ecu.bootctl.read()["last_result"]["reason"] == "PENDING_IMAGE_INVALID"
    assert bed.ecu_state() == before and bed.ecu.running == "A"
    assert last_attack(bed) == "BOOT_INTEGRITY"


def test_crashing_image_exhausts_trial_boots_and_auto_rolls_back():
    trial_boots = []
    bed = bed_with_new(health_check=lambda header: trial_boots.append(header["sw_version"]) or "CRASH")
    before = bed.ecu_state()
    assert bed.client.update() == "ROLLED_BACK"
    assert trial_boots == ["1.6.0"] * MAX_TRIAL_BOOTS               # 每次启动前 bootloader 先扣次数
    assert bed.ecu.bootctl.read()["last_result"]["reason"] == "TRIAL_BOOTS_EXHAUSTED"
    assert bed.ecu_state() == before and bed.ecu.running == "A"


# ---------------------------------------------------------------- 防回滚
def test_anti_rollback_counter_rises_only_at_commit():
    seen_during_trial = []
    bed = bed_with_new(health_check=lambda header: seen_during_trial.append(bed.ecu.counter()) or "OK")
    assert bed.ecu.counter() == FACTORY.secure_version == 2
    assert bed.client.update() == "COMMITTED"
    assert seen_during_trial == [2]                                 # 试运行时还是旧值，所以失败了还能回旧槽
    assert bed.ecu.counter() == NEW.secure_version == 3
    assert not bed.ecu.slot_bootable("A", bed.ecu.counter())        # 提交后旧镜像（secure_version 2）不能再启动
    assert bed.ecu.slot_bootable("A", 2)                            # 镜像本身完好，只是被计数器挡住


def test_old_secure_version_refused_even_if_validly_signed(bed):
    bed.release(NEW)
    bed.assign(NEW)
    assert bed.client.update() == "COMMITTED"
    rerelease = Release("1.5.0", secure_version=2, release_counter=7, rxswin="A-RX-06")   # OEM 正式重新发布旧代码
    bed.release(rerelease)
    bed.assign(rerelease)
    before = bed.ecu_state()
    with pytest.raises(AntiRollbackError):
        bed.client.update()
    assert_rejected(bed, before, "ROLLBACK")


def test_authorized_downgrade_within_security_epoch_allowed(bed):
    patch = Release("1.5.1", secure_version=2, release_counter=6, rxswin="A-RX-06")   # 不涉及型式批准，RXSWIN 不变
    bed.release(patch)
    bed.assign(patch)
    assert bed.client.update() == "COMMITTED"
    assert bed.committed_pair() == ("1.5.1", "A-RX-06")
    back = Release("1.5.0", secure_version=2, release_counter=7, rxswin="A-RX-06")    # 回退 = 一次新的发布
    bed.release(back)
    bed.assign(back)
    assert bed.client.update() == "COMMITTED"
    swid = bed.ecu.active_identity()
    assert (swid["sw_version"], swid["release_counter"], swid["rxswin"]) == ("1.5.0", 7, "A-RX-06")
    assert bed.ecu.counter() == 2                                   # 同一安全等级内回退，计数器不动


def test_release_counter_rollback_rejected(bed):
    older = Release("1.4.9", secure_version=2, release_counter=4, rxswin="A-RX-06")   # 仍在 Image 仓库、签名有效的旧发布
    bed.release(older)
    bed.assign(older)                                               # 被攻破的 Director 想把车指回旧发布
    before = bed.ecu_state()
    with pytest.raises(RollbackAttackError) as exc:
        bed.client.update()
    assert exc.value.role == "image" and "release counter" in str(exc.value)
    assert_rejected(bed, before, "ROLLBACK")


# ---------------------------------------------------------------- 活动控制：叫停、续传、先决条件
def test_campaign_halt_discards_partial_download(bed):
    bed.release(NEW)
    bed.assign(NEW)
    bed.mirror.image_overrides[NEW.filename] = NEW.payload()[:1000]   # 下载到一半断网
    assert bed.client.update() == "DOWNLOAD_INCOMPLETE"
    assert bed.ecu.journal.read()["offset"] == 512                  # 只保留完整写入的块
    del bed.mirror.image_overrides[NEW.filename]
    bed.halt_campaign()                                             # 后端叫停（P3 的 HALT 闸门）
    before = bed.ecu_state()
    assert bed.client.update() == "ABORTED_ASSIGNMENT_CHANGED"
    assert bed.ecu_state() == before and bed.ecu.journal.read()["state"] == "IDLE"
    assert bed.client.update() == "NO_UPDATE"


def test_download_interruption_resumes_after_fresh_verification(bed):
    bed.release(NEW)
    bed.assign(NEW)
    bed.mirror.image_overrides[NEW.filename] = NEW.payload()[:1000]
    assert bed.client.update() == "DOWNLOAD_INCOMPLETE"
    del bed.mirror.image_overrides[NEW.filename]
    bed.mirror.log.clear()
    assert bed.client.update() == "COMMITTED"
    first_image = next(i for i, entry in enumerate(bed.mirror.log) if entry[0] == "image")
    assert bed.mirror.log[first_image] == ("image", NEW.filename, 512)                # 从断点续传
    assert ("meta", "director", "timestamp.json") in bed.mirror.log[:first_image]     # 续传之前重新校验了元数据


@pytest.mark.parametrize("blocker", ["LOW_SOC", "NO_NETWORK"])
def test_activation_deferred_when_preconditions_or_network_missing(blocker):
    missing = ["LOW_SOC"]
    bed = bed_with_new(preconditions=lambda: list(missing))
    before = bed.ecu_state()
    assert bed.client.update() == "DEFERRED_PRECONDITIONS:LOW_SOC"  # 已下载并校验，但不激活
    assert bed.ecu_state() == before and bed.ecu.journal.read()["state"] == "READY"
    if blocker == "NO_NETWORK":
        missing.clear()
        bed.mirror.online = False
        assert bed.client.update() == "DEFERRED_NO_NETWORK"         # 激活前联网确认不了活动仍有效，就不装
        assert bed.ecu_state() == before
        bed.mirror.online = True
    missing.clear()
    assert bed.client.update() == "COMMITTED"


# ---------------------------------------------------------------- 软件标识 / RXSWIN 记录
@pytest.mark.parametrize("health, expected", [("OK", "COMMITTED"), ("FAIL", "ROLLED_BACK")])
def test_software_identification_read_during_trial_and_after_activation(health, expected):
    reads = []

    def check(header):
        reads.append(bed.ecu.read_software_identification())       # 试运行期间经“OBD”读取
        return health

    bed = bed_with_new(health_check=check)
    assert bed.client.update() == expected
    during = reads[0]
    assert (during["committed"]["sw_version"], during["committed"]["rxswin"]) == OLD_PAIR   # 未提交前记录不变
    assert (during["trial"]["sw_version"], during["trial"]["rxswin"]) == NEW_PAIR
    after = bed.ecu.read_software_identification()
    assert after["trial"] is None
    assert (after["committed"]["sw_version"], after["committed"]["rxswin"]) == (NEW_PAIR if health == "OK" else OLD_PAIR)


def test_signed_version_report_carries_rxswin_and_detects_tampering(bed):
    bed.release(NEW)
    bed.assign(NEW)
    evil = bytearray(NEW.payload())
    evil[0] ^= 1
    bed.mirror.image_overrides[NEW.filename] = bytes(evil)
    with pytest.raises(ArbitrarySoftwareError):
        bed.client.update()
    del bed.mirror.image_overrides[NEW.filename]
    report = verify_version_report(bed.ecu.version_report("nonce-1", bed.now), bed.ecu_key.public, "nonce-1")
    assert report["attack_detected"] == "ARBITRARY_SOFTWARE"        # 后端能看到车端拦下的攻击
    assert (report["custom"]["sw_version"], report["custom"]["rxswin"]) == OLD_PAIR
    assert bed.client.update() == "COMMITTED"
    raw = bed.ecu.version_report("nonce-2", bed.now)
    report = verify_version_report(raw, bed.ecu_key.public, "nonce-2")
    assert report["installed_image"]["hashes"]["sha256"] == sha256_hex(NEW.payload())
    assert (report["custom"]["sw_version"], report["custom"]["rxswin"]) == NEW_PAIR
    forged = tamper_signed(raw, lambda signed: signed["custom"].update(rxswin="A-RX-99"))
    with pytest.raises(SignatureThresholdError):                    # 篡改 RXSWIN 后签名失效
        verify_version_report(forged, bed.ecu_key.public, "nonce-2")
    with pytest.raises(RollbackAttackError):                        # 重放旧报告：nonce 不符
        verify_version_report(raw, bed.ecu_key.public, "nonce-3")


def test_rxswin_mismatch_between_director_and_release_record_rejected(bed):
    bed.release(NEW)
    bed.assign(NEW, rxswin="A-RX-08")                               # 活动记录与 Image 仓库签名的发布记录不一致
    before = bed.ecu_state()
    with pytest.raises(MixAndMatchError) as exc:
        bed.client.update()
    assert "RXSWIN" in str(exc.value)
    assert_rejected(bed, before, "MIX_AND_MATCH")
