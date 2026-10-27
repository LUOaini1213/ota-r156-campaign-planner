"""异常与攻击类型标签。

Uptane Standard 2.1.0 §5.4.4.2：任何一步失败，ECU SHALL 返回错误码；针对某类攻击的检查失败时
（rollback、freeze、arbitrary software 等），SHOULD 返回能指明攻击类型的错误码。
这里用“异常类 + attack 标签”实现。attack 标签会写进 ECU 的安全日志和签名版本报告。
"""
from __future__ import annotations


class SecureUpdateError(Exception):
    """所有校验失败的基类。"""

    attack = "VERIFICATION_FAILED"

    def __init__(self, message: str, *, repo: str = "", role: str = "") -> None:
        super().__init__(message)
        self.repo = repo
        self.role = role


class MetadataFormatError(SecureUpdateError):
    """格式不对：不是严格 JSON、有重复键、出现浮点数、字符串不是 NFC、字段缺失或类型不对。"""

    attack = "MALFORMED_METADATA"


class SignatureThresholdError(SecureUpdateError):
    """授权密钥的有效签名数低于门限。§5.4.4.3–§5.4.4.6 把签名检查失败归为 arbitrary software attack。"""

    attack = "ARBITRARY_SOFTWARE"


class RollbackAttackError(SecureUpdateError):
    """版本倒退：元数据版本号、或镜像 release counter 低于已信任的值（§4.3.3 rollback attack）。"""

    attack = "ROLLBACK"


class ExpiredMetadataError(SecureUpdateError):
    """元数据已过期。§5.4.4.3 step 3、§5.4.4.4 step 4：报告可能的 freeze attack。"""

    attack = "FREEZE"


class MixAndMatchError(SecureUpdateError):
    """元数据之间对不上：snapshot 与 timestamp、targets 与 snapshot、Director 与 Image 仓库（§4.3.3 mix-and-match）。"""

    attack = "MIX_AND_MATCH"


class EndlessDataError(SecureUpdateError):
    """收到的数据超过上限或超过签名元数据声明的长度（§4.3.3 endless data attack）。"""

    attack = "ENDLESS_DATA"


class ArbitrarySoftwareError(SecureUpdateError):
    """镜像哈希与已签名元数据不符，或 Director 指向 Image 仓库里没有的镜像（§4.3.4 arbitrary software attack）。"""

    attack = "ARBITRARY_SOFTWARE"


class WrongEcuError(SecureUpdateError):
    """硬件标识或 ECU 标识不匹配（§5.4.3.4 step 3；§5.4.4.6 steps 7–8）。Uptane 没有给这类情况起攻击名，标签是本项目自定的。"""

    attack = "WRONG_ECU"


class AntiRollbackError(SecureUpdateError):
    """镜像的 secure_version 低于 ECU 防回滚计数器。这是本项目的硬件防回滚下限，不是 Uptane 定义的字段。"""

    attack = "ROLLBACK"


class RootRotationError(SecureUpdateError):
    """root 轮换链不合法，例如版本跳号、轮换次数超过上限。"""

    attack = "INVALID_ROOT_CHAIN"


class NetworkUnavailable(Exception):
    """网络或文件不可用。不当作攻击：车辆保持当前版本，稍后重试。"""


class DownloadIncomplete(Exception):
    """镜像数据流提前结束（比如断网）。不当作攻击：保留断点，下次重新校验元数据后续传。"""


class BrickedError(Exception):
    """bootloader 找不到可启动的槽位。测试断言这件事在任何断电点都不会发生。"""
