"""secure_update：车端安全升级演示（P3 的车端补充）。

两部分：
  1. 参照 Uptane 的元数据与校验：root / targets / snapshot / timestamp 四个角色，Director 与 Image 两个仓库，
     Ed25519 门限签名、过期时间、版本号、镜像 SHA-256 与长度、硬件标识绑定、root 密钥轮换。
  2. A/B 槽位的 ECU 更新客户端：下载到非活动槽 → 校验 → 写槽头 → 标记 pending → 重启试运行 →
     健康检查 / 试启动计数 → 提交或自动回滚；独立于软件版本号的防回滚计数器；RXSWIN 记录与 active 槽原子切换。

Uptane-inspired, not a conformant implementation（参照 Uptane Standard 2.1.0，不是符合性实现）。
个人项目，使用 AI 工具辅助完成。全部数据是合成的，密钥只在运行时生成。
"""

__version__ = "0.1.0"
