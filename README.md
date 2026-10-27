# 海外市场 OTA 合规与升级活动规划

个人项目（2026-10），使用 AI 工具辅助完成。练习的工作内容：梳理海外项目的 OTA 需求、策划 OTA 升级活动、保证交付材料合规。

项目把**法规条款 → 威胁与风险 → 升级活动的控制点 → 工具里的检查和故障注入 → 输出的证据**串成一条线。车队数据是合成的，不代表任何车企的真实流程或数据。

## 做了什么

1. **需求清单**：依据 UN R156 官方文本（原版和 2025-11 通过的 01 系列）、R155，以及 GB 44496-2024（并注明 GB 44495 中相关的部分），整理出 77 条要求。每条都有条款号、对应关系和核实状态，并附一张“R156 vs GB 44496 差异”表。
2. **升级活动设计**：
   - 分批推送：试点 → 扩量 → 全量，试点样本量按检出能力计算。
   - 资格筛选在服务端做，先决条件在车端检查。
   - 告知与确认流程。
   - 三态闸门：PASS / HOLD / HALT。
   - 监控 KPI。
   - 追溯矩阵：27 个控制点，每个对应到法规条款。
3. **TARA（简化示例）**：按 ISO/SAE 21434 的步骤整理。
   - 5 个资产、6 个损害场景，影响按安全、财务、运营、隐私四类评级。
   - 8 个威胁场景，都对应 R155 附件5 的威胁编号。
   - 用攻击潜力法评可行性，再算风险值。
   - 风险处置后得出 8 个网络安全目标和 9 个新增控制点（C19–C27）。
   - 这是演示练习，不是认证评估。
4. **工具 `ota_plan.py`**：只用 Python 标准库（3.10+）。
   - 依次做：发布闸门（含防回滚）、资格筛选、分层分批、用固定随机种子模拟安装、按闸门规则暂停或叫停。
   - 附带合成车队生成器：规模按 JPJ 数据中 Chery 约 52,872 辆的 1/10 取 5,287 辆，每行都标 `SYNTHETIC_DEMO`。
5. **故障注入**：共 7 类故障——
   - 下载中断与续传
   - 签名或哈希不符时拒装
   - 安装中电量跌破阈值
   - ECU 刷写失败后自动回滚
   - 批次中断网
   - 某批超过叫停阈值
   - 安装后 RXSWIN 回读不一致

   逐车检查每类故障是否都落到“安全且有记录”的终态，以及软件版本和 RXSWIN 是否成对一致。
6. **车端安全升级 `secure_update/`**：参照 Uptane Standard 2.1.0 设计（Uptane-inspired，不是符合性实现）。
   - Image / Director 两个仓库，各有 root、targets、snapshot、timestamp 四个角色；Ed25519 签名（`cryptography` 库），密钥只在运行时生成。
   - 车端逐项校验：签名门限、过期、版本号、镜像哈希和长度、硬件标识、root 轮换，以及 Director 与 Image 仓库的交叉核对。
   - A/B 槽位客户端：下载到非活动槽 → 读回校验 → 试运行 → 健康检查 → 提交或自动回滚；防回滚计数器独立于软件版本，只在提交后提升；提交时 active 槽和 RXSWIN 一次原子切换。
   - 14 种攻击场景（freeze、rollback、mix-and-match、篡改镜像、超长数据、错装 ECU、签名不足门限、密钥轮换等）全部被拒；在 18 次持久化写入的每一处断电，共 249 种情况，ECU 都能启动，版本与 RXSWIN 始终成对。
   - 每个测试映射到 R155 附件5 威胁 / 缓解编号、本项目的 TARA 和需求编号（`secure_update/traceability_secure_update.csv`）。

## 文件

| 文件 | 内容 |
|---|---|
| `01_OTA需求清单_R156_GB44496.md`、`01_requirements_checklist.csv` | 77 条需求、R155 关联、差异表、来源与未核实清单 |
| `02_升级活动规划设计.md`、`02_traceability_matrix.csv` | 活动设计（第8节是故障注入）；控制点 C01–C27 ↔ 法规条款 ↔ 工具实现与证据 |
| `03_TARA_OTA.md`、`03_tara.csv` | TARA：资产、损害场景、8 个威胁场景的可行性与风险、处置、网络安全目标 |
| `ota_plan.py` | 工具 |
| `campaigns/` | 活动配置：`baseline`、`faulty_variant`（B-H2 硬件兼容问题）、`fault_injection`（低概率注入各类故障）、`fault_halt`（第2批签名无效） |
| `data/fleet_synthetic_MY.csv` | 合成车队 |
| `out/<活动>/` | 每次运行的输出：资格、分批、逐车结局和终态、每批 KPI 与闸门、分层失败分布、`fault_events.csv`、`fault_summary.csv`、活动记录 JSON |
| `tests/` | 72 个 pytest 用例。`test_ota_plan.py` 51 个；`test_fault_injection.py` 21 个，覆盖故障注入、防回滚和 TARA 表复算 |
| `secure_update/` | 车端安全升级代码、55 个测试用例、追溯表 `traceability_secure_update.csv`（38 行）、说明 `README.md`；设计文档第 10 节是汇总 |

## 怎么运行

在本目录下运行。如果 Windows 终端中文显示乱码，先执行 `$env:PYTHONIOENCODING="utf-8"`。

```bash
python ota_plan.py generate                  # 生成 data/fleet_synthetic_MY.csv（5,287 辆，seed 2026）
python ota_plan.py run --fleet data/fleet_synthetic_MY.csv --campaign campaigns/campaign_baseline.json --out out/baseline
python ota_plan.py run --fleet data/fleet_synthetic_MY.csv --campaign campaigns/campaign_faulty_variant.json --out out/faulty_variant
python ota_plan.py run --fleet data/fleet_synthetic_MY.csv --campaign campaigns/campaign_fault_injection.json --out out/fault_injection
python ota_plan.py run --fleet data/fleet_synthetic_MY.csv --campaign campaigns/campaign_fault_halt.json --out out/fault_halt
python -m pytest -q                          # 需要 pytest 和 cryptography；当前 127 passed（原有 72 + secure_update 55）
python -X utf8 -m secure_update.demo         # 14 个攻击场景 + 断电扫描
python -X utf8 -m secure_update.mutation_check   # 逐个关掉 10 道防线，确认每道都有测试能发现
```

**演示结果**（合格车辆 4,567 / 5,287；试点推送 271 辆，覆盖全部 25 个分层）：

| 活动 | 结果 |
|---|---|
| baseline | 四批都 PASS；2,889 次安装，成功率 99.69%，没有车进入安全状态 |
| faulty_variant | 试点回滚 13/167（7.8%，Wilson 下界 4.6% > 2%）→ **HALT**；问题集中在 B-H2（13/40） |
| fault_injection | 512 次故障事件全部落在安全终态：断网 330、续传 83 / 放弃 16、哈希重下 38 / 拒装 15、刷写失败 21、电量跌落 4、RXSWIN 回读不一致 5 都已回滚；四批都 PASS |
| fault_halt | 第2批 2 辆车签名无效、拒装 → **HALT**，第3、4批不执行 |

四个活动的终态检查都通过：4,567 辆车全部处于安全且有记录的终态，版本与 RXSWIN 成对一致。

## 设计取舍问答

- **为什么不给成功率设阈值？** 成功率 = 1 − 回滚率 − 安全状态率，这两项都已经有闸门。
- **先决条件为什么要求联网？** 安装前要确认活动仍然有效，这样叫停后，已经下载的车也不会再装。
- **RXSWIN 什么时候变？** 型式批准相关软件改动、并导致型式批准扩展或新批准时（R156 7.2.1.2.1）。
- **TARA 的分数靠谱吗？** 是示例。方法上，影响按四类分别评、取最高；可行性用攻击潜力五因素打分；风险矩阵和取值要按企业准则定。我能讲清每个分数为什么这样给，比如 TS1 处置前后各因素怎么变。
- **为什么签名失败零容忍，哈希不一致却允许重下？** 哈希不一致多半是传输损坏，重下就能解决；签名无效说明包不是 OEM 签的，可能是攻击，所以车端拒装，活动叫停，交给安全团队。
- **回滚也失败怎么办？** 车辆进入安全状态，版本标为“待核实”，闸门立即 HALT，车辆到店重新刷写并核实。R156 7.2.2.1.1 允许“恢复旧版本”或“进入安全状态”二选一。
- **断网为什么判 HOLD 而不是 HALT？** 断网不说明软件有问题，只是没有足够的安装样本做判断，所以先不扩量。

## 诚实说明

- **未核实的内容**（详见需求清单第 6 节、TARA 第 7 节）：
  - R156 原版和 01 系列的生效日期。
  - GB 44496 第1号修改单终稿，以及第9章的分车型执行时间。
  - GB 44496 第4章编号（4.1.1 除外）、5.1.x 和 5.2.7 的终稿措辞、5.2.10 的内容。
  - ISO/SAE 21434 原文：步骤、取值和风险矩阵。
  - 马来西亚是否适用 R156；JPJ 数字 52,872。
- 车型、硬件、地区比例、概率、阈值和 TARA 评分都是假设。
- `ota_plan.py` 不做密码学运算，车端结果按概率模拟；`secure_update/` 另有车端代码（Ed25519 验签、A/B 槽、断电测试），是 Uptane-inspired，不是符合性实现，也没有 HSM、TLS 和诊断安全访问。
