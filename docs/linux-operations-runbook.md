# 语义摄像头 NVR · Linux 运维 Runbook（安装 / 升级 / 回滚 / 备份恢复）

本文只描述 **Linux 版**。所有破坏性命令或需要 root 的命令都用
**⚠ 人工确认点** 标出：必须由运维人员逐条确认后再执行，并记录执行人、时间、
命令、退出码与输出。`scam.linux_upgrade_contract` 与 `scam.linux_backup`
**都不会**代替人工执行任何一步。

## 0. 先读：本文描述的是目标运维布局

- 本文使用的 **版本化发布目录 + `current` 指针** 是**目标运维布局**，
  **不是 `deploy/install.sh` 当前已实现的行为**。现有 `deploy/install.sh`
  只做四件事：就地创建 `.venv`、`pip install` 依赖与项目、生成
  `cameras.json` 模板、用 `python -m scam.linux_unit render` 渲染 unit 并
  `sudo cp` 注册到 `/etc/systemd/system/scam-nvr.service`
  （**人工确认点**：该 `sudo cp` 为特权操作，执行前需人工确认目标路径）。
  它不做版本化、
  不做发布切换、不做回滚、不做状态备份。
- 没有任何脚本会自动执行 `systemctl`、**不做原子指针切换**、**不做数据库
  迁移**、**不做在线 DB/配置覆盖**；本文每一步都必须人工确认并留证据。
- `scam.linux_upgrade_contract prepare/verify` 只**规划并验证**升级事务合同：
  零网络、零子进程、零服务控制、零发布切换、零在线写入。
  `scam.linux_backup create/verify/restore` 只**生成与校验状态包**，并把包恢复
  到**全新目录**；`restore` 绝不会覆盖在线 DB/配置。
- 诚实边界：两个模块的 `quality_gate_passed` 与 `release_gate_passed` 恒为
  `null`。本文与这两个模块都不构成原生 Linux、真实 RTSP、24 小时、识别质量
  或发布门禁通过的证据。

## 1. 干净安装

```bash
# 1) 安装（现有脚本；就地创建 .venv 并注册 systemd unit）
cd /opt/scam-src && bash deploy/install.sh

# 2) 只渲染 unit 到 stdout 复核（不落盘、不改系统）
python -m scam.linux_unit render --user scam --workdir /opt/scam

# 3) 启动
sudo systemctl enable --now scam-nvr.service
```

- **⚠ 人工确认点（第 1 步）**：确认目标目录、Python ≥ 3.10、`cameras.json`
  内的 RTSP 地址与密码已替换；`install.sh` 会 `pip install` 依赖与项目。
- **⚠ 人工确认点（第 3 步）**：`sudo systemctl enable --now` 由人工执行；
  `install.sh` 不会自动启动服务，`scam.linux_unit` 只输出 unit 文本。
- 健康检查：`curl -fsS http://127.0.0.1:8600/api/health`（远程经
  `ssh -L 8600:127.0.0.1:8600 <host>` 隧道）。日志：`journalctl -u scam-nvr -f`。

## 2. 升级前备份（先于停服，必须先完成并验证）

```bash
# 生成状态包到此前不存在的全新目录（已存在即拒绝，绝不覆盖）
python -m scam.linux_backup create \
    --db /var/lib/scam/cameras.sqlite3 \
    --config /opt/scam/cameras.json \
    --output-dir /var/backups/scam/state-$(date -u +%Y%m%dT%H%M%SZ)

# 只读校验状态包（必须 bundle_valid=true，退出码 0）
python -m scam.linux_backup verify --bundle-dir <上一步的输出目录>
```

- **⚠ 人工确认点**：备份必须在**停服与切换之前**完成并通过 `verify`；
  未通过 `verify` 的状态包不得用于升级，也不得作为回滚依据。
- 状态包只含 SQLite 一致性快照与配置原始字节，**不含录像、缩略图、模型或
  证据资产**；录像与证据请按各自保留策略单独归档。
- **不得绕过** `scam.linux_backup verify`：任何"直接拷贝 DB/config"或
  "跳过校验继续升级"的做法都超出本 runbook，且不会得到 P 合同支持。

## 3. 候选准备（版本化发布目录 + 升级合同）

```bash
# 目标布局：/opt/scam/releases/<version>/  为不可变发布树；/opt/scam/current 为指向当前版本的指针
python -m scam.linux_upgrade_contract prepare \
    --current-release-dir /opt/scam/releases/0.3.0 \
    --candidate-release-dir /opt/scam/releases/0.4.0 \
    --backup-bundle-dir /var/backups/scam/state-20260921T010000Z \
    --output-dir /opt/scam/upgrades/20260921T011000Z

# 只读复核合同、两棵发布树与已绑定状态包
python -m scam.linux_upgrade_contract verify \
    --contract-dir /opt/scam/upgrades/20260921T011000Z
```

- **⚠ 人工确认点**：候选发布目录必须是**新解包、未就地修改**的发布树，
  且**只含发布内容**——合同会对树内**每一个**文件求 SHA-256，不会静默忽略
  任何文件，因此不要把 `.venv`、日志、录像或备份包放进发布树。
- 合同目录固定只含 `contract.json`；已存在的输出目录一律拒绝且内容不变。
- 合同会绑定状态包的 `bundle_valid=true`、manifest SHA-256 与
  database/config 内容摘要；**没有通过 O 模块只读校验的状态包就不可能生成
  可验证合同**。
- 合同里的阶段顺序固定为：
  `preflight_verified → stop_service → switch_release →
  start_and_healthcheck → accept_or_rollback`。

## 4. 停服与发布切换

```bash
# 4.1 停服
sudo systemctl stop scam-nvr.service

# 4.2 切换指向新版本的指针（人工执行，两步式，先准备好再原子切换）
ln -sfn /opt/scam/releases/0.4.0 /opt/scam/current.next
mv -T /opt/scam/current.next /opt/scam/current
```

- **⚠ 人工确认点（4.1）**：确认当前没有正在进行的录像写盘关键操作；
  记录停服命令退出码与 `systemctl is-active scam-nvr.service` 输出。
- **⚠ 人工确认点（4.2）**：`install.sh` **不做**指针切换，systemd unit 的
  `WorkingDirectory` 也不会自动跟随 `current`；切换前必须确认 unit 指向
  `/opt/scam/current`（`python -m scam.linux_unit render --workdir
  /opt/scam/current` 复核），否则服务仍在跑旧路径。
- 本步**不修改**数据库、不执行迁移；任何"顺手升级 schema"的做法都不属于本
  runbook，必须先当作迁移需求单独评审。

## 5. 启动与健康确认

```bash
# 5.1 启动候选版本
sudo systemctl start scam-nvr.service

# 5.2 健康端点
curl -fsS http://127.0.0.1:8600/api/health

# 5.3 日志
journalctl -u scam-nvr.service --since "10 min ago" --no-pager
```

- **⚠ 人工确认点（5.1）**：记录启动命令退出码与服务状态。
- 健康端点返回 2xx **且** JSON 里录像与告警各自状态正常，才算"启动成功"；
  只看进程存在不算。**⚠ 人工确认点（5.2）**：保存完整 JSON 响应原文。
- 若启动失败或健康检查不通过，**不要继续接受**，直接进入第 7 节代码回退。

## 6. 接受

- 逐条核对 P 合同的 `success_checklist`：停服确认、切换记录、启动确认、
  健康端点、日志归档、运维决定，六项都要有证据。
- **⚠ 人工确认点**：由运维人员明确写下"接受 0.4.0"或"回退"的决定与依据；
  没有明确决定不得视为升级完成。
- 接受后保留旧版本发布目录与状态包，至少留到下一次成功升级之后。

## 7. 代码回退（优先手段，先回代码再谈数据）

顺序固定，不得跳步、不得颠倒：

1. **停止失败候选**：`sudo systemctl stop scam-nvr.service`
   **⚠ 人工确认点**：记录退出码并确认无残留进程占用端口。
2. **恢复旧发布指针/工作目录**：把 `/opt/scam/current` 指回旧版本
   **⚠ 人工确认点**：确认 unit 的 `WorkingDirectory` 随之指回旧路径。
3. **启动旧版本**：`sudo systemctl start scam-nvr.service`
   **⚠ 人工确认点**：记录退出码。
4. **先验证旧版本健康**：`curl -fsS http://127.0.0.1:8600/api/health`
   **⚠ 人工确认点**：保存响应；健康不通过时先查旧版本自身日志。
5. 只有在第 8 节的条件成立时才执行状态恢复；否则到此结束。

- **⚠ 人工确认点**：回退期间不修改在线 DB/配置；代码回退能恢复服务时，
  **不要**用状态包覆盖数据。

## 8. 条件性状态恢复（迁移不兼容时的受控最后手段）

只有当升级过程**明确执行过数据迁移**、且**旧版本无法读取当前状态**时，才允许
按下面顺序恢复状态；两个条件都要有证据（迁移命令记录 + 旧版本读取失败日志）。

```bash
# 8.1 先只读校验状态包
python -m scam.linux_backup verify --bundle-dir <升级前状态包>

# 8.2 恢复到全新 staging 目录（已存在即拒绝；绝不覆盖在线 DB/配置）
python -m scam.linux_backup restore \
    --bundle-dir <升级前状态包> \
    --target-dir /var/restores/scam-20260921T020000Z
```

- **⚠ 人工确认点（8.2）**：`restore` 只会写入**此前不存在的全新目录**；
  它不会、也不得替换 `/var/lib/scam/cameras.sqlite3` 或 `/opt/scam/cameras.json`。
- **⚠ 人工确认点（8.3）**：由运维人员逐项复核 staging 内容（设备与规则是否
  符合预期、时间点是否正确），再决定是否**在服务停止状态下**做受控替换；
  替换前请再次备份当前状态。此步是人工操作，不属于任何脚本。
- 恢复**不是**默认动作：能靠代码回退恢复服务时，不恢复状态。

## 9. 证据归档

每次升级/回退都要归档以下内容（推荐放在 `/var/log/scam-upgrades/<时间戳>/`）：

- 每条命令的**完整命令行、执行人、时间、退出码**与关键输出；
- `python -m scam.linux_backup create/verify` 的完整 JSON 输出；
- `python -m scam.linux_upgrade_contract prepare/verify` 的完整 JSON 输出，
  以及 `contract.json` 原文（含两棵树的 SHA-256 与状态包绑定摘要）；
- 健康端点响应原文、`journalctl -u scam-nvr.service` 片段；
- 恢复前后的校验值（若执行了第 8 节）；
- 人工确认点的确认人记录。

- **⚠ 人工确认点**：归档完成后核对 `verify` 输出仍为 `contract_valid=true`；
  证据缺失的升级不得计入"已完成"。

## 10. 已知限制

- 本 runbook 与 P 合同**只规划与验证**：它们不安装、不控制服务、不切换发布、
  不迁移数据、不覆盖在线状态，也**没有任何自动化保证**。
- `deploy/install.sh` 仍是就地安装脚本：**不支持版本化、不支持回滚**；
  第 3、4 节的版本化布局需要运维人员自行准备目录。
- systemd unit 由 `scam.linux_unit render` 单一真值渲染，但**重启后的数据目录、
  指针跟随、迁移兼容性均未由任何脚本保证**。
- 尚未验证项：原生 Linux 主机、真实 RTSP、24 小时浸泡、识别质量与发布门禁
  全部未验证；`quality_gate_passed` 与 `release_gate_passed` 恒为 `null`。
- 状态包不含录像与证据资产；媒体保留策略需单独规划。
