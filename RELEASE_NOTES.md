# 发布说明 / RELEASE NOTES

> 本文件面向发布产物使用者；内部记录本不随包分发。
> 打包：`python scripts/package_release.py`（可复现 tar.gz，含敏感面双闸）。

## 版本

- 见 `pyproject.toml` 的 `version`（打包产物名 `scam-<version>.tar.gz`）。

## 已知限制（诚实清单）

- 全部证据等级为 **Windows 本机合成自动化**：真实 RTSP、真实检测模型推理、
  原生 Linux 主机十步运维、24 小时浸泡、真实 P95/P99 与隐私网络审计
  **均未验证**；
- 检测模型（NanoDet）与 V-JEPA 嵌入权重不随包分发：用
  `scripts/fetch_models.py` 下载校验（哈希未冻结前 fail-closed 拒绝自动
  下载）或自行导出后 `--verify-local` 就位；
- 通知出口 MQTT 依赖可选 extras：`pip install scam[mqtt]`；
- 慢系统 VLM 通道默认关闭（provider 未接线）：重复场景为纯结构匹配 +
  档案复用，新异段标记 `pending_naming`；
- 工作台为单管理员回环形态：无认证、无多用户；远程访问走 SSH 隧道。

## 安装

- Linux NVR：`bash deploy/install.sh`（venv + 依赖 + 项目本身 +
  systemd unit 由 `scam.linux_unit` 渲染单一真值）；
- Win11：`deploy/install-win11.ps1`（PS 5.1/7，venv + 逐步退出码 +
  导入自检）。

## 升级 / 回滚

- 升级：解包新版本覆盖安装目录 → `bash deploy/install.sh` 重装 venv 内
  依赖 → 重启服务；SQLite schema 迁移幂等（`PRAGMA user_version` 前向，
  拒绝降级写入）；
- 回滚：回到旧版目录/包重启即可——数据库不回写（高版本 schema 打开时
  明确拒绝而非静默降级）；升级前备份按运维 runbook（O 线备份工具）执行；
- 配置（cameras.json）与数据（SQLite/证据目录）与代码解耦，升级/回滚
  不触碰。

## 隐私边界

- 默认数据不出本机：SQLite/证据/录像/模式档案全部本机；
- 云端 VLM 为显式 opt-in 且逐次确认；通知出口（MQTT/webhook）仅在管理员
  配置 notify 段后启动，载荷为最小化固定 schema（无凭据/路径）。
