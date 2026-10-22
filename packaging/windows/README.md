# 语义摄像头 Windows 安装器（Inno Setup 轻量包）

Inno Setup 6 安装脚本：当前用户安装，中文界面，开始菜单与可选桌面
快捷方式，Windows 卸载登记。不装服务、不自启、不开放远程访问。

## 前置条件

- [Inno Setup 6](https://jrsoftware.org/isinfo.php)（仅编译时需要；
  本包不含编译器，不自动下载）。
- 桌面壳 publish 输出目录（须含 `语义摄像头.exe` 与
  `backend\semantic-camera-backend.exe`），由宿主工程产出。

## 构建

```bat
iscc /DAppVersion=<版本号> /DAppSource=<发布目录> packaging\windows\semantic-camera.iss
```

- `<版本号>`：构建方必须传入项目版本；版本格式为**三段数字
  `MAJOR.MINOR.PATCH`**（与当前项目版本 `0.1.0` 对应），每段
  1–4 位数字。脚本在编译期做该格式校验（拒绝空值、非数字段、
  空段、超过三段、路径字符与空白），与 `pyproject.toml` 的实际值
  一致性由构建方自行确认。
  **校验边界：静态检查通过、ISPP 编译未验证**（本仓库环境未安装
  Inno Setup 编译器，未执行编译验证）。
- `<发布目录>`：桌面壳 publish 输出目录的完整路径。

安装包输出至发布目录的上一级：`SemanticCamera-Setup-<版本号>.exe`。

## 安装行为

- 当前用户安装到 `{localappdata}\Programs\SemanticCamera`（不请求
  UAC、不写 Program Files）。
- 开始菜单创建"语义摄像头"快捷方式（指向用户桌面 EXE）。
- 桌面快捷方式可选（默认不勾选）。
- Windows"已安装的应用"可正常卸载（卸载登记含名称/版本/图标）。
- 用户数据 `{localappdata}\semantic-camera` 不在安装/卸载范围内；
  不删除用户外部模型、录像或自定义路径。
- 不开机自启、不装 Windows 服务、不开放远程访问。

## 实现与验证边界（未接通项）

- WebView2 Runtime 检测已实现：分别检查机器级和用户级注册信息中的
  `pv`；空值与 `0.0.0.0` 不视为可用。缺少运行时时，经用户同意打开
  官方下载页面，不自动下载或安装。
- 卸载前检查桌面壳与后端进程；可见窗口请求正常关闭，最多等待
  45 秒。进程仍在运行则取消卸载；托盘隐藏时提示用户先从托盘退出。
  不强制结束进程，用户数据保留。
- 安装器的编译、安装、升级和卸载仍需在具备 Inno Setup 6 的环境中
  完成验证。脚本与自动合同通过不代表安装包已实际验证。
