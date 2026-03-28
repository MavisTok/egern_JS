# 烽火/中兴 CPE 网络状态 Scriptable 小组件

实时监控烽火（FiberHome）和中兴（ZTE）CPE 路由器的网络信号与流量状态，在 iPhone/iPad 桌面或锁屏直接查看。

## 功能特性

- **双设备支持**：烽火（FiberHome）和中兴（ZTE）CPE 路由器，首次运行自动识别
- **实时信号监控**：RSRP、RSRQ、SINR、RSSI、频段（如 N78/N79）、Cell ID、PCI
- **网络状态**：制式（2G/3G/4G/5G NSA/5G SA）、运营商、IP/网关/DNS、在线设备数
- **实时速率**：上行/下行实时速率显示
- **四种尺寸**：小、中、大、超大，以及锁屏小组件（Accessory）
- **信号质量着色**：RSRP/SINR 根据强弱自动绿/黄/橙/红色标注，并显示质量评级

## 安装

1. 在 iPhone/iPad 上安装 [Scriptable](https://scriptable.app/)
2. 将 `CPE_egern.js`（Egern）或 `CPE_scriptable.js`（Scriptable）内容复制到对应 App，新建脚本并粘贴
3. 在桌面添加 Scriptable 小组件，选择该脚本
4. 在小组件参数中填写路由器配置（见下方）

## 配置

在 Scriptable 小组件的"参数"字段中填写 JSON：

```json
{
  "CPE_HOST": "192.168.8.1",
  "CPE_USER": "useradmin",
  "CPE_PASS": "你的密码",
  "ZTE_HOST": "192.168.0.1",
  "ZTE_PASS": "",
  "CPE_TYPE": "auto"
}
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `CPE_HOST` | `192.168.8.1` | 烽火路由器 IP |
| `CPE_USER` | `useradmin` | 烽火登录用户名 |
| `CPE_PASS` | _(空)_ | 烽火登录密码 |
| `CPE_API` | _(自动)_ | API 前缀：`api`（LG6121F）或 `fh_api`（其他型号），留空自动检测 |
| `ZTE_HOST` | `192.168.0.1` | 中兴路由器 IP |
| `ZTE_PASS` | _(空)_ | 中兴登录密码，留空使用匿名令牌 |
| `CPE_TYPE` | `auto` | 强制指定设备类型：`fh` / `zte` / `auto` |
| `CPE_REFRESH` | `60` | 刷新间隔（秒） |

> `CPE_TYPE` 设为 `auto` 时，首次连接成功后会自动缓存设备类型，之后无需重新探测。若更换设备，需清除缓存（脚本内 `Keychain.remove('cpe_type')` 或重新安装）。

## 支持设备

| 设备 | 品牌标识 | API 类型 |
| --- | --- | --- |
| 烽火 LG6121F | FH | `/api/` |
| 烽火（其他型号） | FH | `/fh_api/` |
| 中兴 CPE | ZTE | ubus JSON-RPC |

## 小组件尺寸预览

| 尺寸 | 显示内容 |
| --- | --- |
| **小（Small）** | 运营商、频段、RSRP、SINR、上下行速率 |
| **中（Medium）** | 双列详细信号参数 + 速率 |
| **大/超大（Large/XL）** | 完整信息：运营商、时间、在线设备、Cell ID 等 |
| **锁屏（Accessory）** | 信号点 + 上下行速率（极简内联） |

## 调试

项目附带 `debug.html`，可在浏览器中模拟小组件运行：

1. 用 VS Code Live Server 或直接打开 `debug.html`
2. 在侧边栏填写路由器 IP 和密码
3. 选择小组件尺寸，点击 **▶ 运行**
4. 查看渲染结果和网络请求日志

## 技术说明

- **烽火认证**：登录使用纯 JS 实现的 AES-128-CBC 加密，以 Session ID 前 16 字节为密钥
- **中兴认证**：使用 SHA-256 哈希密码，支持匿名令牌（全零令牌）
- **数据刷新**：由 Scriptable 小组件刷新周期控制，通常每 5 分钟自动更新一次

## 参考项目

- [fiberhome-cpe-lg6121f-sms-notice](https://github.com/Curtion/fiberhome-cpe-lg6121f-sms-notice) — 烽火 API 参考
- [ZTE_Desktop_Status](https://github.com/MavisTok/ZTE_Desktop_Status) — 中兴 API 参考
