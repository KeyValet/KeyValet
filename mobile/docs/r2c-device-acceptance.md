# R2-C Android 真机验收

使用 Pixel 7 的正常签名 Debug APK；保持 Android 包验证启用。锁屏 FCM 验收前，
用户须把服务账号放到 simvito 的 `/etc/keyvalet-push/fcm-service-account.json`
（`root:keyvalet-push`、`0640`），由工程侧启动 `keyvalet-push.service`。
完整配置见 [push-deployment.md](push-deployment.md)。

R2-A 安装当前 main 前，可在仓库根目录运行软件执行端：

```sh
CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2c \
  cargo +1.99.0 run --manifest-path rust/Cargo.toml -p kv-mobile-core \
  --locked --example r2c_phone_fixture -- rust/target-r2c/live-fixture
```

状态目录含软件私钥，只能留在被忽略的本机目录，不放入报告证据。fixture 固定连接
`https://relay.keyvalet.dev`。它验证签名和 nonce，但执行计数是合成操作，不能证明
已安装 Mac 的 GUI 在场判定或真实凭证执行。

1. 输入 `pair`，使用打印的 URI 生成二维码：
   `swift mobile/scripts/r2c-pairing-qr.swift <本轮 URI> <本轮 PNG 路径>`。
   手机扫描后，控制台输出 `event=scan_received sas=…`。先核对手机六位数，
   再输入 `confirm <核对码>`，然后由用户在手机确认并按指纹。
   必须看到 `event=paired hardware_phone=true`，配对二维码有效期为 10 分钟。
2. 输入 `request T1 silent`，观察列表和静默通知。保持未决，控制台在真实
   30 秒后输出 `event=escalate`。验证声音、同一通知标识，锁屏动作「允许/拒绝」。
3. Quick 批准后，控制台必须输出 `level=Quick`、`executions=1` 和
   `second_claim=Replay`。此计数只表示 fixture 合成操作执行一次。
4. 输入 `request T2 banner`。通知只能「打开」；App 详情中批准，由用户按指纹，
   控制台必须验证 `level=Strong`。不能用布尔值代替 CryptoObject 签名。
5. 在设备设置页依次切模式、签 1 小时票、revoke-all。记录每次点击到
   `event=directive` / `event=grant` 的时间；Grant 本轮沿用 Strong 要求。
6. 打开「我不在电脑前」，再输入 `request T1 silent`，验证立即横幅。
   `skew -300`、`skew 300` 用于构造带时钟偏差的测试请求，不能修改系统时钟。
7. 退出 App 账户后检查 relay token 已删除、审批通知清除；系统杀进程与重启后
   用真正的 FCM 投递测试。`am force-stop` 属于用户强制停止，不能冒充系统杀进程。
8. 离线一小时后恢复网络，检查已过期/已解决请求消失，未过期待批与 relay 一致。

截图必须来自当前 KeyValet 界面。根目录执行
`python3 mobile/scripts/r2c-phone-evidence.py capture docs/remote-approval-reports/assets/r2c-<步骤>.png`，
工具会在截图前后检查焦点，发现其他 App 时直接丢弃。生物识别系统可能禁止捕获
安全窗口，此时保存 App 的批准前后界面和执行端验签结果，不能制作替代截图。

每步结果、计时、截图和未完成原因记入
[R2-C-mobile.md](../../docs/remote-approval-reports/R2-C-mobile.md)。
