# KeyValet 手机登录推送和内部测试

iOS 使用 TestFlight，Android 使用 Google Play 内部测试。先配置登录与推送，再用测试版验收真实手机审批。

Google Play 的应用已经创建好后，从下面的“Google Play 内部测试”开始。

## Google Play 内部测试

1. 登录 [Google Play Console](https://play.google.com/console/)，打开 KeyValet。
2. 左侧进入 **Test and release → Testing → Internal testing**（测试和发布 → 测试 → 内部测试）。
3. 打开 **Testers**，点击 **Create email list**，添加测试手机使用的 Google 账号邮箱。保存列表，勾选该列表，填写反馈邮箱并保存。
4. 打开 **Releases → Create new release**，上传签名的 `.aab`。包名应为 `dev.keyvalet.mobile`，首次上传按页面提示完成 Play App Signing 配置。填写版本说明，保存并点击 **Next**，审阅后发布到内部测试。创建版本按钮不可用时，先完成 Dashboard 显示的阻塞事项。[官方发布步骤](https://support.google.com/googleplay/android-developer/answer/9859348?hl=en)
5. 打开 **Protected with Play → Play Store distribution → Go to Play app signing**，保存 **App signing key** 栏目的 SHA-1 和 SHA-256。Google 登录使用的是 Play 最终安装包的签名指纹；如页面列出多张应用签名证书，保存各张证书的指纹，用于登记相应客户端。[官方签名说明](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en)
6. 内部测试发布成功后，在 **Testers** 复制加入测试的链接。测试手机用名单中的 Google 账号打开链接，加入测试，再从 Google Play 安装。[官方测试步骤](https://support.google.com/googleplay/android-developer/answer/9845334?hl=en)

第 4 步需要工程侧提供安装包。仓库的 [package-play.sh](../mobile/scripts/package-play.sh) 生成文件到 `mobile/dist/play-internal/`，需要外部上传签名 keystore、别名和密码，对应 `KV_ANDROID_KEYSTORE`、`KV_ANDROID_KEY_ALIAS`、`KV_ANDROID_STORE_PASSWORD`、`KV_ANDROID_KEY_PASSWORD`。脚本只打包，控制台上传和内部测试发布另行执行。后续上传需要增加构建号。

## Google 登录和 Android 推送

Play Console 管理安装包和测试名单；登录配置在 Google Cloud，FCM 推送配置在 Firebase。

1. 在 [Google Cloud Console](https://console.cloud.google.com/) 创建或选中 KeyValet 专用项目。打开 **Google Auth Platform → Branding**，填写产品名和联系邮箱；**Audience** 先使用 External 和 Testing，登记本轮测试邮箱。登录只使用 `openid`、`email`、`profile` 范围。[官方配置说明](https://support.google.com/cloud/answer/15544987?hl=en)
2. 在 **Google Auth Platform → Clients → Create client** 创建以下客户端，并保存 Client ID。[官方客户端说明](https://support.google.com/cloud/answer/15549257?hl=en)

   | 类型 | 填写内容 | Relay 配置名 |
   | --- | --- | --- |
   | Web application | 作为手机登录 ID token 的后端 audience | `KEYVALET_GOOGLE_WEB_CLIENT_ID` |
   | Android | Package name 填 `dev.keyvalet.mobile`，SHA-1 填上一步取得的 Play 应用签名指纹 | `KEYVALET_GOOGLE_ANDROID_CLIENT_ID` |
   | iOS | Bundle ID 填 `dev.keyvalet.mobile`，Team ID 填 `PWCRJPY7YC` | `KEYVALET_GOOGLE_IOS_CLIENT_ID` |

   创建 Web application 时，名称可填 `KeyValet Mobile Backend`，下面两个字段都留空，直接点击创建：

   | 字段 | 填写方式 |
   | --- | --- |
   | 已获授权的 JavaScript 来源 | 留空 |
   | 已获授权的重定向 URI | 留空 |

   当前手机通过原生 Google SDK 登录，再把 ID token 交给 relay 校验。Web Client ID 用于后端 audience 校验，因此这一步无需配置浏览器来源或网页登录回调。创建后保存以 `.apps.googleusercontent.com` 结尾的 Client ID，配置到 `KEYVALET_GOOGLE_WEB_CLIENT_ID`。[Google 手机与后端认证说明](https://developers.google.com/identity/sign-in/ios/backend-auth)

   当前 relay 的 Android Client ID 为单值，填写实际安装包对应的客户端。本轮 Pixel 7 安装的是本机签名的 Debug APK，因此使用下面的 Android Debug ID；切换到 Play 安装包时，需要登记 Play 的应用签名指纹并同步切换 relay 配置。iOS 的 Reversed Client ID 填入 `mobile/ios/Flutter/OAuth.xcconfig`。

   KeyValet 项目 `keyvalet-511408` 已创建以下客户端，公共标识已写入本地 `deploy/relay/account.env` 和 `mobile/ios/Flutter/OAuth.xcconfig`。这两个本地配置由 gitignore 忽略；新环境使用 [relay 环境模板](../rust/crates/kv-server/account.env.example) 和 [iOS OAuth 模板](../mobile/ios/Flutter/OAuth.xcconfig.example) 配置：

   | 类型 | Client ID |
   | --- | --- |
   | Web | `377993819556-9mvtbodaont066ugeen78kphubspa98j.apps.googleusercontent.com` |
   | iOS | `377993819556-a9jv022e3ikitqbb00k698ai4m30ncpu.apps.googleusercontent.com` |
   | Android（原有，保留） | `377993819556-ob6rpvrg42v7j5cjk56cgdcvi92svk01.apps.googleusercontent.com` |
   | Android Debug（当前 Pixel 7） | `377993819556-j3dacrhh8vo4d2oli38ifjq7lammcbiu.apps.googleusercontent.com` |

   Android 下载文件不包含包名和签名指纹。2026-10-12 实机排查发现，原有客户端登记的 SHA-1 是 `15:EC:3D:A1:C5:CE:77:AB:DD:1C:F8:F2:4A:BF:C9:7D:CA:04:23:AF`，与当前 APK 不匹配；Google SDK 因此返回 `canceled / account reauth failed`。已保留原有客户端，新增 `KeyValet Android Debug`，包名为 `dev.keyvalet.mobile`，SHA-1 为 `E9:44:EB:13:AA:99:F0:E9:D4:95:6F:76:FC:CE:0F:33:C7:D1:97:58`，并将 relay 的 Android presenter 切换到对应 ID。原始下载文件留在仓库外，当前登录流程只使用公共 Client ID。

   2026-10-12 已将 Web、iOS 和 Android Debug 三个公共 ID 加载到线上 `keyvalet-relay-server.service`，[providers](https://relay.keyvalet.dev/v1/account/providers) 返回 `google=true`、`apple=false`，[health](https://relay.keyvalet.dev/v1/health) 返回 `ok=true`。服务器环境文件为 `/etc/keyvalet-relay/account.env`，通过 [systemd drop-in](../deploy/relay/account.conf) 加载。iOS 的 Debug 和 Release 构建设置均读取到正确的 Google URL scheme；Android 本轮实机记录见文末。

3. 在 [Firebase Console](https://console.firebase.google.com/) 选择用于推送的项目，然后 **Project settings → General → Add app → Android**。包名填 `dev.keyvalet.mobile`，下载 `google-services.json`，交给工程侧放到 `mobile/android/app/` 并重新打包。Firebase 推送项目可以与 Google 登录的 OAuth 项目独立，但手机推送配置和 FCM 服务器服务账号须对应同一个 Firebase 项目。[官方 Android 配置](https://firebase.google.com/docs/android/setup)
4. 打开 **Project settings → Cloud Messaging**，确认 Firebase Cloud Messaging HTTP v1 API 已启用。为推送服务账号配置发送权限，例如 **Firebase Cloud Messaging API Admin**。已有服务账号 JSON 时复用现有凭据；缺少可用文件时，再在 **Project settings → Service accounts** 生成并保存密钥。[官方 FCM 配置](https://firebase.google.com/docs/cloud-messaging/send/v1-api)
5. 把三类 Client ID、Firebase 项目 ID、`google-services.json` 和服务器服务账号 JSON 的存放路径交给工程侧。服务账号私钥保存到仓库外；`kv-push` 通过 `KV_FCM_SERVICE_ACCOUNT_FILE` 读取它。

本轮提供的 Firebase 项目是 `simvito`，项目编号 `527578968067`，与登录项目 `keyvalet-511408` 分开。Android 配置只保留 `dev.keyvalet.mobile` 条目，已放在 `mobile/android/app/google-services.json`；Debug 和 Release 的 Google Services 任务通过，生成的 Firebase 项目、sender ID 和 Android App ID 均匹配。该文件由现有 Gradle 插件加载并被 gitignore 忽略。iOS Firebase plist 的 Bundle ID 同样是 `dev.keyvalet.mobile`；当前 iOS 推送直接使用 APNs，继续准备 Apple APNs 密钥。

FCM 现有服务账号 JSON 已找到，位于本机 `/Users/guang/Documents/Simvito资料/simvito-5e0a66149f10.json`。项目为 `simvito`，账号为 `firebase-adminsdk-fbsvc@simvito.iam.gserviceaccount.com`，项目、账号和密钥均与 Simvito 后端现有 `FCM_PROJECT_ID`、`FCM_CLIENT_EMAIL`、`FCM_PRIVATE_KEY` 配置匹配。原文件保留在仓库外，本轮不搬运私钥。2026-10-13 用户已在 simvito 提供 `/etc/keyvalet-push/fcm-service-account.json`（`root:keyvalet-push`、`0640`），服务读取此路径。`keyvalet-push.service` 已启动并启用，只监听 `127.0.0.1:8788`；提供商环境文件 root:root、0600，shared bearer 通过 systemd LoadCredential 加载。

R2-C 已接通元数据调度、失败重试和失效 token 清理；nginx 不代理推送端口。真实 FCM 元数据投递返回 202，Pixel 7 的 KeyValet 后台进程被结束后再次唤起并完成原生/Rust 同步，未启动 Flutter UI。该空队列探测不等于锁屏审批通过；扫码、Quick/Strong、升级与设置三步仍需真机继续。配置说明见 [push-deployment.md](../mobile/docs/push-deployment.md)，证据见 [R2-C 报告](remote-approval-reports/R2-C-mobile.md)。

## Apple 登录和 iOS 推送

使用 Simvito Limited 团队 `PWCRJPY7YC` 的 Account Holder 或 Admin 账号登录 [Apple Developer](https://developer.apple.com/account/)。

1. 打开 **Certificates, Identifiers & Profiles → Identifiers**。创建或编辑主 App ID，选择 Explicit，Bundle ID 填 `dev.keyvalet.mobile`。启用 **Sign in with Apple**（Primary App ID）、**Push Notifications**、**App Groups** 和 **Time Sensitive Notifications**，保存。[官方 App ID 步骤](https://developer.apple.com/help/account/identifiers/register-an-app-id/)
2. 在 **Identifiers → + → App Groups** 注册 `group.dev.keyvalet.mobile`。再注册通知扩展 App ID `dev.keyvalet.mobile.KeyValetNSE`，为主 App 和扩展关联同一个 App Group。[官方 App Group 步骤](https://developer.apple.com/help/account/identifiers/register-an-app-group/)
3. 在 **Identifiers → + → Services IDs** 创建登录 Services ID，例如 `dev.keyvalet.mobile.signin`。进入它的 **Sign in with Apple → Configure**，Primary App ID 选择主 App，按下表填写并保存。[官方 Apple 网页登录步骤](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/)

   | 字段 | 填写值 |
   | --- | --- |
   | Domains and Subdomains | `relay.keyvalet.dev` |
   | Return URLs | `https://relay.keyvalet.dev/v1/account/apple/callback` |

   主 App ID 用于 iOS 原生登录；Services ID 用于 Android 的 Apple 浏览器登录。当前 ID token 登录验证只需公共 ID，后续授权码交换和账号生命周期功能需要另外接入服务器凭据。

4. 打开 **Keys → +**，填写密钥名，勾选 **Apple Push Notification service → Configure**。TestFlight 首轮选择 Production；使用 Topic Specific 时，topic 选择 `dev.keyvalet.mobile`。确认并下载 `.p8`，保存 Key ID。文件只能下载一次，保存在仓库外。[官方 APNs 密钥步骤](https://developer.apple.com/help/account/keys/create-a-private-key/)
5. 在 **Profiles → + → Distribution → App Store Connect**，为主 App 和通知扩展分别生成分发 profile，选择团队的 Apple Distribution 签名证书并下载。工程侧的打包 Mac 需要对应证书和私钥；profile 需满足项目的 entitlements。[官方 profile 步骤](https://developer.apple.com/help/account/provisioning-profiles/create-an-app-store-provisioning-profile/)
6. 交接 Services ID、两个 profile 名称和文件、APNs Key ID 与 `.p8` 存放路径。Relay 配置 `KEYVALET_APPLE_APP_ID=dev.keyvalet.mobile` 和 `KEYVALET_APPLE_SERVICES_ID`；TestFlight 推送配置 `KV_APNS_TEAM=PWCRJPY7YC`、`KV_APNS_TOPIC=dev.keyvalet.mobile`、`KV_APNS_KEY_ID`、`KV_APNS_KEY_FILE`、`KV_APNS_SANDBOX=0`。开发签名包使用匹配的 sandbox 配置。

## App Store Connect 和 TestFlight

1. 登录 [App Store Connect](https://appstoreconnect.apple.com/)，打开 **Apps → + → New App**。已有 KeyValet 记录时直接打开。平台选 iOS，名称填 KeyValet，主语言按产品选择，Bundle ID 选择 `dev.keyvalet.mobile`，SKU 可填 `keyvalet-ios`。创建需要 Account Holder、Admin 或 App Manager 权限；Account Holder 需先签署 Business 中的最新协议。[官方创建步骤](https://developer.apple.com/help/app-store-connect/create-an-app-record/add-a-new-app/)
2. 把签名 `.ipa` 用 Mac 上的 **Transporter** 添加并上传，等待处理完成。仓库的 [package-testflight.sh](../mobile/scripts/package-testflight.sh) 生成文件到 `mobile/dist/testflight/`，需要 `KV_IOS_EXPORT_OPTIONS` 指向配置好主 App 和扩展 profile 的 export plist。构建若显示 **Missing Compliance**，按实际加密实现补齐页面要求的信息。[官方上传步骤](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
3. 打开 **Users and Access**，把内部测试者添加为拥有该 App 访问权限的用户，例如 Developer。测试者先接受成员邀请。
4. 进入 **KeyValet → TestFlight → Internal Testing → +**，创建组，例如 `Dogfooding`。点击 **Invite Testers** 选择测试者，再通过 **Add Builds** 选择处理完成的构建，填写测试说明并添加。[官方内部测试步骤](https://developer.apple.com/help/app-store-connect/test-a-beta-version/add-internal-testers/)
5. 测试者在 iPhone 安装 TestFlight，接受测试邀请并安装 KeyValet。普通外部测试者使用 **External Testing** 分组，首个构建需按页面流程提交 Beta App Review。[官方 TestFlight 流程](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/)

## 配置后的验收

工程侧把公共登录 ID 接入 relay，重新打包手机 App，并部署配置好的 `kv-push`。登录配置模板见 [account.env.example](../rust/crates/kv-server/account.env.example)，协议和会话行为见 [account-login.md](../mobile/docs/account-login.md)。

依次验收真实登录、退出、同一身份重新登录；再验收后台和锁屏通知、Quick 解锁后批准、Strong 打开 App 后生物识别批准、30 秒升级和完成后的通知取消。30 秒升级由执行端驱动，手机显示内容与审批强度来自校验后的加密信封。

推送凭据配置完成后，工程侧启动 `kv-push`，检查提供商发送权限并进行实际锁屏投递。控制台创建成功、服务接受推送请求和完整手机审批验收分别记录；单元测试或前台 WebSocket 成功不计作锁屏推送通过。

## Android Google 登录实机记录（2026-10-12）

设备为 Pixel 7，Android 16 / API 36；安装包为 KeyValet `0.3.0` Debug，包名 `dev.keyvalet.mobile`。已重新构建 Rust Android 原生库及 APK，并覆盖安装到手机，保留现有数据和设备密钥。登录使用上文的 Android Debug OAuth 客户端，后端为线上 `relay.keyvalet.dev`。

| 检查 | 手机结果 | Relay 结果 |
| --- | --- | --- |
| 首次 Google 登录 | 原生账号选择和授权成功，进入审批中心；设置页显示 Google 账户 | Google 用户 1、有效账户会话 1、设备用户绑定 1 |
| 退出登录 | 返回欢迎登录页 | 有效账户会话 0、设备用户会话 0；用户和设备绑定保留 |
| 同一账号重新登录 | 再次进入审批中心 | Google 用户仍为 1、设备用户绑定仍为 1；有效账户会话恢复为 1 |
| 强制停止后冷启动 | 无需再次授权，恢复审批中心并重新显示在线 | 有效账户会话仍为 1 |

`flutter analyze`、`flutter test`（40/40）和 APK 的 API 36 / 原生库检查通过。Rust 1.99.0 的全工作区 `fmt --all -- --check`、`clippy --workspace --all-targets -- -D warnings`、`build --workspace --locked`、`test --workspace --locked` 均通过。本轮验收覆盖 Android Google 登录、退出、重新登录和冷启动会话恢复；Play 签名安装包、Apple 登录、后台推送和完整手机审批链路继续按上文验收。
