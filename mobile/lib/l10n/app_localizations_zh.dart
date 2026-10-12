// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Chinese (`zh`).
class AppLocalizationsZh extends AppLocalizations {
  AppLocalizationsZh([String locale = 'zh']) : super(locale);

  @override
  String get appTitle => 'KeyValet';

  @override
  String get pending => '待批';

  @override
  String get devices => '设备';

  @override
  String get activity => '活动';

  @override
  String get settings => '设置';

  @override
  String get connected => '已连接';

  @override
  String get offline => '离线 · 已签发的操作将排队发送';

  @override
  String get noPending => '没有待批请求';

  @override
  String get noDevices => '扫描设备二维码即可开始';

  @override
  String get noActivity => '暂无签发记录';

  @override
  String get addDevice => '添加设备';

  @override
  String get allow => '允许';

  @override
  String get deny => '拒绝';

  @override
  String get cancel => '取消';

  @override
  String get confirm => '确认';

  @override
  String get save => '保存';

  @override
  String get refresh => '刷新';

  @override
  String get allowOnce => '仅允许这次';

  @override
  String get credentialScope => '这个凭证';

  @override
  String get sessionScope => '这个会话';

  @override
  String get remember1h => '记住 1 小时';

  @override
  String get remember8h => '记住 8 小时';

  @override
  String get remember24h => '记住 24 小时';

  @override
  String get standingCredential => '这个凭证以后都不问';

  @override
  String get standingDevice => '这台设备以后都不问';

  @override
  String get scope => '放行范围';

  @override
  String get strong => '签名需要生物识别';

  @override
  String get quick => '需要先解锁手机';

  @override
  String get softwareWarning => '这台设备使用软件密钥，未受硬件保护。';

  @override
  String get clockSkew => '设备时钟有偏差，请注意有效期。';

  @override
  String get requester => '请求设备';

  @override
  String get agent => 'Agent';

  @override
  String get credential => '凭证';

  @override
  String get operation => '操作';

  @override
  String get purpose => 'Agent 自述目的 · 未验证';

  @override
  String get risk => '风险';

  @override
  String get expiry => '到期时间';

  @override
  String get proxyOnly => '仅代理访问，凭证值留在执行端';

  @override
  String get merged => '合并请求数';

  @override
  String get noLongerWaiting => '这条请求已不在等待审批';

  @override
  String get issuedQueued => '已签发，正在等待送达';

  @override
  String get securityUnavailable => '硬件密钥不可用。请解锁手机并录入强生物识别。';

  @override
  String get actionFailed => '操作未完成，请刷新后重试。';

  @override
  String get starting => '正在打开安全存储…';

  @override
  String get scan => '扫描二维码';

  @override
  String get pasteUri => '或粘贴 kv-pair://';

  @override
  String get pairDevice => '配对设备';

  @override
  String get compareSas => '请对比两台设备上的这六位数字';

  @override
  String get sasChecked => '数字一致，我已在执行端确认';

  @override
  String get globalWarning => '全局放行也会覆盖新配对的设备。';

  @override
  String get excludeGlobal => '此设备不接收全局放行';

  @override
  String get pairingExpired => '配对即将过期，必要时请重新生成二维码。';

  @override
  String get mode => '审批模式';

  @override
  String get modePerUse => '每次都问';

  @override
  String get modeRemember => '记住 1 小时';

  @override
  String get modeStanding => '普通操作以后都不问';

  @override
  String get grants => '常设放行与票据';

  @override
  String get noGrants => '暂无放行记录';

  @override
  String get source => '来源';

  @override
  String get remainingBudget => '剩余调用预算';

  @override
  String get unknown => '等待设备回报';

  @override
  String get never => '永久';

  @override
  String get queued => '等待送达';

  @override
  String get issueTicket => '签发 1 小时票';

  @override
  String get globalScope => '所有已配对及未来设备';

  @override
  String get globalScopeWarning => '这也会覆盖未来配对的设备，签名需要生物识别。';

  @override
  String get standing => '永久 · 常设放行';

  @override
  String get unattended => '无人值守敏感操作';

  @override
  String get unattendedWarning => '敏感操作将无需再次询问。仅限这台设备，默认 7 天后到期。';

  @override
  String get permanentWarning => '永久敏感放行不会自动到期，请再次确认。';

  @override
  String get enterDeviceLabel => '输入执行端标签以确认';

  @override
  String get lockVault => '锁定 vault';

  @override
  String get revokeAll => '一键全部收回';

  @override
  String get revokeOne => '收回放行';

  @override
  String get revokeDevice => '吊销设备';

  @override
  String get revokeDeviceWarning => '这会将设备移出账户，需重新配对才能连接。';

  @override
  String get recentActivity => '最近活动';

  @override
  String get relay => 'Relay 地址';

  @override
  String get notifications => '审批通知';

  @override
  String get away => '我不在电脑前';

  @override
  String get awayHint => '执行端首次静默投递时，也立即显示提醒。';

  @override
  String get exportDiagnostics => '复制诊断信息';

  @override
  String get diagnosticsHint => '仅包含计数与连接状态，不含密钥或审批内容。';

  @override
  String get diagnosticsCopied => '已复制诊断信息';

  @override
  String get language => '语言';

  @override
  String get label => '标签';

  @override
  String get protection => '密钥保护';

  @override
  String get continueAction => '继续';

  @override
  String get search => '搜索';

  @override
  String get signatureSource => '由本机签发';

  @override
  String get scopeSensitiveHint => '敏感请求只允许本次审批。';

  @override
  String get confirmationMismatch => '标签必须完全一致';

  @override
  String get queryDetails => '查询参数名';

  @override
  String get bodyBytes => '请求体字节数';

  @override
  String get runtimeDetails => '运行时 · 工作目录 · 用户 · PID';

  @override
  String get reason => '理由（可选）';

  @override
  String get grantIssued => '已签发授权票';

  @override
  String get devicePaired => '已配对设备';

  @override
  String get actionAllowed => '已允许';

  @override
  String get actionDenied => '已拒绝';

  @override
  String get changeApplied => '已执行';

  @override
  String get changeRejected => '执行端已拒绝';

  @override
  String get invalidMessageRejected => '已拒绝无法验证的消息';

  @override
  String get approvalOrigin => '来自审批';

  @override
  String get softwareKeys => '软件密钥';

  @override
  String get executorActivity => '执行端活动';

  @override
  String get controlCenter => '审批控制中心';

  @override
  String get pendingTitle => '审批中心';

  @override
  String get pendingSubtitle => '看清每一次操作，由你决定是否放行。';

  @override
  String get devicesTitle => '已配对设备';

  @override
  String get devicesSubtitle => '查看执行端状态，掌握每一份授权。';

  @override
  String get activityTitle => '签发记录';

  @override
  String get activitySubtitle => '这台手机做出的每一次决定，都有迹可循。';

  @override
  String get settingsTitle => '偏好设置';

  @override
  String get settingsSubtitle => '按你的习惯，保持连接与提醒。';

  @override
  String get queueLabel => '待批队列';

  @override
  String get requestsWaiting => '条请求等待决定';

  @override
  String get allCaughtUp => '现在，一切就绪';

  @override
  String get allCaughtUpHint => '新的审批请求会出现在这里。';

  @override
  String pairedDevices(int count) {
    return '已配对 $count 台设备';
  }

  @override
  String sensitiveRequests(int count) {
    return '$count 条敏感请求';
  }

  @override
  String get needsReview => '等待你审核';

  @override
  String get riskReadOnly => '只读';

  @override
  String get riskOrdinary => '普通操作';

  @override
  String get riskSensitive => '敏感操作';

  @override
  String get biometricTag => '生物识别';

  @override
  String get quickTag => '快捷审批';

  @override
  String get escalatedTag => '已升级提醒';

  @override
  String get silentTag => '静默';

  @override
  String get bannerTag => '横幅提醒';

  @override
  String get emptyPendingHint => '已配对设备的请求会汇集在这里。确认操作内容后，再决定是否允许。';

  @override
  String get firstDeviceHint => '配对第一台执行端，即可在手机上审批请求、管理授权。';

  @override
  String get emptyActivityHint => '你在这里签发的审批、授权票和设备变更，会按时间记录。';

  @override
  String get pairingHint => '扫描电脑上 KeyValet 显示的二维码，再核对两端的六位数字。';

  @override
  String get pairingCodeTitle => '确认设备连接';

  @override
  String get pasteSection => '已有配对链接？';

  @override
  String get connectionSection => '连接';

  @override
  String get notificationsSection => '通知';

  @override
  String get displaySection => '显示';

  @override
  String get diagnosticsSection => '诊断';

  @override
  String get notificationHint => '当有请求需要你处理时，接收审批提醒。';

  @override
  String get privacyTitle => '凭证留在执行端';

  @override
  String get privacyHint => '手机只接收审批所需的信息，凭证值始终保留在执行端。';

  @override
  String get onlineTag => '在线';

  @override
  String get offlineTag => '离线';

  @override
  String get relayOnline => 'Relay 在线';

  @override
  String get relayOffline => 'Relay 离线';

  @override
  String grantsCount(int count) {
    return '$count 张授权票';
  }

  @override
  String get delivered => '已送达';

  @override
  String get accessControls => '访问控制';

  @override
  String get requestDetails => '请求详情';

  @override
  String get signingRequirement => '签名要求';

  @override
  String get allowBiometric => '允许 · 生物识别';

  @override
  String unattendedCount(int count) {
    return '敏感授权票：$count';
  }

  @override
  String get requestedAt => '发起时间';

  @override
  String unlockTimeout(int seconds) {
    return '解锁有效期：$seconds 秒';
  }

  @override
  String get signInHeadline => '你的审批，\n由你掌控。';

  @override
  String get signInIntro => '连接设备，逐项确认请求，随时掌握权限。';

  @override
  String get signInDevices => '你的设备';

  @override
  String get signInApproval => '生物识别审批';

  @override
  String get signInTitle => '欢迎使用 KeyValet';

  @override
  String get signInSubtitle => '登录后，即可配对设备、处理审批。';

  @override
  String get signInGoogle => '通过 Google 继续';

  @override
  String get signInApple => '通过 Apple 继续';

  @override
  String get signInPrivacy => '审批密钥始终留在手机上。登录不会批准任何请求。';

  @override
  String get signInNotReady => '此 relay 尚未开启登录，请在配置完成后重试。';

  @override
  String get signInNetworkError => '暂时无法连接 relay，请检查网络后重试。';

  @override
  String get signInRateLimited => '尝试次数过多，请稍后重试。';

  @override
  String get signInAccountConflict => '这台手机已绑定其他账户，请使用最初设置时的账户登录。';

  @override
  String get signInInvalidRelay => '请输入 HTTPS relay 地址。';

  @override
  String get signInRelayBound => '手机已与当前 relay 配对，请先移除配对设备再更换。';

  @override
  String get signInFailed => '未能完成登录，请重试。';

  @override
  String get restoringSession => '正在检查登录状态…';

  @override
  String get signingIn => '正在登录…';

  @override
  String get signInAccount => '已登录账户';

  @override
  String get signOut => '退出登录';

  @override
  String get signOutHint => '退出后将暂停审批，重新登录即可继续。配对设备和历史记录会保留在手机上。';
}
