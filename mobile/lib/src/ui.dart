import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../l10n/app_localizations.dart';
import 'controller.dart';
import 'design.dart';
import 'rust/view.dart';
import 'auth/sign_in_page.dart';

String scopeLabel(AppLocalizations l, String scope) => switch (scope) {
  'per_use' => l.allowOnce,
  'per_credential' => l.credentialScope,
  'per_session' => l.sessionScope,
  'remember:1h' => l.remember1h,
  'remember:8h' => l.remember8h,
  'remember:24h' => l.remember24h,
  'standing:credential' => l.standingCredential,
  'standing:device' => l.standingDevice,
  _ => scope,
};
String modeLabel(AppLocalizations l, String mode) => switch (mode) {
  'per_use' => l.modePerUse,
  'remember:1h' => l.modeRemember,
  'remember:0h' => l.modeStanding,
  '' => l.unknown,
  _ => mode,
};
String protectionLabel(AppLocalizations l, String protection) =>
    ['software', 'software_key'].contains(protection)
        ? l.softwareKeys
        : protection;
String sourceLabel(AppLocalizations l, String source) => switch (source) {
  'settings' => l.settings,
  'approval' => l.approvalOrigin,
  _ => source,
};
String activityLabel(AppLocalizations l, ActivityView activity) =>
    switch (activity.kind) {
      'grant' =>
        activity.summary == 'Unattended grant' ? l.unattended : l.grantIssued,
      'pair' => l.devicePaired,
      'decision' =>
        activity.summary == 'Allowed' ? l.actionAllowed : l.actionDenied,
      'directive_result' =>
        activity.summary == 'Applied' ? l.changeApplied : l.changeRejected,
      'rejected' => l.invalidMessageRejected,
      'executor_applied' => '${l.executorActivity} · ${l.changeApplied}',
      'executor_rejected' => '${l.executorActivity} · ${l.changeRejected}',
      'executor_activity' => l.executorActivity,
      'directive' => switch (activity.summary) {
        'lock' => l.lockVault,
        'revoke_all_grants' => l.revokeAll,
        'revoke_grant' => l.revokeOne,
        'set_mode' => l.mode,
        'revoke_device' => l.revokeDevice,
        _ => l.refresh,
      },
      _ => activity.summary,
    };
String date(int seconds) => DateTime.fromMillisecondsSinceEpoch(
  seconds * 1000,
).toLocal().toString().substring(0, 16);

String riskLabel(AppLocalizations l, String tier) => switch (tier) {
  'T0' => l.riskReadOnly,
  'T1' => l.riskOrdinary,
  'T2' => l.riskSensitive,
  _ => tier,
};

void openPair(BuildContext context, MobileController controller) =>
    Navigator.push(
      context,
      MaterialPageRoute<void>(builder: (_) => PairPage(controller: controller)),
    );

class KeyValetApp extends StatelessWidget {
  const KeyValetApp({super.key, required this.controller, this.fontFamily});
  final MobileController controller;
  final String? fontFamily;
  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: controller,
    builder:
        (context, _) => MaterialApp(
          key: ValueKey(controller.signedIn),
          title: 'KeyValet',
          debugShowCheckedModeBanner: false,
          locale: Locale(
            controller.account?.locale ??
                controller.state?.settings.locale ??
                'en',
          ),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          theme: appTheme(Brightness.light, fontFamily: fontFamily),
          darkTheme: appTheme(Brightness.dark, fontFamily: fontFamily),
          builder: (context, child) {
            final theme = Theme.of(context);
            return Theme(
              data:
                  MediaQuery.disableAnimationsOf(context)
                      ? theme.copyWith(
                        pageTransitionsTheme: const PageTransitionsTheme(
                          builders: {
                            TargetPlatform.android: _ReducedTransitions(),
                            TargetPlatform.iOS: _ReducedTransitions(),
                          },
                        ),
                      )
                      : theme,
              child: child!,
            );
          },
          home:
              controller.signedIn
                  ? Home(controller: controller)
                  : SignInPage(controller: controller),
        ),
  );
}

class _ReducedTransitions extends PageTransitionsBuilder {
  const _ReducedTransitions();
  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) => child;
}

class Home extends StatefulWidget {
  const Home({super.key, required this.controller});
  final MobileController controller;
  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  int tab = 0;
  bool _openingNotification = false;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), c = widget.controller, s = c.state;
    final p = AppPalette.of(context);
    final compactHeader =
        MediaQuery.sizeOf(context).width < 360 ||
        MediaQuery.textScalerOf(context).scale(14) > 18;
    final approvalId = c.notificationApprovalId;
    if (!_openingNotification &&
        approvalId != null &&
        s?.pending.any((r) => r.id == approvalId) == true) {
      _openingNotification = true;
      c.notificationApprovalId = null;
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        if (!mounted) return;
        await Navigator.push(
          context,
          MaterialPageRoute<void>(
            builder:
                (_) => ApprovalDetail(controller: c, requestId: approvalId),
          ),
        );
        _openingNotification = false;
      });
    }
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 20,
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (!compactHeader) ...[
              const IconTile(icon: Icons.shield_outlined, size: 36),
              const SizedBox(width: 10),
            ],
            Flexible(
              child: Text(
                l.appTitle,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(
                  context,
                ).textTheme.titleLarge?.copyWith(letterSpacing: -0.5),
              ),
            ),
          ],
        ),
        actions: [
          if (s != null && compactHeader)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Semantics(
                label: s.connected ? l.relayOnline : l.relayOffline,
                child: Icon(
                  s.connected
                      ? Icons.check_circle_outline
                      : Icons.cloud_off_outlined,
                  color: s.connected ? p.success : p.warning,
                ),
              ),
            ),
          if (s != null && !compactHeader)
            Tooltip(
              message: s.connected ? l.connected : l.offline,
              child: StatusTag(
                label: s.connected ? l.onlineTag : l.offlineTag,
                icon:
                    s.connected
                        ? Icons.check_circle_outline
                        : Icons.cloud_off_outlined,
                tone: s.connected ? TagTone.success : TagTone.warning,
              ),
            ),
          IconButton(
            tooltip: l.refresh,
            onPressed: c.busy ? null : c.refresh,
            icon: const Icon(Icons.refresh_rounded),
          ),
          const SizedBox(width: 4),
        ],
      ),
      body:
          s == null
              ? PageScroll(
                children: [
                  PageHeading(
                    eyebrow: l.controlCenter,
                    title: l.pendingTitle,
                    subtitle: l.pendingSubtitle,
                  ),
                  EmptyPanel(
                    title: c.error == null ? l.starting : l.protection,
                    description:
                        c.error == null ? l.starting : l.securityUnavailable,
                    icon: Icons.shield_outlined,
                  ),
                ],
              )
              : Column(
                children: [
                  if (c.busy) const LinearProgressIndicator(minHeight: 2),
                  Expanded(
                    child: switch (tab) {
                      0 => PendingPage(controller: c, notice: pageNotice(l, c)),
                      1 => DevicesPage(controller: c, notice: pageNotice(l, c)),
                      2 => ActivityPage(
                        items: s.activity,
                        notice: pageNotice(l, c),
                      ),
                      _ => SettingsPage(
                        controller: c,
                        notice: pageNotice(l, c),
                      ),
                    },
                  ),
                ],
              ),
      bottomNavigationBar: DecoratedBox(
        decoration: BoxDecoration(
          border: Border(top: BorderSide(color: p.border)),
        ),
        child: NavigationBar(
          height: 76,
          selectedIndex: tab,
          onDestinationSelected: (value) => setState(() => tab = value),
          destinations: [
            NavigationDestination(
              icon: Badge(
                isLabelVisible: (s?.pending.length ?? 0) > 0,
                label: Text('${s?.pending.length ?? 0}'),
                child: const Icon(Icons.inbox_outlined),
              ),
              label: l.pending,
            ),
            NavigationDestination(
              icon: const Icon(Icons.devices_outlined),
              label: l.devices,
            ),
            NavigationDestination(
              icon: const Icon(Icons.history_rounded),
              label: l.activity,
            ),
            NavigationDestination(
              icon: const Icon(Icons.tune_rounded),
              label: l.settings,
            ),
          ],
        ),
      ),
    );
  }
}

class QueueSummary extends StatelessWidget {
  const QueueSummary({super.key, required this.snapshot, this.onPair});
  final Snapshot snapshot;
  final VoidCallback? onPair;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), t = Theme.of(context).textTheme;
    final count = snapshot.pending.length;
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: AppPalette.hero,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l.queueLabel,
            style: t.labelMedium?.copyWith(
              color: AppPalette.heroMuted,
              letterSpacing: 1.2,
            ),
          ),
          const SizedBox(height: 20),
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      count == 0
                          ? l.allCaughtUp
                          : count.toString().padLeft(2, '0'),
                      style: t.headlineLarge?.copyWith(
                        color: Colors.white,
                        fontSize: count == 0 ? 26 : 48,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      count == 0 ? l.allCaughtUpHint : l.requestsWaiting,
                      style: t.bodyMedium?.copyWith(
                        color: AppPalette.heroMuted,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 16),
              ExcludeSemantics(
                child: Icon(
                  count == 0
                      ? Icons.verified_user_outlined
                      : Icons.mark_email_unread_outlined,
                  size: 52,
                  color: AppPalette.heroAccent,
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          Divider(color: Colors.white.withValues(alpha: 0.16)),
          const SizedBox(height: 16),
          Wrap(
            spacing: 20,
            runSpacing: 12,
            children: [
              _HeroMeta(
                icon: Icons.devices_outlined,
                text: l.pairedDevices(snapshot.devices.length),
              ),
              if (count > 0)
                _HeroMeta(
                  icon: Icons.fingerprint_rounded,
                  text: l.sensitiveRequests(
                    snapshot.pending.where((r) => r.tier == 'T2').length,
                  ),
                ),
            ],
          ),
          if (snapshot.devices.isEmpty) ...[
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: onPair,
                icon: const Icon(Icons.qr_code_scanner_rounded),
                label: Text(l.addDevice),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _HeroMeta extends StatelessWidget {
  const _HeroMeta({required this.icon, required this.text});
  final IconData icon;
  final String text;
  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      ExcludeSemantics(
        child: Icon(icon, size: 16, color: AppPalette.heroMuted),
      ),
      const SizedBox(width: 8),
      Flexible(
        child: Text(
          text,
          style: Theme.of(
            context,
          ).textTheme.bodySmall?.copyWith(color: AppPalette.heroMuted),
        ),
      ),
    ],
  );
}

class PendingPage extends StatelessWidget {
  const PendingPage({super.key, required this.controller, this.notice});
  final MobileController controller;
  final Widget? notice;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), s = controller.state!;
    return PageScroll(
      children: [
        if (notice != null) notice!,
        PageHeading(
          eyebrow: l.controlCenter,
          title: l.pendingTitle,
          subtitle: l.pendingSubtitle,
        ),
        QueueSummary(
          snapshot: s,
          onPair: controller.busy ? null : () => openPair(context, controller),
        ),
        SectionHeading(
          title: l.needsReview,
          trailing: StatusTag(label: '${s.pending.length}'),
        ),
        if (s.pending.isEmpty)
          EmptyPanel(
            title: l.noPending,
            description:
                s.devices.isEmpty ? l.firstDeviceHint : l.emptyPendingHint,
            icon: Icons.check_rounded,
          ),
        ...s.pending.map(
          (r) => ApprovalCard(
            request: r,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute<void>(
                    builder:
                        (_) => ApprovalDetail(
                          controller: controller,
                          requestId: r.id,
                        ),
                  ),
                ),
          ),
        ),
      ],
    );
  }
}

class ApprovalCard extends StatelessWidget {
  const ApprovalCard({super.key, required this.request, required this.onTap});
  final ApprovalView request;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), r = request;
    final p = AppPalette.of(context), t = Theme.of(context).textTheme;
    return SurfaceCard(
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              IconTile(
                icon: r.strong ? Icons.fingerprint_rounded : Icons.key_outlined,
                danger: r.tier == 'T2',
                size: 40,
              ),
              const SizedBox(width: 12),
              Expanded(child: Text(r.credentialName, style: t.labelLarge)),
              const SizedBox(width: 8),
              ExcludeSemantics(
                child: Icon(
                  Icons.arrow_forward_rounded,
                  color: p.muted,
                  size: 20,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(r.summary, style: t.titleLarge),
          const SizedBox(height: 8),
          Text(
            '${r.requesterLabel} · ${r.runtime}',
            style: t.bodyMedium?.copyWith(color: p.muted),
          ),
          const SizedBox(height: 14),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: p.background,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Text(
              '${r.method} ${r.host}${r.path}',
              style: t.bodySmall?.copyWith(
                fontFamily: 'monospace',
                color: p.ink,
              ),
            ),
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              StatusTag(
                label: '${r.tier} · ${riskLabel(l, r.tier)}',
                tone: r.tier == 'T2' ? TagTone.danger : TagTone.neutral,
              ),
              StatusTag(
                label: r.strong ? l.biometricTag : l.quickTag,
                icon:
                    r.strong
                        ? Icons.fingerprint_rounded
                        : Icons.touch_app_outlined,
                tone: TagTone.accent,
              ),
              if (r.escalated)
                StatusTag(
                  label: l.escalatedTag,
                  icon: Icons.notifications_active_outlined,
                  tone: TagTone.warning,
                )
              else
                StatusTag(
                  label: r.banner ? l.bannerTag : l.silentTag,
                  icon:
                      r.banner
                          ? Icons.notifications_outlined
                          : Icons.notifications_none_rounded,
                ),
            ],
          ),
          const SizedBox(height: 14),
          Text('${l.expiry} · ${date(r.expiresAt)}', style: t.bodySmall),
        ],
      ),
    );
  }
}

class ApprovalDetail extends StatefulWidget {
  const ApprovalDetail({
    super.key,
    required this.controller,
    required this.requestId,
  });
  final MobileController controller;
  final String requestId;
  @override
  State<ApprovalDetail> createState() => _ApprovalDetailState();
}

class _ApprovalDetailState extends State<ApprovalDetail> {
  String? selected;
  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: widget.controller,
    builder: (context, _) {
      final l = AppLocalizations.of(context), c = widget.controller;
      final matches = (c.state?.pending ?? <ApprovalView>[]).where(
        (r) => r.id == widget.requestId,
      );
      if (matches.isEmpty)
        return Scaffold(
          appBar: AppBar(title: Text(l.pending)),
          body: PageScroll(
            children: [
              EmptyPanel(
                title: l.noLongerWaiting,
                description: l.emptyPendingHint,
                icon: Icons.check_rounded,
              ),
            ],
          ),
        );
      final r = matches.first;
      final scope =
          r.scopeOptions.contains(selected)
              ? selected
              : r.scopeOptions.contains(r.requestedScope)
              ? r.requestedScope
              : r.scopeOptions.firstOrNull;
      final strong = r.strong || (scope?.startsWith('standing:') ?? false);
      final p = AppPalette.of(context), t = Theme.of(context).textTheme;
      return Scaffold(
        appBar: AppBar(title: Text(l.requestDetails)),
        body: PageScroll(
          children: [
            if (pageNotice(l, c) case final notice?) notice,
            if (c.busy) const LinearProgressIndicator(minHeight: 2),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                StatusTag(
                  label: '${r.tier} · ${riskLabel(l, r.tier)}',
                  tone: r.tier == 'T2' ? TagTone.danger : TagTone.accent,
                ),
                StatusTag(
                  label: r.strong ? l.biometricTag : l.quickTag,
                  icon:
                      r.strong
                          ? Icons.fingerprint_rounded
                          : Icons.touch_app_outlined,
                ),
                if (r.escalated)
                  StatusTag(label: l.escalatedTag, tone: TagTone.warning),
              ],
            ),
            const SizedBox(height: 20),
            Text(r.summary, style: t.headlineLarge),
            const SizedBox(height: 12),
            SurfaceCard(
              child: SelectableText(
                '${r.method} ${r.host}${r.path}',
                style: t.titleMedium?.copyWith(fontFamily: 'monospace'),
              ),
            ),
            if (r.tier == 'T2')
              Notice(text: l.scopeSensitiveHint, danger: true),
            if (r.softwareWarning)
              Notice(text: l.softwareWarning, danger: true),
            if (r.clockSkew) Notice(text: l.clockSkew),
            SectionHeading(title: l.requester),
            SurfaceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Field(title: l.label, text: r.requesterLabel),
                  Field(
                    title: l.protection,
                    text: '${r.os} · ${protectionLabel(l, r.protection)}',
                  ),
                  Field(
                    title: l.runtimeDetails,
                    text:
                        '${r.runtime}\n${r.cwd}\n${r.user} · PID ${r.agentPid}',
                  ),
                ],
              ),
            ),
            SectionHeading(title: l.credential),
            SurfaceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Field(
                    title: l.credential,
                    text:
                        '${r.credentialName}\n${r.credentialRef} · ${r.credentialKind}',
                  ),
                  if (r.proxyOnly)
                    Notice(text: l.proxyOnly, tone: TagTone.accent),
                ],
              ),
            ),
            SectionHeading(title: l.operation),
            SurfaceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Field(
                    title: l.queryDetails,
                    text: r.queryKeys.isEmpty ? '—' : r.queryKeys.join(', '),
                  ),
                  Field(title: l.bodyBytes, text: '${r.bodyBytes}'),
                  Field(title: l.purpose, text: r.purpose),
                  const Divider(),
                  Field(title: l.merged, text: '${r.mergedCount}'),
                  Field(title: l.requestedAt, text: date(r.createdAt)),
                  Field(title: l.expiry, text: date(r.expiresAt)),
                ],
              ),
            ),
            SectionHeading(title: l.scope),
            SurfaceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (scope == null)
                    Notice(text: l.actionFailed, danger: true)
                  else
                    DropdownButtonFormField<String>(
                      isExpanded: true,
                      key: ValueKey('scope-${r.id}'),
                      initialValue: scope,
                      decoration: InputDecoration(labelText: l.scope),
                      items:
                          r.scopeOptions
                              .map(
                                (v) => DropdownMenuItem(
                                  value: v,
                                  child: Text(
                                    scopeLabel(l, v),
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                              )
                              .toList(),
                      onChanged:
                          c.busy
                              ? null
                              : (value) => setState(() => selected = value),
                    ),
                  const SizedBox(height: 16),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ExcludeSemantics(
                        child: Icon(
                          strong
                              ? Icons.fingerprint_rounded
                              : Icons.lock_open_rounded,
                          size: 22,
                          color: p.primary,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(l.signingRequirement, style: t.labelMedium),
                            const SizedBox(height: 4),
                            Text(
                              strong ? l.strong : l.quick,
                              style: t.bodyMedium,
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 24),
                  LayoutBuilder(
                    builder: (context, constraints) {
                      final deny = OutlinedButton(
                        onPressed:
                            c.busy || scope == null
                                ? null
                                : () => c.decide(r, scope, false),
                        child: Text(l.deny),
                      );
                      final allow = FilledButton.icon(
                        key: const ValueKey('allow-approval'),
                        onPressed:
                            c.busy || scope == null
                                ? null
                                : () => c.decide(r, scope, true),
                        icon: Icon(
                          strong
                              ? Icons.fingerprint_rounded
                              : Icons.check_rounded,
                        ),
                        label: Text(strong ? l.allowBiometric : l.allow),
                      );
                      if (constraints.maxWidth < 360 ||
                          MediaQuery.textScalerOf(context).scale(16) > 20) {
                        return Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [allow, const SizedBox(height: 12), deny],
                        );
                      }
                      return Row(
                        children: [
                          Expanded(child: deny),
                          const SizedBox(width: 12),
                          Expanded(flex: 2, child: allow),
                        ],
                      );
                    },
                  ),
                ],
              ),
            ),
          ],
        ),
      );
    },
  );
}

class DevicesPage extends StatelessWidget {
  const DevicesPage({super.key, required this.controller, this.notice});
  final MobileController controller;
  final Widget? notice;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), items = controller.state!.devices;
    final p = AppPalette.of(context), t = Theme.of(context).textTheme;
    return PageScroll(
      children: [
        if (notice != null) notice!,
        PageHeading(
          eyebrow: l.controlCenter,
          title: l.devicesTitle,
          subtitle: l.devicesSubtitle,
        ),
        if (items.isEmpty)
          EmptyPanel(
            title: l.noDevices,
            description: l.firstDeviceHint,
            icon: Icons.devices_outlined,
            action: FilledButton.icon(
              onPressed: () => openPair(context, controller),
              icon: const Icon(Icons.qr_code_scanner_rounded),
              label: Text(l.addDevice),
            ),
          )
        else ...[
          FilledButton.icon(
            onPressed:
                controller.busy ? null : () => openPair(context, controller),
            icon: const Icon(Icons.add_rounded),
            label: Text(l.addDevice),
          ),
          SectionHeading(title: l.pairedDevices(items.length)),
          ...items.map(
            (d) => SurfaceCard(
              onTap: () {
                controller
                    .directive(d, 'query_status')
                    .then((_) => controller.directive(d, 'query_grants'))
                    .then((_) => controller.directive(d, 'query_audit'));
                Navigator.push(
                  context,
                  MaterialPageRoute<void>(
                    builder:
                        (_) => DeviceDetail(
                          controller: controller,
                          deviceId: d.id,
                        ),
                  ),
                );
              },
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const IconTile(icon: Icons.computer_outlined),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(d.label, style: t.titleMedium),
                            const SizedBox(height: 4),
                            Text(d.os, style: t.bodySmall),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      ExcludeSemantics(
                        child: Icon(
                          Icons.chevron_right_rounded,
                          color: p.muted,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      StatusTag(
                        label: d.online ? l.onlineTag : l.offlineTag,
                        icon:
                            d.online
                                ? Icons.check_circle_outline
                                : Icons.cloud_off_outlined,
                        tone: d.online ? TagTone.success : TagTone.warning,
                      ),
                      StatusTag(
                        label: protectionLabel(l, d.protection),
                        tone:
                            ['software', 'software_key'].contains(d.protection)
                                ? TagTone.danger
                                : TagTone.neutral,
                      ),
                      if (d.unattended)
                        StatusTag(label: l.unattended, tone: TagTone.danger),
                    ],
                  ),
                  const SizedBox(height: 16),
                  const Divider(),
                  const SizedBox(height: 16),
                  Text(modeLabel(l, d.mode), style: t.bodyLarge),
                  const SizedBox(height: 4),
                  Text(l.grantsCount(d.grants.length), style: t.bodySmall),
                ],
              ),
            ),
          ),
        ],
        const SizedBox(height: 12),
        PrivacyPanel(),
      ],
    );
  }
}

class PrivacyPanel extends StatelessWidget {
  const PrivacyPanel({super.key});
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context),
        p = AppPalette.of(context),
        t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ExcludeSemantics(
            child: Icon(Icons.shield_outlined, size: 20, color: p.muted),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  l.privacyTitle,
                  style: t.labelLarge?.copyWith(color: p.muted),
                ),
                const SizedBox(height: 6),
                Text(l.privacyHint, style: t.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class DeviceDetail extends StatelessWidget {
  const DeviceDetail({
    super.key,
    required this.controller,
    required this.deviceId,
  });
  final MobileController controller;
  final String deviceId;
  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: controller,
    builder: (context, _) {
      final l = AppLocalizations.of(context),
          p = AppPalette.of(context),
          t = Theme.of(context).textTheme;
      final found = (controller.state?.devices ?? <DeviceView>[]).where(
        (d) => d.id == deviceId,
      );
      if (found.isEmpty)
        return Scaffold(
          appBar: AppBar(title: Text(l.devices)),
          body: Center(child: Text(l.noDevices)),
        );
      final d = found.first;
      return Scaffold(
        appBar: AppBar(title: Text(d.label)),
        body: PageScroll(
          children: [
            if (pageNotice(l, controller) case final notice?) notice,
            if (controller.busy) const LinearProgressIndicator(minHeight: 2),
            SurfaceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const IconTile(icon: Icons.computer_outlined),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(d.label, style: t.titleLarge),
                            Text(
                              '${d.os} · ${protectionLabel(l, d.protection)}',
                              style: t.bodySmall?.copyWith(
                                color:
                                    [
                                          'software',
                                          'software_key',
                                        ].contains(d.protection)
                                        ? p.danger
                                        : p.muted,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  StatusTag(
                    label: d.online ? l.onlineTag : l.offlineTag,
                    tone: d.online ? TagTone.success : TagTone.warning,
                    icon:
                        d.online
                            ? Icons.check_circle_outline
                            : Icons.cloud_off_outlined,
                  ),
                  const SizedBox(height: 10),
                  Text(l.unlockTimeout(d.unlockTtlS), style: t.bodySmall),
                ],
              ),
            ),
            // Tightening controls remain in the first screen, before grants and settings.
            OutlinedButton.icon(
              onPressed:
                  controller.busy
                      ? null
                      : () => controller.directive(d, 'lock'),
              icon: const Icon(Icons.lock_outline_rounded),
              label: Text(l.lockVault),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: p.danger,
                foregroundColor: p.dark ? AppPalette.hero : Colors.white,
              ),
              onPressed:
                  controller.busy
                      ? null
                      : () => controller.directive(d, 'revoke_all_grants'),
              icon: const Icon(Icons.block_rounded),
              label: Text(l.revokeAll),
            ),
            SectionHeading(title: l.accessControls),
            SurfaceCard(
              child: DropdownButtonFormField<String>(
                isExpanded: true,
                initialValue:
                    ['per_use', 'remember:1h', 'remember:0h'].contains(d.mode)
                        ? d.mode
                        : null,
                decoration: InputDecoration(labelText: l.mode),
                items: [
                  DropdownMenuItem(
                    value: 'per_use',
                    child: Text(l.modePerUse, overflow: TextOverflow.ellipsis),
                  ),
                  DropdownMenuItem(
                    value: 'remember:1h',
                    child: Text(
                      l.modeRemember,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  DropdownMenuItem(
                    value: 'remember:0h',
                    child: Text(
                      l.modeStanding,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
                onChanged:
                    controller.busy
                        ? null
                        : (value) {
                          if (value != null)
                            controller.directive(d, 'set_mode', value: value);
                        },
              ),
            ),
            SectionHeading(
              title: l.grants,
              trailing: StatusTag(label: '${d.grants.length}'),
            ),
            if (d.grants.isEmpty)
              SurfaceCard(
                child: Text(
                  l.noGrants,
                  style: t.bodyMedium?.copyWith(color: p.muted),
                ),
              ),
            ...d.grants.map(
              (g) => SurfaceCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const IconTile(
                          icon: Icons.confirmation_number_outlined,
                          size: 40,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            g.credential.isEmpty ? g.level : g.credential,
                            style: t.titleMedium,
                          ),
                        ),
                        IconButton(
                          tooltip: l.revokeOne,
                          icon: const Icon(Icons.remove_circle_outline_rounded),
                          onPressed:
                              controller.busy
                                  ? null
                                  : () => controller.directive(
                                    d,
                                    'revoke_grant',
                                    value: g.id,
                                  ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        StatusTag(label: g.maxTier),
                        StatusTag(
                          label:
                              '${l.remainingBudget}: ${g.remainingCalls ?? l.unknown}',
                          tone: TagTone.accent,
                        ),
                        if (g.pendingDelivery)
                          StatusTag(label: l.queued, tone: TagTone.warning),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Text(
                      '${l.expiry}: ${g.expiresAt == null ? l.never : date(g.expiresAt!)}',
                      style: t.bodySmall,
                    ),
                    Text(
                      '${l.source}: ${sourceLabel(l, g.origin)}',
                      style: t.bodySmall,
                    ),
                  ],
                ),
              ),
            ),
            OutlinedButton.icon(
              onPressed:
                  controller.busy
                      ? null
                      : () => grantDialog(context, controller, d, false),
              icon: const Icon(Icons.add_rounded),
              label: Text(l.issueTicket),
            ),
            const SizedBox(height: 24),
            SurfaceCard(
              padding: EdgeInsets.zero,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SwitchListTile(
                    activeTrackColor: p.danger,
                    title: Text(
                      l.unattended,
                      style: t.titleMedium?.copyWith(color: p.danger),
                    ),
                    subtitle: Text(l.unattendedWarning),
                    value: d.unattended,
                    onChanged:
                        controller.busy
                            ? null
                            : (value) {
                              if (value) {
                                grantDialog(context, controller, d, true);
                              } else {
                                controller.directive(d, 'revoke_all_grants');
                              }
                            },
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                    child: StatusTag(
                      label: l.unattendedCount(d.unattendedCount),
                      tone: TagTone.danger,
                    ),
                  ),
                ],
              ),
            ),
            SectionHeading(title: l.recentActivity),
            if (d.recentActivity.isEmpty)
              Text(l.noActivity, style: t.bodyMedium?.copyWith(color: p.muted)),
            ...d.recentActivity.map(
              (a) => ActivityCard(item: a, showSource: false),
            ),
            const SizedBox(height: 16),
            TextButton(
              onPressed:
                  controller.busy
                      ? null
                      : () async {
                        final label = await typedConfirmation(
                          context,
                          d.label,
                          l.revokeDeviceWarning,
                        );
                        if (label != null)
                          await controller.directive(
                            d,
                            'revoke_device',
                            value: d.id,
                            confirmation: label,
                          );
                      },
              style: TextButton.styleFrom(foregroundColor: p.danger),
              child: Text(l.revokeDevice),
            ),
          ],
        ),
      );
    },
  );
}

Future<String?> typedConfirmation(
  BuildContext context,
  String label,
  String explanation,
) async {
  final l = AppLocalizations.of(context);
  String input = '';
  return showDialog<String>(
    context: context,
    builder:
        (dialog) => StatefulBuilder(
          builder:
              (dialog, update) => AlertDialog(
                title: Text(l.enterDeviceLabel),
                content: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(explanation),
                      const SizedBox(height: 16),
                      Text(
                        label,
                        style: Theme.of(dialog).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 16),
                      TextField(
                        decoration: InputDecoration(labelText: l.label),
                        autocorrect: false,
                        onChanged: (value) => update(() => input = value),
                      ),
                    ],
                  ),
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(dialog),
                    child: Text(l.cancel),
                  ),
                  FilledButton(
                    onPressed:
                        input == label
                            ? () => Navigator.pop(dialog, input)
                            : null,
                    child: Text(l.confirm),
                  ),
                ],
              ),
        ),
  );
}

Future<void> grantDialog(
  BuildContext context,
  MobileController c,
  DeviceView d,
  bool sensitive,
) async {
  final l = AppLocalizations.of(context);
  String credential = '', scope = 'device';
  bool standing = false;
  final accepted = await showDialog<bool>(
    context: context,
    builder:
        (dialog) => StatefulBuilder(
          builder:
              (dialog, update) => AlertDialog(
                title: Text(sensitive ? l.unattended : l.issueTicket),
                content: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Notice(text: l.strong),
                      if (sensitive)
                        Notice(text: l.unattendedWarning, danger: true),
                      if (!sensitive)
                        DropdownButton<String>(
                          value: scope,
                          isExpanded: true,
                          items: [
                            DropdownMenuItem(
                              value: 'credential',
                              child: Text(l.credentialScope),
                            ),
                            DropdownMenuItem(
                              value: 'device',
                              child: Text(l.standingDevice),
                            ),
                            DropdownMenuItem(
                              value: 'global',
                              child: Text(l.globalScope),
                            ),
                          ],
                          onChanged: (v) => update(() => scope = v!),
                        ),
                      if (scope == 'credential')
                        TextField(
                          decoration: InputDecoration(labelText: l.credential),
                          onChanged: (v) => credential = v,
                        ),
                      if (scope == 'global')
                        Notice(text: l.globalScopeWarning, danger: true),
                      SwitchListTile(
                        title: Text(l.standing),
                        value: standing,
                        onChanged: (v) => update(() => standing = v),
                      ),
                    ],
                  ),
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(dialog, false),
                    child: Text(l.cancel),
                  ),
                  FilledButton(
                    onPressed: () => Navigator.pop(dialog, true),
                    child: Text(l.continueAction),
                  ),
                ],
              ),
        ),
  );
  if (accepted != true || !context.mounted) return;
  String confirmation = '';
  if (sensitive) {
    confirmation =
        await typedConfirmation(context, d.label, l.unattendedWarning) ?? '';
    if (confirmation.isEmpty || !context.mounted) return;
    if (standing) {
      final again = await typedConfirmation(
        context,
        d.label,
        l.permanentWarning,
      );
      if (again == null) return;
    }
  }
  await c.grant(
    GrantInput(
      deviceId: d.id,
      credential: credential,
      scope: scope,
      hours: sensitive ? 168 : 1,
      standing: standing,
      sensitive: sensitive,
      confirmation: confirmation,
      calls: 0,
    ),
  );
}

class ActivityPage extends StatelessWidget {
  const ActivityPage({super.key, required this.items, this.notice});
  final List<ActivityView> items;
  final Widget? notice;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final children = <Widget>[
      if (notice != null) notice!,
      PageHeading(
        eyebrow: l.controlCenter,
        title: l.activityTitle,
        subtitle: l.activitySubtitle,
      ),
    ];
    if (items.isEmpty)
      children.add(
        EmptyPanel(
          title: l.noActivity,
          description: l.emptyActivityHint,
          icon: Icons.history_rounded,
        ),
      );
    String previous = '';
    for (final item in items) {
      final day = date(item.at).substring(0, 10);
      if (day != previous) {
        children.add(SectionHeading(title: day));
        previous = day;
      }
      children.add(ActivityCard(item: item));
    }
    return PageScroll(children: children);
  }
}

class ActivityCard extends StatelessWidget {
  const ActivityCard({super.key, required this.item, this.showSource = true});
  final ActivityView item;
  final bool showSource;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), t = Theme.of(context).textTheme;
    return SurfaceCard(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          IconTile(
            icon: switch (item.kind) {
              'grant' => Icons.confirmation_number_outlined,
              'pair' => Icons.devices_outlined,
              'decision' => Icons.done_rounded,
              _ => Icons.history_rounded,
            },
            size: 40,
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(activityLabel(l, item), style: t.titleMedium),
                const SizedBox(height: 4),
                Text(
                  '${showSource ? '${l.signatureSource} · ' : ''}${date(item.at)}',
                  style: t.bodySmall,
                ),
                if (item.kind.startsWith('executor_'))
                  Text(item.summary, style: t.bodySmall),
                const SizedBox(height: 12),
                StatusTag(
                  label: item.delivered ? l.delivered : l.queued,
                  icon:
                      item.delivered
                          ? Icons.check_circle_outline
                          : Icons.schedule_rounded,
                  tone: item.delivered ? TagTone.success : TagTone.warning,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key, required this.controller, this.notice});
  final MobileController controller;
  final Widget? notice;
  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), s = controller.state!.settings;
    final p = AppPalette.of(context);
    return PageScroll(
      children: [
        if (notice != null) notice!,
        PageHeading(
          eyebrow: l.controlCenter,
          title: l.settingsTitle,
          subtitle: l.settingsSubtitle,
        ),
        SectionHeading(title: l.signInAccount),
        SurfaceCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  const IconTile(icon: Icons.person_outline_rounded, size: 40),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          controller.account?.email ?? '',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        Text(
                          controller.account?.provider == 'apple'
                              ? 'Apple'
                              : 'Google',
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              OutlinedButton(
                onPressed:
                    controller.busy
                        ? null
                        : () async {
                          final approved = await showDialog<bool>(
                            context: context,
                            builder:
                                (dialog) => AlertDialog(
                                  title: Text(l.signOut),
                                  content: Text(l.signOutHint),
                                  actions: [
                                    TextButton(
                                      onPressed:
                                          () => Navigator.pop(dialog, false),
                                      child: Text(l.cancel),
                                    ),
                                    FilledButton(
                                      onPressed:
                                          () => Navigator.pop(dialog, true),
                                      child: Text(l.signOut),
                                    ),
                                  ],
                                ),
                          );
                          if (approved == true) await controller.signOut();
                        },
                child: Text(l.signOut),
              ),
            ],
          ),
        ),
        SectionHeading(title: l.notificationsSection),
        SurfaceCard(
          padding: EdgeInsets.zero,
          child: Column(
            children: [
              SwitchListTile(
                title: Text(l.notifications),
                subtitle: Text(l.notificationHint),
                value: s.notifications,
                onChanged:
                    controller.busy
                        ? null
                        : (v) => controller.preferences(notifications: v),
              ),
              Divider(indent: 16, endIndent: 16, color: p.border),
              SwitchListTile(
                title: Text(l.away),
                subtitle: Text(l.awayHint),
                value: s.awayFromComputer,
                onChanged:
                    controller.busy
                        ? null
                        : (v) => controller.preferences(away: v),
              ),
            ],
          ),
        ),
        SectionHeading(title: l.displaySection),
        SurfaceCard(
          child: DropdownButtonFormField<String>(
            isExpanded: true,
            initialValue: s.locale,
            decoration: InputDecoration(labelText: l.language),
            items: const [
              DropdownMenuItem(value: 'en', child: Text('English')),
              DropdownMenuItem(value: 'zh', child: Text('中文')),
            ],
            onChanged:
                controller.busy
                    ? null
                    : (value) {
                      if (value != null) controller.preferences(locale: value);
                    },
          ),
        ),
        SectionHeading(title: l.diagnosticsSection),
        SurfaceCard(
          padding: EdgeInsets.zero,
          child: ListTile(
            leading: const IconTile(icon: Icons.description_outlined, size: 40),
            title: Text(l.exportDiagnostics),
            subtitle: Text(l.diagnosticsHint),
            trailing: const ExcludeSemantics(child: Icon(Icons.copy_outlined)),
            onTap: () async {
              final diagnostic = await controller.diagnostics();
              await Clipboard.setData(ClipboardData(text: diagnostic));
              if (context.mounted)
                ScaffoldMessenger.of(
                  context,
                ).showSnackBar(SnackBar(content: Text(l.diagnosticsCopied)));
            },
          ),
        ),
        const PrivacyPanel(),
      ],
    );
  }
}

class PairPage extends StatefulWidget {
  const PairPage({super.key, required this.controller});
  final MobileController controller;
  @override
  State<PairPage> createState() => _PairPageState();
}

class _PairPageState extends State<PairPage> {
  String uri = '';
  bool scanning = false, loading = false, checked = false, exclude = false;
  PairingView? pairing;
  bool failed = false;
  Future<void> begin(String value) async {
    if (loading) return;
    setState(() {
      loading = true;
      scanning = false;
      failed = false;
    });
    try {
      final p = await widget.controller.beginPair(value);
      if (mounted) setState(() => pairing = p);
    } catch (_) {
      if (mounted) setState(() => failed = true);
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), p = pairing;
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: Text(l.addDevice)),
      body:
          scanning
              ? SafeArea(
                child: Column(
                  children: [
                    Expanded(
                      child: MobileScanner(
                        onDetect: (capture) {
                          for (final code in capture.barcodes) {
                            if (code.rawValue != null) {
                              begin(code.rawValue!);
                              break;
                            }
                          }
                        },
                      ),
                    ),
                    Padding(
                      padding: const EdgeInsets.all(20),
                      child: SizedBox(
                        width: double.infinity,
                        child: OutlinedButton(
                          onPressed: () => setState(() => scanning = false),
                          child: Text(l.cancel),
                        ),
                      ),
                    ),
                  ],
                ),
              )
              : PageScroll(
                children: [
                  if (loading || widget.controller.busy)
                    const LinearProgressIndicator(),
                  if (failed || widget.controller.error != null)
                    Notice(text: l.actionFailed, danger: true),
                  if (p == null) ...[
                    PageHeading(
                      eyebrow: l.controlCenter,
                      title: l.pairingCodeTitle,
                      subtitle: l.pairingHint,
                    ),
                    SurfaceCard(
                      child: Column(
                        children: [
                          const TrustIllustration(
                            icon: Icons.qr_code_2_rounded,
                          ),
                          const SizedBox(height: 24),
                          SizedBox(
                            width: double.infinity,
                            child: FilledButton.icon(
                              onPressed:
                                  loading
                                      ? null
                                      : () => setState(() => scanning = true),
                              icon: const Icon(Icons.qr_code_scanner_rounded),
                              label: Text(l.scan),
                            ),
                          ),
                        ],
                      ),
                    ),
                    SectionHeading(title: l.pasteSection),
                    SurfaceCard(
                      child: Column(
                        children: [
                          TextField(
                            decoration: InputDecoration(labelText: l.pasteUri),
                            autocorrect: false,
                            keyboardType: TextInputType.url,
                            onChanged: (v) => uri = v,
                          ),
                          const SizedBox(height: 16),
                          SizedBox(
                            width: double.infinity,
                            child: OutlinedButton(
                              onPressed: loading ? null : () => begin(uri),
                              child: Text(l.pairDevice),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const PrivacyPanel(),
                  ] else ...[
                    PageHeading(
                      eyebrow: l.pairingCodeTitle,
                      title: p.peerLabel,
                      subtitle: l.compareSas,
                    ),
                    SurfaceCard(
                      child: Column(
                        children: [
                          const IconTile(icon: Icons.phonelink_lock_rounded),
                          const SizedBox(height: 24),
                          Text(
                            p.sas,
                            key: const ValueKey('pairing-code'),
                            style: t.headlineLarge?.copyWith(
                              fontFamily: 'monospace',
                              fontSize: 38,
                              letterSpacing: 4,
                            ),
                          ),
                          const SizedBox(height: 16),
                          Notice(text: l.pairingExpired),
                        ],
                      ),
                    ),
                    SurfaceCard(
                      padding: EdgeInsets.zero,
                      child: CheckboxListTile(
                        title: Text(l.sasChecked),
                        value: checked,
                        onChanged: (v) => setState(() => checked = v!),
                      ),
                    ),
                    if (p.globalGrants > 0) ...[
                      Notice(text: l.globalWarning, danger: true),
                      SurfaceCard(
                        padding: EdgeInsets.zero,
                        child: CheckboxListTile(
                          title: Text(l.excludeGlobal),
                          value: exclude,
                          onChanged: (v) => setState(() => exclude = v!),
                        ),
                      ),
                    ],
                    Notice(text: l.strong, tone: TagTone.accent),
                    FilledButton(
                      onPressed:
                          !checked || widget.controller.busy
                              ? null
                              : () async {
                                await widget.controller.confirmPair(p, exclude);
                                if (context.mounted &&
                                    widget.controller.error == null)
                                  Navigator.pop(context);
                              },
                      child: Text(l.confirm),
                    ),
                  ],
                ],
              ),
    );
  }
}

class Field extends StatelessWidget {
  const Field({super.key, required this.title, required this.text});
  final String title, text;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 10),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: Theme.of(context).textTheme.labelMedium),
        const SizedBox(height: 6),
        SelectableText(text, style: Theme.of(context).textTheme.bodyLarge),
      ],
    ),
  );
}

Widget? pageNotice(AppLocalizations l, MobileController controller) {
  if (controller.error != null)
    return Notice(text: l.actionFailed, danger: true);
  if (controller.state?.connected == false) return Notice(text: l.offline);
  return null;
}

class Notice extends StatelessWidget {
  const Notice({
    super.key,
    required this.text,
    this.danger = false,
    this.tone = TagTone.warning,
  });
  final String text;
  final bool danger;
  final TagTone tone;
  @override
  Widget build(BuildContext context) {
    final p = AppPalette.of(context);
    final resolved = danger ? TagTone.danger : tone;
    final (foreground, background, icon) = switch (resolved) {
      TagTone.danger => (p.danger, p.dangerSoft, Icons.warning_amber_rounded),
      TagTone.accent => (p.primary, p.soft, Icons.shield_outlined),
      _ => (p.warning, p.warningSoft, Icons.info_outline_rounded),
    };
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.symmetric(vertical: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ExcludeSemantics(child: Icon(icon, size: 20, color: foreground)),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: foreground),
            ),
          ),
        ],
      ),
    );
  }
}
