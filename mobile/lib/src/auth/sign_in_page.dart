import 'package:flutter/material.dart';
import '../../l10n/app_localizations.dart';
import '../controller.dart';
import '../design.dart';

class SignInPage extends StatelessWidget {
  const SignInPage({super.key, required this.controller});
  final MobileController controller;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context), p = AppPalette.of(context);
    final t = Theme.of(context).textTheme;
    final disabled = controller.busy || controller.restoring;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(24, 24, 24, 24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 42,
                        height: 42,
                        decoration: BoxDecoration(
                          color: p.ink,
                          borderRadius: BorderRadius.circular(13),
                        ),
                        child: Icon(
                          Icons.key_rounded,
                          color: p.surface,
                          size: 25,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(child: Text('KeyValet', style: t.titleLarge)),
                    ],
                  ),
                  const SizedBox(height: 32),
                  Container(
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: AppPalette.hero,
                      borderRadius: BorderRadius.circular(24),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const ExcludeSemantics(
                          child: Icon(
                            Icons.verified_user_outlined,
                            color: AppPalette.heroAccent,
                            size: 34,
                          ),
                        ),
                        const SizedBox(height: 24),
                        Semantics(
                          header: true,
                          child: Text(
                            l.signInHeadline,
                            style: t.headlineLarge?.copyWith(
                              color: Colors.white,
                              height: 1.25,
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          l.signInIntro,
                          style: t.bodyLarge?.copyWith(
                            color: AppPalette.heroMuted,
                          ),
                        ),
                        const SizedBox(height: 24),
                        Wrap(
                          spacing: 20,
                          runSpacing: 12,
                          children: [
                            _Feature(Icons.devices_rounded, l.signInDevices),
                            _Feature(
                              Icons.fingerprint_rounded,
                              l.signInApproval,
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 28),
                  Text(l.signInTitle, style: t.titleLarge),
                  const SizedBox(height: 8),
                  Text(
                    l.signInSubtitle,
                    style: t.bodyMedium?.copyWith(color: p.muted),
                  ),
                  const SizedBox(height: 20),
                  OutlinedButton.icon(
                    key: const ValueKey('google-sign-in'),
                    onPressed:
                        disabled ? null : () => controller.signIn('google'),
                    style: OutlinedButton.styleFrom(
                      backgroundColor: Colors.white,
                      foregroundColor: const Color(0xff1f1f1f),
                      side: const BorderSide(color: Color(0xff747775)),
                    ),
                    icon: const ExcludeSemantics(
                      child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CustomPaint(painter: _GoogleMark()),
                      ),
                    ),
                    label: Text(l.signInGoogle),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    key: const ValueKey('apple-sign-in'),
                    onPressed:
                        disabled ? null : () => controller.signIn('apple'),
                    style: FilledButton.styleFrom(
                      backgroundColor: p.dark ? Colors.white : Colors.black,
                      foregroundColor: p.dark ? Colors.black : Colors.white,
                    ),
                    icon: const ExcludeSemantics(
                      child: Icon(Icons.apple, size: 24),
                    ),
                    label: Text(l.signInApple),
                  ),
                  if (disabled) ...[
                    const SizedBox(height: 20),
                    Semantics(
                      liveRegion: true,
                      child: Row(
                        children: [
                          const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              controller.restoring
                                  ? l.restoringSession
                                  : l.signingIn,
                              style: t.bodyMedium,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                  if (!disabled &&
                      (controller.error != null ||
                          (controller.account != null &&
                              !controller.account!.googleAvailable &&
                              !controller.account!.appleAvailable))) ...[
                    const SizedBox(height: 20),
                    Semantics(
                      liveRegion: true,
                      child: Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: p.warningSoft,
                          borderRadius: BorderRadius.circular(14),
                        ),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Icon(
                              Icons.info_outline_rounded,
                              color: p.warning,
                              size: 20,
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Text(
                                signInMessage(l, controller.error),
                                style: t.bodyMedium?.copyWith(color: p.warning),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                  const SizedBox(height: 24),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(
                        Icons.lock_outline_rounded,
                        size: 17,
                        color: p.muted,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(l.signInPrivacy, style: t.bodySmall),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

String signInMessage(AppLocalizations l, String? code) => switch (code) {
  'network_unavailable' || 'relay_unavailable' => l.signInNetworkError,
  'rate_limited' => l.signInRateLimited,
  'login_account_conflict' => l.signInAccountConflict,
  'invalid_relay_url' => l.signInInvalidRelay,
  'relay_bound_to_pairing' => l.signInRelayBound,
  'hardware_unavailable' => l.securityUnavailable,
  null || 'login_configuration_required' => l.signInNotReady,
  _ => l.signInFailed,
};

class _Feature extends StatelessWidget {
  const _Feature(this.icon, this.label);
  final IconData icon;
  final String label;
  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      ExcludeSemantics(
        child: Icon(icon, color: AppPalette.heroAccent, size: 18),
      ),
      const SizedBox(width: 8),
      Flexible(
        child: Text(
          label,
          style: Theme.of(
            context,
          ).textTheme.labelMedium?.copyWith(color: AppPalette.heroMuted),
        ),
      ),
    ],
  );
}

/// The official four-color G paths, shared with Simvito's Google brand asset.
class _GoogleMark extends CustomPainter {
  const _GoogleMark();
  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.scale(size.width / 48, size.height / 48);
    final red =
        Path()
          ..moveTo(24, 9.5)
          ..cubicTo(27.54, 9.5, 30.71, 10.72, 33.21, 13.1)
          ..lineTo(40.06, 6.25)
          ..cubicTo(35.9, 2.38, 30.47, 0, 24, 0)
          ..cubicTo(14.62, 0, 6.51, 5.38, 2.56, 13.22)
          ..lineTo(10.54, 19.41)
          ..cubicTo(12.43, 13.72, 17.74, 9.5, 24, 9.5)
          ..close();
    final blue =
        Path()
          ..moveTo(46.98, 24.55)
          ..cubicTo(46.98, 22.98, 46.83, 21.46, 46.6, 20)
          ..lineTo(24, 20)
          ..lineTo(24, 29.02)
          ..lineTo(36.94, 29.02)
          ..cubicTo(36.36, 31.98, 34.68, 34.5, 32.16, 36.2)
          ..lineTo(39.89, 42.2)
          ..cubicTo(44.4, 38.02, 46.98, 31.84, 46.98, 24.55)
          ..close();
    final yellow =
        Path()
          ..moveTo(10.53, 28.59)
          ..cubicTo(10.05, 27.14, 9.77, 25.6, 9.77, 24)
          ..cubicTo(9.77, 22.4, 10.04, 20.86, 10.53, 19.41)
          ..lineTo(2.55, 13.22)
          ..cubicTo(0.92, 16.46, 0, 20.12, 0, 24)
          ..cubicTo(0, 27.88, 0.92, 31.54, 2.56, 34.78)
          ..lineTo(10.53, 28.59)
          ..close();
    final green =
        Path()
          ..moveTo(24, 48)
          ..cubicTo(30.48, 48, 35.93, 45.87, 39.89, 42.19)
          ..lineTo(32.16, 36.19)
          ..cubicTo(30.01, 37.64, 27.24, 38.49, 24, 38.49)
          ..cubicTo(17.74, 38.49, 12.43, 34.27, 10.53, 28.58)
          ..lineTo(2.55, 34.77)
          ..cubicTo(6.51, 42.62, 14.62, 48, 24, 48)
          ..close();
    for (final item in [
      (red, 0xffea4335),
      (blue, 0xff4285f4),
      (yellow, 0xfffbbc05),
      (green, 0xff34a853),
    ]) {
      canvas.drawPath(item.$1, Paint()..color = Color(item.$2));
    }
    canvas.restore();
  }

  @override
  bool shouldRepaint(_GoogleMark oldDelegate) => false;
}
