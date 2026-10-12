import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Presentation tokens only. Security state always comes from the Rust models.
class AppPalette {
  AppPalette(this.dark);
  factory AppPalette.of(BuildContext context) =>
      AppPalette(Theme.of(context).brightness == Brightness.dark);
  final bool dark;
  Color get background =>
      dark ? const Color(0xff101725) : const Color(0xfff4f6fa);
  Color get surface => dark ? const Color(0xff1a2333) : Colors.white;
  Color get ink => dark ? const Color(0xffeef2fa) : const Color(0xff172338);
  Color get muted => dark ? const Color(0xffaebbd0) : const Color(0xff5d6b81);
  Color get border => dark ? const Color(0xff334157) : const Color(0xffdfe5ef);
  Color get controlBorder =>
      dark ? const Color(0xff7d8fa1) : const Color(0xff7d8aa1);
  Color get primary => dark ? const Color(0xffaabdff) : const Color(0xff3454d1);
  Color get soft => dark ? const Color(0xff26334b) : const Color(0xffedf1fc);
  Color get success => dark ? const Color(0xff77d8b0) : const Color(0xff147653);
  Color get successSoft =>
      dark ? const Color(0xff183b32) : const Color(0xffe8f5ef);
  Color get warning => dark ? const Color(0xffffce83) : const Color(0xff8a5100);
  Color get warningSoft =>
      dark ? const Color(0xff3d3021) : const Color(0xfffff3df);
  Color get danger => dark ? const Color(0xffffaca9) : const Color(0xffb52e3d);
  Color get dangerSoft =>
      dark ? const Color(0xff432730) : const Color(0xffffedf0);
  static const hero = Color(0xff172338);
  static const heroMuted = Color(0xffbdcbe1);
  static const heroAccent = Color(0xff9ab3ff);
}

ThemeData appTheme(Brightness brightness, {String? fontFamily}) {
  final p = AppPalette(brightness == Brightness.dark);
  final scheme = ColorScheme.fromSeed(
    seedColor: p.primary,
    brightness: brightness,
  ).copyWith(
    primary: p.primary,
    onPrimary: p.dark ? AppPalette.hero : Colors.white,
    surface: p.surface,
    onSurface: p.ink,
    onSurfaceVariant: p.muted,
    outline: p.muted,
    outlineVariant: p.border,
    error: p.danger,
    onError: p.dark ? AppPalette.hero : Colors.white,
    errorContainer: p.dangerSoft,
    surfaceContainerHighest: p.soft,
  );
  final base = ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    fontFamily: fontFamily,
  );
  final text = base.textTheme
      .apply(bodyColor: p.ink, displayColor: p.ink)
      .copyWith(
        headlineLarge: TextStyle(
          fontSize: 32,
          height: 1.18,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.8,
          color: p.ink,
        ),
        headlineSmall: TextStyle(
          fontSize: 26,
          height: 1.25,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.5,
          color: p.ink,
        ),
        titleLarge: TextStyle(
          fontSize: 21,
          height: 1.3,
          fontWeight: FontWeight.w700,
          color: p.ink,
        ),
        titleMedium: TextStyle(
          fontSize: 17,
          height: 1.4,
          fontWeight: FontWeight.w600,
          color: p.ink,
        ),
        bodyLarge: TextStyle(fontSize: 16, height: 1.5, color: p.ink),
        bodyMedium: TextStyle(fontSize: 14, height: 1.5, color: p.ink),
        bodySmall: TextStyle(fontSize: 13, height: 1.45, color: p.muted),
        labelLarge: TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w600,
          color: p.ink,
        ),
        labelMedium: TextStyle(
          fontSize: 13,
          fontWeight: FontWeight.w600,
          color: p.muted,
        ),
      )
      .apply(fontFamily: fontFamily ?? base.textTheme.bodyLarge?.fontFamily);
  final shape = RoundedRectangleBorder(borderRadius: BorderRadius.circular(14));
  return base.copyWith(
    scaffoldBackgroundColor: p.background,
    textTheme: text,
    appBarTheme: AppBarTheme(
      backgroundColor: p.background,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
      titleTextStyle: text.titleLarge,
      iconTheme: IconThemeData(color: p.ink),
      systemOverlayStyle:
          p.dark ? SystemUiOverlayStyle.light : SystemUiOverlayStyle.dark,
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        minimumSize: const Size(48, 52),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
        shape: shape,
        textStyle: text.labelLarge,
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(48, 52),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
        side: BorderSide(color: p.controlBorder),
        shape: shape,
        textStyle: text.labelLarge,
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        minimumSize: const Size(48, 48),
        textStyle: text.labelLarge,
      ),
    ),
    iconButtonTheme: IconButtonThemeData(
      style: IconButton.styleFrom(minimumSize: const Size(48, 48)),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: p.surface,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 18),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: p.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: p.controlBorder),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: p.primary, width: 2),
      ),
      labelStyle: TextStyle(color: p.muted),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: p.surface,
      surfaceTintColor: Colors.transparent,
      indicatorColor: p.soft,
      labelTextStyle: WidgetStateProperty.resolveWith(
        (states) => TextStyle(
          fontSize: 12,
          fontWeight:
              states.contains(WidgetState.selected)
                  ? FontWeight.w700
                  : FontWeight.w500,
          color: states.contains(WidgetState.selected) ? p.primary : p.muted,
        ),
      ),
      iconTheme: WidgetStateProperty.resolveWith(
        (states) => IconThemeData(
          size: 24,
          color: states.contains(WidgetState.selected) ? p.primary : p.muted,
        ),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: p.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
    ),
    dividerTheme: DividerThemeData(color: p.border, thickness: 1, space: 1),
    listTileTheme: ListTileThemeData(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      iconColor: p.muted,
    ),
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
  );
}

/// One scroll region with a readable measure on phones, landscape and tablets.
class PageScroll extends StatelessWidget {
  const PageScroll({super.key, required this.children});
  final List<Widget> children;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder:
        (context, constraints) => ListView(
          padding: EdgeInsets.fromLTRB(
            math.max(20, (constraints.maxWidth - 680) / 2),
            16,
            math.max(20, (constraints.maxWidth - 680) / 2),
            28,
          ),
          children: children,
        ),
  );
}

class PageHeading extends StatelessWidget {
  const PageHeading({
    super.key,
    required this.eyebrow,
    required this.title,
    required this.subtitle,
  });
  final String eyebrow, title, subtitle;
  @override
  Widget build(BuildContext context) {
    final p = AppPalette.of(context), t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            eyebrow,
            style: t.labelMedium?.copyWith(
              color: p.primary,
              letterSpacing: 1.2,
            ),
          ),
          const SizedBox(height: 8),
          Semantics(header: true, child: Text(title, style: t.headlineLarge)),
          const SizedBox(height: 8),
          Text(subtitle, style: t.bodyMedium?.copyWith(color: p.muted)),
        ],
      ),
    );
  }
}

class SurfaceCard extends StatelessWidget {
  const SurfaceCard({
    super.key,
    required this.child,
    this.onTap,
    this.padding = const EdgeInsets.all(20),
  });
  final Widget child;
  final VoidCallback? onTap;
  final EdgeInsetsGeometry padding;
  @override
  Widget build(BuildContext context) {
    final p = AppPalette.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Material(
        color: p.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
          side: BorderSide(color: p.border),
        ),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: onTap,
          child: Padding(padding: padding, child: child),
        ),
      ),
    );
  }
}

enum TagTone { neutral, accent, success, warning, danger }

class StatusTag extends StatelessWidget {
  const StatusTag({
    super.key,
    required this.label,
    this.icon,
    this.tone = TagTone.neutral,
  });
  final String label;
  final IconData? icon;
  final TagTone tone;
  @override
  Widget build(BuildContext context) {
    final p = AppPalette.of(context);
    final (foreground, background) = switch (tone) {
      TagTone.accent => (p.primary, p.soft),
      TagTone.success => (p.success, p.successSoft),
      TagTone.warning => (p.warning, p.warningSoft),
      TagTone.danger => (p.danger, p.dangerSoft),
      TagTone.neutral => (p.muted, p.background),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            ExcludeSemantics(child: Icon(icon, color: foreground, size: 15)),
            const SizedBox(width: 6),
          ],
          Flexible(
            child: Text(
              label,
              style: Theme.of(
                context,
              ).textTheme.labelMedium?.copyWith(color: foreground),
            ),
          ),
        ],
      ),
    );
  }
}

class IconTile extends StatelessWidget {
  const IconTile({
    super.key,
    required this.icon,
    this.danger = false,
    this.size = 48,
  });
  final IconData icon;
  final bool danger;
  final double size;
  @override
  Widget build(BuildContext context) {
    final p = AppPalette.of(context);
    return ExcludeSemantics(
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          color: danger ? p.dangerSoft : p.soft,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Icon(icon, size: 24, color: danger ? p.danger : p.primary),
      ),
    );
  }
}

class SectionHeading extends StatelessWidget {
  const SectionHeading({super.key, required this.title, this.trailing});
  final String title;
  final Widget? trailing;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(top: 16, bottom: 16),
    child: Row(
      children: [
        Expanded(
          child: Semantics(
            header: true,
            child: Text(title, style: Theme.of(context).textTheme.titleMedium),
          ),
        ),
        if (trailing != null) ...[const SizedBox(width: 12), trailing!],
      ],
    ),
  );
}

class EmptyPanel extends StatelessWidget {
  const EmptyPanel({
    super.key,
    required this.title,
    required this.description,
    required this.icon,
    this.action,
  });
  final String title, description;
  final IconData icon;
  final Widget? action;
  @override
  Widget build(BuildContext context) => SurfaceCard(
    child: Column(
      children: [
        const SizedBox(height: 8),
        TrustIllustration(icon: icon),
        const SizedBox(height: 16),
        Text(
          title,
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 12),
        Text(
          description,
          textAlign: TextAlign.center,
          style: Theme.of(
            context,
          ).textTheme.bodyMedium?.copyWith(color: AppPalette.of(context).muted),
        ),
        if (action != null) ...[
          const SizedBox(height: 24),
          SizedBox(width: double.infinity, child: action!),
        ],
        const SizedBox(height: 12),
      ],
    ),
  );
}

/// A quiet vector illustration; it never represents measured security status.
class TrustIllustration extends StatelessWidget {
  const TrustIllustration({super.key, required this.icon});
  final IconData icon;
  @override
  Widget build(BuildContext context) => ExcludeSemantics(
    child: SizedBox(
      width: 216,
      height: 128,
      child: CustomPaint(
        painter: _TrustPainter(AppPalette.of(context)),
        child: Center(
          child: Container(
            width: 72,
            height: 80,
            decoration: BoxDecoration(
              color: AppPalette.of(context).surface,
              border: Border.all(color: AppPalette.of(context).border),
              borderRadius: BorderRadius.circular(22),
              boxShadow: [
                BoxShadow(
                  color: AppPalette.of(context).ink.withValues(alpha: 0.05),
                  blurRadius: 24,
                  offset: const Offset(0, 8),
                ),
              ],
            ),
            child: Icon(icon, size: 36, color: AppPalette.of(context).primary),
          ),
        ),
      ),
    ),
  );
}

class _TrustPainter extends CustomPainter {
  _TrustPainter(this.palette);
  final AppPalette palette;
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    canvas.drawCircle(center, 58, Paint()..color = palette.soft);
    canvas.drawOval(
      Rect.fromCenter(center: center, width: 192, height: 88),
      Paint()
        ..color = palette.border
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1,
    );
    for (final (x, y) in [(25.0, 76.0), (184.0, 30.0)]) {
      final rect = RRect.fromRectAndRadius(
        Rect.fromLTWH(x, y, 28, 24),
        const Radius.circular(8),
      );
      canvas.drawRRect(rect, Paint()..color = palette.surface);
      canvas.drawRRect(
        rect,
        Paint()
          ..color = palette.border
          ..style = PaintingStyle.stroke,
      );
      canvas.drawLine(
        Offset(x + 8, y + 9),
        Offset(x + 20, y + 9),
        Paint()
          ..color = palette.primary
          ..strokeWidth = 2,
      );
      canvas.drawLine(
        Offset(x + 8, y + 15),
        Offset(x + 15, y + 15),
        Paint()
          ..color = palette.muted
          ..strokeWidth = 2,
      );
    }
    canvas.drawCircle(
      const Offset(37, 34),
      3,
      Paint()..color = palette.primary,
    );
    canvas.drawCircle(
      const Offset(187, 98),
      4,
      Paint()..color = palette.primary,
    );
  }

  @override
  bool shouldRepaint(_TrustPainter oldDelegate) =>
      palette.dark != oldDelegate.palette.dark;
}
