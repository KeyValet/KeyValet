import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keyvalet_mobile/src/design.dart';
import 'package:keyvalet_mobile/src/ui.dart';
import 'fixture.dart';

double contrast(Color a, Color b) {
  final first = a.computeLuminance(), second = b.computeLuminance();
  final lighter = first > second ? first : second;
  final darker = first > second ? second : first;
  return (lighter + 0.05) / (darker + 0.05);
}

void main() {
  for (final dark in [false, true]) {
    test('${dark ? 'dark' : 'light'} semantic text pairs meet WCAG AA', () {
      final p = AppPalette(dark);
      for (final pair in [
        (p.ink, p.surface),
        (p.muted, p.surface),
        (p.muted, p.background),
        (p.primary, p.soft),
        (p.success, p.successSoft),
        (p.warning, p.warningSoft),
        (p.danger, p.dangerSoft),
        (dark ? AppPalette.hero : Colors.white, p.primary),
        (AppPalette.heroMuted, AppPalette.hero),
      ]) {
        expect(contrast(pair.$1, pair.$2), greaterThanOrEqualTo(4.5));
      }
      expect(contrast(p.controlBorder, p.surface), greaterThanOrEqualTo(3));
      expect(contrast(p.controlBorder, p.background), greaterThanOrEqualTo(3));
    });
  }

  for (final (size, scale, locale, brightness) in [
    (const Size(375, 812), 1.0, 'en', Brightness.light),
    (const Size(375, 812), 1.0, 'zh', Brightness.dark),
    (const Size(320, 740), 2.0, 'zh', Brightness.light),
    (const Size(320, 740), 2.0, 'en', Brightness.dark),
    (const Size(320, 740), 3.2, 'en', Brightness.dark),
    (const Size(320, 740), 3.2, 'zh', Brightness.light),
    (const Size(844, 390), 1.5, 'zh', Brightness.dark),
    (const Size(1024, 768), 2.0, 'en', Brightness.light),
  ]) {
    testWidgets(
      'pages and approval actions reflow at $size / $scale / $locale / $brightness',
      (tester) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1;
        tester.platformDispatcher.textScaleFactorTestValue = scale;
        tester.platformDispatcher.platformBrightnessTestValue = brightness;
        tester.platformDispatcher.accessibilityFeaturesTestValue =
            FakeAccessibilityFeatures(disableAnimations: true);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
        addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
        addTearDown(
          tester.platformDispatcher.clearAccessibilityFeaturesTestValue,
        );
        final c = FakeController(locale: locale, connected: false);
        await tester.pumpWidget(KeyValetApp(controller: c));
        await tester.pumpAndSettle();
        final labels =
            locale == 'zh'
                ? ['待批', '设备', '活动', '设置']
                : ['Pending', 'Devices', 'Activity', 'Settings'];
        for (final label in labels) {
          await tester.tap(find.text(label));
          await tester.pumpAndSettle();
          expect(tester.takeException(), isNull);
          await tester.drag(find.byType(ListView).last, const Offset(0, -1000));
          await tester.pumpAndSettle();
          expect(tester.takeException(), isNull);
        }
        // The detail and its scope/signing controls must remain reachable at large text sizes.
        c.notificationApprovalId = 'approval-2';
        await c.refresh();
        await tester.pumpAndSettle();
        expect(find.byType(ApprovalDetail), findsOneWidget);
        expect(tester.takeException(), isNull);
        await tester.scrollUntilVisible(
          find.byKey(const ValueKey('allow-approval')).hitTestable(),
          200,
          scrollable:
              find
                  .descendant(
                    of: find.byType(ListView).last,
                    matching: find.byType(Scrollable),
                  )
                  .first,
          maxScrolls: 80,
        );
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        await tester.tap(find.byKey(const ValueKey('allow-approval')));
        await tester.pumpAndSettle();
        expect(c.intents, contains('decide:approval-2:per_use:true'));
      },
    );
  }

  testWidgets('primary controls have labeled Android-sized touch targets', (
    tester,
  ) async {
    final handle = tester.ensureSemantics();
    await tester.pumpWidget(
      KeyValetApp(controller: FakeController(empty: true)),
    );
    await tester.pumpAndSettle();
    expect(tester, meetsGuideline(androidTapTargetGuideline));
    expect(tester, meetsGuideline(labeledTapTargetGuideline));
    handle.dispose();
  });
}
