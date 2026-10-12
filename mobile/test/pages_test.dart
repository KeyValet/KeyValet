import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keyvalet_mobile/src/ui.dart';
import 'fixture.dart';

Future<void> open(WidgetTester tester, FakeController controller) async {
  tester.view.physicalSize = const Size(390, 844);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(KeyValetApp(controller: controller));
  await tester.pumpAndSettle();
}

Future<void> reveal(WidgetTester tester, Finder target) async {
  await tester.scrollUntilVisible(
    target.hitTestable(),
    160,
    scrollable:
        find
            .descendant(
              of: find.byType(ListView).last,
              matching: find.byType(Scrollable),
            )
            .first,
    maxScrolls: 60,
  );
  await tester.pumpAndSettle();
}

void main() {
  WidgetController.hitTestWarningShouldBeFatal = true;
  testWidgets(
    'notification navigation uses only an existing Rust pending model',
    (tester) async {
      final c = FakeController()..notificationApprovalId = 'approval-2';
      await open(tester, c);
      expect(find.byType(ApprovalDetail), findsOneWidget);
      expect(c.notificationApprovalId, isNull);
      expect(find.text('Delete a repository'), findsOneWidget);
    },
  );
  testWidgets('unknown push identifiers cannot fabricate an approval detail', (
    tester,
  ) async {
    final c = FakeController()..notificationApprovalId = 'unverified-push-id';
    await open(tester, c);
    expect(find.byType(ApprovalDetail), findsNothing);
  });
  testWidgets('pending details show safe fields and only offered scopes', (
    tester,
  ) async {
    final c = FakeController();
    await open(tester, c);
    await tester.tap(find.text('Read GitHub profile'));
    await tester.pumpAndSettle();
    expect(find.text('GET api.github.com/user'), findsOneWidget);
    await reveal(tester, find.text('GitHub\ngithub/default · static'));
    expect(find.text('GitHub\ngithub/default · static'), findsOneWidget);
    await reveal(tester, find.text('Agent stated purpose · unverified'));
    expect(find.text('Agent stated purpose · unverified'), findsOneWidget);
    expect(find.text('page'), findsOneWidget);
    await reveal(tester, find.byKey(const ValueKey('allow-approval')));
    await tester.tap(find.byKey(const ValueKey('allow-approval')));
    await tester.pumpAndSettle();
    expect(c.intents, contains('decide:approval-1:per_use:true'));
  });
  testWidgets(
    'sensitive requests offer only allow once and require biometric signing',
    (tester) async {
      final c = FakeController();
      await open(tester, c);
      await reveal(tester, find.text('Delete a repository'));
      await tester.tap(find.text('Delete a repository'));
      await tester.pumpAndSettle();
      await reveal(tester, find.byKey(const ValueKey('allow-approval')));
      expect(find.text('Allow with biometrics'), findsOneWidget);
      expect(find.text('Biometrics required to sign'), findsOneWidget);
      await tester.tap(find.byType(DropdownButtonFormField<String>));
      await tester.pumpAndSettle();
      expect(find.text('Remember for 1 hour'), findsNothing);
      expect(find.text('Always allow this credential'), findsNothing);
      await tester.tap(find.text('Allow once').last);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('allow-approval')));
      await tester.pumpAndSettle();
      expect(c.intents, contains('decide:approval-2:per_use:true'));
    },
  );
  testWidgets(
    'device page shows budget source expiry and sends tightening actions',
    (tester) async {
      final c = FakeController();
      await open(tester, c);
      await tester.tap(find.text('Devices'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('CI executor'));
      await tester.pumpAndSettle();
      expect(c.intents, contains('query_status::'));
      expect(c.intents, contains('query_grants::'));
      expect(c.intents, contains('query_audit::'));
      expect(
        find.widgetWithText(FilledButton, 'Revoke all grants').hitTestable(),
        findsOneWidget,
      );
      expect(find.textContaining('Remaining calls: 8'), findsOneWidget);
      await tester.scrollUntilVisible(
        find.widgetWithText(FilledButton, 'Revoke all grants'),
        150,
        scrollable:
            find
                .descendant(
                  of: find.byType(ListView).last,
                  matching: find.byType(Scrollable),
                )
                .first,
      );
      await tester.tap(find.text('Revoke all grants'));
      await tester.pumpAndSettle();
      expect(c.intents, contains('revoke_all_grants::'));
    },
  );
  testWidgets(
    'unattended grant cannot proceed without exact typed executor label',
    (tester) async {
      final c = FakeController();
      await open(tester, c);
      await tester.tap(find.text('Devices'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('CI executor'));
      await tester.pumpAndSettle();
      await reveal(tester, find.byType(SwitchListTile));
      await tester.tap(find.byType(SwitchListTile));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Continue'));
      await tester.pumpAndSettle();
      expect(
        tester
            .widget<FilledButton>(find.widgetWithText(FilledButton, 'Confirm'))
            .onPressed,
        isNull,
      );
      await tester.enterText(find.byType(TextField), 'CI executor');
      await tester.pumpAndSettle();
      await tester.tap(find.text('Confirm'));
      await tester.pumpAndSettle();
      expect(c.intents, contains('grant:168:true:CI executor'));
    },
  );
  testWidgets(
    'pairing has no account page and requires both-device SAS confirmation',
    (tester) async {
      final c = FakeController(empty: true);
      await open(tester, c);
      await tester.tap(find.text('Devices'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Add device'));
      await tester.pumpAndSettle();
      await reveal(tester, find.byType(TextField));
      await tester.enterText(
        find.byType(TextField),
        'kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA',
      );
      await reveal(tester, find.text('Pair device'));
      await tester.tap(find.text('Pair device'));
      await tester.pumpAndSettle();
      await reveal(tester, find.widgetWithText(FilledButton, 'Confirm'));
      expect(find.text('123456'), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(find.widgetWithText(FilledButton, 'Confirm'))
            .onPressed,
        isNull,
      );
      await reveal(
        tester,
        find.text('The digits match and I confirmed on the executor'),
      );
      await tester.tap(
        find.text('The digits match and I confirmed on the executor'),
      );
      await tester.pumpAndSettle();
      await reveal(tester, find.text('Exclude this device from global grants'));
      await tester.tap(find.text('Exclude this device from global grants'));
      await tester.pumpAndSettle();
      await reveal(tester, find.widgetWithText(FilledButton, 'Confirm'));
      await tester.tap(find.text('Confirm'));
      await tester.pumpAndSettle();
      expect(c.intents, contains('confirm:123456:true'));
    },
  );
  testWidgets('activity groups locally issued records by day', (tester) async {
    await open(tester, FakeController());
    await tester.tap(find.text('Activity'));
    await tester.pumpAndSettle();
    expect(find.text('Grant issued'), findsOneWidget);
    expect(find.textContaining('Issued by this phone'), findsOneWidget);
  });
  testWidgets('settings sends preferences and exports only Rust diagnostics', (
    tester,
  ) async {
    final c = FakeController();
    await open(tester, c);
    await tester.tap(find.text('Settings'));
    await tester.pumpAndSettle();
    await reveal(tester, find.text('I am away from my computer'));
    await tester.tap(find.text('I am away from my computer'));
    await tester.pumpAndSettle();
    expect(c.intents, contains('preferences:true:null:null'));
    await reveal(tester, find.text('Copy diagnostics'));
    expect(
      find.text(
        'Counts and connection state only; no keys or approval content.',
      ),
      findsOneWidget,
    );
  });
  testWidgets('Chinese pages and empty states are localized', (tester) async {
    await open(tester, FakeController(locale: 'zh', empty: true));
    expect(find.text('没有待批请求'), findsOneWidget);
    await tester.tap(find.text('设备'));
    await tester.pumpAndSettle();
    expect(find.text('添加设备'), findsOneWidget);
    await tester.tap(find.text('活动'));
    await tester.pumpAndSettle();
    expect(find.text('暂无签发记录'), findsOneWidget);
    await tester.tap(find.text('设置'));
    await tester.pumpAndSettle();
    expect(find.text('我不在电脑前'), findsOneWidget);
  });
  testWidgets('hardware setup failure exposes no signed action', (
    tester,
  ) async {
    final c = FakeController();
    c.state = null;
    c.error = 'hardware_unavailable';
    await open(tester, c);
    expect(
      find.textContaining('Hardware keys are unavailable'),
      findsOneWidget,
    );
    expect(find.text('Allow'), findsNothing);
  });
  testWidgets('first pairing action is visible before scrolling when offline', (
    tester,
  ) async {
    final c = FakeController(empty: true, connected: false);
    await open(tester, c);
    expect(find.text('Offline · signed changes stay queued'), findsOneWidget);
    expect(
      find.widgetWithText(FilledButton, 'Add device').hitTestable(),
      findsOneWidget,
    );
    await tester.tap(find.text('Add device'));
    await tester.pumpAndSettle();
    expect(find.byType(PairPage), findsOneWidget);
    expect(c.intents, isEmpty);
  });
  testWidgets('detail exposes signing errors and disables duplicate intents', (
    tester,
  ) async {
    final c = FakeController()..notificationApprovalId = 'approval-2';
    await open(tester, c);
    await reveal(tester, find.byKey(const ValueKey('allow-approval')));
    c.busy = true;
    await c.refresh();
    await tester.pump();
    expect(
      tester
          .widget<FilledButton>(find.byKey(const ValueKey('allow-approval')))
          .onPressed,
      isNull,
    );
    expect(
      tester
          .widget<DropdownButtonFormField<String>>(
            find.byType(DropdownButtonFormField<String>),
          )
          .onChanged,
      isNull,
    );
    c.busy = false;
    c.error = 'action_failed';
    await c.refresh();
    await tester.pumpAndSettle();
    await tester.drag(find.byType(ListView).last, const Offset(0, 5000));
    await tester.pumpAndSettle();
    expect(
      find
          .text('The action could not be completed. Refresh and try again.')
          .hitTestable(),
      findsOneWidget,
    );
    expect(c.intents, isEmpty);
  });
  testWidgets('capture public-model design previews', (tester) async {
    const directory = String.fromEnvironment('W8_SCREENSHOTS');
    if (directory.isEmpty) return;
    const font = String.fromEnvironment('W8_SCREENSHOT_FONT');
    const latin = String.fromEnvironment('W8_SCREENSHOT_LATIN');
    const mono = String.fromEnvironment('W8_SCREENSHOT_MONO');
    const icons = String.fromEnvironment('W8_SCREENSHOT_ICONS');
    if (font.isNotEmpty) {
      await tester.runAsync(() async {
        final loader = FontLoader('W8Preview');
        if (latin.isNotEmpty)
          loader.addFont(
            Future.value(ByteData.sublistView(await File(latin).readAsBytes())),
          );
        loader.addFont(
          Future.value(ByteData.sublistView(await File(font).readAsBytes())),
        );
        await loader.load();
        if (mono.isNotEmpty)
          await (FontLoader('monospace')..addFont(
            Future.value(ByteData.sublistView(await File(mono).readAsBytes())),
          )).load();
        if (icons.isNotEmpty)
          await (FontLoader('MaterialIcons')..addFont(
            Future.value(ByteData.sublistView(await File(icons).readAsBytes())),
          )).load();
        Directory(directory).createSync(recursive: true);
      });
    }
    tester.view.physicalSize = const Size(1170, 2532);
    tester.view.devicePixelRatio = 3;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
    for (final (locale, brightness, empty) in [
      ('zh', Brightness.light, false),
      ('en', Brightness.light, false),
      ('zh', Brightness.dark, false),
      ('zh', Brightness.light, true),
    ]) {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pumpAndSettle();
      tester.platformDispatcher.platformBrightnessTestValue = brightness;
      final key = GlobalKey(), c = FakeController(locale: locale, empty: empty);
      await tester.pumpWidget(
        RepaintBoundary(
          key: key,
          child: KeyValetApp(
            controller: c,
            fontFamily: font.isEmpty ? null : 'W8Preview',
          ),
        ),
      );
      await tester.pumpAndSettle();
      final prefix =
          'w8-ui-$locale-${brightness.name}-${empty ? 'empty' : 'populated'}';
      Future<void> capture(String name) async {
        await tester.runAsync(() async {
          final image = await (key.currentContext!.findRenderObject()
                  as RenderRepaintBoundary)
              .toImage(pixelRatio: 3);
          final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
          File(
            '$directory/$prefix-$name.png',
          ).writeAsBytesSync(bytes!.buffer.asUint8List());
          image.dispose();
        });
      }

      final labels =
          locale == 'zh'
              ? ['待批', '设备', '活动', '设置']
              : ['Pending', 'Devices', 'Activity', 'Settings'];
      for (final (index, label) in labels.indexed) {
        await tester.tap(find.text(label));
        await tester.pumpAndSettle();
        await capture(['pending', 'devices', 'activity', 'settings'][index]);
      }
      if (!empty) {
        c.notificationApprovalId = 'approval-2';
        await c.refresh();
        await tester.pumpAndSettle();
        await capture('approval-detail');
        await reveal(tester, find.byKey(const ValueKey('allow-approval')));
        await capture('approval-signing');
        tester.state<NavigatorState>(find.byType(Navigator).last).pop();
        await tester.pumpAndSettle();
        await tester.tap(find.text(labels[1]));
        await tester.pumpAndSettle();
        await tester.tap(find.text('CI executor'));
        await tester.pumpAndSettle();
        await capture('device-detail');
      } else {
        await tester.tap(find.text(labels[1]));
        await tester.pumpAndSettle();
        await tester.tap(find.text(locale == 'zh' ? '添加设备' : 'Add device'));
        await tester.pumpAndSettle();
        await capture('pairing');
      }
      expect(tester.takeException(), isNull);
    }
  });
}
