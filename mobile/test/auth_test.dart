import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keyvalet_mobile/l10n/app_localizations.dart';
import 'package:keyvalet_mobile/src/auth/account_gateway.dart';
import 'package:keyvalet_mobile/src/auth/platform_sign_in.dart';
import 'package:keyvalet_mobile/src/auth/sign_in_page.dart';
import 'package:keyvalet_mobile/src/controller.dart';
import 'package:keyvalet_mobile/src/rust/view.dart';
import 'package:keyvalet_mobile/src/ui.dart';
import 'fixture.dart';

AccountView profile({
  bool signedIn = false,
  String locale = 'en',
  bool configured = true,
}) => AccountView(
  signedIn: signedIn,
  userId: signedIn ? 'ci-user' : '',
  provider: signedIn ? 'google' : '',
  email: signedIn ? 'owner@example.test' : '',
  displayName: signedIn ? 'Owner' : '',
  expiresAt: signedIn ? 1900000000 : 0,
  relayUrl: 'https://relay.keyvalet.dev/',
  locale: locale,
  googleAvailable: configured,
  appleAvailable: configured,
);

class Gateway extends AccountGateway {
  AccountView current = profile();
  final List<String> calls = [];
  Object? beginError;
  Object? completeError;
  Completer<AccountView>? restorePending;
  Completer<AccountView>? completePending;
  @override
  Future<AccountView> status() async => current;
  @override
  Future<AccountView> restore() async {
    calls.add('restore');
    return restorePending == null ? current : restorePending!.future;
  }

  @override
  Future<SignInOptions> begin(String provider) async {
    calls.add('begin:$provider');
    if (beginError != null) throw beginError!;
    return SignInOptions(
      attemptId: 'attempt',
      provider: provider,
      nonceHash: 'nonce-from-rust',
      state: 'state-from-rust',
      googleWebClientId: 'web',
      googleIosClientId: 'ios',
      appleServicesId: 'service',
    );
  }

  @override
  Future<AccountView> complete(
    SignInOptions attempt,
    ProviderCredential credential,
  ) async {
    calls.add('verify:' + attempt.provider);
    if (completeError != null) throw completeError!;
    if (completePending != null) return completePending!.future;
    current = profile(signedIn: true);
    return current;
  }

  @override
  Future<void> logout() async {
    calls.add('logout');
    current = profile();
  }

  @override
  Future<void> start() async {
    calls.add('start');
  }

  @override
  Future<void> stop() async {
    calls.add('stop');
  }

  @override
  Future<Snapshot> snapshot() async {
    calls.add('snapshot');
    return const Snapshot(
      pending: [],
      devices: [],
      activity: [],
      settings: settings,
      connected: true,
    );
  }
}

class Provider extends PlatformSignIn {
  Object? failure;
  Completer<ProviderCredential>? pending;
  final List<String> calls = [];
  @override
  Future<ProviderCredential> authenticate(SignInOptions options) async {
    calls.add(options.provider);
    if (failure != null) throw failure!;
    if (pending != null) return pending!.future;
    return ProviderCredential('opaque-sdk-credential', state: options.state);
  }

  @override
  Future<void> signOut() async {}
}

void main() {
  testWidgets(
    'relay address is hidden on sign-in and every tab in both languages',
    (tester) async {
      final semantics = tester.ensureSemantics();
      void expectNoAddress() {
        expect(
          find.textContaining('relay.keyvalet.dev', skipOffstage: false),
          findsNothing,
        );
        expect(
          find.bySemanticsLabel(
            RegExp(r'relay\.keyvalet\.dev'),
            skipOffstage: false,
          ),
          findsNothing,
        );
        expect(find.byType(TextFormField), findsNothing);
      }

      for (final locale in ['en', 'zh']) {
        final c = FakeController(locale: locale)
          ..account = profile(locale: locale);
        addTearDown(c.dispose);
        await tester.pumpWidget(KeyValetApp(controller: c));
        await tester.pumpAndSettle();
        expectNoAddress();
        expect(find.byIcon(Icons.tune_rounded), findsNothing);
        c.account = profile(signedIn: true, locale: locale);
        await c.refresh();
        await tester.pumpAndSettle();
        final l = AppLocalizations.of(tester.element(find.byType(Home)));
        for (final tab in [l.pending, l.devices, l.activity, l.settings]) {
          await tester.tap(find.text(tab));
          await tester.pumpAndSettle();
          expectNoAddress();
        }
      }
      semantics.dispose();
    },
  );
  testWidgets(
    'signed-out phone cannot enter private tabs even with cached data or a push route',
    (tester) async {
      final c =
          FakeController()
            ..account = profile()
            ..notificationApprovalId = 'approval-2';
      await tester.pumpWidget(KeyValetApp(controller: c));
      await tester.pumpAndSettle();
      expect(find.byType(SignInPage), findsOneWidget);
      expect(find.byType(ApprovalDetail), findsNothing);
      expect(find.byType(NavigationBar), findsNothing);
      expect(find.text('CI executor'), findsNothing);
    },
  );
  for (final provider in ['google', 'apple']) {
    testWidgets(
      '$provider requires relay verification before activating device transport',
      (tester) async {
        final gateway = Gateway(), sdk = Provider();
        final c =
            MobileController(accounts: gateway, platformSignIn: sdk)
              ..restoring = false
              ..account = profile();
        addTearDown(c.dispose);
        await c.signIn(provider);
        expect(c.signedIn, isTrue);
        expect(gateway.calls, [
          'begin:$provider',
          'verify:$provider',
          'start',
          'snapshot',
        ]);
        expect(sdk.calls, [provider]);
        await c.signOut();
        expect(c.signedIn, isFalse);
        expect(c.state, isNull);
      },
    );
  }
  testWidgets(
    'provider cancellation is quiet and a rejected token never starts transport',
    (tester) async {
      final gateway = Gateway(), sdk = Provider()..failure = SignInCanceled();
      final c = MobileController(accounts: gateway, platformSignIn: sdk)
        ..restoring = false;
      addTearDown(c.dispose);
      await c.signIn('google');
      expect(c.error, isNull);
      expect(c.signedIn, isFalse);
      sdk.failure = null;
      gateway.completeError = StateError('login_failed');
      await c.signIn('google');
      expect(c.error, 'login_failed');
      expect(gateway.calls, isNot(contains('start')));
    },
  );
  testWidgets(
    'missing configuration gives a visible error without invoking the SDK',
    (tester) async {
      final gateway =
              Gateway()
                ..beginError = StateError('login_configuration_required'),
          sdk = Provider();
      final c =
          MobileController(accounts: gateway, platformSignIn: sdk)
            ..restoring = false
            ..account = profile(configured: false);
      addTearDown(c.dispose);
      await tester.pumpWidget(KeyValetApp(controller: c));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const ValueKey('google-sign-in')));
      await tester.tap(find.byKey(const ValueKey('google-sign-in')));
      await tester.pumpAndSettle();
      expect(c.error, 'login_configuration_required');
      expect(sdk.calls, isEmpty);
      expect(find.textContaining('not enabled'), findsOneWidget);
    },
  );
  testWidgets('logout cancels a late restore without resurrecting private UI', (
    tester,
  ) async {
    final gateway = Gateway()..restorePending = Completer<AccountView>();
    final c = MobileController(accounts: gateway, platformSignIn: Provider())
      ..restoring = false;
    addTearDown(c.dispose);
    final restoring = c.restoreLogin();
    await tester.pump();
    await c.signOut();
    gateway.restorePending!.complete(profile(signedIn: true));
    await restoring;
    expect(c.signedIn, isFalse);
    expect(gateway.calls, isNot(contains('start')));
  });
  testWidgets(
    'logout cancels a late provider result and suppresses duplicate sign-in taps',
    (tester) async {
      final gateway = Gateway(),
          sdk = Provider()..pending = Completer<ProviderCredential>();
      final c = MobileController(accounts: gateway, platformSignIn: sdk)
        ..restoring = false;
      addTearDown(c.dispose);
      final signing = c.signIn('google');
      await tester.pump();
      await c.signIn('apple');
      await c.signOut();
      sdk.pending!.complete(const ProviderCredential('late-token'));
      await signing;
      expect(gateway.calls, isNot(contains('verify:google')));
      expect(sdk.calls, ['google']);
      expect(c.signedIn, isFalse);
    },
  );
  testWidgets('expiry removes all private routes and notification navigation', (
    tester,
  ) async {
    final c = FakeController()..notificationApprovalId = 'approval-2';
    await tester.pumpWidget(KeyValetApp(controller: c));
    await tester.pumpAndSettle();
    expect(find.byType(ApprovalDetail), findsOneWidget);
    c.account = profile();
    c.state = null;
    await c.refresh();
    await tester.pumpAndSettle();
    expect(find.byType(SignInPage), findsOneWidget);
    expect(find.byType(ApprovalDetail), findsNothing);
  });
  for (final (locale, scale, brightness) in [
    ('en', 1.0, Brightness.light),
    ('zh', 1.0, Brightness.dark),
    ('en', 3.2, Brightness.dark),
    ('zh', 3.2, Brightness.light),
  ]) {
    testWidgets('login reflows at 320px / $scale / $locale / $brightness', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(320, 740);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = scale;
      tester.platformDispatcher.platformBrightnessTestValue = brightness;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      final c =
          FakeController()
            ..account = profile(locale: locale, configured: false);
      await tester.pumpWidget(KeyValetApp(controller: c));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      for (final key in ['google-sign-in', 'apple-sign-in']) {
        await tester.ensureVisible(find.byKey(ValueKey(key)));
        await tester.pumpAndSettle();
        expect(find.byKey(ValueKey(key)).hitTestable(), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });
  }
  testWidgets('login controls expose labels and adequate touch targets', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    final c = FakeController()..account = profile();
    await tester.pumpWidget(KeyValetApp(controller: c));
    await tester.pumpAndSettle();
    expect(tester, meetsGuideline(androidTapTargetGuideline));
    expect(tester, meetsGuideline(labeledTapTargetGuideline));
    semantics.dispose();
  });
  testWidgets('capture login previews', (tester) async {
    final directory = Platform.environment['KV_AUTH_PREVIEW_DIR'];
    if (directory == null) return;
    final latin = Platform.environment['KV_AUTH_PREVIEW_FONT'];
    final icons = Platform.environment['KV_AUTH_PREVIEW_ICONS'];
    if (latin != null) {
      await tester.runAsync(() async {
        final font = FontLoader('AuthPreview');
        font.addFont(
          Future.value(ByteData.sublistView(await File(latin).readAsBytes())),
        );
        await font.load();
        if (icons != null) {
          final iconFont = FontLoader('MaterialIcons');
          iconFont.addFont(
            Future.value(ByteData.sublistView(await File(icons).readAsBytes())),
          );
          await iconFont.load();
        }
      });
    }
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final key = GlobalKey();
    final c = FakeController()..account = profile(configured: false);
    await tester.pumpWidget(
      RepaintBoundary(
        key: key,
        child: KeyValetApp(
          controller: c,
          fontFamily: latin == null ? null : 'AuthPreview',
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.runAsync(() async {
      final image = await (key.currentContext!.findRenderObject()
              as RenderRepaintBoundary)
          .toImage(pixelRatio: 2);
      final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
      await Directory(directory).create(recursive: true);
      await File(
        '$directory/w8-auth-login-en.png',
      ).writeAsBytes(bytes!.buffer.asUint8List());
      image.dispose();
    });
  });
}
