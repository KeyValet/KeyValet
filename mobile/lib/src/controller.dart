import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show ExternalLibrary;
import 'package:kv_native/kv_native.dart';
import 'rust/api.dart' as rust;
import 'rust/frb_generated.dart';
import 'rust/view.dart';
import 'auth/account_gateway.dart';
import 'auth/platform_sign_in.dart';

/// Public models and user intents only. Cryptography and protocol parsing stay in Rust.
class MobileController extends ChangeNotifier with WidgetsBindingObserver {
  MobileController({AccountGateway? accounts, PlatformSignIn? platformSignIn})
    : _accounts = accounts ?? AccountGateway(),
      _platformSignIn = platformSignIn ?? PlatformSignIn();
  final AccountGateway _accounts;
  final PlatformSignIn _platformSignIn;
  AccountView? account;
  bool restoring = true;
  bool get signedIn => account?.signedIn == true;
  Snapshot? state;
  String? error;
  bool busy = false;
  String? notificationApprovalId;
  Timer? _timer;
  bool _refreshing = false;
  bool _disposed = false;
  int _epoch = 0;
  bool _ready = false;
  Future<void> initialize() async {
    WidgetsBinding.instance.addObserver(this);
    try {
      await KvNative.initialize();
      await RustLib.init(
        externalLibrary:
            Platform.isIOS
                ? ExternalLibrary.process(iKnowHowToUseIt: true)
                : ExternalLibrary.open('libkv_mobile_core.so'),
      );
      _ready = true;
      notificationApprovalId = await KvNative.initialApprovalId();
      await restoreLogin();
    } catch (_) {
      error = 'hardware_unavailable';
      restoring = false;
      notifyListeners();
    }
  }

  Future<void> restoreLogin() async {
    final epoch = _epoch;
    restoring = true;
    error = null;
    notifyListeners();
    try {
      // A previously verified, unexpired Rust session can be used offline.
      final local = await _accounts.status();
      if (_disposed || epoch != _epoch) return;
      account = local;
      final restored = await _accounts.restore();
      if (_disposed || epoch != _epoch) return;
      account = restored;
      if (signedIn) {
        await _activate();
      } else {
        state = null;
        _timer?.cancel();
        await _accounts.stop();
        if (_ready) {
          try {
            await KvNative.clearNotifications();
          } catch (_) {}
        }
      }
    } catch (failure) {
      if (!_disposed && epoch == _epoch) {
        error = loginError(failure);
        if (signedIn) await _activate();
      }
    } finally {
      if (!_disposed && epoch == _epoch) {
        restoring = false;
        notifyListeners();
      }
    }
  }

  Future<void> _activate() async {
    final epoch = _epoch;
    await _accounts.start();
    if (_disposed || epoch != _epoch || !signedIn) return;
    await refresh();
    if (_disposed || epoch != _epoch || !signedIn) return;
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) => refresh());
  }

  Future<void> signIn(String provider) async {
    if (busy || restoring) return;
    final epoch = ++_epoch;
    busy = true;
    error = null;
    notifyListeners();
    var stage = 'begin';
    try {
      final attempt = await _accounts.begin(provider);
      if (_disposed || epoch != _epoch) return;
      stage = 'provider';
      final credential = await _platformSignIn.authenticate(attempt);
      if (_disposed || epoch != _epoch) return;
      stage = 'verify';
      final verified = await _accounts.complete(attempt, credential);
      if (_disposed || epoch != _epoch) return;
      account = verified;
      if (!signedIn) throw StateError('login_failed');
      stage = 'activate';
      await _activate();
    } on SignInCanceled {
      if (kDebugMode) debugPrint('KeyValet sign-in canceled: $provider');
      // Dismissing the provider dialog is not a sign-in failure.
    } catch (failure) {
      if (kDebugMode) {
        debugPrint(
          'KeyValet sign-in failed: provider=$provider stage=$stage '
          'code=${loginError(failure)}',
        );
      }
      if (!_disposed && epoch == _epoch) error = loginError(failure);
    } finally {
      if (!_disposed && epoch == _epoch) {
        busy = false;
        notifyListeners();
      }
    }
  }

  Future<void> signOut() async {
    final epoch = ++_epoch;
    _timer?.cancel();
    state = null;
    account = null;
    notificationApprovalId = null;
    busy = false;
    restoring = false;
    error = null;
    notifyListeners();
    try {
      // Rust deletes local credentials before attempting remote revocation.
      await _accounts.logout();
      if (_ready) {
        try {
          await KvNative.clearNotifications();
        } catch (_) {}
      }
      if (_disposed || epoch != _epoch) return;
      final status = await _accounts.status();
      if (_disposed || epoch != _epoch) return;
      account = status;
      await _platformSignIn.signOut();
    } catch (_) {
      if (!_disposed && epoch == _epoch) error = 'logout_failed';
    }
    if (!_disposed) notifyListeners();
  }

  Future<void> refresh() async {
    if (_refreshing || _disposed || !signedIn) return;
    final epoch = _epoch;
    _refreshing = true;
    try {
      final status = await _accounts.status();
      if (_disposed || epoch != _epoch) return;
      account = status;
      if (!signedIn) {
        state = null;
        _timer?.cancel();
        await _accounts.stop();
        if (_ready) {
          try {
            await KvNative.clearNotifications();
          } catch (_) {}
        }
        return;
      }
      final snapshot = await _accounts.snapshot();
      if (_disposed || epoch != _epoch) return;
      state = snapshot;
      error = null;
    } catch (_) {
      error = 'action_failed';
    } finally {
      _refreshing = false;
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> execute(Future<void> Function() operation) async {
    if (busy || !signedIn) return;
    final epoch = _epoch;
    busy = true;
    error = null;
    notifyListeners();
    try {
      await operation();
      if (_ready) {
        try {
          await KvNative.refreshNotifications();
        } catch (_) {}
      }
      await refresh();
    } catch (_) {
      if (!_disposed && epoch == _epoch) error = 'action_failed';
    } finally {
      if (!_disposed && epoch == _epoch) {
        busy = false;
        notifyListeners();
      }
    }
  }

  Future<PairingView> beginPair(String uri) => rust.beginPair(uri: uri);
  Future<void> confirmPair(PairingView pair, bool exclude) =>
      execute(() => rust.confirmPair(sas: pair.sas, excludeGlobal: exclude));
  Future<void> decide(ApprovalView request, String scope, bool allow) =>
      execute(
        () =>
            rust.decide(id: request.id, scope: scope, allow: allow, reason: ''),
      );
  Future<void> grant(GrantInput input) =>
      execute(() => rust.issueGrant(input: input));
  Future<void> directive(
    DeviceView device,
    String op, {
    String value = '',
    String confirmation = '',
  }) => execute(
    () => rust.directive(
      deviceId: device.id,
      op: op,
      value: value,
      confirmation: confirmation,
    ),
  );
  Future<void> preferences({bool? away, bool? notifications, String? locale}) =>
      execute(
        () => rust.preferences(
          away: away ?? state!.settings.awayFromComputer,
          notifications: notifications ?? state!.settings.notifications,
          locale: locale ?? state!.settings.locale,
        ),
      );
  Future<String> diagnostics() => rust.diagnostics();
  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycle) {
    if (!signedIn || !_ready) return;
    if (lifecycle == AppLifecycleState.resumed) {
      _resume();
    } else if (lifecycle == AppLifecycleState.paused) {
      _accounts.stop();
    }
  }

  Future<void> _resume() async {
    await restoreLogin();
    if (signedIn) await _notificationResume();
  }

  Future<void> _notificationResume() async {
    try {
      notificationApprovalId =
          await KvNative.initialApprovalId() ?? notificationApprovalId;
    } catch (_) {}
    await refresh();
  }

  @override
  void dispose() {
    _disposed = true;
    ++_epoch;
    _timer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    if (_ready) _accounts.stop();
    super.dispose();
  }
}

String loginError(Object failure) {
  final value = failure.toString();
  for (final code in [
    'login_configuration_required',
    'login_account_conflict',
    'invalid_relay_url',
    'relay_bound_to_pairing',
    'network_unavailable',
    'relay_unavailable',
    'rate_limited',
    'hardware_unavailable',
  ]) {
    if (value.contains(code)) return code;
  }
  return 'login_failed';
}
