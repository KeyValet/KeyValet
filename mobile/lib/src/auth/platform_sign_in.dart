import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import '../rust/view.dart';
import 'endpoints.dart';

class SignInCanceled implements Exception {}

/// The SDK result goes straight to Rust and the relay. Dart never decodes a token.
class ProviderCredential {
  const ProviderCredential(
    this.identityToken, {
    this.state = '',
    this.displayName = '',
  });
  final String identityToken;
  final String state;
  final String displayName;
}

class PlatformSignIn {
  Future<void>? _googleReady;
  String? _googleConfiguration;

  Future<ProviderCredential> authenticate(SignInOptions options) async {
    if (options.provider == 'google') return _google(options);
    if (options.provider == 'apple') return _apple(options);
    throw StateError('invalid_login_provider');
  }

  Future<ProviderCredential> _google(SignInOptions options) async {
    final google = GoogleSignIn.instance;
    final configuration =
        '${options.googleWebClientId}:${options.googleIosClientId}';
    if (_googleConfiguration != configuration) {
      _googleConfiguration = configuration;
      _googleReady = null;
    }
    final initialization =
        _googleReady ??= google.initialize(
          clientId:
              defaultTargetPlatform == TargetPlatform.iOS
                  ? options.googleIosClientId
                  : null,
          serverClientId: options.googleWebClientId,
        );
    try {
      await initialization;
    } catch (_) {
      if (identical(_googleReady, initialization)) _googleReady = null;
      rethrow;
    }
    try {
      final token = (await google.authenticate()).authentication.idToken;
      if (token == null || token.isEmpty) throw StateError('login_failed');
      // google_sign_in 7.2.0 does not expose a nonce. Rust binds its hash to a
      // one-use relay attempt with the hardware device identity key instead.
      return ProviderCredential(token);
    } on GoogleSignInException catch (error) {
      final description = error.description?.toLowerCase() ?? '';
      final providerFailed =
          description.contains('account reauth failed') ||
          description.contains('developer console is not set up correctly');
      if (kDebugMode) {
        debugPrint(
          'KeyValet Google SDK failed: code=${error.code.name} '
          'account_reauth=${description.contains("account reauth failed")} '
          'console_configuration='
          '${description.contains("developer console is not set up correctly")}',
        );
      }
      if (error.code == GoogleSignInExceptionCode.canceled && !providerFailed)
        throw SignInCanceled();
      rethrow;
    }
  }

  Future<ProviderCredential> _apple(SignInOptions options) async {
    try {
      final android = defaultTargetPlatform == TargetPlatform.android;
      final credential = await SignInWithApple.getAppleIDCredential(
        scopes: const [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        nonce: options.nonceHash,
        state: options.state,
        webAuthenticationOptions:
            android
                ? WebAuthenticationOptions(
                  clientId: options.appleServicesId,
                  redirectUri: keyValetAppleCallback,
                )
                : null,
      );
      final token = credential.identityToken;
      if (token == null || token.isEmpty || credential.state != options.state)
        throw StateError('login_failed');
      return ProviderCredential(
        token,
        state: credential.state!,
        displayName: [
          credential.givenName,
          credential.familyName,
        ].whereType<String>().where((s) => s.isNotEmpty).join(' '),
      );
    } on SignInWithAppleAuthorizationException catch (error) {
      if (error.code == AuthorizationErrorCode.canceled) throw SignInCanceled();
      rethrow;
    }
  }

  Future<void> signOut() async {
    if (_googleReady != null) await GoogleSignIn.instance.signOut();
  }
}
