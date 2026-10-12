import '../rust/api.dart' as rust;
import '../rust/view.dart';
import 'platform_sign_in.dart';

/// A test seam around the public Rust API. Only Rust stores session credentials.
class AccountGateway {
  Future<AccountView> status() => rust.accountStatus();
  Future<AccountView> restore() => rust.restoreAccount();
  Future<SignInOptions> begin(String provider) =>
      rust.beginSignIn(provider: provider);
  Future<AccountView> complete(
    SignInOptions attempt,
    ProviderCredential credential,
  ) => rust.completeSignIn(
    attemptId: attempt.attemptId,
    identityToken: credential.identityToken,
    returnedState: credential.state,
    displayName: credential.displayName,
  );
  Future<void> logout() => rust.signOut();
  Future<void> start() => rust.startForeground();
  Future<void> stop() => rust.stopForeground();
  Future<Snapshot> snapshot() => rust.snapshot();
}
