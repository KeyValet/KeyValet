import 'package:flutter/services.dart';

/// Native setup only. Key handles, plaintext envelopes and signatures never enter Dart.
class KvNative {
  static const _channel = MethodChannel('dev.keyvalet/kv_native');
  static Future<void> initialize() async =>
      _channel.invokeMethod<void>('initialize');
  static Future<String?> initialApprovalId() =>
      _channel.invokeMethod<String>('initialApprovalId');
  static Future<String?> pushToken() =>
      _channel.invokeMethod<String>('pushToken');
}
