import 'package:flutter/widgets.dart';
import 'src/controller.dart';
import 'src/ui.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = MobileController();
  runApp(KeyValetApp(controller: controller));
  controller.initialize();
}
