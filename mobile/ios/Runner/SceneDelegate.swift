import Flutter
import UIKit
import kv_native

class SceneDelegate: FlutterSceneDelegate {
  override func sceneDidBecomeActive(_ scene: UIScene) { super.sceneDidBecomeActive(scene); NativeRuntime.setForeground(true) }
  override func sceneWillResignActive(_ scene: UIScene) { NativeRuntime.setForeground(false); super.sceneWillResignActive(scene) }
}
