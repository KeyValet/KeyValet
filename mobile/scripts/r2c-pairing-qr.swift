// Deterministic pairing QR for the live software executor fixture. No account credentials.
import AppKit
import CoreImage
import Foundation

guard CommandLine.arguments.count == 3,
      CommandLine.arguments[1].hasPrefix("kv-pair://relay.keyvalet.dev/"),
      let data = CommandLine.arguments[1].data(using: .ascii),
      let filter = CIFilter(name: "CIQRCodeGenerator") else { exit(2) }
filter.setValue(data, forKey: "inputMessage")
filter.setValue("M", forKey: "inputCorrectionLevel")
guard let code = filter.outputImage else { exit(2) }
let quiet = CIImage(color: CIColor.white).cropped(to: code.extent.insetBy(dx: -4, dy: -4))
let image = code.composited(over: quiet).transformed(by: CGAffineTransform(scaleX: 12, y: 12))
guard let cgImage = CIContext().createCGImage(image, from: image.extent),
      let png = NSBitmapImageRep(cgImage: cgImage).representation(using: .png, properties: [:]) else { exit(2) }
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[2]))
