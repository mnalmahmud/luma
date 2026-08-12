import Foundation
import Frida

#if canImport(CoreGraphics)
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
#endif

public extension Icon {
    var pngData: Data? {
        switch self {
        case .png(let bytes):
            return Data(bytes)
        case .rgba:
            return rgbaPNGData
        }
    }

    #if canImport(CoreGraphics)
    private var rgbaPNGData: Data? {
        encodeCGImageAsPNG(cgImage)
    }
    #else
    private var rgbaPNGData: Data? {
        guard case let .rgba(width, height, pixels) = self else { return nil }
        return PNGEncoder.encodeRGBA(width: width, height: height, pixels: pixels)
    }
    #endif
}

public extension ProcessSession {
    mutating func adoptIcon(from process: ProcessDetails) {
        guard iconPNGData == nil, let icon = process.icons.last else { return }
        iconPNGData = icon.pngData
    }
}

#if canImport(CoreGraphics)
private func encodeCGImageAsPNG(_ image: CGImage) -> Data? {
    let buffer = NSMutableData()
    guard let destination = CGImageDestinationCreateWithData(
        buffer as CFMutableData,
        UTType.png.identifier as CFString,
        1,
        nil
    ) else { return nil }
    CGImageDestinationAddImage(destination, image, nil)
    guard CGImageDestinationFinalize(destination) else { return nil }
    return buffer as Data
}
#endif
