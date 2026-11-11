import AppKit
import ImageIO
import UniformTypeIdentifiers

@main
struct AppIconGenerator {
    static func main() throws {
        let iconset = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
        for points in [16, 32, 128, 256, 512] {
            try writeIcon(size: points, to: iconset.appendingPathComponent("icon_\(points)x\(points).png"))
            try writeIcon(size: points * 2, to: iconset.appendingPathComponent("icon_\(points)x\(points)@2x.png"))
        }
    }

    private static func writeIcon(size: Int, to url: URL) throws {
        guard let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: CGColorSpace(name: CGColorSpace.sRGB)!,
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw CocoaError(.fileWriteUnknown)
        }
        context.translateBy(x: 0, y: CGFloat(size))
        context.scaleBy(x: 1, y: -1)
        BrandMark.drawBadge(in: context, rect: CGRect(x: 0, y: 0, width: size, height: size))
        guard let image = context.makeImage(),
              let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString,
                                                               1, nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw CocoaError(.fileWriteUnknown) }
    }
}
