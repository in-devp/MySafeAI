import AppKit

enum BrandMark {
    enum Indicator {
        case off, checking, trusted, paused, warning
    }

    @MainActor static let badge = NSImage(size: NSSize(width: 24, height: 24), flipped: true) { rect in
        guard let context = NSGraphicsContext.current?.cgContext else { return false }
        drawBadge(in: context, rect: rect)
        return true
    }

    static func menuIcon(_ indicator: Indicator, label: String) -> NSImage {
        let image = NSImage(size: NSSize(width: 20, height: 18), flipped: true) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            draw(in: context, rect: rect) {
                context.setStrokeColor(CGColor(gray: 0, alpha: 1))
                context.setFillColor(CGColor(gray: 0, alpha: 1))
                context.addPath(route)
                context.setLineWidth(2.65)
                context.setLineCap(.round)
                context.setLineJoin(.round)
                context.strokePath()
                drawIndicator(indicator, in: context)
            }
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = label
        return image
    }

    static func drawBadge(in context: CGContext, rect: CGRect) {
        draw(in: context, rect: rect) {
            let tile = CGRect(x: 1.25, y: 1.25, width: 21.5, height: 21.5)
            let border = CGPath(roundedRect: tile, cornerWidth: 5.1, cornerHeight: 5.1, transform: nil)
            context.saveGState()
            context.addPath(border)
            context.clip()
            gradient(in: context, from: color(0.23, 0.19, 0.36), to: color(0.075, 0.065, 0.15),
                     start: CGPoint(x: 4, y: 1), end: CGPoint(x: 20, y: 23))
            context.restoreGState()

            context.addPath(border)
            context.setLineWidth(0.26)
            context.setStrokeColor(color(0.77, 0.70, 1, alpha: 0.32))
            context.strokePath()

            context.saveGState()
            context.addPath(route.copy(strokingWithWidth: 2.45, lineCap: .round, lineJoin: .round, miterLimit: 1))
            context.clip()
            gradient(in: context, from: color(0.98, 0.95, 1), to: color(0.69, 0.62, 0.99),
                     start: CGPoint(x: 12, y: 5), end: CGPoint(x: 12, y: 19))
            context.restoreGState()

            context.setFillColor(color(1, 0.76, 0.55))
            drawIndicator(.trusted, in: context)
        }
    }

    private static var route: CGPath {
        let path = CGMutablePath()
        path.move(to: CGPoint(x: 14.3, y: 5.8))
        path.addLine(to: CGPoint(x: 9.3, y: 5.8))
        path.addLine(to: CGPoint(x: 4.7, y: 10.5))
        path.addLine(to: CGPoint(x: 10.7, y: 10.5))

        path.move(to: CGPoint(x: 8.7, y: 18.2))
        path.addLine(to: CGPoint(x: 14.7, y: 18.2))
        path.addLine(to: CGPoint(x: 19.3, y: 13.5))
        path.addLine(to: CGPoint(x: 13.3, y: 13.5))
        return path
    }

    private static func drawIndicator(_ indicator: Indicator, in context: CGContext) {
        context.saveGState()
        context.translateBy(x: 19.2, y: 5.8)
        defer { context.restoreGState() }
        switch indicator {
        case .trusted:
            context.fillEllipse(in: CGRect(x: -1.55, y: -1.55, width: 3.1, height: 3.1))
        case .checking:
            context.setLineWidth(1.2)
            context.strokeEllipse(in: CGRect(x: -1.45, y: -1.45, width: 2.9, height: 2.9))
        case .off:
            context.setLineWidth(1.75)
            context.move(to: CGPoint(x: -1.4, y: 0))
            context.addLine(to: CGPoint(x: 1.4, y: 0))
            context.strokePath()
        case .paused:
            context.fill(CGRect(x: -2.1, y: -2, width: 1.5, height: 4))
            context.fill(CGRect(x: 0.6, y: -2, width: 1.5, height: 4))
        case .warning:
            context.setLineWidth(1.65)
            context.move(to: CGPoint(x: 0, y: -2.35))
            context.addLine(to: CGPoint(x: 0, y: -0.8))
            context.strokePath()
            context.fillEllipse(in: CGRect(x: -0.9, y: 0.8, width: 1.8, height: 1.8))
        }
    }

    private static func draw(in context: CGContext, rect: CGRect, content: () -> Void) {
        let scale = min(rect.width, rect.height) / 24
        context.saveGState()
        context.translateBy(x: rect.midX - 12 * scale, y: rect.midY - 12 * scale)
        context.scaleBy(x: scale, y: scale)
        content()
        context.restoreGState()
    }

    private static func color(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat, alpha: CGFloat = 1) -> CGColor {
        CGColor(red: red, green: green, blue: blue, alpha: alpha)
    }

    private static func gradient(in context: CGContext, from: CGColor, to: CGColor, start: CGPoint, end: CGPoint) {
        guard let gradient = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
                                        colors: [from, to] as CFArray, locations: [0, 1]) else { return }
        context.drawLinearGradient(gradient, start: start, end: end,
                                   options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    }
}
