import SwiftUI

struct PanelButtonStyle: ButtonStyle {
    enum Emphasis {
        case primary, secondary, quiet
    }

    enum Size {
        case regular, compact, icon, row
    }

    nonisolated static let accent = Color(red: 0.53, green: 0.89, blue: 0.76)
    private let emphasis: Emphasis
    private let size: Size
    private let fullWidth: Bool

    init(_ emphasis: Emphasis = .secondary, size: Size = .regular, fullWidth: Bool = false) {
        self.emphasis = emphasis
        self.size = size
        self.fullWidth = fullWidth
    }

    func makeBody(configuration: Configuration) -> some View {
        Surface(label: configuration.label, pressed: configuration.isPressed,
                emphasis: emphasis, size: size, fullWidth: fullWidth)
    }

    private struct Surface: View {
        let label: Configuration.Label
        let pressed: Bool
        let emphasis: Emphasis
        let size: Size
        let fullWidth: Bool

        @Environment(\.isEnabled) private var enabled
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        @State private var hovering = false

        private var height: CGFloat {
            switch size {
            case .compact, .icon: 28
            case .regular: 34
            case .row: 36
            }
        }

        private var highlighted: Bool { enabled && (hovering || pressed) }

        private var foreground: Color {
            emphasis == .primary
                ? Color(red: 0.06, green: 0.14, blue: 0.12)
                : Color(red: 0.92, green: 0.94, blue: 0.95)
        }

        private var fill: Color {
            switch emphasis {
            case .primary:
                highlighted ? Color(red: 0.65, green: 0.94, blue: 0.83) : PanelButtonStyle.accent
            case .secondary:
                .white.opacity(highlighted ? 0.115 : 0.075)
            case .quiet:
                highlighted ? .white.opacity(0.09) : .clear
            }
        }

        var body: some View {
            let shape = RoundedRectangle(cornerRadius: 8)
            label
                .font(.system(size: size == .compact ? 12 : 13, weight: .medium))
                .lineLimit(1)
                .padding(.horizontal, size == .icon ? 0 : 10)
                .frame(width: size == .icon ? height : nil)
                .frame(maxWidth: fullWidth ? .infinity : nil, minHeight: height)
                .foregroundStyle(foreground)
                .background(fill, in: shape)
                .overlay {
                    if emphasis == .secondary {
                        shape.strokeBorder(.white.opacity(highlighted ? 0.16 : 0.09))
                    }
                }
                .contentShape(.interaction, shape)
                .opacity(enabled ? 1 : 0.45)
                .scaleEffect(pressed && enabled && !reduceMotion ? 0.96 : 1)
                .animation(reduceMotion ? nil : .easeOut(duration: 0.13), value: pressed)
                .onHover { hovering = $0 }
        }
    }
}
