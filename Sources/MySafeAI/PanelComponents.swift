import SwiftUI

struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrangement(width: proposal.width, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrangement(width: bounds.width, subviews: subviews)
        for (subview, origin) in zip(subviews, result.origins) {
            subview.place(at: CGPoint(x: bounds.minX + origin.x, y: bounds.minY + origin.y),
                          proposal: ProposedViewSize(width: bounds.width, height: nil))
        }
    }

    private func arrangement(width: CGFloat?, subviews: Subviews) -> (size: CGSize, origins: [CGPoint]) {
        let limit = max(0, width ?? .infinity)
        var origins: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var contentWidth: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(ProposedViewSize(width: width, height: nil))
            if x > 0 && x + size.width > limit {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            origins.append(CGPoint(x: x, y: y))
            contentWidth = max(contentWidth, x + size.width)
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return (CGSize(width: contentWidth, height: y + rowHeight), origins)
    }
}

extension View {
    func panelGroup() -> some View {
        padding(3)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.white.opacity(0.048), in: .rect(cornerRadius: 12))
            .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(.white.opacity(0.08)) }
    }
}

struct PanelGroupDivider: View {
    var inset: CGFloat = 12

    var body: some View {
        Rectangle()
            .fill(.white.opacity(0.07))
            .frame(height: 1)
            .padding(.leading, inset)
            .padding(.trailing, 10)
            .accessibilityHidden(true)
    }
}

struct PanelSelectionMark: View {
    let selected: Bool

    var body: some View {
        Image(systemName: selected ? "checkmark.circle.fill" : "circle")
            .font(.system(size: 15, weight: .medium))
            .foregroundStyle(selected ? PanelButtonStyle.accent : Color.secondary)
            .frame(width: 20)
            .accessibilityHidden(true)
    }
}

struct PanelIconTile: View {
    let symbol: String

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(.secondary)
            .frame(width: 24, height: 24)
            .background(.white.opacity(0.07), in: .rect(cornerRadius: 6))
            .accessibilityHidden(true)
    }
}
