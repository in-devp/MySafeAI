import AppKit

enum DesktopProtectionTarget: String, Codable, CaseIterable, Hashable {
    case chatGPT, cursor, claude

    var title: String {
        switch self {
        case .chatGPT: "ChatGPT и Codex"
        case .cursor: "Cursor"
        case .claude: "Claude Desktop"
        }
    }

    var symbol: String {
        switch self {
        case .chatGPT: "bubble.left.and.bubble.right"
        case .cursor: "cursorarrow"
        case .claude: "sparkles"
        }
    }

    var bundleIdentifiers: [String] {
        switch self {
        case .chatGPT: ["com.openai.codex", "com.openai.chat"]
        case .cursor: ["com.todesktop.230313mzl4w4u92", "co.anysphere.cursor.nightly"]
        case .claude: ["com.anthropic.claudefordesktop"]
        }
    }

    @MainActor var installedURL: URL? {
        bundleIdentifiers.lazy.compactMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }.first
    }

    static func identify(bundleID: String) -> Self? {
        allCases.first { $0.bundleIdentifiers.contains(bundleID) }
    }
}
