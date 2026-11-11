import Foundation

public enum CLIProtectionTarget: String, Codable, CaseIterable, Hashable, Sendable {
    case codex
    case claude

    public var title: String {
        switch self {
        case .codex: "Codex CLI"
        case .claude: "Claude Code"
        }
    }

    public static func identify(executable: String, firstArgument: String?) -> Self? {
        let path = URL(fileURLWithPath: executable)
        let name = path.lastPathComponent
        let inBundle = path.pathComponents.contains { $0.hasSuffix(".app") }

        if executable.hasSuffix("/codex-cli/CodexCLI.app/Contents/MacOS/codex") {
            // The desktop app also uses this binary as a backend.
            guard let firstArgument, firstArgument != "app-server" else { return nil }
            return .codex
        }
        guard !inBundle else { return nil }

        if name == "codex" || name == "codex-aarch64-apple-darwin" || name == "codex-x86_64-apple-darwin" {
            return firstArgument == "app-server" ? nil : .codex
        }
        if name == "claude" || (path.deletingLastPathComponent().path.hasSuffix("/.local/share/claude/versions")
                                && name.first?.isNumber == true) {
            return .claude
        }

        guard name == "node", let script = firstArgument, script.hasPrefix("/") else { return nil }
        let resolved = URL(fileURLWithPath: script).resolvingSymlinksInPath().path
        if resolved.hasSuffix("/node_modules/@openai/codex/bin/codex.js") { return .codex }
        if resolved.hasSuffix("/node_modules/@anthropic-ai/claude-code/cli.js") { return .claude }
        return nil
    }
}
