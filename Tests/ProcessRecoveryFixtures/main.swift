import Darwin
import Foundation

@main
@MainActor
struct RecoveryFixture {
    static var pauser: ProcessPauser?
    static var roots: [ProcessIdentity] = []
    static var directory: URL!

    static func record(_ phase: String) throws {
        let value: [String: Any] = ["pid": getpid(), "phase": phase,
                                   "restored": pauser?.restoredSession == true]
        try JSONSerialization.data(withJSONObject: value)
            .write(to: directory.appendingPathComponent("ready.json"), options: .atomic)
    }

    static func main() {
        do {
            try run()
        } catch {
            FileHandle.standardError.write(Data("Recovery fixture: \(error)\n".utf8))
            exit(2)
        }
    }

    static func run() throws {
        directory = URL(fileURLWithPath: ProcessInfo.processInfo.environment["RECOVERY_FIXTURE_DIRECTORY"]!)
        let arguments = CommandLine.arguments
        if arguments.count == 3, arguments[1] == "--recover-paused",
           let token = UUID(uuidString: arguments[2]) {
            ProcessPauser.recover(token, directory: directory)
            return
        }
        let pids = try JSONDecoder().decode([pid_t].self, from: Data(
            contentsOf: directory.appendingPathComponent("targets.json")
        ))
        roots = pids.compactMap { ProcessIdentity.info($0).map(ProcessIdentity.init) }
        pauser = try ProcessPauser(directory: directory) {
            do {
                try pauser?.rearm()
                _ = try pauser?.pause(roots)
                try record("watchdog-rearmed")
            } catch {
                try? record("failed")
            }
        }
        let restored = arguments.count == 3 && arguments[1] == "--restore-paused"
        if restored || ProcessInfo.processInfo.environment["RECOVERY_FIXTURE_TRUSTED"] != "1" {
            if ProcessInfo.processInfo.environment["RECOVERY_FIXTURE_SCOPED"] == "1" {
                let childPIDs = try String(contentsOf: directory.appendingPathComponent("tree"), encoding: .utf8)
                guard let pid = childPIDs.split(separator: " ").first.flatMap({ pid_t($0) }),
                      let child = ProcessIdentity.info(pid).map(ProcessIdentity.init), let root = roots.first else {
                    throw POSIXError(.ESRCH)
                }
                _ = try pauser?.pause([root: "cli:parent", child: "cli:child"])
            } else {
                _ = try pauser?.pause(roots)
            }
        }
        try record(restored ? "restored" : "ready")
        Task { @MainActor in
            let commandFile = directory.appendingPathComponent("command")
            while true {
                if let command = try? String(contentsOf: commandFile, encoding: .utf8) {
                    try? FileManager.default.removeItem(at: commandFile)
                    do {
                        switch command {
                        case "trust":
                            try pauser?.resumeAll()
                            try record("trusted")
                        case "trust-parent":
                            try pauser?.resumeAllowed(["cli:parent"], allAllowed: false)
                            try record("parent-trusted")
                        case "close-child":
                            if let pauser {
                                let closing = pauser.closable(previouslyAllowed: ["cli:child"])
                                pauser.requestClose(closing, desktopRoots: []) { _ in }
                                try pauser.resumeAllowed(["cli:child", "cli:parent"], allAllowed: false, excluding: closing)
                                try await Task.sleep(for: .milliseconds(150))
                                _ = try pauser.closePaused(only: closing)
                            }
                            try record("child-closed")
                        case "stop":
                            try pauser?.finish()
                            try record("stopped")
                            exit(0)
                        default:
                            exit(3)
                        }
                    } catch {
                        try? record("failed")
                    }
                }
                try? await Task.sleep(for: .milliseconds(50))
            }
        }
        RunLoop.main.run()
    }
}
