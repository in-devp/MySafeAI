import Darwin
import Foundation

extension ProcessPauser {
    nonisolated static func recover(_ token: UUID, directory: URL = PauseRecoveryStore.directory) {
        var byte: UInt8 = 0
        while true {
            let count = read(STDIN_FILENO, &byte, 1)
            if count > 0 { return }
            if count == 0 || errno != EINTR { break }
        }

        for _ in 0..<3 {
            do {
                guard try prepareRestart(token, directory: directory) else { return }
            } catch LocalProcessLock.Failure.alreadyOwned {
                return
            } catch {
                // Preserve the journal and all pauses when recovery state cannot be read or saved.
                return
            }

            let monitor = Process()
            monitor.executableURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
            monitor.arguments = ["--restore-paused", token.uuidString]
            monitor.standardInput = FileHandle.nullDevice
            monitor.standardOutput = FileHandle.nullDevice
            monitor.standardError = FileHandle.nullDevice
            do {
                try monitor.run()
            } catch {
                Thread.sleep(forTimeInterval: 0.5)
                continue
            }

            // Wait for the replacement to claim its journal and install its own watchdog.
            for _ in 0..<50 {
                if let current = try? PauseRecoveryStore.read(directory: directory),
                   current.token != token || current.owner.isRunning {
                    return
                }
                if !monitor.isRunning { break }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if monitor.isRunning { return }
        }
    }

    nonisolated private static func prepareRestart(_ token: UUID, directory: URL) throws -> Bool {
        // EOF can arrive just before the previous process releases its journal lock.
        var store: PauseRecoveryStore?
        for _ in 0..<20 {
            do {
                store = try PauseRecoveryStore(directory: directory, adopting: false)
                break
            } catch LocalProcessLock.Failure.alreadyOwned {
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        guard let store, store.state.token == token else { return false }
        if store.state.mode == .stopping {
            try store.finish()
            return false
        }

        let elapsed = store.state.lastRestart.map { Date.now.timeIntervalSince($0) } ?? 60
        if elapsed < 0 || elapsed >= 60 { store.state.restartAttempts = 0 }
        guard (store.state.restartAttempts ?? 0) < 3 else { return false }
        store.state.restartAttempts = (store.state.restartAttempts ?? 0) + 1
        store.state.lastRestart = .now
        try store.save()
        return true
    }
}
