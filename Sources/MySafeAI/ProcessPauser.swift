import Darwin
import Foundation

/// Persists ownership of pauses before signalling a process. A watchdog restarts the monitor after a crash.
@MainActor
final class ProcessPauser {
    private var worker: Process?
    private var lifetime: Pipe?
    private let store: PauseRecoveryStore
    private let executable: URL
    private var onWorkerExit: @MainActor @Sendable () -> Void

    private var stopped: [ProcessIdentity] {
        get { store.state.stopped }
        set { store.state.stopped = newValue }
    }

    var isAvailable: Bool { worker?.isRunning == true }
    var restoredSession: Bool { store.restored }
    var pausedCount: Int { stopped.filter(Self.isStopped).count }

    static var requiresRecovery: Bool {
        do {
            guard let state = try PauseRecoveryStore.read() else { return false }
            return state.mode == .guarding || !state.stopped.isEmpty
        } catch {
            // An unreadable journal requires user-visible recovery, without releasing processes.
            return true
        }
    }

    init(directory: URL = PauseRecoveryStore.directory,
         onWorkerExit: @escaping @MainActor @Sendable () -> Void) throws {
        store = try PauseRecoveryStore(directory: directory)
        executable = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        self.onWorkerExit = onWorkerExit
        try startWorker()
        try store.save()
        for identity in stopped {
            guard let info = ProcessIdentity.info(identity.pid), ProcessIdentity(info) == identity,
                  info.pbi_status != UInt32(SSTOP) else { continue }
            if kill(identity.pid, SIGSTOP) != 0 && errno != ESRCH { throw Failure.pauseFailed }
        }
    }

    func rearm(onWorkerExit: (@MainActor @Sendable () -> Void)? = nil) throws {
        if let onWorkerExit { self.onWorkerExit = onWorkerExit }
        store.state.mode = .guarding
        try store.save()
        if !isAvailable { try startWorker() }
    }

    func hasPause(_ identity: ProcessIdentity) -> Bool {
        stopped.contains(identity) && Self.isStopped(identity)
    }

    private nonisolated static func isStopped(_ identity: ProcessIdentity) -> Bool {
        guard let info = ProcessIdentity.info(identity.pid) else { return false }
        return ProcessIdentity(info) == identity && info.pbi_status == UInt32(SSTOP)
    }

    func pause(_ roots: [ProcessIdentity]) throws -> Int {
        try pauseTrees(roots.map { ($0, nil) })
    }

    func pause(_ roots: [ProcessIdentity: String]) throws -> Int {
        try pauseTrees(roots.map { ($0.key, Optional($0.value)) })
    }

    private func pauseTrees(_ roots: [(ProcessIdentity, String?)]) throws -> Int {
        guard isAvailable else { throw Failure.recoveryUnavailable }
        stopped.removeAll { !$0.isRunning }
        let live = Set(stopped)
        store.state.targetOwners = store.state.targetOwners?.filter { live.contains($0.key) }
        for (root, owner) in roots.sorted(by: {
            ($0.0.startedSeconds, $0.0.startedMicroseconds, $0.0.pid) < ($1.0.startedSeconds, $1.0.startedMicroseconds, $1.0.pid)
        }) {
            var visited: Set<ProcessIdentity> = []
            try pauseTree(root, owner: owner, visited: &visited)
        }
        return pausedCount
    }

    func resumeAll() throws {
        try store.resumeRecorded()
    }

    func resumeAllowed(_ allowed: Set<String>, allAllowed: Bool, excluding: Set<ProcessIdentity> = []) throws {
        let owners = store.state.targetOwners ?? [:]
        let shouldResume: (ProcessIdentity) -> Bool = {
            !excluding.contains($0) && (owners[$0]?.isSubset(of: allowed) ?? allAllowed)
        }
        guard stopped.contains(where: shouldResume) else { return }
        try store.resumeRecorded(where: shouldResume)
    }

    func retiredPolicyOwners(known: Set<String>) -> Set<String> {
        let owners = store.state.targetOwners ?? [:]
        return Set(owners.values.flatMap { $0 }.filter { owner in
            !owner.hasPrefix(PauseRecoveryStore.admissionPrefix) && !known.contains(owner)
        })
    }

    func canResume(_ identity: ProcessIdentity, allowed: Set<String>) -> Bool {
        hasPause(identity) && store.state.targetOwners?[identity]?.isSubset(of: allowed) == true
    }

    func adoptSuspended(_ identity: ProcessIdentity, owner: String, admission: String) throws {
        guard isAvailable else { throw Failure.recoveryUnavailable }
        guard let info = ProcessIdentity.info(identity.pid), ProcessIdentity(info) == identity,
              info.pbi_status == UInt32(SSTOP) else { return }
        try record(identity, owner: admission)
        try record(identity, owner: owner)
    }

    func closable(previouslyAllowed: Set<String>) -> Set<ProcessIdentity> {
        Set(stopped.filter { identity in
            guard hasPause(identity), let owners = store.state.targetOwners?[identity] else { return false }
            return !owners.isDisjoint(with: previouslyAllowed) &&
                !owners.contains { $0.hasPrefix(PauseRecoveryStore.admissionPrefix) }
        })
    }

    func requestClose(_ identities: Set<ProcessIdentity>, desktopRoots: Set<ProcessIdentity>,
                      terminateDesktop: (ProcessIdentity) -> Void) {
        for identity in stopped.reversed() where identities.contains(identity) && hasPause(identity) {
            if desktopRoots.contains(identity) { terminateDesktop(identity) }
            else if store.state.targetOwners?[identity]?.allSatisfy({ $0.hasPrefix("cli:") }) == true {
                _ = kill(identity.pid, SIGTERM)
            }
        }
    }

    func closePaused(only identities: Set<ProcessIdentity>? = nil) throws -> Int {
        var closed = 0
        var failed = false
        for identity in Array(stopped.reversed()) {
            guard identities?.contains(identity) ?? true else { continue }
            guard let info = ProcessIdentity.info(identity.pid), ProcessIdentity(info) == identity,
                  info.pbi_status == UInt32(SSTOP) else { continue }
            if kill(identity.pid, SIGKILL) == 0 {
                closed += 1
            } else if errno != ESRCH {
                failed = true
                continue
            }
            stopped.removeAll { $0 == identity }
            store.state.targetOwners?.removeValue(forKey: identity)
        }
        try store.save()
        if failed { throw Failure.closeFailed }
        return closed
    }

    func finish() throws {
        try store.finish()
        disarmWorker()
    }

    static func releasePendingProtection() throws {
        let store = try PauseRecoveryStore()
        try store.finish()
    }

    private func startWorker() throws {
        disarmWorker()
        let pipe = Pipe()
        let writer = pipe.fileHandleForWriting.fileDescriptor
        guard fcntl(writer, F_SETFD, FD_CLOEXEC) != -1,
              fcntl(writer, F_SETNOSIGPIPE, 1) != -1 else {
            throw Failure.recoveryUnavailable
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--recover-paused", store.state.token.uuidString]
        process.standardInput = pipe
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] ended in
            Task { @MainActor in
                guard let self, self.worker === ended else { return }
                self.onWorkerExit()
            }
        }
        lifetime = pipe
        worker = process
        do {
            try process.run()
        } catch {
            worker = nil
            lifetime = nil
            throw error
        }
    }

    private func disarmWorker() {
        worker?.terminationHandler = nil
        // The stop request is also persisted by finish(), so EOF during shutdown can complete it.
        try? lifetime?.fileHandleForWriting.write(contentsOf: Data([1]))
        try? lifetime?.fileHandleForWriting.close()
        lifetime = nil
        worker = nil
    }

    private func record(_ identity: ProcessIdentity, owner: String?) throws {
        let before = store.state
        var changed = false
        if !stopped.contains(identity) {
            stopped.append(identity)
            changed = true
        }
        if let owner, store.state.targetOwners?[identity]?.contains(owner) != true {
            var owners = store.state.targetOwners ?? [:]
            owners[identity, default: []].insert(owner)
            store.state.targetOwners = owners
            changed = true
        }
        if changed {
            do { try store.save() } catch {
                store.state = before
                throw error
            }
        }
    }

    private func pauseTree(_ identity: ProcessIdentity, owner: String?, visited: inout Set<ProcessIdentity>) throws {
        guard visited.insert(identity).inserted, let info = ProcessIdentity.info(identity.pid),
              ProcessIdentity(info) == identity, identity.pid != worker?.processIdentifier else { return }

        if info.pbi_status != SSTOP {
            try record(identity, owner: owner)
            guard let current = ProcessIdentity.info(identity.pid), ProcessIdentity(current) == identity else {
                stopped.removeAll { $0 == identity }
                store.state.targetOwners?.removeValue(forKey: identity)
                try store.save()
                return
            }
            if kill(identity.pid, SIGSTOP) != 0 {
                let disappeared = errno == ESRCH
                stopped.removeAll { $0 == identity }
                store.state.targetOwners?.removeValue(forKey: identity)
                try store.save()
                if disappeared { return }
                throw Failure.pauseFailed
            }
        } else if stopped.contains(identity) {
            try record(identity, owner: owner)
        }

        let children = Self.children(of: identity.pid)
        guard identity.isRunning else { return }
        for pid in children {
            guard let child = ProcessIdentity.info(pid), child.pbi_ppid == UInt32(identity.pid) else { continue }
            try pauseTree(ProcessIdentity(child), owner: owner, visited: &visited)
        }
    }

    private static func children(of pid: pid_t) -> [pid_t] {
        var pids = [pid_t](repeating: 0, count: 32)
        while true {
            let capacity = pids.count
            let count = pids.withUnsafeMutableBufferPointer {
                Int(proc_listchildpids(pid, $0.baseAddress, Int32(capacity * MemoryLayout<pid_t>.stride)))
            }
            if count < capacity { return Array(pids.prefix(max(0, count))) }
            pids = [pid_t](repeating: 0, count: capacity * 2)
        }
    }

    enum Failure: Error {
        case recoveryUnavailable
        case pauseFailed
        case closeFailed
    }
}
