import Darwin
import Foundation

final class LocalProcessLock {
    enum Failure: Error { case alreadyOwned }
    private var descriptor: Int32 = -1

    init(directory: URL, name: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = directory.appendingPathComponent(name).path
        let opened = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard opened >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var info = stat()
        guard fstat(opened, &info) == 0, info.st_uid == getuid(),
              info.st_mode & S_IFMT == S_IFREG else {
            close(opened)
            throw POSIXError(.EACCES)
        }
        guard flock(opened, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(opened)
            if code == EWOULDBLOCK { throw Failure.alreadyOwned }
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
        descriptor = opened
    }

    deinit {
        if descriptor >= 0 { close(descriptor) }
    }
}

struct PauseRecoveryState: Codable {
    enum Mode: String, Codable { case guarding, stopping }
    let version: Int
    let token: UUID
    var owner: ProcessIdentity
    var mode: Mode
    var stopped: [ProcessIdentity]
    var targetOwners: [ProcessIdentity: Set<String>]?
    var restartAttempts: Int?
    var lastRestart: Date?

    init(owner: ProcessIdentity) {
        version = 1
        token = UUID()
        self.owner = owner
        mode = .guarding
        stopped = []
        restartAttempts = 0
        lastRestart = nil
    }
}

final class PauseRecoveryStore {
    static let admissionPrefix = "admission:"
    enum Failure: Error { case invalidJournal, resumeFailed }
    static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MySafeAI/ProcessProtection", isDirectory: true)
    }

    let directory: URL
    private let lock: LocalProcessLock
    var state: PauseRecoveryState
    let restored: Bool

    init(directory: URL = PauseRecoveryStore.directory, adopting: Bool = true) throws {
        self.directory = directory
        lock = try LocalProcessLock(directory: directory, name: "session.lock")
        let previous = try Self.read(directory: directory)
        let owner = try ProcessIdentity.current()
        if var previous {
            guard !previous.owner.isRunning || previous.owner == owner else {
                throw LocalProcessLock.Failure.alreadyOwned
            }
            restored = previous.mode == .guarding || !previous.stopped.isEmpty
            if adopting {
                previous.owner = owner
                previous.mode = .guarding
                previous.stopped.removeAll { !$0.isRunning }
            }
            state = previous
        } else {
            restored = false
            state = PauseRecoveryState(owner: owner)
        }
    }

    private var file: URL { Self.file(in: directory) }

    static func file(in directory: URL) -> URL {
        directory.appendingPathComponent("paused.json")
    }

    static func read(directory: URL = PauseRecoveryStore.directory) throws -> PauseRecoveryState? {
        let data: Data
        do {
            data = try Data(contentsOf: file(in: directory))
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return nil
        }
        let value = try JSONDecoder().decode(PauseRecoveryState.self, from: data)
        guard value.version == 1 else { throw Failure.invalidJournal }
        return value
    }

    func save() throws {
        try JSONEncoder().encode(state).write(to: file, options: .atomic)
    }

    func resumeRecorded(where shouldResume: (ProcessIdentity) -> Bool = { _ in true }) throws {
        var failed = false
        state.stopped = Array(state.stopped.reversed().filter { identity in
            guard shouldResume(identity) else { return identity.isRunning }
            if identity.resume() { return false }
            failed = true
            return true
        }.reversed())
        let remaining = Set(state.stopped)
        state.targetOwners = state.targetOwners?.filter { remaining.contains($0.key) }
        try save()
        if failed { throw Failure.resumeFailed }
    }

    func finish() throws {
        state.mode = .stopping
        try save()
        let pending = state.stopped.filter { identity in
            state.targetOwners?[identity]?.contains { owner in
                guard owner.hasPrefix(Self.admissionPrefix),
                      let id = UUID(uuidString: String(owner.dropFirst(Self.admissionPrefix.count))) else { return false }
                let file = directory.appendingPathComponent("Commands/\(id.uuidString).admitted")
                return !FileManager.default.fileExists(atPath: file.path)
            } == true
        }
        for identity in pending {
            if let info = ProcessIdentity.info(identity.pid), ProcessIdentity(info) == identity,
               kill(identity.pid, SIGKILL) != 0, errno != ESRCH {
                throw Failure.resumeFailed
            }
            state.stopped.removeAll { $0 == identity }
            state.targetOwners?.removeValue(forKey: identity)
        }
        try resumeRecorded()
        try FileManager.default.removeItem(at: file)
    }
}
