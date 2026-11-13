import Darwin
import Foundation
import NetworkDiagnostics

struct ManagedCommand: Codable, Sendable, Identifiable {
    let id: UUID
    let parent: ProcessIdentity
    let process: ProcessIdentity
    let target: CLIProtectionTarget?

    var protectionTarget: ProtectionTarget { target.map(ProtectionTarget.cli) ?? .managed }
    var admitted: Bool { FileManager.default.fileExists(atPath: path(extension: "admitted").path) }
    var admission: String { PauseRecoveryStore.admissionPrefix + id.uuidString }

    private static var directory: URL {
        PauseRecoveryStore.directory.appendingPathComponent("Commands", isDirectory: true)
    }

    static func active() -> [Self] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.compactMap { file in
            guard file.pathExtension == "json", let data = try? Data(contentsOf: file),
                  let item = try? JSONDecoder().decode(Self.self, from: data),
                  file.lastPathComponent == item.path(extension: "json").lastPathComponent else { return nil }
            guard let info = ProcessIdentity.info(item.process.pid), ProcessIdentity(info) == item.process else {
                item.remove()
                return nil
            }
            if item.admitted { return item }
            if !item.parent.isRunning {
                if info.pbi_status == UInt32(SSTOP) { _ = kill(item.process.pid, SIGKILL) }
                item.remove()
                return nil
            }
            return info.pbi_ppid == UInt32(item.parent.pid) ? item : nil
        }
    }

    func register() throws {
        try FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(self).write(to: path(extension: "json"), options: .atomic)
    }

    func admit() throws -> Bool {
        guard let lock = try? LocalProcessLock(directory: Self.directory, name: id.uuidString + ".lock") else {
            return false
        }
        return try withExtendedLifetime(lock) {
            guard FileManager.default.fileExists(atPath: path(extension: "json").path),
                  !FileManager.default.fileExists(atPath: path(extension: "cancelled").path),
                  parent.isRunning, let info = ProcessIdentity.info(process.pid), ProcessIdentity(info) == process,
                  info.pbi_ppid == UInt32(parent.pid), info.pbi_status == UInt32(SSTOP) else { return false }
            try Data().write(to: path(extension: "admitted"), options: .atomic)
            return true
        }
    }

    func cancelIfPending() -> Bool {
        for _ in 0..<20 {
            if let lock = try? LocalProcessLock(directory: Self.directory, name: id.uuidString + ".lock") {
                return withExtendedLifetime(lock) {
                    guard !admitted else { return false }
                    try? Data().write(to: path(extension: "cancelled"), options: .atomic)
                    if process.isRunning { _ = kill(process.pid, SIGKILL) }
                    return true
                }
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        if !admitted && process.isRunning { _ = kill(process.pid, SIGKILL) }
        return !admitted
    }

    func remove() {
        try? FileManager.default.removeItem(at: path(extension: "json"))
        try? FileManager.default.removeItem(at: path(extension: "admitted"))
        try? FileManager.default.removeItem(at: path(extension: "cancelled"))
        try? FileManager.default.removeItem(at: path(extension: "lock"))
    }

    private func path(extension suffix: String) -> URL {
        Self.directory.appendingPathComponent(id.uuidString).appendingPathExtension(suffix)
    }
}

enum ManagedCLI {
    static func run(_ arguments: [String]) -> Int32 {
        guard arguments.first == "--", arguments.count >= 2 else {
            return error(L10n.text("Использование: mysafeai run -- команда [аргументы]"), code: 64)
        }
        guard let state = try? PauseRecoveryStore.read(), state.mode == .guarding, state.owner.isRunning else {
            return error(L10n.text("Откройте MySafeAI и включите защиту."))
        }
        let command = Array(arguments.dropFirst())
        guard let executable = executablePath(command[0]) else { return error(L10n.text("Команда не найдена."), code: 127) }
        let environment = ProcessInfo.processInfo.environment
        let routeOverrides: Set<String> = [
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL",
            "OPENAI_API_BASE", "CODEX_API_BASE_URL", "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"
        ]
        if environment.contains(where: { routeOverrides.contains($0.key.uppercased()) && !$0.value.isEmpty && $0.value != "0" }) {
            return error(L10n.text("Переменные прокси или адреса провайдера меняют маршрут команды. Уберите их перед запуском через MySafeAI."))
        }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { return error(L10n.text("Не удалось подготовить запуск.")) }
        defer { posix_spawnattr_destroy(&attributes) }
        var blocked = sigset_t()
        var originalMask = sigset_t()
        sigemptyset(&blocked)
        for interrupt in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] { sigaddset(&blocked, interrupt) }
        guard pthread_sigmask(SIG_BLOCK, &blocked, &originalMask) == 0 else {
            return error(L10n.text("Не удалось подготовить запуск."))
        }
        var masking = true
        defer { if masking { pthread_sigmask(SIG_SETMASK, &originalMask, nil) } }
        let flags = Int16(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGMASK)
        guard posix_spawnattr_setsigmask(&attributes, &originalMask) == 0,
              posix_spawnattr_setflags(&attributes, flags) == 0 else {
            return error(L10n.text("Не удалось настроить безопасный запуск."))
        }
        var argv = command.map { strdup($0) } + [nil]
        var env = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            for item in argv { free(item) }
            for item in env { free(item) }
        }
        guard argv.dropLast().allSatisfy({ $0 != nil }), env.dropLast().allSatisfy({ $0 != nil }) else {
            return error(L10n.text("Недостаточно памяти."))
        }
        var pid: pid_t = 0
        let result = argv.withUnsafeMutableBufferPointer { argv in
            env.withUnsafeMutableBufferPointer { env in
                posix_spawn(&pid, executable, nil, &attributes, argv.baseAddress!, env.baseAddress!)
            }
        }
        guard result == 0 else { return error(L10n.text("Не удалось запустить команду (код \(result))."), code: 126) }

        let resolved = URL(fileURLWithPath: executable).resolvingSymlinksInPath().path
        let target = CLIProtectionTarget.identify(executable: resolved, firstArgument: command.dropFirst().first) ??
            CLIProtectionTarget.identify(executable: executable, firstArgument: command.dropFirst().first)
        guard let info = ProcessIdentity.info(pid), let parent = try? ProcessIdentity.current() else {
            _ = kill(pid, SIGKILL)
            _ = waitForExit(pid)
            return error(L10n.text("Не удалось подтвердить процесс."))
        }
        let item = ManagedCommand(id: UUID(), parent: parent, process: ProcessIdentity(info), target: target)
        defer { item.remove() }
        do { try item.register() } catch {
            _ = kill(pid, SIGKILL)
            _ = waitForExit(pid)
            return self.error(L10n.text("Не удалось передать команду монитору."))
        }
        // Until the durable registration exists, don't interrupt the wrapper between spawn and registration.
        masking = false
        pthread_sigmask(SIG_SETMASK, &originalMask, nil)
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        let showProgressAt = clock.now.advanced(by: .milliseconds(700))
        var canShowProgress = isatty(STDERR_FILENO) == 1
        while !item.admitted && clock.now < deadline {
            var status: Int32 = 0
            if waitpid(pid, &status, WNOHANG) == pid { return exitCode(status) }
            if canShowProgress && clock.now >= showProgressAt {
                canShowProgress = false
                try? FileHandle.standardError.write(contentsOf: Data(
                    L10n.text("MySafeAI проверяет маршрут. Новый IP можно подтвердить в строке меню.\n").utf8
                ))
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        if !item.admitted && item.cancelIfPending() {
            _ = waitForExit(pid)
            return error(L10n.text("Маршрут не подтверждён. Команда не запущена."))
        }
        return waitForExit(pid)
    }

    private static func executablePath(_ name: String) -> String? {
        let manager = FileManager.default
        let paths = name.contains("/") ? [name] :
            (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin")
                .components(separatedBy: ":").map { ($0.isEmpty ? "." : $0) + "/" + name }
        return paths.first { manager.isExecutableFile(atPath: $0) }
    }

    private static func waitForExit(_ pid: pid_t) -> Int32 {
        var status: Int32 = 0
        while true {
            let result = waitpid(pid, &status, 0)
            if result == pid { return exitCode(status) }
            if result == -1 && errno != EINTR { return 70 }
        }
    }

    private static func exitCode(_ status: Int32) -> Int32 {
        let signal = status & 0x7f
        return signal == 0 ? (status >> 8) & 0xff : 128 + signal
    }

    private static func error(_ message: String, code: Int32 = 69) -> Int32 {
        try? FileHandle.standardError.write(contentsOf: Data((message + "\n").utf8))
        return code
    }
}
