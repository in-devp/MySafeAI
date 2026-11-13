import AppKit
import Darwin
import Foundation
import NetworkDiagnostics
import Observation
import SwiftUI

@MainActor
@Observable
final class BrowserProtection {
    private(set) var installing = false
    private var messageValue: L10n.Value?
    var message: String? { messageValue.map { L10n.text($0) } }
    private(set) var writeFailed = false
    @ObservationIgnored private var heartbeat: Task<Void, Never>?
    @ObservationIgnored private var provider: (@MainActor () -> BrowserAccessSnapshot?)?
    @ObservationIgnored private var terminationObserver: NSObjectProtocol?
    @ObservationIgnored private var published = false
    @ObservationIgnored private var stopped = false

    private static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MySafeAI", isDirectory: true)
    }

    private static var stateFile: URL { directory.appendingPathComponent("browser-state.json") }

    func start(_ provider: @escaping @MainActor () -> BrowserAccessSnapshot?) {
        // A window smoke test must never overwrite the live user's permission.
        guard !CommandLine.arguments.contains("--smoke-window"), heartbeat == nil else { return }
        self.provider = provider
        published = true
        revoke()
        publish()
        terminationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.shutdown() }
        }
        heartbeat = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled, self != nil else { break }
                self?.publish()
            }
        }
    }

    func publish() {
        guard !stopped, let provider else { return }
        guard let snapshot = provider() else {
            revoke()
            return
        }
        do {
            try Self.write(snapshot)
            published = true
            writeFailed = false
        } catch {
            // Leave no last-known permission when publishing fails. If removal
            // also fails, the native host still expires the previous short lease.
            published = true
            revoke()
            writeFailed = true
        }
    }

    func connect(onInstalled: @escaping @MainActor () -> Void) {
        guard !installing else { return }
        guard !Bundle.main.bundleURL.path.contains("/AppTranslocation/") else {
            messageValue = "Перенесите MySafeAI в «Программы», откройте оттуда и повторите подключение."
            return
        }
        guard let executable = Bundle.main.executableURL?.deletingLastPathComponent()
            .appendingPathComponent("mysafeai-browser-host"),
              FileManager.default.isExecutableFile(atPath: executable.path) else {
            messageValue = "В этой сборке нет компонента браузера. Установите актуальную полную сборку MySafeAI."
            return
        }
        installing = true
        messageValue = nil
        Task {
            let installed = await Task.detached(priority: .utility) {
                Self.installHost(executable)
            }.value
            installing = false
            if installed {
                onInstalled()
                messageValue = "Связь настроена. Установите расширение по инструкции и откройте его в браузере."
            } else {
                messageValue = "Не удалось настроить связь. Проверьте доступ к настройкам браузеров и повторите попытку."
            }
        }
    }

    private func shutdown() {
        stopped = true
        heartbeat?.cancel()
        heartbeat = nil
        published = true
        revoke()
    }

    private func revoke() {
        guard published else { return }
        do {
            try FileManager.default.removeItem(at: Self.stateFile)
            published = false
            writeFailed = false
        } catch let error as CocoaError where error.code == .fileNoSuchFile {
            published = false
            writeFailed = false
        } catch {
            writeFailed = true
        }
    }

    private static func write(_ snapshot: BrowserAccessSnapshot) throws {
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        let temporary = directory.appendingPathComponent(".browser-state-" + UUID().uuidString)
        defer { try? manager.removeItem(at: temporary) }
        let data = try JSONEncoder().encode(snapshot)
        guard manager.createFile(atPath: temporary.path, contents: data,
                                 attributes: [.posixPermissions: 0o600]),
              rename(temporary.path, stateFile.path) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private nonisolated static func installHost(_ executable: URL) -> Bool {
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--install", "all"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while process.isRunning, ContinuousClock.now < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if process.isRunning {
                process.terminate()
                return false
            }
            process.waitUntilExit()
            return process.terminationReason == .exit && process.terminationStatus == 0
        } catch {
            return false
        }
    }
}

struct BrowserProtectionSettings: View {
    let model: MonitorModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.text("Защита сайтов в браузере"))
                .font(.system(size: 12, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 10) {
                Toggle(L10n.text("Связь с расширением"), isOn: Binding(
                    get: { model.protection.browserProtectionEnabled },
                    set: { model.setBrowserProtectionEnabled($0) }
                ))
                .toggleStyle(.switch)
                .controlSize(.small)
                Text(L10n.text("Расширение приостанавливает выбранные AI-сайты. Остальные вкладки и сам браузер продолжают работать."))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                Button(model.browser.installing ? L10n.text("Подключаем…") : L10n.text("Подключить расширение")) {
                    model.connectBrowserExtension()
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
                .disabled(model.browser.installing)
                HStack(spacing: 14) {
                    Link(L10n.text("Скачать расширение"), destination: URL(string: "https://github.com/in-devp/MySafeAI/releases/latest")!)
                    Link(L10n.text("Инструкция"), destination: URL(string: "https://github.com/in-devp/MySafeAI/blob/main/docs/browser-extension.md")!)
                }
                .font(.system(size: 11))
            }
            .padding(10)
            .panelGroup()
            Text(L10n.text("Chrome, Edge, Brave и Firefox. Используется общая политика IP. Проверка не подтверждает отдельный выход браузера через его прокси. При отключённой связи сайты в расширении остаются заблокированы."))
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let message = model.browser.message {
                Text(message).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if model.browser.writeFailed {
                Label(L10n.text("Не удалось обновить состояние для расширения. Доступ к сайтам остаётся закрытым."),
                      systemImage: "exclamationmark.triangle")
                    .font(.system(size: 11)).foregroundStyle(.orange)
            }
        }
    }
}
