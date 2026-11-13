import NetworkDiagnostics
import Foundation
import Observation

struct ProtectionEvent: Codable, Identifiable {
    enum Kind: String, Codable {
        case enabled, disabled, paused, resumed, approved, declined, closing, closed, closeFailed, checked, recovered, failed

        var title: String {
            switch self {
            case .enabled: L10n.text("Защита включена")
            case .disabled: L10n.text("Защита выключена")
            case .paused: L10n.text("Процессы на паузе")
            case .resumed: L10n.text("Работа продолжена")
            case .approved: L10n.text("IP разрешён")
            case .declined: L10n.text("IP отклонён")
            case .closing: L10n.text("Запрошено закрытие приложений")
            case .closed: L10n.text("Приложения закрыты после обрыва")
            case .closeFailed: L10n.text("Не удалось закрыть все процессы")
            case .checked: L10n.text("Проверка утечек")
            case .recovered: L10n.text("Контроль защиты восстановлен")
            case .failed: L10n.text("Ошибка защиты")
            }
        }

        var icon: String {
            switch self {
            case .enabled, .approved: "checkmark.shield"
            case .disabled: "shield.slash"
            case .paused: "pause.circle"
            case .resumed: "play.circle"
            case .closing, .closed: "stop.circle"
            case .checked: "network.badge.shield.half.filled"
            case .recovered: "arrow.clockwise"
            case .declined, .closeFailed, .failed: "exclamationmark.circle"
            }
        }
    }

    let id: UUID
    let date: Date
    let kind: Kind
    let detail: String

    var localizedDetail: String {
        // Older journals contain rendered messages. Translate only the known
        // summaries; application names and addresses must remain user data.
        let messages: [L10n.Value]
        switch kind {
        case .checked:
            messages = ["Есть риски утечки", "Часть проверок не завершена", "Проверки завершены"]
        case .disabled:
            messages = ["Пауза на 15 минут"]
        default:
            return detail
        }
        if let message = messages.first(where: {
            L10n.text($0, language: "ru") == detail || L10n.text($0, language: "en") == detail
        }) { return L10n.text(message) }
        return detail
    }
}

@MainActor
@Observable
final class ProtectionJournal {
    private(set) var events: [ProtectionEvent]
    private(set) var writeFailed = false
    private let file: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        file = support.appendingPathComponent("MySafeAI/protection-events.json")
        let data = try? Data(contentsOf: file)
        events = data.flatMap { try? JSONDecoder().decode([ProtectionEvent].self, from: $0) } ?? []
    }

    func append(_ kind: ProtectionEvent.Kind, detail: String = "") {
        events.insert(.init(id: UUID(), date: .now, kind: kind, detail: detail), at: 0)
        if events.count > 250 { events.removeLast(events.count - 250) }
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            try JSONEncoder().encode(events).write(to: file, options: .atomic)
            writeFailed = false
        } catch {
            writeFailed = true
        }
    }
}
