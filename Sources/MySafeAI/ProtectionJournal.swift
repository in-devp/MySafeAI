import Foundation
import Observation

struct ProtectionEvent: Codable, Identifiable {
    enum Kind: String, Codable {
        case enabled, disabled, paused, resumed, approved, declined, closing, closed, closeFailed, checked, recovered, failed

        var title: String {
            switch self {
            case .enabled: "Защита включена"
            case .disabled: "Защита выключена"
            case .paused: "Процессы на паузе"
            case .resumed: "Работа продолжена"
            case .approved: "IP разрешён"
            case .declined: "IP отклонён"
            case .closing: "Запрошено закрытие приложений"
            case .closed: "Приложения закрыты после обрыва"
            case .closeFailed: "Не удалось закрыть все процессы"
            case .checked: "Проверка утечек"
            case .recovered: "Контроль защиты восстановлен"
            case .failed: "Ошибка защиты"
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
