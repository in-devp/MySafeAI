import Foundation
import Observation
import ServiceManagement
import UserNotifications

@MainActor
@Observable
final class BackgroundOptions {
    private static let notificationsKey = "showsProtectionNotifications"
    private(set) var loginStatus = SMAppService.mainApp.status
    private(set) var notifications = UserDefaults.standard.bool(forKey: notificationsKey)
    private(set) var message: String?
    @ObservationIgnored private var lastStatus: ProtectionController.Status?
    @ObservationIgnored private var notificationRequest = UUID()

    func refresh() {
        loginStatus = SMAppService.mainApp.status
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        message = nil
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            message = "macOS не применила настройку. Проверьте объекты входа в системных настройках."
        }
        refresh()
    }

    func openLoginSettings() { SMAppService.openSystemSettingsLoginItems() }

    func setNotifications(_ enabled: Bool) {
        let request = UUID()
        notificationRequest = request
        message = nil
        if !enabled {
            notifications = false
            UserDefaults.standard.set(false, forKey: Self.notificationsKey)
            return
        }
        Task {
            do {
                let granted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
                guard notificationRequest == request else { return }
                notifications = granted
                UserDefaults.standard.set(granted, forKey: Self.notificationsKey)
                if !granted { message = "Разрешите уведомления MySafeAI в системных настройках." }
            } catch {
                guard notificationRequest == request else { return }
                message = "Не удалось включить системные уведомления."
            }
        }
    }

    func announce(_ status: ProtectionController.Status, paused: [String]) {
        if status == .checking || status == lastStatus { return }
        if case .paused = status, paused.isEmpty { return }
        let previous = lastStatus
        lastStatus = status
        guard notifications else { return }
        let content = UNMutableNotificationContent()
        switch status {
        case .paused:
            content.title = "Приложения на паузе"
            content.body = "\(paused.joined(separator: ", ")). \(status.title)."
        case .trusted:
            guard let previous, case .paused = previous else { return }
            content.title = "Доверенный маршрут восстановлен"
            content.body = "MySafeAI возобновил разрешённые приложения."
        case .failed:
            content.title = "Ошибка защиты"
            content.body = "Откройте MySafeAI, чтобы восстановить контроль."
        default:
            return
        }
        UNUserNotificationCenter.current().add(UNNotificationRequest(
            identifier: "protection-status", content: content, trigger: nil
        )) { _ in }
    }
}
