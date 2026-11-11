import AppKit
import Observation
import SwiftUI

@main
@MainActor
final class MySafeAIApp: NSObject, NSApplicationDelegate, NSPopoverDelegate, NSWindowDelegate {
    private let model = MonitorModel()
    private let popover = NSPopover()
    private var statusItem: NSStatusItem?
    private var offeredAddresses: [String] = []
    private var approvalPanel: NSPanel?

    static func main() {
        let arguments = CommandLine.arguments
        if arguments.dropFirst().first == "run" {
            exit(ManagedCLI.run(Array(arguments.dropFirst(2))))
        }
        if arguments.count == 3, arguments[1] == "--recover-paused" {
            if let token = UUID(uuidString: arguments[2]) { ProcessPauser.recover(token) }
            return
        }
        if arguments.count > 1, arguments[1] == "--restore-paused" {
            guard arguments.count == 3, let token = UUID(uuidString: arguments[2]),
                  (try? PauseRecoveryStore.read())?.token == token else { return }
        }
        let application = NSApplication.shared
        do {
            let instance = try LocalProcessLock(directory: PauseRecoveryStore.directory, name: "application.lock")
            let delegate = MySafeAIApp()
            application.setActivationPolicy(.accessory)
            application.delegate = delegate
            withExtendedLifetime((delegate, instance)) {
                application.run()
            }
        } catch LocalProcessLock.Failure.alreadyOwned {
            return
        } catch {
            let alert = NSAlert()
            alert.messageText = "Не удалось открыть состояние защиты"
            alert.informativeText = "Проверьте доступ к папке MySafeAI в Application Support и запустите приложение повторно."
            alert.runModal()
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        popover.behavior = .transient
        popover.animates = false
        popover.appearance = NSAppearance(named: .darkAqua)
        popover.delegate = self

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem = item
        item.button?.target = self
        item.button?.action = #selector(togglePopover)
        observeProtectionStatus()

        let workspace = NSWorkspace.shared.notificationCenter
        workspace.addObserver(self, selector: #selector(applicationLaunched),
                              name: NSWorkspace.didLaunchApplicationNotification, object: nil)
        workspace.addObserver(self, selector: #selector(willSleep),
                              name: NSWorkspace.willSleepNotification, object: nil)
        workspace.addObserver(self, selector: #selector(didWake),
                              name: NSWorkspace.didWakeNotification, object: nil)
        model.startProtectionIfConfigured()
    }

    func applicationWillTerminate(_ notification: Notification) {
        model.protection.stop()
    }

    @objc private func applicationLaunched() { model.protection.enforce() }
    @objc private func willSleep() { model.sleepChanged(true) }
    @objc private func didWake() { model.sleepChanged(false) }

    func popoverDidClose(_ notification: Notification) {
        model.panelVisibilityChanged(approvalPanel?.isVisible == true)
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, window === approvalPanel else { return }
        model.panelVisibilityChanged(popover.isShown)
    }

    private func observeProtectionStatus() {
        withObservationTracking {
            let status = model.protection.status
            model.background.announce(status, paused: model.protection.pausedApplications)
            let pending = model.protection.pendingAddresses
            let needsApproval = !pending.isEmpty && pending != model.protection.declinedAddresses
            let indicator: BrandMark.Indicator
            switch status {
            case .off: indicator = .off
            case .trusted: indicator = .trusted
            case .checking: indicator = .checking
            case .paused: indicator = .paused
            case .failed: indicator = .warning
            }
            let label = needsApproval ? "MySafeAI · Подтвердить IP VPN" : "MySafeAI · \(status.title)"
            statusItem?.button?.image = BrandMark.menuIcon(needsApproval ? .warning : indicator, label: label)
            statusItem?.button?.toolTip = label
            if status == .trusted || status == .off {
                offeredAddresses = []
                if approvalPanel?.isVisible == true {
                    Task { @MainActor [weak self] in self?.approvalPanel?.close() }
                }
            }
            if needsApproval, pending != offeredAddresses {
                Task { @MainActor [weak self] in self?.showApproval(for: pending) }
            }
        } onChange: { [weak self] in
            Task { @MainActor in self?.observeProtectionStatus() }
        }
    }

    @objc private func togglePopover(_ sender: NSStatusBarButton) {
        if approvalPanel?.isVisible == true {
            approvalPanel?.makeKeyAndOrderFront(nil)
            return
        }
        if popover.isShown {
            popover.close()
            return
        }

        showPopover(at: sender, activate: true)
    }

    private func showApproval(for addresses: [String]) {
        guard addresses == model.protection.pendingAddresses,
              addresses != model.protection.declinedAddresses,
              addresses != offeredAddresses else { return }
        if !popover.isShown && approvalPanel?.isVisible != true {
            if let button = statusItem?.button { showPopover(at: button, activate: false) }
            if !popover.isShown { showApprovalPanel() }
        }
        if popover.isShown || approvalPanel?.isVisible == true { offeredAddresses = addresses }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if approvalPanel?.isVisible == true {
            approvalPanel?.makeKeyAndOrderFront(nil)
            return true
        }
        if !popover.isShown, let button = statusItem?.button {
            showPopover(at: button, activate: true)
        }
        return true
    }

    private func showApprovalPanel() {
        let panel = approvalPanel ?? NSPanel(
            contentRect: CGRect(origin: .zero, size: Dashboard.size),
            styleMask: [.titled, .closable, .nonactivatingPanel],
            backing: .buffered, defer: false
        )
        panel.title = "MySafeAI"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.appearance = NSAppearance(named: .darkAqua)
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.level = .floating
        panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        panel.delegate = self
        panel.contentViewController = NSHostingController(rootView: Dashboard(model: model))
        panel.setContentSize(Dashboard.size)
        panel.center()
        approvalPanel = panel
        panel.orderFrontRegardless()
        model.panelVisibilityChanged(true)
    }

    private func showPopover(at button: NSStatusBarButton, activate: Bool) {
        model.background.refresh()
        let controller = NSHostingController(rootView: Dashboard(model: model))
        popover.contentViewController = controller
        popover.contentSize = Dashboard.size
        if activate { NSApplication.shared.activate() }
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        if activate { controller.view.window?.makeKey() }
        if popover.isShown { model.panelVisibilityChanged(true) }
    }
}
