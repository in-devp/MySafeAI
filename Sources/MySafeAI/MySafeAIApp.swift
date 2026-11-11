import AppKit
import Carbon
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
    private var desktopWindow: NSWindow?
    private let applicationIcon = Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
        .flatMap { NSImage(contentsOf: $0) } ?? BrandMark.badge
    private let restoring: Bool
    private let smokeWindow: Bool
    private var trayOnly: Bool
    private static let trayOnlyKey = "trayOnly"

    private init(restoring: Bool, smokeWindow: Bool) {
        self.restoring = restoring
        self.smokeWindow = smokeWindow
        self.trayOnly = !smokeWindow && UserDefaults.standard.bool(forKey: Self.trayOnlyKey)
    }

    static func main() {
        let arguments = CommandLine.arguments
        if arguments.dropFirst().first == "run" {
            exit(ManagedCLI.run(Array(arguments.dropFirst(2))))
        }
        if arguments.count == 3, arguments[1] == "--recover-paused" {
            if let token = UUID(uuidString: arguments[2]) { ProcessPauser.recover(token) }
            return
        }
        let restoring = arguments.dropFirst().first == "--restore-paused"
        if restoring {
            guard arguments.count == 3, let token = UUID(uuidString: arguments[2]),
                  (try? PauseRecoveryStore.read())?.token == token else { return }
        }
        let application = NSApplication.shared
        let smokeWindow = arguments.dropFirst().first == "--smoke-window"
        if smokeWindow {
            let delegate = MySafeAIApp(restoring: false, smokeWindow: true)
            application.delegate = delegate
            withExtendedLifetime(delegate) { application.run() }
            exit(1)
        }
        do {
            let instance = try LocalProcessLock(directory: PauseRecoveryStore.directory, name: "application.lock")
            let delegate = MySafeAIApp(restoring: restoring, smokeWindow: false)
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

        installMenu()
        if smokeWindow {
            showDesktopWindow()
            Task { @MainActor in
                guard self.desktopWindow?.isVisible == true, NSApp.activationPolicy() == .regular else { exit(1) }
                let finderIcon = NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath)
                guard let expected = self.iconCenter(self.applicationIcon),
                      let dock = self.iconCenter(NSApp.applicationIconImage),
                      let finder = self.iconCenter(finderIcon),
                      [dock, finder].allSatisfy({
                          abs($0.blueComponent - expected.blueComponent) < 0.06 &&
                              abs($0.redComponent - expected.redComponent) < 0.06
                      }) else {
                    print("The Dock or Finder did not load the MySafeAI icon")
                    exit(1)
                }
                self.setTrayOnly(true)
                guard self.desktopWindow?.isVisible == false, NSApp.activationPolicy() == .accessory else { exit(1) }
                self.openDesktopMode()
                guard self.desktopWindow?.isVisible == true, NSApp.activationPolicy() == .regular else { exit(1) }
                print("macOS desktop window, tray mode and reopen passed")
                exit(0)
            }
            return
        }
        let launchKind = NSAppleEventManager.shared().currentAppleEvent?
            .paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue
        if !trayOnly && !restoring && launchKind != keyAELaunchedAsLogInItem {
            showDesktopWindow()
        }

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
        updatePanelVisibility()
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        updatePanelVisibility(excluding: window)
    }

    func windowDidMiniaturize(_ notification: Notification) { updatePanelVisibility() }
    func windowDidDeminiaturize(_ notification: Notification) { updatePanelVisibility() }

    private var desktopVisible: Bool {
        desktopWindow?.isVisible == true && desktopWindow?.isMiniaturized == false
    }

    private func updatePanelVisibility(excluding window: NSWindow? = nil) {
        guard !smokeWindow else { return }
        let hasDesktop = desktopVisible && (window == nil || window !== desktopWindow)
        let hasApproval = approvalPanel?.isVisible == true && (window == nil || window !== approvalPanel)
        model.panelVisibilityChanged(popover.isShown || hasDesktop || hasApproval)
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
        if desktopVisible {
            offeredAddresses = addresses
            return
        }
        if !popover.isShown && approvalPanel?.isVisible != true {
            if let button = statusItem?.button { showPopover(at: button, activate: false) }
            if !popover.isShown { showApprovalPanel() }
        }
        if popover.isShown || approvalPanel?.isVisible == true { offeredAddresses = addresses }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !trayOnly {
            showDesktopWindow()
            return true
        }
        if approvalPanel?.isVisible == true {
            approvalPanel?.makeKeyAndOrderFront(nil)
            return true
        }
        if !popover.isShown, let button = statusItem?.button {
            showPopover(at: button, activate: true)
        }
        return true
    }

    @objc private func openDesktopMode() {
        setTrayOnly(false)
    }

    private func setTrayOnly(_ enabled: Bool) {
        trayOnly = enabled
        if !smokeWindow { UserDefaults.standard.set(enabled, forKey: Self.trayOnlyKey) }
        if enabled {
            hideDesktopWindow()
            NSApp.setActivationPolicy(.accessory)
            if !smokeWindow, !popover.isShown, approvalPanel?.isVisible != true, let button = statusItem?.button {
                showPopover(at: button, activate: true)
            }
        } else {
            showDesktopWindow()
        }
    }

    private func showDesktopWindow() {
        NSApp.setActivationPolicy(.regular)
        NSApp.applicationIconImage = applicationIcon
        let window: NSWindow
        if let desktopWindow {
            window = desktopWindow
        } else {
            window = NSWindow(
                contentRect: CGRect(x: 0, y: 0, width: 470, height: 550),
                styleMask: [.titled, .closable, .miniaturizable, .resizable],
                backing: .buffered, defer: false
            )
            window.title = "MySafeAI"
            window.appearance = NSAppearance(named: .darkAqua)
            window.isReleasedWhenClosed = false
            window.delegate = self
            window.contentViewController = NSHostingController(rootView: dashboard(inWindow: true))
            window.contentMinSize = CGSize(width: Dashboard.size.width, height: 410)
            window.center()
            if !smokeWindow { window.setFrameAutosaveName("MySafeAI desktop") }
            desktopWindow = window
        }
        if window.isMiniaturized { window.deminiaturize(nil) }
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
        popover.close()
        if approvalPanel?.isVisible == true { approvalPanel?.close() }
        updatePanelVisibility()
    }

    private func hideDesktopWindow() {
        desktopWindow?.orderOut(nil)
        updatePanelVisibility()
    }

    private func iconCenter(_ icon: NSImage?) -> NSColor? {
        guard let image = icon?.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return nil }
        return NSBitmapImageRep(cgImage: image)
            .colorAt(x: image.width / 2, y: image.height / 2)?.usingColorSpace(.sRGB)
    }

    private func dashboard(inWindow: Bool = false) -> Dashboard {
        Dashboard(model: model, inWindow: inWindow,
                  windowAction: inWindow ? hideDesktopWindow : openDesktopMode,
                  setTrayOnly: setTrayOnly)
    }

    private func installMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "MySafeAI")
        let openItem = appMenu.addItem(withTitle: "Открыть окно MySafeAI", action: #selector(openDesktopMode), keyEquivalent: "0")
        openItem.target = self
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Выйти из MySafeAI", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)
        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "Правка")
        editMenu.addItem(withTitle: "Вырезать", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Копировать", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Вставить", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Выбрать всё", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        main.addItem(editItem)
        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Окно")
        windowMenu.addItem(withTitle: "Закрыть окно", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowMenu.addItem(withTitle: "Свернуть", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = windowMenu
        main.addItem(windowItem)
        NSApp.mainMenu = main
        NSApp.windowsMenu = windowMenu
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
        panel.contentViewController = NSHostingController(rootView: dashboard())
        panel.setContentSize(Dashboard.size)
        panel.center()
        approvalPanel = panel
        panel.orderFrontRegardless()
        updatePanelVisibility()
    }

    private func showPopover(at button: NSStatusBarButton, activate: Bool) {
        model.background.refresh()
        let controller = NSHostingController(rootView: dashboard())
        popover.contentViewController = controller
        popover.contentSize = Dashboard.size
        if activate { NSApplication.shared.activate() }
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        if activate { controller.view.window?.makeKey() }
        updatePanelVisibility()
    }
}
