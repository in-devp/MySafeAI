import Foundation
import Network
import NetworkDiagnostics
import Observation

@MainActor
@Observable
final class MonitorModel {
    private static let addressSettingsKey = "addressSources"
    private static let dnsObservationKey = "observesDNSExternally"

    private(set) var snapshot: NetworkSnapshot?
    private(set) var lastCheck: Date?
    private(set) var addressResults: [AddressCheckResult] = []
    private(set) var checkingAddress = false
    private(set) var addressSettings: AddressSourceSettings
    private(set) var leakReport: LeakCheckReport?
    private(set) var checkingLeaks = false
    private(set) var leakMessage: String?
    private(set) var observesDNSExternally: Bool
    private(set) var servicePaths: [ServicePath] = []
    private(set) var serviceCountries: [String: String] = [:]
    private(set) var checkingServicePaths = false
    private(set) var checkingTrustedNetwork = false
    private(set) var trustedNetworkMessage: String?
    let background = BackgroundOptions()
    let protection = ProtectionController()

    @ObservationIgnored private let monitor = NWPathMonitor()
    @ObservationIgnored private var settingsObserver: NetworkSettingsObserver?
    @ObservationIgnored private var checking = false
    @ObservationIgnored private var needsRefresh = false
    @ObservationIgnored private var protectionResumeTask: Task<Void, Never>?
    @ObservationIgnored private var networkGeneration = 0
    @ObservationIgnored private var sleeping = false
    @ObservationIgnored private var panelVisible = false
    @ObservationIgnored private var addressTask: Task<Void, Never>?
    @ObservationIgnored private var addressRequest = UUID()
    @ObservationIgnored private var leakTask: Task<Void, Never>?
    @ObservationIgnored private var leakRequest = UUID()
    @ObservationIgnored private var serviceTask: Task<Void, Never>?
    @ObservationIgnored private var serviceRequest = UUID()

    init() {
        let defaults = UserDefaults.standard
        observesDNSExternally = defaults.bool(forKey: Self.dnsObservationKey)
        let saved = defaults.data(forKey: Self.addressSettingsKey).flatMap {
            try? JSONDecoder().decode(AddressSourceSettings.self, from: $0)
        }
        addressSettings = saved ?? AddressSourceSettings(
            previousEndpoint: defaults.string(forKey: "addressEchoEndpoint")
        )
        addressSettings.migrateIPv6Sources()
        addressSettings.migrateIPv4Backup()
        protection.onPreflightRequested = { [weak self] in self?.refresh() }
        monitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.networkChanged()
            }
        }
        monitor.start(queue: DispatchQueue(label: "MySafeAI.NetworkPath"))
        settingsObserver = NetworkSettingsObserver { [weak self] in
            Task { @MainActor [weak self] in self?.networkChanged() }
        }

        Task { [weak self] in
            while !Task.isCancelled {
                guard self != nil else { break }
                self?.refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    func refresh() {
        if !sleeping, let until = protection.protectionPausedUntil, until <= .now {
            protection.enable()
        }
        guard !checking else {
            needsRefresh = true
            return
        }

        checking = true
        Task {
            repeat {
                needsRefresh = false
                let generation = networkGeneration
                let result = await NetworkSnapshot.read()
                if generation == networkGeneration, !sleeping {
                    if let snapshot, snapshot != result {
                        clearAddress()
                        clearLeakCheck()
                        clearServicePaths()
                        protection.networkChanged()
                    }
                    snapshot = result
                    lastCheck = Date.now
                    protection.update(snapshot: result, sources: addressSettings.enabledSources, preview: panelVisible)
                }
            } while needsRefresh
            checking = false
        }
    }

    private func networkChanged() {
        networkGeneration &+= 1
        snapshot = nil
        lastCheck = nil
        clearAddress()
        clearLeakCheck()
        clearServicePaths()
        protection.networkChanged()
        if !sleeping { refresh() }
    }

    func sleepChanged(_ isSleeping: Bool) {
        sleeping = isSleeping
        protection.sleepChanged(isSleeping)
        networkChanged()
    }

    func panelVisibilityChanged(_ visible: Bool) {
        panelVisible = visible
        if visible {
            refresh()
        } else {
            protection.previewClosed()
        }
    }

    func approveVPNAddress(_ addresses: [String]) {
        protection.approveCurrentAddresses(addresses)
        refresh()
    }

    func enableProtection() {
        protectionResumeTask?.cancel()
        protectionResumeTask = nil
        protection.enable()
        refresh()
    }

    func disableProtection() {
        protectionResumeTask?.cancel()
        protectionResumeTask = nil
        protection.disableProtection()
    }

    func pauseProtection() {
        protection.pauseProtection()
        scheduleProtectionResume()
    }

    func startProtectionIfConfigured() {
        if protection.protectionPausedUntil != nil {
            scheduleProtectionResume()
            refresh()
        } else if !protection.isManuallyDisabled && (protection.enablesOnLaunch || ProcessPauser.requiresRecovery) {
            enableProtection()
        }
    }

    private func scheduleProtectionResume() {
        protectionResumeTask?.cancel()
        guard let until = protection.protectionPausedUntil else { return }
        protectionResumeTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(max(0, until.timeIntervalSinceNow)))
            guard !Task.isCancelled, let self, self.protection.protectionPausedUntil == until else { return }
            self.refresh()
        }
    }

    func setBlocksOutsideDNS(_ enabled: Bool) {
        protection.setBlocksOutsideDNS(enabled)
        networkChanged()
    }

    func addAddressSource(_ input: String) -> Bool {
        guard addressSettings.add(input) else { return false }
        saveAddressSettings()
        return true
    }

    func removeAddressSource(_ url: URL) {
        addressSettings.remove(url)
        saveAddressSettings()
    }

    func enableAddressSource(_ provider: BuiltInAddressSource, enabled: Bool) {
        if enabled {
            addressSettings.enabledBuiltIns.insert(provider)
        } else {
            addressSettings.enabledBuiltIns.remove(provider)
        }
        saveAddressSettings()
    }

    private func saveAddressSettings() {
        if let data = try? JSONEncoder().encode(addressSettings) {
            UserDefaults.standard.set(data, forKey: Self.addressSettingsKey)
        }
        networkChanged()
    }

    func checkAddress() {
        let sources = addressSettings.enabledSources.filter { snapshot?.ipv6 != .missing || !$0.isIPv6Only }
        guard !sources.isEmpty, !checkingAddress else { return }
        let request = UUID()
        addressRequest = request
        checkingAddress = true
        addressResults = []

        addressTask = Task {
            let results = await AddressClient.checkAll(sources)
            guard addressRequest == request else { return }
            addressResults = results
            checkingAddress = false
            addressTask = nil
        }
    }

    func setObservesDNSExternally(_ enabled: Bool) {
        observesDNSExternally = enabled
        UserDefaults.standard.set(enabled, forKey: Self.dnsObservationKey)
        clearLeakCheck(message: "Настройки DNS-теста изменились. Запустите проверку.")
    }

    func checkServicePaths() {
        guard !checkingServicePaths, !sleeping else { return }
        let id = UUID()
        serviceRequest = id
        checkingServicePaths = true
        let targets = protection.policyTargets
        let rules = protection.applicationRules
        serviceTask = Task {
            let snapshot = await NetworkSnapshot.read()
            let proxy = SystemProxyConfiguration.read()
            let paths = await ConnectionPolicy.diagnosticPaths(targets: targets, rules: rules)
            let countries = await ConnectionPolicy.serviceCountries(paths: paths)
            let current = await NetworkSnapshot.read()
            guard serviceRequest == id, !Task.isCancelled else { return }
            serviceTask = nil
            checkingServicePaths = false
            guard snapshot == current, proxy == SystemProxyConfiguration.read() else { return }
            servicePaths = paths
            serviceCountries = countries
        }
    }

    private func clearServicePaths() {
        serviceRequest = UUID()
        serviceTask?.cancel()
        serviceTask = nil
        servicePaths = []
        serviceCountries = [:]
        checkingServicePaths = false
    }

    func rememberTrustedNetwork(_ name: String) {
        let title = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty, title.count <= 60, !checkingTrustedNetwork, !sleeping else { return }
        checkingTrustedNetwork = true
        trustedNetworkMessage = nil
        let generation = networkGeneration
        let sources = addressSettings.enabledSources
        Task {
            defer { checkingTrustedNetwork = false }
            let snapshot = await NetworkSnapshot.read()
            guard let router = snapshot.router, !SystemProxyConfiguration.read().isEnabled else {
                trustedNetworkMessage = "Подключитесь к этой сети с выключенным VPN и системным прокси."
                return
            }
            let ips = await ConnectionPolicy.localAddresses(snapshot: snapshot, sources: sources)
            guard !ips.isEmpty, await NetworkSnapshot.read() == snapshot,
                  !SystemProxyConfiguration.read().isEnabled, generation == networkGeneration, !sleeping else {
                trustedNetworkMessage = "Маршрут или внешний IP не подтверждён. Повторите проверку."
                return
            }
            protection.addTrustedNetwork(.init(id: router, name: title, addresses: Set(ips)))
            trustedNetworkMessage = "Сеть «\(title)» сохранена."
            refresh()
        }
    }

    func checkLeaks() {
        guard !checkingLeaks, !sleeping else { return }
        let request = UUID()
        leakRequest = request
        checkingLeaks = true
        leakMessage = nil
        leakReport = nil
        let sources = addressSettings.enabledSources.filter { !$0.isIPv6Only }
        let ipv6Sources = addressSettings.enabledSources.filter(\.isIPv6Only)
        let observesDNS = observesDNSExternally
        leakTask = Task {
            let before = await NetworkSnapshot.read()
            let proxy = SystemProxyConfiguration.read()
            async let direct = AddressClient.checkAll(sources, direct: true)
            async let system = AddressClient.checkAll(sources)
            async let ipv6 = AddressClient.checkAll(ipv6Sources, direct: true)
            async let dns: DNSObservation = observesDNS ? DNSObservationClient.check() : .disabled
            let values = await (direct, system, ipv6, dns)
            let after = await NetworkSnapshot.read()
            guard leakRequest == request, !Task.isCancelled else { return }
            checkingLeaks = false
            leakTask = nil
            guard before == after, proxy == SystemProxyConfiguration.read() else {
                leakMessage = "Подключение изменилось во время теста. Повторите проверку."
                return
            }
            let report = LeakCheckReport(snapshot: after, proxy: proxy, direct: values.0,
                                         system: values.1, ipv6: values.2, dns: values.3)
            leakReport = report
            addressResults = report.direct
            protection.journal.append(.checked, detail: report.summary)
        }
    }

    private func clearLeakCheck(message: String = "Сеть изменилась. Запустите проверку заново.") {
        let hadResults = checkingLeaks || leakReport != nil
        leakRequest = UUID()
        leakTask?.cancel()
        leakTask = nil
        checkingLeaks = false
        leakReport = nil
        if hadResults { leakMessage = message }
    }

    private func clearAddress() {
        addressRequest = UUID()
        addressTask?.cancel()
        addressTask = nil
        checkingAddress = false
        addressResults = []
    }
}
