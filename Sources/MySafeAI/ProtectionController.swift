import AppKit
import NetworkDiagnostics
import Observation
import UniformTypeIdentifiers

struct ProtectedApplication: Codable, Identifiable, Equatable {
    let path: String
    let bundleID: String
    let name: String
    var id: String { path }

    init?(_ url: URL) {
        let url = url.resolvingSymlinksInPath().standardizedFileURL
        guard url.pathExtension.lowercased() == "app", let bundle = Bundle(url: url),
              let id = bundle.bundleIdentifier, id != Bundle.main.bundleIdentifier,
              bundle.executableURL != nil else { return nil }
        path = url.path
        bundleID = id
        name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? url.deletingPathExtension().lastPathComponent
    }
}

@MainActor
@Observable
final class ProtectionController {
    enum Status: Equatable {
        case off
        case checking
        case trusted
        case paused(ProtectionIssue)
        case failed
    }

    enum AddressState: Equatable {
        case checking, noTunnel, unsafeIPv6, unverifiedIPv6, unavailable, disagreement
        case current([String])
        case serviceUnverified, proxyUnverified
    }

    private struct Rules: Codable {
        var applications: [ProtectedApplication] = []
        var trustedAddresses: Set<String> = []
        // Optional so existing rules decode without a migration.
        var cliTargets: Set<CLIProtectionTarget>?
        var desktopTargets: Set<DesktopProtectionTarget>?
        var enablesOnLaunch: Bool?
        var closesAfterTimeout: Bool?
        var blocksOutsideDNS: Bool?
        var networks: [TrustedLocalNetwork]?
        var globalAddresses: AddressAccessPolicy?
        var applicationRules: [String: ApplicationAccessRule]?
    }

    private static let rulesKey = "localProtectionRules"
    private static let disabledKey = "protectionManuallyDisabled"
    private static let pauseKey = "protectionPausedUntil"
    private var rules: Rules
    private(set) var status: Status = .off
    private(set) var pausedCount = 0
    private(set) var pausedApplications: [String] = []
    private(set) var protectedApplications: [String] = []
    private(set) var closeDeadline: Date?
    private(set) var selectionError = false
    private(set) var addressState: AddressState = .checking
    private(set) var declinedAddresses: [String] = []
    private(set) var pendingAddresses: [String] = []
    private(set) var pendingDirectTarget: String?
    private(set) var protectionPausedUntil: Date?
    private(set) var assessment: ConnectionAssessment?
    let journal = ProtectionJournal()
    @ObservationIgnored var onPreflightRequested: (@MainActor () -> Void)?

    @ObservationIgnored private var pauser: ProcessPauser?
    @ObservationIgnored private var workerID: UUID?
    @ObservationIgnored private var enforcement: Task<Void, Never>?
    @ObservationIgnored private var verification: Task<Void, Never>?
    @ObservationIgnored private var verificationID = UUID()
    @ObservationIgnored private var allowedTargets: Set<String> = []
    @ObservationIgnored private var previouslyAllowed: Set<String> = []
    @ObservationIgnored private var waitingCommands: Set<UUID> = []
    @ObservationIgnored private var verifiedCommands: Set<UUID> = []
    @ObservationIgnored private var pausedRoots: [ProcessIdentity: String] = [:]
    @ObservationIgnored private var closeTask: Task<Void, Never>?
    @ObservationIgnored private var attemptedClose: Set<ProcessIdentity> = []
    @ObservationIgnored private var closing: Set<ProcessIdentity> = []
    @ObservationIgnored private var sleeping = false

    var applications: [ProtectedApplication] { rules.applications }
    var trustedAddresses: [String] { rules.trustedAddresses.sorted() }
    var globalAddressPolicy: AddressAccessPolicy {
        var policy = rules.globalAddresses ?? .init()
        policy.addresses = rules.trustedAddresses
        return policy
    }
    var applicationRules: [String: ApplicationAccessRule] { rules.applicationRules ?? [:] }
    var trustedNetworks: [TrustedLocalNetwork] { rules.networks ?? [] }
    var cliTargets: Set<CLIProtectionTarget> { rules.cliTargets ?? Set(CLIProtectionTarget.allCases) }
    var desktopTargets: Set<DesktopProtectionTarget> {
        rules.desktopTargets ?? Set(DesktopProtectionTarget.allCases)
    }
    var hasTargets: Bool { !applications.isEmpty || !cliTargets.isEmpty || !desktopTargets.isEmpty }
    var enablesOnLaunch: Bool { rules.enablesOnLaunch ?? true }
    var closesAfterTimeout: Bool { rules.closesAfterTimeout ?? false }
    var blocksOutsideDNS: Bool { rules.blocksOutsideDNS ?? false }
    var isEnabled: Bool { status != .off && status != .failed }
    var isManuallyDisabled: Bool { UserDefaults.standard.bool(forKey: Self.disabledKey) }

    var currentAddresses: [String] {
        if case .current(let addresses) = addressState { return addresses }
        return []
    }

    var policyTargets: [ProtectionTarget] {
        CLIProtectionTarget.allCases.map(ProtectionTarget.cli) +
        DesktopProtectionTarget.allCases.flatMap { target in
            target.bundleIdentifiers.map { ProtectionTarget.desktop(target, bundleID: $0) }
        } + applications.map(ProtectionTarget.custom) + [.managed]
    }

    private var enabledPolicyIDs: Set<String> {
        Set(cliTargets.map { ProtectionTarget.cli($0).id } + desktopTargets.flatMap { target in
            target.bundleIdentifiers.map { ProtectionTarget.desktop(target, bundleID: $0).id }
        } + applications.map { ProtectionTarget.custom($0).id })
    }

    init() {
        protectionPausedUntil = UserDefaults.standard.object(forKey: Self.pauseKey) as? Date
        let data = UserDefaults.standard.data(forKey: Self.rulesKey)
        rules = data.flatMap { try? JSONDecoder().decode(Rules.self, from: $0) } ?? Rules()
        if rules.desktopTargets == nil {
            rules.applications.removeAll { DesktopProtectionTarget.identify(bundleID: $0.bundleID) != nil }
        }
    }

    func selectApplication() {
        guard !isEnabled else { return }
        let picker = NSOpenPanel()
        picker.title = "Выберите приложение для защиты"
        picker.prompt = "Добавить"
        picker.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        picker.allowedContentTypes = [.applicationBundle]
        picker.canChooseDirectories = false
        picker.canChooseFiles = true
        guard picker.runModal() == .OK, let url = picker.url else { return }
        guard let application = ProtectedApplication(url) else {
            selectionError = true
            return
        }
        selectionError = false
        if let target = DesktopProtectionTarget.identify(bundleID: application.bundleID) {
            setDesktopTarget(target, enabled: true)
            return
        }
        guard !rules.applications.contains(where: { $0.id == application.id }) else { return }
        rules.applications.append(application)
        saveRules()
    }

    func removeApplication(_ app: ProtectedApplication) {
        guard !isEnabled else { return }
        rules.applications.removeAll { $0.id == app.id }
        saveRules()
    }

    func setCLITarget(_ target: CLIProtectionTarget, enabled: Bool) {
        guard !isEnabled else { return }
        var targets = cliTargets
        if enabled { targets.insert(target) } else { targets.remove(target) }
        rules.cliTargets = targets
        saveRules()
    }

    func setDesktopTarget(_ target: DesktopProtectionTarget, enabled: Bool) {
        guard !isEnabled else { return }
        var targets = desktopTargets
        if enabled { targets.insert(target) } else { targets.remove(target) }
        rules.desktopTargets = targets
        saveRules()
    }

    func setEnablesOnLaunch(_ enabled: Bool) {
        rules.enablesOnLaunch = enabled
        saveRules()
    }

    func setClosesAfterTimeout(_ enabled: Bool) {
        rules.closesAfterTimeout = enabled
        saveRules()
        if enabled { scheduleCloseIfNeeded() } else if closing.isEmpty { cancelClose() }
    }

    func setBlocksOutsideDNS(_ enabled: Bool) {
        rules.blocksOutsideDNS = enabled
        saveRules()
    }

    func approveCurrentAddresses(_ addresses: [String]) {
        guard !addresses.isEmpty, addresses == pendingAddresses else { return }
        if let target = pendingDirectTarget {
            if target == "global" {
                var access = globalAddressPolicy
                access.directAddresses = (access.directAddresses ?? []).union(addresses)
                access.addresses = []
                rules.globalAddresses = access
            } else {
                guard var rule = applicationRules[target], var access = rule.addressPolicy else { return }
                access.directAddresses = (access.directAddresses ?? []).union(addresses)
                rule.addressPolicy = access
                rules.applicationRules?[target] = rule
            }
        } else {
            rules.trustedAddresses.formUnion(addresses)
        }
        saveRules()
        declinedAddresses = []
        journal.append(.approved, detail: addresses.joined(separator: ", "))
        networkChanged()
    }

    func declineCurrentAddresses(_ addresses: [String]) {
        guard !addresses.isEmpty, addresses == pendingAddresses, declinedAddresses != addresses else { return }
        declinedAddresses = addresses
        journal.append(.declined, detail: addresses.joined(separator: ", "))
    }

    func addAddress(_ input: String) -> Bool {
        guard !isEnabled, let ip = AddressEcho.parse(input) else { return false }
        rules.trustedAddresses.insert(ip)
        saveRules()
        return true
    }

    func removeAddress(_ address: String) {
        guard !isEnabled else { return }
        rules.trustedAddresses.remove(address)
        saveRules()
    }

    func setGlobalAddressPolicy(_ policy: AddressAccessPolicy) {
        rules.trustedAddresses = policy.addresses
        var extras = policy
        extras.addresses = []
        rules.globalAddresses = extras
        saveRules()
        networkChanged()
    }

    func setApplicationRule(_ rule: ApplicationAccessRule, target: ProtectionTarget) {
        guard rule.transport != .systemProxy || target.supportsSystemProxy else { return }
        rules.applicationRules = applicationRules.merging([target.id: rule]) { _, new in new }
        saveRules()
        networkChanged()
    }

    func addTrustedNetwork(_ network: TrustedLocalNetwork) {
        rules.networks = trustedNetworks.filter { $0.id != network.id } + [network]
        saveRules()
        networkChanged()
    }

    func removeTrustedNetwork(_ network: TrustedLocalNetwork) {
        rules.networks = trustedNetworks.filter { $0.id != network.id }
        saveRules()
        networkChanged()
    }

    func isGloballyTrusted(_ address: String) -> Bool {
        globalAddressPolicy.allows(address, country: assessment?.countries[address])
    }

    func enable() {
        guard !isEnabled else { return }
        setSuspension(disabled: false, until: nil)
        cancelVerification()
        cancelClose()
        enforcement?.cancel()
        previouslyAllowed = []
        attemptedClose = []
        let id = UUID()
        do {
            let exited: @MainActor @Sendable () -> Void = { [weak self] in
                guard self?.workerID == id else { return }
                self?.restoreWorker()
            }
            if let pauser {
                try pauser.rearm(onWorkerExit: exited)
            } else {
                pauser = try ProcessPauser(onWorkerExit: exited)
            }
            workerID = id
            addressState = .checking
            status = .checking
            journal.append(pauser?.restoredSession == true ? .recovered : .enabled)
            enforce()
            guard isEnabled else { return }
            enforcement = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(850))
                    guard !Task.isCancelled, let self else { break }
                    self.enforce()
                }
            }
        } catch {
            fail()
        }
    }

    func disableProtection() {
        guard stop() else { return }
        setSuspension(disabled: true, until: nil)
    }

    func pauseProtection() {
        guard isEnabled, stop(reason: "Пауза на 15 минут") else { return }
        setSuspension(disabled: false, until: .now.addingTimeInterval(15 * 60))
    }

    private func setSuspension(disabled: Bool, until: Date?) {
        protectionPausedUntil = until
        UserDefaults.standard.set(until, forKey: Self.pauseKey)
        UserDefaults.standard.set(disabled, forKey: Self.disabledKey)
    }

    @discardableResult func stop(reason: String = "") -> Bool {
        let wasEnabled = isEnabled
        cancelVerification()
        cancelClose()
        previouslyAllowed = []
        waitingCommands = []
        attemptedClose = []
        enforcement?.cancel()
        enforcement = nil
        workerID = nil
        do {
            let resuming = pausedTargetNames
            if let pauser {
                try pauser.finish()
            } else if ProcessPauser.requiresRecovery {
                try ProcessPauser.releasePendingProtection()
            }
            pauser = nil
            pausedRoots = [:]
            pausedCount = 0
            pausedApplications = []
            protectedApplications = []
            status = .off
            if !resuming.isEmpty { journal.append(.resumed, detail: resuming) }
            if wasEnabled { journal.append(.disabled, detail: reason) }
            return true
        } catch {
            status = .failed
            return false
        }
    }

    func networkChanged() {
        cancelVerification()
        addressState = .checking
        guard isEnabled else { return }
        status = .checking
        enforce()
    }

    func previewClosed() {
        if !isEnabled { networkChanged() }
    }

    func sleepChanged(_ isSleeping: Bool) {
        sleeping = isSleeping
        if isSleeping, closing.isEmpty { cancelClose() }
    }

    func update(snapshot: NetworkSnapshot, sources: [AddressSource], preview: Bool = false) {
        guard (isEnabled || preview), verification == nil else { return }
        let request = verificationID
        let admittedByThisCheck = waitingCommands
        let activeIDs = enabledPolicyIDs.union(ManagedCommand.active().map { $0.protectionTarget.id })
        let targets = policyTargets.filter { activeIDs.contains($0.id) }
        let policies = applicationRules
        let global = globalAddressPolicy
        let networks = trustedNetworks
        let dns = blocksOutsideDNS
        verification = Task {
            let result = await ConnectionPolicy.evaluate(snapshot: snapshot, sources: sources, targets: targets,
                rules: policies, global: global, networks: networks, blocksOutsideDNS: dns)
            guard request == verificationID else { return }
            verification = nil
            guard let result else {
                networkChanged()
                return
            }
            verifiedCommands = admittedByThisCheck
            apply(result)
        }
    }

    private func apply(_ result: ConnectionAssessment) {
        assessment = result
        let relevant = enabledPolicyIDs.union(ManagedCommand.active().map { $0.protectionTarget.id })
        let direct = relevant.sorted().lazy.compactMap { id -> (target: String, addresses: [String])? in
            guard let proof = result.decisions[id], proof.direct,
                  proof.issue == .unexpectedAddress || proof.issue == .unsafeDNS else { return nil }
            let access = self.applicationRules[id]?.addressPolicy
            let addresses = proof.addresses.filter { !(access ?? self.globalAddressPolicy).allowsDirect($0) }
            return addresses.isEmpty ? nil : (access == nil ? "global" : id, addresses)
        }.first
        if isEnabled, let direct {
            pendingDirectTarget = direct.target
            pendingAddresses = direct.addresses
        } else {
            pendingDirectTarget = nil
            let proposals = relevant.sorted().flatMap { id -> [String] in
                guard applicationRules[id]?.addressPolicy == nil,
                      let proof = result.decisions[id], proof.issue == .unexpectedAddress,
                      !proof.direct else { return [] }
                return proof.addresses.filter { !isGloballyTrusted($0) }
            }
            pendingAddresses = isEnabled ? Set(proposals).sorted() : []
        }
        let addresses = result.base.addresses.isEmpty
            ? relevant.sorted().compactMap { result.decisions[$0]?.addresses }.first(where: { !$0.isEmpty }) ?? []
            : result.base.addresses
        if !addresses.isEmpty || !pendingAddresses.isEmpty {
            addressState = .current(pendingAddresses.isEmpty ? addresses : pendingAddresses)
        } else {
            let preferred = relevant.sorted().compactMap { result.decisions[$0]?.issue }
                .first { $0 == .proxyUnverified || $0 == .serviceUnverified }
            switch preferred ?? result.base.issue {
            case .noTunnel: addressState = .noTunnel
            case .unsafeIPv6: addressState = .unsafeIPv6
            case .disagreement: addressState = .disagreement
            case .serviceUnverified: addressState = .serviceUnverified
            case .proxyUnverified: addressState = .proxyUnverified
            default: addressState = .unavailable
            }
        }
        guard isEnabled else { return }
        allowedTargets = Set(result.decisions.compactMap { id, proof in proof.issue == nil ? id : nil })
        enforce()
    }

    func enforce() {
        guard isEnabled, let pauser else { return }
        let commands = ManagedCommand.active()
        let unadmitted = Set(commands.filter { !$0.admitted }.map(\.id))
        let hasNewCommand = !unadmitted.isSubset(of: waitingCommands)
        if hasNewCommand {
            // A new preflight needs a fresh result without interrupting already approved apps.
            cancelVerification(preservingCurrentPolicy: true)
        }
        waitingCommands = unadmitted
        if hasNewCommand { onPreflightRequested?() }
        var roots = CLIProcesses.roots(for: cliTargets).mapValues(ProtectionTarget.cli)
        var titles = roots.mapValues(\.title)
        for app in NSWorkspace.shared.runningApplications {
            guard !app.isTerminated, let bundle = app.bundleIDAndPath else {
                continue
            }
            let target: ProtectionTarget
            if let preset = DesktopProtectionTarget.identify(bundleID: bundle.id),
               desktopTargets.contains(preset) {
                target = .desktop(preset, bundleID: bundle.id)
            } else if let rule = rules.applications.first(where: {
                $0.path == bundle.path && $0.bundleID == bundle.id
            }) {
                target = .custom(rule)
            } else {
                continue
            }
            guard let info = ProcessIdentity.info(app.processIdentifier) else {
                if app.processIdentifier > 1 && kill(app.processIdentifier, 0) == 0 {
                    fail()
                    return
                }
                continue
            }
            let identity = ProcessIdentity(info)
            roots[identity] = target
            titles[identity] = app.localizedName ?? target.title
        }
        do {
            for command in commands {
                let target = roots[command.process] ?? command.protectionTarget
                roots[command.process] = target
                titles[command.process] = target.title
                if !command.admitted {
                    try pauser.adoptSuspended(command.process, owner: target.id, admission: command.admission)
                }
            }
            let denied = roots.filter { !allowedTargets.contains($0.value.id) }
            _ = try pauser.pause(denied.mapValues(\.id))
            if let assessment {
                var permitted = allowedTargets.union(commands.filter(\.admitted).map(\.admission))
                for command in commands where !command.admitted && verifiedCommands.contains(command.id) &&
                    pauser.canResume(command.process, allowed: allowedTargets.union([command.admission])) {
                    if try command.admit() { permitted.insert(command.admission) }
                }
                let legacyAllowed = assessment.base.issue == nil && !assessment.base.addresses.isEmpty &&
                    assessment.base.addresses.allSatisfy {
                        assessment.base.direct ? globalAddressPolicy.allowsDirect($0) : isGloballyTrusted($0)
                    } && enabledPolicyIDs.isSubset(of: allowedTargets)
                if legacyAllowed {
                    // A deleted custom rule may still own descendants in a recovered journal.
                    let known = enabledPolicyIDs.union(commands.map { $0.protectionTarget.id })
                    permitted.formUnion(pauser.retiredPolicyOwners(known: known))
                }
                try pauser.resumeAllowed(permitted, allAllowed: legacyAllowed, excluding: closing)
            }
            pausedCount = pauser.pausedCount
            let stopped = titles.merging(pausedRoots) { current, _ in current }.filter { pauser.hasPause($0.key) }
            let added = stopped.filter { pausedRoots[$0.key] == nil }
            let resumed = pausedRoots.filter { stopped[$0.key] == nil && $0.key.isRunning }
            pausedRoots = stopped
            pausedApplications = Set(stopped.values).sorted()
            protectedApplications = Set(titles.filter {
                stopped[$0.key] == nil && roots[$0.key].map { allowedTargets.contains($0.id) } == true
            }.values).sorted()
            if !added.isEmpty {
                journal.append(.paused, detail: Set(added.values).sorted().joined(separator: ", "))
            }
            if !resumed.isEmpty {
                journal.append(.resumed, detail: Set(resumed.values).sorted().joined(separator: ", "))
            }
            if let assessment {
                let currentIDs = roots.isEmpty ? enabledPolicyIDs : Set(roots.values.map(\.id))
                let issue = currentIDs.sorted().compactMap { assessment.decisions[$0]?.issue }.first
                status = issue.map(Status.paused) ?? (pausedCount == 0 ? .trusted : .paused(.unexpectedAddress))
                previouslyAllowed.formUnion(currentIDs.intersection(allowedTargets))
            }
            let closable = pauser.closable(previouslyAllowed: previouslyAllowed)
            attemptedClose.formIntersection(closable)
            if closable.isEmpty, closeTask != nil, closing.isEmpty { cancelClose() }
            scheduleCloseIfNeeded()
        } catch {
            fail()
        }
    }

    private func scheduleCloseIfNeeded() {
        guard isEnabled, !sleeping, status != .trusted, let pauser,
              closesAfterTimeout, closeTask == nil else { return }
        let candidates = pauser.closable(previouslyAllowed: previouslyAllowed).subtracting(attemptedClose)
        guard !candidates.isEmpty else { return }
        closeDeadline = .now.addingTimeInterval(20)
        closeTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(20)) } catch { return }
            await self?.closeTimedOutApplications(candidates)
        }
    }

    private func cancelClose() {
        closeTask?.cancel()
        closeTask = nil
        closeDeadline = nil
        closing = []
    }

    private func closeTimedOutApplications(_ expired: Set<ProcessIdentity>) async {
        guard isEnabled, status != .trusted, closesAfterTimeout, let pauser else {
            cancelClose()
            return
        }
        let candidates = expired.intersection(pauser.closable(previouslyAllowed: previouslyAllowed))
        guard !candidates.isEmpty else {
            cancelClose()
            scheduleCloseIfNeeded()
            return
        }
        attemptedClose.formUnion(candidates)
        closing = candidates
        closeDeadline = .now.addingTimeInterval(5)
        let names = Set(pausedRoots.filter { candidates.contains($0.key) }.values).sorted().joined(separator: ", ")
        journal.append(.closing, detail: names)
        let desktopRoots = Set(NSWorkspace.shared.runningApplications.compactMap { app in
            ProcessIdentity.info(app.processIdentifier).map(ProcessIdentity.init)
        })
        pauser.requestClose(candidates, desktopRoots: desktopRoots.intersection(candidates)) { identity in
            _ = NSRunningApplication(processIdentifier: identity.pid)?.terminate()
        }
        do { try await Task.sleep(for: .seconds(5)) } catch { return }
        guard isEnabled, self.pauser === pauser else { return }
        let remaining = candidates.intersection(pauser.closable(previouslyAllowed: previouslyAllowed))
        cancelClose()
        do {
            let forced = try pauser.closePaused(only: remaining)
            if forced > 0 || candidates.allSatisfy({ !$0.isRunning }) { journal.append(.closed, detail: names) }
        } catch {
            journal.append(.closeFailed, detail: names)
        }
        enforce()
    }

    private func cancelVerification(preservingCurrentPolicy: Bool = false) {
        verificationID = UUID()
        verification?.cancel()
        verification = nil
        verifiedCommands = []
        guard !preservingCurrentPolicy else { return }
        allowedTargets = []
        assessment = nil
        pendingAddresses = []
        pendingDirectTarget = nil
    }

    private func fail() {
        cancelVerification()
        cancelClose()
        status = .failed
        journal.append(.failed)
    }

    private func restoreWorker() {
        guard let pauser, status != .off else { return }
        cancelVerification()
        cancelClose()
        addressState = .checking
        status = .checking
        do {
            try pauser.rearm()
            enforce()
            if status != .failed { journal.append(.recovered) }
        } catch {
            fail()
        }
    }

    private var pausedTargetNames: String {
        Set(pausedRoots.filter { ProcessIdentity.info($0.key.pid).map(ProcessIdentity.init) == $0.key }.values)
            .sorted().joined(separator: ", ")
    }

    private func saveRules() {
        if let data = try? JSONEncoder().encode(rules) {
            UserDefaults.standard.set(data, forKey: Self.rulesKey)
        }
    }
}

private extension NSRunningApplication {
    var bundleIDAndPath: (id: String, path: String)? {
        guard let id = bundleIdentifier, let url = bundleURL else { return nil }
        return (id, url.resolvingSymlinksInPath().standardizedFileURL.path)
    }
}
