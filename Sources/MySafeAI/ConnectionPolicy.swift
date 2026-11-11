import Foundation
import NetworkDiagnostics

struct ProtectionTarget: Identifiable, Sendable {
    let id: String
    let title: String
    let hosts: [String]
    let supportsSystemProxy: Bool

    static let managed = Self(id: "cli:managed", title: "Команды MySafeAI", hosts: [], supportsSystemProxy: false)

    static func cli(_ target: CLIProtectionTarget) -> Self {
        Self(id: "cli:" + target.rawValue, title: target.title,
             hosts: target == .claude ? ["api.anthropic.com"] : ["chatgpt.com", "api.openai.com"],
             supportsSystemProxy: false)
    }

    static func desktop(_ target: DesktopProtectionTarget, bundleID: String) -> Self {
        let hosts: [String]
        switch target {
        case .chatGPT: hosts = ["chatgpt.com", "ws.chatgpt.com", "api.openai.com"]
        case .claude: hosts = ["claude.ai", "api.anthropic.com"]
        case .cursor: hosts = ["api2.cursor.sh"]
        }
        let title: String
        switch bundleID {
        case "com.openai.chat": title = "ChatGPT Desktop"
        case "com.openai.codex": title = "Codex Desktop"
        case "co.anysphere.cursor.nightly": title = "Cursor Nightly"
        default: title = target.title
        }
        return Self(id: "desktop:" + bundleID, title: title, hosts: hosts, supportsSystemProxy: true)
    }

    static func custom(_ app: ProtectedApplication) -> Self {
        Self(id: "app:" + app.path, title: app.name, hosts: [], supportsSystemProxy: true)
    }
}

struct ConnectionProof: Equatable, Sendable {
    var addresses: [String] = []
    var issue: ProtectionIssue?
}

struct ConnectionAssessment: Sendable {
    let base: ConnectionProof
    let decisions: [String: ConnectionProof]
    let countries: [String: String]
    let servicePaths: [ServicePath]
    let trustedNetwork: String?
}

enum ConnectionPolicy {
    static func diagnosticPaths(targets: [ProtectionTarget], rules: [String: ApplicationAccessRule]) async -> [ServicePath] {
        let serviceHosts = Set(targets.flatMap { target in
            Self.hosts(for: target, rule: rules[target.id] ?? ApplicationAccessRule())
        })
        let proxyHosts: Set<String> = SystemProxyConfiguration.read().isEnabled ? serviceHosts : []
        return await probe(direct: serviceHosts, system: proxyHosts)
    }

    static func evaluate(snapshot: NetworkSnapshot, sources: [AddressSource],
                         targets: [ProtectionTarget], rules: [String: ApplicationAccessRule],
                         global: AddressAccessPolicy, networks: [TrustedLocalNetwork],
                         blocksOutsideDNS: Bool) async -> ConnectionAssessment? {
        let proxy = SystemProxyConfiguration.read()
        let ruleFor: (ProtectionTarget) -> ApplicationAccessRule = { rules[$0.id] ?? .init() }
        let splitHosts = Set(targets.filter { ruleFor($0).transport == .serviceTunnel }
            .flatMap { hosts(for: $0, rule: ruleFor($0)) })
        let proxyHosts = Set(targets.filter { proxy.isEnabled && $0.supportsSystemProxy && ruleFor($0).transport == .systemProxy }
            .flatMap { hosts(for: $0, rule: ruleFor($0)) })
        async let paths = probe(direct: splitHosts, system: proxyHosts)
        async let base = baseProof(snapshot: snapshot, sources: sources, blocksOutsideDNS: blocksOutsideDNS)
        let possibleNetwork = proxy.isEnabled ? nil : networks.first { $0.id == snapshot.router }
        async let local = possibleNetwork != nil
            ? localAddresses(snapshot: snapshot, sources: sources) : []
        let (generic, probes, localIPs) = await (base, paths, local)
        let home = possibleNetwork?.matches(router: snapshot.router, addresses: localIPs) == true ? possibleNetwork : nil
        let usesCountries = targets.contains { !(ruleFor($0).addressPolicy ?? global).countries.isEmpty }
        let verifiedPaths = probes.filter {
            $0.confirms($0.systemProxy ? .systemProxy : .serviceTunnel, ipv6: snapshot.ipv6)
        }
        let fallback = usesCountries && generic.issue == nil ? Set(generic.addresses) : []
        let countries = usesCountries ? await serviceCountries(paths: verifiedPaths, fallback: fallback) : [:]
        let splitTunnels = Set(verifiedPaths.compactMap { path -> String? in
            if !path.systemProxy, case .tunnel(let tunnel) = path.route { return tunnel }
            return nil
        })
        let dnsRoutes = await withTaskGroup(of: (String, DNSRoute).self) { group in
            if blocksOutsideDNS {
                for tunnel in splitTunnels {
                    group.addTask { (tunnel, await snapshot.dnsRoute(usingTunnel: tunnel)) }
                }
            }
            var routes: [String: DNSRoute] = [:]
            for await (tunnel, route) in group { routes[tunnel] = route }
            return routes
        }
        guard !Task.isCancelled, await NetworkSnapshot.read() == snapshot,
              SystemProxyConfiguration.read() == proxy else { return nil }

        var decisions: [String: ConnectionProof] = [:]
        for target in targets {
            let rule = ruleFor(target)
            if rule.allowsTrustedNetworks, home != nil {
                decisions[target.id] = ConnectionProof(addresses: localIPs)
                continue
            }
            var proof = generic
            if rule.transport != .tunnel {
                let system = rule.transport == .systemProxy
                let required = Set(hosts(for: target, rule: rule))
                let relevant = probes.filter { $0.systemProxy == system && required.contains($0.host) }
                let verified = !required.isEmpty && relevant.count == required.count &&
                    relevant.allSatisfy { $0.confirms(rule.transport, ipv6: snapshot.ipv6) }
                let available = !system || (proxy.isEnabled && target.supportsSystemProxy)
                if !verified || !available {
                    proof = ConnectionProof(issue: system ? .proxyUnverified : .serviceUnverified)
                } else if blocksOutsideDNS && !(system ? snapshot.dnsRoute == .viaTunnel : relevant.allSatisfy {
                    $0.route.interface.flatMap { dnsRoutes[$0] } == .viaTunnel
                }) {
                    proof = ConnectionProof(issue: .unsafeDNS)
                } else {
                    proof = ConnectionProof(addresses: Set(relevant.compactMap(\.observedAddress)).sorted())
                }
            }
            let access = rule.addressPolicy ?? global
            if proof.issue == nil && (proof.addresses.isEmpty ||
                !proof.addresses.allSatisfy({ access.allows($0, country: countries[$0]) })) {
                proof.issue = .unexpectedAddress
            }
            decisions[target.id] = proof
        }
        return ConnectionAssessment(base: generic, decisions: decisions, countries: countries,
                                    servicePaths: probes, trustedNetwork: home?.name)
    }

    static func serviceCountries(paths: [ServicePath], fallback: Set<String> = []) async -> [String: String] {
        var locations: [String: Set<String>] = [:]
        for path in paths {
            if let ip = path.observedAddress, let country = path.country {
                locations[ip, default: []].insert(country)
            }
        }
        var result = await IPCountryLookup.shared.lookup(fallback.subtracting(locations.keys))
        for (ip, values) in locations where values.count == 1 { result[ip] = values.first }
        return result
    }

    static func localAddresses(snapshot: NetworkSnapshot, sources: [AddressSource]) async -> [String] {
        guard snapshot.router != nil, case .other(let interface) = snapshot.ipv4,
              snapshot.ipv6 == .missing || snapshot.ipv6 == .other(interface) else { return [] }
        let summary = AddressCheckSummary(await AddressClient.checkAll(
            sources.filter { snapshot.ipv6 != .missing || !$0.isIPv6Only }, direct: true, requiredRoute: .other(interface)
        ))
        guard !summary.hasDisagreement, let ipv4 = summary.confirmedIPv4 else { return [] }
        if snapshot.ipv6 == .missing { return summary.ipv6.isEmpty ? [ipv4] : [] }
        return summary.confirmedIPv6.map { [ipv4, $0] } ?? []
    }

    private static func baseProof(snapshot: NetworkSnapshot, sources: [AddressSource],
                                  blocksOutsideDNS: Bool) async -> ConnectionProof {
        guard let route = TrustedRoute(ipv4: snapshot.ipv4, ipv6: snapshot.ipv6) else {
            if case .tunnel = snapshot.ipv4 { return ConnectionProof(issue: .unsafeIPv6) }
            return ConnectionProof(issue: .noTunnel)
        }
        let results = await AddressClient.checkAll(sources.filter { route.requiresIPv6 || !$0.isIPv6Only }, direct: true)
        switch route.verify(results) {
        case .confirmed(let addresses):
            return ConnectionProof(addresses: addresses,
                                   issue: blocksOutsideDNS && snapshot.dnsRoute == .outsideTunnel ? .unsafeDNS : nil)
        case .disagreement: return ConnectionProof(issue: .disagreement)
        case .insufficientIPv4: return ConnectionProof(issue: .noResponse)
        case .insufficientIPv6: return ConnectionProof(issue: .unsafeIPv6)
        }
    }

    private static func hosts(for target: ProtectionTarget, rule: ApplicationAccessRule) -> [String] {
        guard target.hosts.isEmpty else { return target.hosts }
        return rule.customHost.flatMap(ServicePath.validatedHost).map { [$0] } ?? []
    }

    private static func probe(direct: Set<String>, system: Set<String>) async -> [ServicePath] {
        await withTaskGroup(of: ServicePath.self) { group in
            for host in direct { group.addTask { await AddressClient.servicePath(host, systemProxy: false) } }
            for host in system { group.addTask { await AddressClient.servicePath(host, systemProxy: true) } }
            var results: [ServicePath] = []
            for await path in group { results.append(path) }
            return results.sorted { $0.id < $1.id }
        }
    }
}

actor IPCountryLookup {
    static let shared = IPCountryLookup()
    private struct Result: Decodable { let ip: String; let country: String }
    private var cache: [String: (country: String?, expires: Date)] = [:]
    private var pending: [String: Task<String?, Never>] = [:]

    func lookup(_ addresses: Set<String>) async -> [String: String] {
        var result: [String: String] = [:]
        for ip in addresses.sorted() where !Task.isCancelled {
            result[ip] = await country(ip)
        }
        return result
    }

    private func country(_ address: String) async -> String? {
        if let entry = cache[address], entry.expires > .now { return entry.country }
        if let task = pending[address] { return await task.value }
        let task = Task { () -> String? in
            guard let ip = AddressEcho.parse(address), let url = URL(string: "https://api.country.is/\(ip)"),
                  let data = try? await AddressClient.readJSON(url),
                  let result = try? JSONDecoder().decode(Result.self, from: data),
                  AddressEcho.parse(result.ip) == ip else { return nil }
            return AddressAccessPolicy.countryCode(result.country)
        }
        pending[address] = task
        let value = await task.value
        pending[address] = nil
        if cache.count >= 128 { cache.removeAll(keepingCapacity: true) }
        cache[address] = (value, .now.addingTimeInterval(value == nil ? 60 : 1800))
        return value
    }
}
