import Foundation

public enum BuiltInAddressSource: String, CaseIterable, Codable, Sendable {
    case aws
    case cloudflare
    case ipify
    case ipinfo
    case identIPv6
    case ipifyIPv6

    public var source: AddressSource {
        switch self {
        case .aws:
            AddressSource(name: "AWS", url: URL(string: "https://checkip.amazonaws.com/")!, ipVersion: 4)
        case .cloudflare:
            AddressSource(name: "Cloudflare", url: URL(string: "https://1.1.1.1/cdn-cgi/trace")!, isTrace: true, ipVersion: 4)
        case .ipify:
            AddressSource(name: "ipify", url: URL(string: "https://api.ipify.org/")!, ipVersion: 4)
        case .ipinfo:
            AddressSource(name: "IPinfo", url: URL(string: "https://ipinfo.io/ip")!, ipVersion: 4)
        case .identIPv6:
            AddressSource(name: "ident.me · IPv6", url: URL(string: "https://6.ident.me/")!, ipVersion: 6)
        case .ipifyIPv6:
            AddressSource(name: "ipify · IPv6", url: URL(string: "https://api6.ipify.org/")!, ipVersion: 6)
        }
    }
}

public struct AddressSource: Identifiable, Sendable {
    public let name: String
    public let url: URL
    private let isTrace: Bool
    public let ipVersion: Int?
    public var isIPv6Only: Bool { ipVersion == 6 }

    fileprivate init(name: String, url: URL, isTrace: Bool = false, ipVersion: Int? = nil) {
        self.name = name
        self.url = url
        self.isTrace = isTrace
        self.ipVersion = ipVersion
    }

    public var id: URL { url }
    var provider: String { url.host?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) ?? "" }

    public func parse(_ body: String) -> String? {
        let address = isTrace ? AddressEcho.parseTrace(body) : AddressEcho.parse(body)
        if let ipVersion, let address, address.contains(":") != (ipVersion == 6) { return nil }
        return address
    }
}

public struct AddressSourceSettings: Codable, Sendable {
    public var enabledBuiltIns: Set<BuiltInAddressSource> = [.aws, .cloudflare, .identIPv6, .ipifyIPv6]
    public private(set) var customURLs: [URL] = []
    // Existing settings predate a pair of dedicated IPv6 sources.
    private var configuresIPv6: Bool? = true

    public mutating func migrateIPv6Sources() {
        guard configuresIPv6 == nil else { return }
        if enabledBuiltIns.contains(.aws) && enabledBuiltIns.contains(.cloudflare) {
            enabledBuiltIns.formUnion([.identIPv6, .ipifyIPv6])
        }
        configuresIPv6 = true
    }

    public init(previousEndpoint: String? = nil) {
        guard let previousEndpoint, let url = AddressEcho.endpoint(previousEndpoint) else { return }
        if let builtIn = BuiltInAddressSource.allCases.first(where: { $0.source.url == url }) {
            enabledBuiltIns = [builtIn]
        } else if add(previousEndpoint) {
            enabledBuiltIns = []
        }
    }

    public var enabledSources: [AddressSource] {
        let builtIns = BuiltInAddressSource.allCases.filter { enabledBuiltIns.contains($0) }.map(\.source)
        let custom = customURLs.compactMap { saved -> AddressSource? in
            guard let url = AddressEcho.endpoint(saved.absoluteString) else { return nil }
            return AddressSource(name: url.host ?? url.absoluteString, url: url)
        }
        return builtIns + custom
    }

    public func canAdd(_ input: String) -> Bool {
        newURL(input) != nil
    }

    @discardableResult public mutating func add(_ input: String) -> Bool {
        guard let url = newURL(input) else { return false }
        customURLs.append(url)
        return true
    }

    public mutating func remove(_ url: URL) {
        customURLs.removeAll { $0 == url }
    }

    private func newURL(_ input: String) -> URL? {
        guard let url = AddressEcho.endpoint(input), !customURLs.contains(url),
              !BuiltInAddressSource.allCases.contains(where: { $0.source.url == url }) else {
            return nil
        }
        return url
    }
}

public struct AddressCheckResult: Identifiable, Sendable {
    public enum Outcome: Equatable, Sendable {
        case address(String)
        case invalidResponse
        case unavailable
    }

    public let source: AddressSource
    public let outcome: Outcome
    public let usedProxy: Bool?
    public var id: URL { source.id }

    public init(source: AddressSource, outcome: Outcome, usedProxy: Bool? = nil) {
        self.source = source
        self.outcome = outcome
        self.usedProxy = usedProxy
    }
}

public struct AddressCheckSummary {
    public let responseCount: Int
    public let ipv4: Set<String>
    public let ipv6: Set<String>
    public let ipv4SourceCount: Int
    public let ipv6SourceCount: Int

    public init(_ results: [AddressCheckResult]) {
        var v4: Set<String> = []
        var v6: Set<String> = []
        var v4Providers: Set<String> = []
        var v6Providers: Set<String> = []
        var count = 0
        for result in results {
            guard case .address(let address) = result.outcome else { continue }
            count += 1
            if address.contains(":") {
                v6.insert(address)
                v6Providers.insert(result.source.provider)
            } else {
                v4.insert(address)
                v4Providers.insert(result.source.provider)
            }
        }
        responseCount = count
        ipv4 = v4
        ipv6 = v6
        ipv4SourceCount = v4Providers.count
        ipv6SourceCount = v6Providers.count
    }

    public var hasDisagreement: Bool {
        ipv4.count > 1 || ipv6.count > 1
    }

    public var preferredAddress: String? {
        guard !hasDisagreement else { return nil }
        return ipv4.first ?? ipv6.first
    }

    public var confirmedIPv4: String? { ipv4.count == 1 && ipv4SourceCount >= 2 ? ipv4.first : nil }
    public var confirmedIPv6: String? { ipv6.count == 1 && ipv6SourceCount >= 2 ? ipv6.first : nil }
}
