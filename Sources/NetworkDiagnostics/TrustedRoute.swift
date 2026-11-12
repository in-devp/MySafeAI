public enum ProtectionIssue: Equatable, Sendable {
    case noTunnel
    case unsafeIPv6
    case unsafeDNS
    case noResponse
    case disagreement
    case unexpectedAddress
    case serviceUnverified
    case proxyUnverified
}

public struct TrustedRoute: Equatable, Sendable {
    public enum Verification: Equatable, Sendable {
        case confirmed([String])
        case disagreement, insufficientIPv4, insufficientIPv6
    }
    public let interface: String
    public let requiresIPv6: Bool

    public init?(ipv4: DefaultRoute, ipv6: DefaultRoute) {
        guard let interface = ipv4.interface, interface != "lo0",
              ipv6 == .missing || ipv6 == ipv4 else { return nil }
        self.interface = interface
        requiresIPv6 = ipv6 != .missing
    }

    public func verify(_ results: [AddressCheckResult]) -> Verification {
        let summary = AddressCheckSummary(results)
        if summary.hasDisagreement || (!requiresIPv6 && !summary.ipv6.isEmpty) {
            return .disagreement
        }
        guard let v4 = summary.confirmedIPv4 else { return .insufficientIPv4 }
        guard requiresIPv6 else { return .confirmed([v4]) }
        guard let v6 = summary.confirmedIPv6 else { return .insufficientIPv6 }
        return .confirmed([v4, v6])
    }
}
