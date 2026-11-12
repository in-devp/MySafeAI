import Foundation

public struct ServicePath: Identifiable, Equatable, Sendable {
    public let host: String
    public let systemProxy: Bool
    public let usedProxy: Bool?
    public let remoteAddress: String?
    public let route: DefaultRoute
    public let observedAddress: String?
    public let country: String?
    public var id: String { "\(host)|\(systemProxy)" }

    public init(host: String, systemProxy: Bool, usedProxy: Bool?, remoteAddress: String?,
                route: DefaultRoute, observedAddress: String?, country: String? = nil) {
        self.host = host
        self.systemProxy = systemProxy
        self.usedProxy = usedProxy
        self.remoteAddress = remoteAddress
        self.route = route
        self.observedAddress = observedAddress
        self.country = country.flatMap(AddressAccessPolicy.countryCode)
    }

    public static func validatedHost(_ input: String) -> String? {
        let host = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard host.utf8.count <= 253, labels.count >= 2,
              labels.allSatisfy({ label in
                  (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-" &&
                      label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
              }), labels.last?.contains(where: \.isLetter) == true else { return nil }
        return host
    }

    public func confirms(_ transport: ProtectionTransport, ipv6: DefaultRoute) -> Bool {
        guard observedAddress.flatMap(AddressEcho.parse) != nil,
              remoteAddress.flatMap(AddressEcho.parse) != nil else { return false }
        switch transport {
        case .serviceTunnel:
            guard !systemProxy, usedProxy == false, case .tunnel = route else { return false }
            return ipv6 == .missing || ipv6 == route
        case .systemProxy:
            return systemProxy && usedProxy == true
        case .automatic, .tunnel:
            return false
        }
    }
}
