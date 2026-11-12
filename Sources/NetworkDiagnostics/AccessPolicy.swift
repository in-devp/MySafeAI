import Darwin
import Foundation

public struct IPSubnet: Hashable, Codable, Sendable {
    public let notation: String
    private let network: [UInt8]
    private let prefix: Int

    public init?(_ input: String) {
        let parts = input.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let ip = AddressEcho.parse(String(parts[0])),
              let bytes = Self.bytes(ip), let prefix = Int(parts[1]), (0...bytes.count * 8).contains(prefix) else { return nil }
        self.prefix = prefix
        network = bytes.enumerated().map { index, byte in
            let bits = max(0, min(8, prefix - index * 8))
            return bits == 0 ? 0 : byte & (UInt8.max << (8 - bits))
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = bytes.count == 4 ? AF_INET : AF_INET6
        let formatted = network.withUnsafeBytes { inet_ntop(family, $0.baseAddress, &buffer, socklen_t(buffer.count)) }
        guard formatted != nil else { return nil }
        notation = String(decoding: buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self) + "/\(prefix)"
    }

    public func contains(_ address: String) -> Bool {
        guard let bytes = Self.bytes(address), bytes.count == network.count else { return false }
        let whole = prefix / 8
        guard bytes.prefix(whole).elementsEqual(network.prefix(whole)) else { return false }
        let remaining = prefix % 8
        return remaining == 0 || bytes[whole] & (UInt8.max << (8 - remaining)) == network[whole]
    }

    public init(from decoder: Decoder) throws {
        let box = try decoder.singleValueContainer()
        guard let subnet = Self(try box.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: box, debugDescription: "Invalid CIDR")
        }
        self = subnet
    }

    public func encode(to encoder: Encoder) throws {
        var box = encoder.singleValueContainer()
        try box.encode(notation)
    }

    private static func bytes(_ address: String) -> [UInt8]? {
        guard !address.utf8.contains(0) else { return nil }
        let family = address.contains(":") ? AF_INET6 : AF_INET
        var bytes = [UInt8](repeating: 0, count: family == AF_INET6 ? 16 : 4)
        return bytes.withUnsafeMutableBytes { inet_pton(family, address, $0.baseAddress) } == 1 ? bytes : nil
    }
}

public struct AddressAccessPolicy: Codable, Equatable, Sendable {
    public var addresses: Set<String> = []
    public var subnets: Set<IPSubnet> = []
    public var countries: Set<String> = []
    public var directAddresses: Set<String>?

    public init(addresses: Set<String> = [], subnets: Set<IPSubnet> = [], countries: Set<String> = []) {
        self.addresses = addresses
        self.subnets = subnets
        self.countries = countries
    }

    public func allows(_ address: String, country: String?) -> Bool {
        guard let ip = AddressEcho.parse(address) else { return false }
        return addresses.contains(ip) || subnets.contains { $0.contains(ip) } ||
            (country.flatMap(Self.countryCode).map(countries.contains) ?? false)
    }

    public func allowsDirect(_ address: String) -> Bool {
        guard let ip = AddressEcho.parse(address) else { return false }
        return directAddresses?.contains(ip) == true
    }

    public static func countryCode(_ value: String) -> String? {
        let code = value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        return Locale.Region.isoRegions.contains(Locale.Region(code)) ? code : nil
    }
}

public enum ProtectionTransport: String, CaseIterable, Codable, Sendable {
    case automatic, tunnel, serviceTunnel, systemProxy

    public var checksServiceHosts: Bool { self == .serviceTunnel || self == .systemProxy }
}

public struct ApplicationAccessRule: Codable, Equatable, Sendable {
    public var transport: ProtectionTransport = .automatic
    public var addressPolicy: AddressAccessPolicy?
    public var allowsTrustedNetworks = true
    public var customHost: String?

    public init() {}
}

public struct TrustedLocalNetwork: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let addresses: Set<String>

    public init(id: String, name: String, addresses: Set<String>) {
        self.id = id
        self.name = name
        self.addresses = addresses
    }

    public func matches(router: String?, addresses: [String]) -> Bool {
        id == router && !addresses.isEmpty && self.addresses == Set(addresses)
    }
}
