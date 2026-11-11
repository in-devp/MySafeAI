import Darwin
import Foundation
import CryptoKit

public enum DefaultRoute: Equatable, Sendable {
    case tunnel(String)
    case other(String)
    case missing
    case unavailable

    public init(output: String, exitCode: Int32) {
        // macOS can print this routing-socket error while returning exit status 0.
        if output.contains("route: writing to routing socket: not in table") {
            self = .missing
            return
        }
        guard exitCode == 0 else {
            self = .unavailable
            return
        }
        guard let line = output.split(separator: "\n").first(where: {
            $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:")
        }), let interface = line.split(whereSeparator: \.isWhitespace).last,
            interface != "interface:" else {
            self = .unavailable
            return
        }
        let name = String(interface)
        self = name.range(of: #"^(utun|tun|tap|ppp|ipsec)[0-9]+$"#, options: .regularExpression) == nil
            ? .other(name)
            : .tunnel(name)
    }

    public var interface: String? {
        switch self {
        case .tunnel(let name), .other(let name): name
        case .missing, .unavailable: nil
        }
    }
}

public struct DNSResolver: Equatable, Sendable {
    public let interface: String?
    public let isScoped: Bool
    public let servers: [String]
}

public enum DNSRoute: Equatable, Sendable {
    case viaTunnel, outsideTunnel, unknown

    public init(tunnel: String, routes: [DefaultRoute]) {
        if routes.contains(where: {
            switch $0 {
            case .other(let name): name != "lo0"
            case .tunnel(let name): name != tunnel
            case .missing, .unavailable: false
            }
        }) {
            self = .outsideTunnel
        } else if !routes.isEmpty && routes.allSatisfy({ $0 == .tunnel(tunnel) }) {
            self = .viaTunnel
        } else {
            self = .unknown
        }
    }
}

public enum DNSConfiguration: Equatable, Sendable {
    case available([DNSResolver])
    case unavailable

    public init(output: String, exitCode: Int32) {
        guard exitCode == 0, output.hasPrefix("DNS configuration") else {
            self = .unavailable
            return
        }

        var resolvers: [DNSResolver] = []
        var isScoped = false
        var servers: [String] = []
        var interface: String?

        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("DNS configuration") || line.hasPrefix("resolver #") {
                if !servers.isEmpty {
                    resolvers.append(DNSResolver(interface: interface, isScoped: isScoped, servers: servers))
                }
                servers = []
                interface = nil
                if line.hasPrefix("DNS configuration") {
                    isScoped = line == "DNS configuration (for scoped queries)"
                }
            } else if line.hasPrefix("nameserver["), let delimiter = line.firstIndex(of: ":"),
                      let address = line[line.index(after: delimiter)...].split(separator: "%").first,
                      let ip = AddressEcho.parse(String(address)) {
                servers.append(ip)
            } else if line.hasPrefix("if_index"), let start = line.lastIndex(of: "("),
                      line.hasSuffix(")") {
                interface = String(line[line.index(after: start)..<line.index(before: line.endIndex)])
            }
        }

        if !servers.isEmpty {
            resolvers.append(DNSResolver(interface: interface, isScoped: isScoped, servers: servers))
        }
        self = .available(resolvers)
    }
}

public struct NetworkSnapshot: Equatable, Sendable {
    public let ipv4: DefaultRoute
    public let ipv6: DefaultRoute
    public let dns: DNSConfiguration
    public let dnsRoute: DNSRoute
    public let router: String?

    public init(ipv4: DefaultRoute, ipv6: DefaultRoute, dns: DNSConfiguration, dnsRoute: DNSRoute = .unknown,
                router: String? = nil) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.dns = dns
        self.dnsRoute = dnsRoute
        self.router = router
    }

    public static func read() async -> Self {
        async let v4 = run("/sbin/route", ["-n", "get", "-inet", "default"])
        async let v6 = readIPv6Route()
        async let dns = run("/usr/sbin/scutil", ["--dns"])
        let result = await dns
        let v4Result = await v4
        let ipv4 = DefaultRoute(output: v4Result.output, exitCode: v4Result.exitCode)
        let configuration = DNSConfiguration(output: result.output, exitCode: result.exitCode)
        let dnsRoute = await assessDNS(configuration, ipv4: ipv4)
        return await Self(
            ipv4: ipv4,
            ipv6: v6,
            dns: configuration,
            dnsRoute: dnsRoute,
            router: routerFingerprint(route: ipv4, output: v4Result.output)
        )
    }

    public static func route(to destination: String) async -> DefaultRoute {
        guard let ip = AddressEcho.parse(destination) else { return .unavailable }
        return await readRoute(family: ip.contains(":") ? "-inet6" : "-inet", destination: ip)
    }

    public func dnsRoute(usingTunnel tunnel: String) async -> DNSRoute {
        if ipv4 == .tunnel(tunnel) { return dnsRoute }
        return await Self.assessDNS(dns, ipv4: .tunnel(tunnel))
    }

    private static func routerFingerprint(route: DefaultRoute, output: String) -> String? {
        guard case .other(let interface) = route, interface.hasPrefix("en"),
              let line = output.split(separator: "\n").first(where: {
                  $0.trimmingCharacters(in: .whitespaces).hasPrefix("gateway:")
              }), let raw = line.split(whereSeparator: \.isWhitespace).last,
              let gateway = AddressEcho.parse(String(raw)), !gateway.contains(":") else { return nil }
        let reply = run("/usr/sbin/arp", ["-n", "-i", interface, gateway])
        let words = reply.output.split(whereSeparator: \.isWhitespace)
        guard reply.exitCode == 0, let at = words.firstIndex(of: "at"), at + 1 < words.count else { return nil }
        let fields = words[at + 1].split(separator: ":")
        let bytes = fields.compactMap { UInt8($0, radix: 16) }
        guard fields.count == 6, bytes.count == 6, bytes[0] & 1 == 0, bytes.contains(where: { $0 != 0 }) else { return nil }
        let data = Data("\(interface)|\(gateway)|".utf8) + Data(bytes)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func readIPv6Route() async -> DefaultRoute {
        let route = await readRoute(family: "-inet6")
        guard route == .missing else { return route }
        return await readRoute(family: "-inet6", destination: "2606:4700:4700::1111")
    }

    private static func assessDNS(_ config: DNSConfiguration, ipv4: DefaultRoute) async -> DNSRoute {
        guard case .tunnel(let tunnel) = ipv4, case .available(let resolvers) = config else { return .unknown }
        let servers = Set(resolvers.filter { !$0.isScoped }.flatMap(\.servers))
        return await withTaskGroup(of: DefaultRoute.self) { group in
            for server in servers {
                group.addTask {
                    await readRoute(family: server.contains(":") ? "-inet6" : "-inet", destination: server)
                }
            }
            var routes: [DefaultRoute] = []
            for await route in group { routes.append(route) }
            return DNSRoute(tunnel: tunnel, routes: routes)
        }
    }

    private static func readRoute(family: String, destination: String = "default") async -> DefaultRoute {
        let result = run("/sbin/route", ["-n", "get", family, destination])
        return DefaultRoute(output: result.output, exitCode: result.exitCode)
    }

    private static func run(_ path: String, _ arguments: [String]) -> (output: String, exitCode: Int32) {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["LC_ALL": "C"]
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let output = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (String(decoding: output, as: UTF8.self), process.terminationStatus)
        } catch {
            return ("", -1)
        }
    }
}

public enum AddressEcho {
    public static func endpoint(_ input: String) -> URL? {
        guard var parts = URLComponents(string: input.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme?.lowercased() == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil else {
            return nil
        }
        parts.scheme = "https"
        parts.host = host.lowercased()
        if parts.port == 443 { parts.port = nil }
        if parts.path.isEmpty { parts.path = "/" }
        return parts.url
    }

    public static func parse(_ input: String) -> String? {
        let address = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !address.utf8.contains(0) else { return nil }
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return address
        }
        guard address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
        var buffer = [UInt8](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return String(decoding: buffer.prefix(while: { $0 != 0 }), as: UTF8.self)
    }

    public static func parseTrace(_ input: String) -> String? {
        let fields = input.split(whereSeparator: \.isNewline).filter { $0.hasPrefix("ip=") }
        guard fields.count == 1, let field = fields.first else { return nil }
        return parse(String(field.dropFirst(3)))
    }
}
