import CFNetwork
import CryptoKit
import Foundation

public struct SystemProxyConfiguration: Equatable, Sendable {
    public let modes: [String]
    private let endpoints: [String]
    public var isEnabled: Bool { !modes.isEmpty }

    public init(modes: [String], endpoints: [String] = []) {
        self.modes = modes
        self.endpoints = endpoints
    }

    public static func read() -> Self {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return Self(modes: [])
        }
        let entries = [
            ("HTTPEnable", "HTTP"),
            ("HTTPSEnable", "HTTPS"),
            ("SOCKSEnable", "SOCKS"),
            ("ProxyAutoConfigEnable", "PAC"),
            ("ProxyAutoDiscoveryEnable", "Автонастройка")
        ]
        let enabled = entries.filter { (settings[$0.0] as? NSNumber)?.boolValue == true }
        let fingerprint = JSONSerialization.isValidJSONObject(settings)
            ? (try? JSONSerialization.data(withJSONObject: settings, options: [.sortedKeys])).map { SHA256.hash(data: $0).description }
            : nil
        return Self(modes: enabled.map { $0.1 }, endpoints: [fingerprint ?? ""])
    }
}

public struct LeakFinding: Identifiable, Sendable {
    public enum Level: Sendable { case good, warning, unknown, info }
    public let id: String
    public let title: String
    public let value: String
    public let detail: String
    public let level: Level
}

public struct DNSObserverSession: Sendable {
    private static let service = URL(string: "https://bash.ws")!
    public static let startURL = service.appending(path: "id")
    private let testID: String

    public init?(response: String) {
        let token = response.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...63).contains(token.utf8.count),
              token.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else { return nil }
        testID = token
    }

    public var hostnames: [String] {
        (1...6).map { "\($0).\(testID).bash.ws" }
    }

    public var resultURL: URL {
        Self.service.appending(path: "dnsleak/test/\(testID)").appending(queryItems: [.init(name: "json", value: "2")])
    }
}

public struct ObservedDNSResolver: Identifiable, Sendable {
    public let ip: String
    public let country: String?
    public let label: String
    public var id: String { ip }
}

public struct DNSObserverReport: Decodable, Sendable {
    private struct Row: Decodable {
        let type: String
        let ip: String?
        let org: String?
        let asn: String?
        let country: String?
        let countryName: String?

        enum CodingKeys: String, CodingKey {
            case type, ip, org, asn, country
            case countryName = "country_name"
        }
    }

    public let answeringResolvers: [ObservedDNSResolver]

    public init(from decoder: any Decoder) throws {
        let rows = try decoder.singleValueContainer().decode([Row].self)
        guard !rows.contains(where: { $0.type == "error" }) else {
            answeringResolvers = []
            return
        }
        var seen: Set<String> = []
        answeringResolvers = rows.compactMap { row in
            guard row.type == "dns", let ip = row.ip.flatMap(AddressEcho.parse),
                  seen.insert(ip).inserted else { return nil }
            let name = Self.nonEmpty(row.org) ?? Self.nonEmpty(row.asn) ?? ip
            return .init(ip: ip, country: Self.nonEmpty(row.countryName) ?? Self.nonEmpty(row.country),
                         label: String(name.prefix(90)))
        }
    }

    private static func nonEmpty(_ text: String?) -> String? {
        guard let value = text?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
        return value
    }
}

public enum DNSObservation: Sendable {
    case disabled
    case unavailable
    case observed([ObservedDNSResolver])
}

public struct LeakCheckReport: Sendable {
    public let date: Date
    public let snapshot: NetworkSnapshot
    public let proxy: SystemProxyConfiguration
    public let direct: [AddressCheckResult]
    public let system: [AddressCheckResult]
    public let ipv6: [AddressCheckResult]
    public let dns: DNSObservation

    public init(date: Date = .now, snapshot: NetworkSnapshot, proxy: SystemProxyConfiguration,
                direct: [AddressCheckResult], system: [AddressCheckResult],
                ipv6: [AddressCheckResult], dns: DNSObservation) {
        self.date = date
        self.snapshot = snapshot
        self.proxy = proxy
        self.direct = direct
        self.system = system
        self.ipv6 = ipv6
        self.dns = dns
    }

    public var findings: [LeakFinding] {
        [directFinding, proxyFinding, ipv6Finding, dnsRouteFinding, dnsObserverFinding]
    }

    public var hasWarnings: Bool { findings.contains { $0.level == .warning } }
    public var hasUnknowns: Bool { findings.contains { $0.level == .unknown } }
    public var summary: String {
        if hasWarnings { return "Есть риски утечки" }
        if hasUnknowns { return "Часть проверок не завершена" }
        return "Проверки завершены"
    }

    private var directFinding: LeakFinding {
        let summary = AddressCheckSummary(direct)
        guard let address = summary.confirmedIPv4 else {
            return .init(id: "direct", title: "Прямой IPv4 · CLI", value: "IP не подтверждён",
                         detail: "Нужны совпавшие ответы двух источников. Проверьте их доступность в настройках.",
                         level: summary.hasDisagreement ? .warning : .unknown)
        }
        if case .tunnel(let interface) = snapshot.ipv4 {
            return .init(id: "direct", title: "Прямой IPv4 · CLI", value: address,
                         detail: "Два источника подтвердили IP. Основной маршрут идёт через \(interface).",
                         level: .good)
        }
        return .init(id: "direct", title: "Прямой IPv4 · CLI", value: address,
                     detail: "Туннельный маршрут не подтверждён. Включите TUN или VPN для всего устройства.",
                     level: .warning)
    }

    private var proxyFinding: LeakFinding {
        let directIP = AddressCheckSummary(direct).confirmedIPv4
        let summary = AddressCheckSummary(system)
        let usedProxy = system.contains { $0.usedProxy == true }
        guard let address = summary.confirmedIPv4 else {
            return .init(id: "proxy", title: "Системный путь", value: "IP не подтверждён",
                         detail: "Системное подключение должно получить совпавшие ответы двух источников.",
                         level: summary.hasDisagreement ? .warning : .unknown)
        }
        if let directIP, address != directIP {
            return .init(id: "proxy", title: "Системный путь", value: address,
                         detail: usedProxy
                            ? "Прокси и прямой выход CLI показывают разные IP. Включите TUN или перенаправление всего трафика в VPN-клиенте."
                            : "Системное и прямое подключения показывают разные IP. Проверьте прокси и раздельную маршрутизацию.",
                         level: .warning)
        }
        if usedProxy {
            return .init(id: "proxy", title: "Системный путь · прокси", value: address,
                         detail: directIP == nil ? "Прокси работает, прямой выход CLI ещё не подтверждён."
                            : "Запросы действительно использовали прокси. IP совпал с прямым выходом CLI.",
                         level: directIP == nil ? .unknown : .good)
        }
        let successful = system.filter {
            if case .address = $0.outcome { return true }
            return false
        }
        let knownDirect = successful.allSatisfy { $0.usedProxy == false }
        return .init(id: "proxy", title: "Системный путь", value: address,
                     detail: knownDirect
                        ? proxy.isEnabled ? "Для тестовых адресов система выбрала подключение без прокси."
                            : "Тестовые запросы прошли без прокси. Проверяется обычный системный выход."
                        : "Метрики использования прокси не получены. Путь запроса требует проверки.",
                     level: knownDirect ? .info : .unknown)
    }

    private var ipv6Finding: LeakFinding {
        let summary = AddressCheckSummary(ipv6)
        if summary.hasDisagreement {
            return .init(id: "ipv6", title: "IPv6", value: "Источники видят разные IP",
                         detail: "Проверьте маршрутизацию IPv6 в VPN-клиенте.", level: .warning)
        }
        if let address = summary.ipv6.first {
            let sameTunnel = snapshot.ipv6 == snapshot.ipv4
            if case .tunnel = snapshot.ipv6, sameTunnel, summary.confirmedIPv6 != nil {
                return .init(id: "ipv6", title: "IPv6", value: address,
                             detail: "Два источника подтвердили IPv6. Основной маршрут использует тот же туннель, что IPv4.",
                             level: .good)
            }
            return .init(id: "ipv6", title: "IPv6", value: address,
                         detail: sameTunnel ? "Ответил один источник. Нужна независимая проверка IPv6."
                            : "IPv6 доступен, его путь через основной VPN-туннель не подтверждён.",
                         level: sameTunnel ? .unknown : .warning)
        }
        if snapshot.ipv6 == .missing && ipv6.count >= 2 {
            return .init(id: "ipv6", title: "IPv6", value: "Прямой IPv6 недоступен",
                         detail: "Маршрут отсутствует, обе HTTPS-проверки IPv6 не получили адрес.", level: .info)
        }
        return .init(id: "ipv6", title: "IPv6", value: "Выход не подтверждён",
                     detail: "Проверьте, что VPN обслуживает IPv6 или блокирует его.",
                     level: snapshot.ipv6.interface != nil && snapshot.ipv6 != snapshot.ipv4 ? .warning : .unknown)
    }

    private var dnsRouteFinding: LeakFinding {
        switch snapshot.dnsRoute {
        case .viaTunnel:
            .init(id: "dnsRoute", title: "Маршруты DNS", value: "Через туннель",
                  detail: "Основные DNS-серверы доступны через VPN-интерфейс.", level: .good)
        case .outsideTunnel:
            .init(id: "dnsRoute", title: "Маршруты DNS", value: "Есть путь вне VPN",
                  detail: "Включите DNS через туннель в VPN-клиенте. MySafeAI может ставить приложения на паузу при таком маршруте.",
                  level: .warning)
        case .viaDirect:
            .init(id: "dnsRoute", title: "Маршруты DNS", value: "Через текущую сеть",
                  detail: "Основные DNS-серверы доступны через интерфейс прямого подключения.", level: .good)
        case .outsideDirect:
            .init(id: "dnsRoute", title: "Маршруты DNS", value: "Через другую сеть",
                  detail: "Часть основных DNS-серверов доступна через другой сетевой интерфейс.", level: .warning)
        case .unknown:
            .init(id: "dnsRoute", title: "Маршруты DNS", value: "Путь не определён",
                  detail: "Локальный DNS-прокси может пересылать запросы дальше. Его следующий сетевой участок требует отдельной проверки.",
                  level: .unknown)
        }
    }

    private var dnsObserverFinding: LeakFinding {
        switch dns {
        case .disabled:
            return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: "Внешний тест выключен",
                         detail: "Включается в настройках. Сервис увидит IP устройства и адреса резолверов.", level: .info)
        case .unavailable:
            return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: "Резолверы не подтверждены",
                         detail: "bash.ws не вернул список резолверов. Можно повторить внешний тест.", level: .unknown)
        case .observed(let resolvers):
            let labels = Set(resolvers.map(\.label)).sorted().joined(separator: ", ")
            return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: labels,
                         detail: "bash.ws увидел эти резолверы при тесте. Сверьте их с DNS-настройками VPN.", level: .info)
        }
    }
}
