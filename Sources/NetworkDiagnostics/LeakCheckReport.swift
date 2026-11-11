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

public struct DNSObserverSession: Decodable, Sendable {
    public let testId: String
    public let hostnames: [String]

    public var isValid: Bool {
        guard !testId.isEmpty, testId.count <= 80,
              testId.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }),
              (2...12).contains(hostnames.count), Set(hostnames).count == hostnames.count else { return false }
        return hostnames.allSatisfy {
            let suffix = String($0.dropFirst(testId.count + 1))
            return $0.hasPrefix(testId.lowercased() + "-") &&
                suffix.range(of: #"^[aq][0-9]{2}\.t\.dnsleak\.dev$"#, options: .regularExpression) != nil
        } && hostnames.contains(where: { $0.hasPrefix(testId.lowercased() + "-a") })
          && hostnames.contains(where: { $0.hasPrefix(testId.lowercased() + "-q") })
    }
}

public struct ObservedDNSResolver: Decodable, Identifiable, Sendable {
    public let ip: String
    public let country: String?
    public let operatorName: String?
    public let org: String?
    public let role: String?
    public let ecs: String?
    public var id: String { ip }
    public var label: String { String((operatorName ?? org ?? ip).prefix(90)) }

    enum CodingKeys: String, CodingKey {
        case ip, country, org, role, ecs
        case operatorName = "operator"
    }
}

public struct DNSObserverReport: Decodable, Sendable {
    public struct Verdict: Decodable, Sendable { public let status: String }
    public let lookups: Int
    public let resolvers: [ObservedDNSResolver]
    public let verdict: Verdict
    public let truncated: Bool?

    public var answeringResolvers: [ObservedDNSResolver] {
        var seen: Set<String> = []
        return resolvers.filter {
            $0.role == "resolver" && AddressEcho.parse($0.ip) != nil && seen.insert($0.ip).inserted
        }
    }
}

public enum DNSObservation: Sendable {
    case disabled
    case unavailable
    case observed(DNSObserverReport, expected: Int)
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
            return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: "Сервис не ответил",
                         detail: "Активный тест DNS не завершён. Повторите проверку позднее.", level: .unknown)
        case .observed(let report, let expected):
            let resolvers = report.answeringResolvers
            guard report.lookups >= expected, !resolvers.isEmpty, report.truncated != true else {
                return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: "Получена часть ответов",
                             detail: "Дошло запросов: \(max(0, report.lookups)) из \(expected). Повторите тест.",
                             level: .unknown)
            }
            let labels = Set(resolvers.map(\.label)).sorted().joined(separator: ", ")
            switch report.verdict.status {
            case "split":
                return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: labels,
                             detail: "Часть запросов ушла к другому оператору. Сверьте список с DNS-настройками VPN.",
                             level: .warning)
            case "no_leak", "inconclusive":
                return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: labels,
                             detail: "Сервер увидел эти резолверы при разрешении случайных имён. Сверьте операторов с настройками VPN.",
                             level: report.verdict.status == "inconclusive" ? .unknown : .info)
            default:
                return .init(id: "dnsObserver", title: "Наблюдаемые DNS", value: labels,
                             detail: "Сервис вернул незнакомый результат. Автоматическая оценка недоступна.",
                             level: .unknown)
            }
        }
    }
}
