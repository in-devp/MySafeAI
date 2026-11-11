import Foundation
import NetworkDiagnostics
import Testing

private func checks(_ ip: String, proxy: Bool = false) -> [AddressCheckResult] {
    [BuiltInAddressSource.aws, .cloudflare].map {
        .init(source: $0.source, outcome: .address(ip), usedProxy: proxy)
    }
}

@Test func identifiesAProxyOnlyExitDespiteASuccessfulSystemCheck() throws {
    let report = LeakCheckReport(
        snapshot: .init(ipv4: .other("en0"), ipv6: .missing, dns: .unavailable),
        proxy: .init(modes: ["HTTPS"]),
        direct: checks("203.0.113.2"), system: checks("198.51.100.2", proxy: true),
        ipv6: [], dns: .disabled
    )
    #expect(report.findings.first(where: { $0.id == "proxy" })?.level == .warning)
    #expect(report.hasWarnings)
}

@Test func recordsProxyBypassAndKeepsMissingMetricsInconclusive() {
    let snapshot = NetworkSnapshot(ipv4: .tunnel("utun4"), ipv6: .missing,
                                   dns: .unavailable, dnsRoute: .viaTunnel)
    let direct = checks("203.0.113.2")
    let bypassed = LeakCheckReport(snapshot: snapshot, proxy: .init(modes: ["PAC"]),
                                  direct: direct, system: direct, ipv6: [], dns: .disabled)
    #expect(bypassed.findings.first(where: { $0.id == "proxy" })?.level == .info)
    let missingMetrics = direct.map { AddressCheckResult(source: $0.source, outcome: $0.outcome) }
    let unknown = LeakCheckReport(snapshot: snapshot, proxy: .init(modes: ["HTTPS"]),
                                 direct: direct, system: missingMetrics, ipv6: [], dns: .disabled)
    #expect(unknown.findings.first(where: { $0.id == "proxy" })?.level == .unknown)
}

@Test func detectsReachableIPv6OutsideTheIPv4Tunnel() {
    let ipv6: [AddressCheckResult] = [BuiltInAddressSource.identIPv6, .ipifyIPv6].map {
        .init(source: $0.source, outcome: .address("2001:db8::1"))
    }
    let report = LeakCheckReport(
        snapshot: .init(ipv4: .tunnel("utun4"), ipv6: .other("en0"), dns: .unavailable),
        proxy: .init(modes: []), direct: checks("203.0.113.2"), system: checks("203.0.113.2"),
        ipv6: ipv6, dns: .disabled
    )
    #expect(report.findings.first(where: { $0.id == "ipv6" })?.level == .warning)
}

@Test func rejectsDNSObserverHostnamesOutsideTheFixedTestZone() throws {
    let decoder = JSONDecoder()
    let valid = try decoder.decode(DNSObserverSession.self, from: Data(
        #"{"testId":"abc123","hostnames":["abc123-a01.t.dnsleak.dev","abc123-q01.t.dnsleak.dev"]}"#.utf8
    ))
    #expect(valid.isValid)
    let invalid = try decoder.decode(DNSObserverSession.self, from: Data(
        #"{"testId":"abc123","hostnames":["abc123-a01.t.dnsleak.dev.evil.example","router.internal"]}"#.utf8
    ))
    #expect(!invalid.isValid)
    let traversal = try decoder.decode(DNSObserverSession.self, from: Data(
        #"{"testId":"../../local","hostnames":["abc-a01.t.dnsleak.dev","abc-q01.t.dnsleak.dev"]}"#.utf8
    ))
    #expect(!traversal.isValid)
}

@Test func preservesIncompleteDNSAndUnknownRemoteVerdicts() throws {
    let snapshot = NetworkSnapshot(ipv4: .tunnel("utun4"), ipv6: .missing,
                                   dns: .unavailable, dnsRoute: .viaTunnel)
    for (lookups, verdict) in [(1, "no_leak"), (12, "inconclusive"), (12, "future-status")] {
        let payload = """
        {"lookups":\(lookups),"resolvers":[
            {"ip":"192.0.2.53","role":"resolver","operator":"Test DNS"},
            {"ip":"192.0.2.54","role":"observer","operator":"Observer"}
        ],"verdict":{"status":"\(verdict)"}}
        """
        let observation = try JSONDecoder().decode(DNSObserverReport.self, from: Data(payload.utf8))
        #expect(observation.answeringResolvers.map(\.ip) == ["192.0.2.53"])
        let report = LeakCheckReport(snapshot: snapshot, proxy: .init(modes: []),
                                     direct: checks("203.0.113.2"), system: checks("203.0.113.2"),
                                     ipv6: [], dns: .observed(observation, expected: 12))
        #expect(report.findings.first(where: { $0.id == "dnsObserver" })?.level == .unknown)
    }
}
