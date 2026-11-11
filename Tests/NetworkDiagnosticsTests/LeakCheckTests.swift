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

@Test func restrictsBashWSSessionIDsToTheFixedTestZone() throws {
    let valid = try #require(DNSObserverSession(response: "0123456789abcdef\n"))
    #expect(valid.hostnames.count == 6)
    #expect(valid.hostnames.first == "1.0123456789abcdef.bash.ws")
    #expect(valid.resultURL.absoluteString == "https://bash.ws/dnsleak/test/0123456789abcdef?json=2")
    for response in ["", "example.org", "../../local", "bad/id", "abc?json=3", "a\nb", "проба",
                     String(repeating: "a", count: 64)] {
        #expect(DNSObserverSession(response: response) == nil)
    }
}

@Test func decodesBashWSResolversWithoutTrustingTheRemoteVerdict() throws {
    let payload = """
    [
      {"type":"ip","ip":"192.0.2.1","org":"Client ISP"},
      {"type":"dns","ip":"2001:0db8::53","org":"Test DNS","asn":"AS64500","country":"NL","country_name":"Netherlands"},
      {"type":"dns","ip":"2001:db8::53","asn":"AS64500"},
      {"type":"dns","ip":"192.0.2.53","org":"","asn":"AS64501"},
      {"type":"dns","ip":"unknown"},
      {"type":"conclusion","text":"No DNS leak detected"}
    ]
    """
    let observation = try JSONDecoder().decode(DNSObserverReport.self, from: Data(payload.utf8))
    #expect(observation.answeringResolvers.map(\.ip) == ["2001:db8::53", "192.0.2.53"])
    #expect(observation.answeringResolvers.map(\.label) == ["Test DNS", "AS64501"])
    #expect(observation.answeringResolvers.first?.country == "Netherlands")

    let snapshot = NetworkSnapshot(ipv4: .tunnel("utun4"), ipv6: .missing,
                                   dns: .unavailable, dnsRoute: .outsideTunnel)
    let report = LeakCheckReport(snapshot: snapshot, proxy: .init(modes: []),
                                 direct: checks("203.0.113.2"), system: checks("203.0.113.2"),
                                 ipv6: [], dns: .observed(observation.answeringResolvers))
    #expect(report.findings.first(where: { $0.id == "dnsObserver" })?.level == .info)
    #expect(report.findings.first(where: { $0.id == "dnsRoute" })?.level == .warning)
}

@Test func treatsBashWSErrorsAndMissingResolversAsUnconfirmed() throws {
    for payload in [
        #"[{"type":"error","text":"Test ID not found"}]"#,
        #"[{"type":"ip","ip":"192.0.2.1"},{"type":"conclusion","text":"No DNS leak detected"}]"#,
        #"[{"type":"dns","ip":"192.0.2.53"},{"type":"error","text":"Test is incomplete"}]"#
    ] {
        let report = try JSONDecoder().decode(DNSObserverReport.self, from: Data(payload.utf8))
        #expect(report.answeringResolvers.isEmpty)
    }
}
