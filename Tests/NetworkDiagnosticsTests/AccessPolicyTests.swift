import Foundation
import Testing
@testable import NetworkDiagnostics

@Test func matchesIPv4AndIPv6SubnetsAtPrefixBoundaries() throws {
    let v4 = try #require(IPSubnet("203.0.113.42/27"))
    #expect(v4.notation == "203.0.113.32/27")
    #expect(v4.contains("203.0.113.32"))
    #expect(v4.contains("203.0.113.63"))
    #expect(!v4.contains("203.0.113.64"))
    #expect(!v4.contains("::ffff:203.0.113.42"))
    let v6 = try #require(IPSubnet("2001:db8:0:1:ffff::2/65"))
    #expect(v6.contains("2001:db8:0:1:8000::"))
    #expect(!v6.contains("2001:db8:0:1:7fff::"))
    #expect(IPSubnet("::/0")?.contains("2001:db8::1") == true)
    #expect(IPSubnet("0.0.0.0/0")?.contains("203.0.113.42") == true)
    #expect(IPSubnet("2001:db8::1/128")?.contains("2001:db8::2") == false)
    #expect(IPSubnet("203.0.113.42/33") == nil)
    #expect(IPSubnet("2001:db8::1/-1") == nil)
    #expect(try JSONDecoder().decode(IPSubnet.self, from: JSONEncoder().encode(v6)) == v6)
}

@Test func deniesUnknownCountriesAndKeepsAnIndependentAllowlist() throws {
    let subnet = try #require(IPSubnet("198.51.100.0/24"))
    let shared = AddressAccessPolicy(addresses: ["203.0.113.42"], subnets: [subnet], countries: ["NL"])
    let independent = AddressAccessPolicy()
    #expect(shared.allows("203.0.113.42", country: nil))
    #expect(shared.allows("198.51.100.15", country: nil))
    #expect(shared.allows("192.0.2.40", country: "nl"))
    #expect(!shared.allows("192.0.2.40", country: nil))
    #expect(!shared.allows("invalid", country: "NL"))
    #expect(!independent.allows("203.0.113.42", country: "NL"))
    #expect(AddressAccessPolicy.countryCode("ZZ") == nil)
}

@Test func trustedNetworkRequiresRouterAndEveryPinnedAddress() {
    let profile = TrustedLocalNetwork(id: "router", name: "Дом", addresses: ["203.0.113.42", "2001:db8::1"])
    #expect(profile.matches(router: "router", addresses: ["2001:db8::1", "203.0.113.42"]))
    #expect(!profile.matches(router: "other", addresses: ["2001:db8::1", "203.0.113.42"]))
    #expect(!profile.matches(router: "router", addresses: ["203.0.113.42"]))
    #expect(!profile.matches(router: "router", addresses: []))
}

@Test func directAddressesRequireSeparateExactApproval() throws {
    let legacy = Data(#"{"addresses":["203.0.113.42"],"subnets":[],"countries":["NL"]}"#.utf8)
    var policy = try JSONDecoder().decode(AddressAccessPolicy.self, from: legacy)
    #expect(policy.allows("203.0.113.42", country: nil))
    #expect(!policy.allowsDirect("203.0.113.42"))
    policy.directAddresses = ["2001:db8::42"]
    #expect(policy.allowsDirect("2001:0db8::42"))
    #expect(!policy.allows("2001:db8::42", country: nil))
    #expect(!policy.allowsDirect("2001:db8::43"))
    #expect(try JSONDecoder().decode(AddressAccessPolicy.self, from: JSONEncoder().encode(policy)) == policy)
}

@Test func explicitVPNRuleKeepsItsTransportAfterUpgrade() throws {
    let saved = Data(#"{"transport":"tunnel","allowsTrustedNetworks":true}"#.utf8)
    let rule = try JSONDecoder().decode(ApplicationAccessRule.self, from: saved)
    #expect(rule.transport == .tunnel)
    #expect(ApplicationAccessRule().transport == .automatic)
}

@Test func servicePolicyDistinguishesPACBypassTunnelAndUnverifiedTrace() {
    func probe(system: Bool, used: Bool?, route: DefaultRoute, address: String? = "203.0.113.42") -> ServicePath {
        ServicePath(host: "api.openai.com", systemProxy: system, usedProxy: used,
                    remoteAddress: "192.0.2.1", route: route, observedAddress: address)
    }
    #expect(probe(system: true, used: true, route: .other("en0")).confirms(.systemProxy, ipv6: .missing))
    #expect(!probe(system: true, used: false, route: .other("en0")).confirms(.systemProxy, ipv6: .missing))
    #expect(!probe(system: true, used: nil, route: .other("en0")).confirms(.systemProxy, ipv6: .missing))
    #expect(!probe(system: true, used: true, route: .other("en0"), address: nil).confirms(.systemProxy, ipv6: .missing))
    #expect(probe(system: false, used: false, route: .tunnel("utun4")).confirms(.serviceTunnel, ipv6: .missing))
    #expect(!probe(system: false, used: false, route: .tunnel("utun4")).confirms(.serviceTunnel, ipv6: .other("en0")))
    #expect(!probe(system: false, used: false, route: .other("en0")).confirms(.serviceTunnel, ipv6: .missing))
    #expect(ServicePath.validatedHost(" API.OpenAI.COM ") == "api.openai.com")
    #expect(ServicePath.validatedHost("api.openai.com@evil.example") == nil)
}
