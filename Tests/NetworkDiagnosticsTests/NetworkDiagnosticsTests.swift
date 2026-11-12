import Foundation
import NetworkDiagnostics
import Testing

@Test func macOSMissingIPv6RouteDoesNotBlockAnIPv4Tunnel() {
    let missingIPv6 = DefaultRoute(output: "route: writing to routing socket: not in table\n", exitCode: 0)
    #expect(missingIPv6 == .missing)
    #expect(TrustedRoute(ipv4: .tunnel("utun4"), ipv6: missingIPv6)?.requiresIPv6 == false)
}

@Test func recognizesRoutesAndPreservesUncertainty() {
    #expect(DefaultRoute(output: "  interface: utun4", exitCode: 0) == .tunnel("utun4"))
    #expect(DefaultRoute(output: "  interface: en0", exitCode: 0) == .other("en0"))
    #expect(DefaultRoute(output: "  interface: utun-extra", exitCode: 0) == .other("utun-extra"))
    #expect(DefaultRoute(output: "route: writing to routing socket: not in table", exitCode: 1) == .missing)
    #expect(DefaultRoute(output: "route: permission denied", exitCode: 1) == .unavailable)
    #expect(DefaultRoute(output: "  interface: ", exitCode: 0) == .unavailable)
}

@Test func separatesScopedDNSAndSkipsMulticastResolvers() {
    let config = DNSConfiguration(output: """
    DNS configuration

    resolver #1
      nameserver[0] : 192.0.2.53
      if_index : 12 (utun4)

    resolver #2
      domain : local
      options  : mdns

    DNS configuration (for scoped queries)

    resolver #1
      nameserver[0] : 198.51.100.53
      if_index : 2 (en0)
    """, exitCode: 0)

    guard case .available(let resolvers) = config else {
        Issue.record("Expected DNS resolver configuration")
        return
    }
    #expect(resolvers.map(\.interface) == ["utun4", "en0"])
    #expect(resolvers.map(\.servers) == [["192.0.2.53"], ["198.51.100.53"]])
    #expect(resolvers.map(\.isScoped) == [false, true])
    #expect(DNSConfiguration(output: "Permission denied", exitCode: 1) == .unavailable)
}

@Test func acceptsPlainIPResponsesAndHTTPSOnly() {
    #expect(AddressEcho.parse("  203.0.113.42\n") == "203.0.113.42")
    #expect(AddressEcho.parse("2001:db8::42") == "2001:db8::42")
    #expect(AddressEcho.parse("2001:0DB8:0:0::42") == "2001:db8::42")
    #expect(AddressEcho.parse("203.0.113.42\u{0}suffix") == nil)
    #expect(AddressEcho.parse("{\"ip\":\"203.0.113.42\"}") == nil)
    #expect(AddressEcho.endpoint(" https://example.com/ip ") != nil)
    #expect(AddressEcho.endpoint("http://example.com/ip") == nil)
    #expect(AddressEcho.endpoint("https://user@example.com/ip") == nil)
    #expect(AddressEcho.endpoint("https://example.com/ip?token=abc") == nil)
    #expect(AddressEcho.endpoint("https://[2001:db8::1]/ip")?.absoluteString == "https://[2001:db8::1]/ip")
}

@Test func parsesCloudflareTraceAndRejectsAmbiguousResponses() {
    let source = BuiltInAddressSource.cloudflare.source
    #expect(source.parse("h=1.1.1.1\r\nip=203.0.113.42\r\nloc=NL\r\n") == "203.0.113.42")
    #expect(AddressEcho.parseTrace("ip=2001:0db8::42\nloc=NL") == "2001:db8::42")
    #expect(source.parse("ip=2001:0db8::42\nloc=NL") == nil)
    #expect(source.parse("loc=NL\nuag=ip=203.0.113.42") == nil)
    #expect(source.parse("ip=203.0.113.42\nip=203.0.113.43") == nil)
    #expect(source.parse("ip=not-an-ip") == nil)
}

@Test func defaultsToThreeIPv4SourcesAndPreservesCustomOnlySettings() throws {
    var settings = AddressSourceSettings()
    #expect(settings.enabledSources.map(\.name) == ["AWS", "Cloudflare", "ipify", "ident.me · IPv6", "ipify · IPv6"])
    #expect(!settings.canAdd("HTTPS://CHECKIP.AMAZONAWS.COM:443"))
    let added = settings.add("https://example.com/ip")
    #expect(added)
    #expect(!settings.canAdd("https://EXAMPLE.com:443/ip"))
    settings.enabledBuiltIns.insert(.ipify)
    let decoded = try JSONDecoder().decode(AddressSourceSettings.self, from: JSONEncoder().encode(settings))
    #expect(decoded.enabledSources.map(\.name) == ["AWS", "Cloudflare", "ipify", "ident.me · IPv6", "ipify · IPv6", "example.com"])
    settings.remove(try #require(settings.customURLs.first))
    #expect(settings.customURLs.isEmpty)

    let previous = AddressSourceSettings(previousEndpoint: "https://example.com/ip")
    #expect(previous.enabledSources.map(\.name) == ["example.com"])
    let previousAWS = AddressSourceSettings(previousEndpoint: "https://checkip.amazonaws.com")
    #expect(previousAWS.enabledSources.map(\.name) == ["AWS"])
}

@Test func comparesAddressesWithinTheirIPFamily() {
    let aws = BuiltInAddressSource.aws.source
    let cloudflare = BuiltInAddressSource.cloudflare.source
    let ident = BuiltInAddressSource.identIPv6.source
    let first = AddressCheckResult(source: aws, outcome: .address("203.0.113.42"))
    let ipv6 = AddressCheckResult(source: ident, outcome: .address("2001:db8::42"))
    let differentIPv4 = AddressCheckResult(source: cloudflare, outcome: .address("198.51.100.24"))
    let timeout = AddressCheckResult(source: cloudflare, outcome: .unavailable)

    let partial = AddressCheckSummary([first, timeout])
    #expect(partial.responseCount == 1)
    #expect(partial.preferredAddress == "203.0.113.42")

    let dualStack = AddressCheckSummary([first, ipv6])
    #expect(!dualStack.hasDisagreement)
    #expect(dualStack.preferredAddress == "203.0.113.42")

    let mismatch = AddressCheckSummary([first, differentIPv4, ipv6])
    #expect(mismatch.hasDisagreement)
    #expect(mismatch.preferredAddress == nil)
}

@Test func acceptsDirectRoutesAndBlocksMixedOrUnverifiedIPv6() throws {
    #expect(TrustedRoute(ipv4: .other("en0"), ipv6: .missing)?.requiresIPv6 == false)
    #expect(TrustedRoute(ipv4: .other("en0"), ipv6: .other("en0"))?.requiresIPv6 == true)
    #expect(TrustedRoute(ipv4: .other("en0"), ipv6: .other("en1")) == nil)
    #expect(TrustedRoute(ipv4: .other("lo0"), ipv6: .missing) == nil)
    #expect(TrustedRoute(ipv4: .tunnel("utun4"), ipv6: .other("en0")) == nil)
    #expect(TrustedRoute(ipv4: .tunnel("utun4"), ipv6: .tunnel("utun5")) == nil)
    #expect(TrustedRoute(ipv4: .tunnel("utun4"), ipv6: .unavailable) == nil)

    let dual = try #require(TrustedRoute(ipv4: .tunnel("utun4"), ipv6: .tunnel("utun4")))
    let v4: [AddressCheckResult] = [BuiltInAddressSource.aws, .cloudflare].map {
        .init(source: $0.source, outcome: .address("203.0.113.42"))
    }
    let v6: [AddressCheckResult] = [BuiltInAddressSource.identIPv6, .ipifyIPv6].map {
        .init(source: $0.source, outcome: .address("2001:db8::42"))
    }
    #expect(dual.verify(v4) == .insufficientIPv6)
    #expect(dual.verify(v4 + Array(v6.prefix(1))) == .insufficientIPv6)
    #expect(dual.verify(v4 + v6) == .confirmed(["203.0.113.42", "2001:db8::42"]))
}

@Test func requiresTwoAgreeingHostsAndToleratesAnUnavailableThirdSource() throws {
    let route = try #require(TrustedRoute(ipv4: .tunnel("utun4"), ipv6: .missing))
    let ip = "203.0.113.42"
    let aws = AddressCheckResult(source: BuiltInAddressSource.aws.source, outcome: .address(ip))
    let cloudflare = BuiltInAddressSource.cloudflare.source
    #expect(route.verify([]) == .insufficientIPv4)
    #expect(route.verify([aws, aws]) == .insufficientIPv4)
    #expect(route.verify([aws, .init(source: cloudflare, outcome: .unavailable)]) == .insufficientIPv4)
    #expect(route.verify([aws, .init(source: cloudflare, outcome: .address("203.0.113.43"))]) == .disagreement)
    let agreeing = [aws, AddressCheckResult(source: cloudflare, outcome: .address(ip))]
    #expect(route.verify(agreeing + [.init(source: BuiltInAddressSource.ipify.source, outcome: .unavailable)])
            == .confirmed([ip]))
    #expect(route.verify(agreeing + [.init(source: BuiltInAddressSource.ipify.source, outcome: .address("203.0.113.43"))])
            == .disagreement)

    var settings = AddressSourceSettings()
    let added = settings.add("https://checkip.amazonaws.com/second-path")
    #expect(added)
    let sameHost = try #require(settings.enabledSources.last)
    #expect(route.verify([aws, .init(source: sameHost, outcome: .address(ip))]) == .insufficientIPv4)
}

@Test func classifiesDNSRoutesAndPreservesUncertaintyForLocalStubs() {
    #expect(DNSRoute(tunnel: "utun4", routes: [.tunnel("utun4")]) == .viaTunnel)
    #expect(DNSRoute(tunnel: "utun4", routes: [.tunnel("utun4"), .other("en0")]) == .outsideTunnel)
    #expect(DNSRoute(tunnel: "utun4", routes: [.tunnel("utun5")]) == .outsideTunnel)
    #expect(DNSRoute(tunnel: "utun4", routes: [.other("lo0")]) == .unknown)
    #expect(DNSRoute(tunnel: "utun4", routes: [.tunnel("utun4"), .unavailable]) == .unknown)
    #expect(DNSRoute(tunnel: "utun4", routes: []) == .unknown)
}

@Test func recognizesDNSOnTheSameDirectConnection() {
    let wifi = DefaultRoute.other("en0")
    #expect(DNSRoute(connection: wifi, routes: [wifi]) == .viaDirect)
    #expect(DNSRoute(connection: wifi, routes: [wifi, .other("en1")]) == .outsideDirect)
    #expect(DNSRoute(connection: wifi, routes: [.tunnel("utun4")]) == .outsideDirect)
    #expect(DNSRoute(connection: wifi, routes: [wifi, .other("lo0")]) == .unknown)
    #expect(DNSRoute(connection: wifi, routes: []) == .unknown)
}

@Test func standardSourcesCanConfirmIPv4WhileAWSIsUnavailable() throws {
    let decoder = JSONDecoder()
    var settings = try decoder.decode(AddressSourceSettings.self, from: Data(#"{"enabledBuiltIns":["aws","cloudflare","identIPv6","ipifyIPv6"],"customURLs":[]}"#.utf8))
    settings.migrateIPv4Backup()
    #expect(settings.enabledBuiltIns.contains(.ipify))
    let route = try #require(TrustedRoute(ipv4: .other("en0"), ipv6: .missing))
    let ip = "203.0.113.42"
    let results: [AddressCheckResult] = [
        .init(source: BuiltInAddressSource.aws.source, outcome: .unavailable),
        .init(source: BuiltInAddressSource.cloudflare.source, outcome: .address(ip)),
        .init(source: BuiltInAddressSource.ipify.source, outcome: .address(ip)),
    ]
    #expect(route.verify(results) == .confirmed([ip]))
    settings.enabledBuiltIns.remove(.ipify)
    settings = try decoder.decode(AddressSourceSettings.self, from: JSONEncoder().encode(settings))
    settings.migrateIPv4Backup()
    #expect(!settings.enabledBuiltIns.contains(.ipify))
}

@Test func migratesStandardAddressSourcesWithoutChangingCustomOnlyConfiguration() throws {
    let decoder = JSONDecoder()
    var settings = try decoder.decode(AddressSourceSettings.self, from: Data(#"{"enabledBuiltIns":["aws","cloudflare"],"customURLs":[]}"#.utf8))
    settings.migrateIPv6Sources()
    #expect(settings.enabledBuiltIns.contains(.ipifyIPv6))
    #expect(settings.enabledBuiltIns.contains(.identIPv6))
    settings.enabledBuiltIns.remove(.identIPv6)
    settings = try decoder.decode(AddressSourceSettings.self, from: JSONEncoder().encode(settings))
    settings.migrateIPv6Sources()
    #expect(!settings.enabledBuiltIns.contains(.identIPv6))

    var custom = try decoder.decode(AddressSourceSettings.self, from: Data(#"{"enabledBuiltIns":[],"customURLs":["https://example.com/ip"]}"#.utf8))
    custom.migrateIPv6Sources()
    custom.migrateIPv4Backup()
    #expect(custom.enabledSources.map(\.name) == ["example.com"])
}

@Test func recognizesTerminalAgentsWithoutMatchingDesktopBackendsOrOtherNodeScripts() {
    let bundled = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
    #expect(CLIProtectionTarget.identify(executable: bundled, firstArgument: "") == .codex)
    #expect(CLIProtectionTarget.identify(executable: bundled, firstArgument: "app-server") == nil)
    #expect(CLIProtectionTarget.identify(executable: bundled, firstArgument: nil) == nil)
    #expect(CLIProtectionTarget.identify(executable: "/opt/homebrew/bin/codex", firstArgument: "exec") == .codex)
    #expect(CLIProtectionTarget.identify(executable: "/Users/example/.local/share/claude/versions/2.1.311",
                                         firstArgument: nil) == .claude)
    #expect(CLIProtectionTarget.identify(executable: "/Applications/Claude.app/Contents/MacOS/Claude",
                                         firstArgument: nil) == nil)
    #expect(CLIProtectionTarget.identify(executable: "/opt/homebrew/bin/node",
        firstArgument: "/example/node_modules/@anthropic-ai/claude-code/cli.js") == .claude)
    #expect(CLIProtectionTarget.identify(executable: "/opt/homebrew/bin/node",
        firstArgument: "/example/node_modules/@openai/codex/bin/codex.js") == .codex)
    #expect(CLIProtectionTarget.identify(executable: "/opt/homebrew/bin/node",
        firstArgument: "/example/claude-code/cli.js") == nil)
}
