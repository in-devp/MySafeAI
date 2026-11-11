import Foundation
import NetworkDiagnostics

final class AddressClient: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private struct InvalidResponse: Error {}
    // Each delegate belongs to one request. Delegate callbacks and the reader share this value.
    private let metricLock = NSLock()
    private var usedProxy: Bool?
    private var remoteAddress: String?

    static func checkAll(_ sources: [AddressSource], direct: Bool = false,
                         requiredRoute: DefaultRoute? = nil) async -> [AddressCheckResult] {
        await withTaskGroup(of: AddressCheckResult.self) { group in
            for source in sources {
                group.addTask { await check(source, direct: direct, requiredRoute: requiredRoute) }
            }
            var byURL: [URL: AddressCheckResult] = [:]
            for await result in group {
                byURL[result.id] = result
            }
            return sources.compactMap { byURL[$0.id] }
        }
    }

    private static func check(_ source: AddressSource, direct: Bool, requiredRoute: DefaultRoute?) async -> AddressCheckResult {
        let outcome: AddressCheckResult.Outcome
        var usedProxy: Bool?
        do {
            try Task.checkCancellation()
            if direct {
                let result = try lookupDirect(source)
                if let requiredRoute, await NetworkSnapshot.route(to: result.peer) != requiredRoute {
                    throw URLError(.cannotConnectToHost)
                }
                outcome = .address(result.address)
                usedProxy = false
            } else {
                let measured = try await lookup(source)
                outcome = .address(measured.address)
                usedProxy = measured.usedProxy
            }
        } catch is InvalidResponse {
            outcome = .invalidResponse
        } catch {
            outcome = .unavailable
        }
        return AddressCheckResult(source: source, outcome: outcome, usedProxy: usedProxy)
    }

    private static func lookupDirect(_ source: AddressSource) throws -> (address: String, peer: String) {
        let curl = Process()
        let output = Pipe()
        curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        let family = source.ipVersion.map { ["--ipv\($0)"] } ?? []
        curl.arguments = family + [
            "--disable", "--noproxy", "*", "--proto", "=https", "--globoff", "--silent",
            "--max-time", "7", "--max-filesize", "4096", "--header", "Cache-Control: no-cache",
            "--write-out", "\n%{http_code}\n%{remote_ip}",
            "--url", source.url.absoluteString
        ]
        curl.environment = ["LC_ALL": "C"]
        curl.standardOutput = output
        curl.standardError = FileHandle.nullDevice
        curl.standardInput = FileHandle.nullDevice
        try curl.run()

        let reader = output.fileHandleForReading
        var data = Data()
        defer {
            if curl.isRunning { curl.terminate() }
            try? reader.close()
        }
        while let chunk = try reader.read(upToCount: 1024), !chunk.isEmpty {
            guard data.count + chunk.count <= 4150 else { throw InvalidResponse() }
            data.append(chunk)
        }
        curl.waitUntilExit()
        guard curl.terminationStatus == 0 else { throw URLError(.cannotConnectToHost) }
        guard let text = String(data: data, encoding: .utf8), let separator = text.lastIndex(of: "\n"),
              let peer = AddressEcho.parse(String(text[text.index(after: separator)...])),
              text[..<separator].hasSuffix("\n200"),
              let address = source.parse(String(text[..<separator].dropLast(4))) else { throw InvalidResponse() }
        return (address, peer)
    }

    private static func lookup(_ source: AddressSource) async throws -> (address: String, usedProxy: Bool?) {
        let delegate = AddressClient()
        let data = try await delegate.read(source.url)
        guard let text = String(data: data, encoding: .utf8), let address = source.parse(text) else {
            throw InvalidResponse()
        }
        return (address, delegate.metricLock.withLock { delegate.usedProxy })
    }

    static func readJSON(_ url: URL) async throws -> Data {
        try await AddressClient().read(url, direct: true, limit: 65_536, accept: "application/json")
    }

    static func servicePath(_ host: String, systemProxy: Bool) async -> ServicePath {
        let client = AddressClient()
        var address: String?
        var country: String?
        if ServicePath.validatedHost(host) == host, let url = URL(string: "https://\(host)/cdn-cgi/trace"),
           let body = try? await client.read(url, direct: !systemProxy, timeout: 5, measureErrorResponse: true),
           let trace = String(data: body, encoding: .utf8),
           trace.split(whereSeparator: \.isNewline).contains(Substring("h=" + host)) {
            address = AddressEcho.parseTrace(trace)
            let countries = trace.split(whereSeparator: \.isNewline).filter { $0.hasPrefix("loc=") }
            if address != nil, countries.count == 1 { country = String(countries[0].dropFirst(4)) }
        }
        let (proxy, peer) = client.metricLock.withLock { (client.usedProxy, client.remoteAddress) }
        let route = if let peer { await NetworkSnapshot.route(to: peer) } else { DefaultRoute.unavailable }
        return ServicePath(host: host, systemProxy: systemProxy, usedProxy: proxy,
                           remoteAddress: peer, route: route, observedAddress: address, country: country)
    }

    static func triggerDNSLookup(_ hostname: String) async {
        guard let url = URL(string: "https://\(hostname)/") else { return }
        // TUN clients with synthetic DNS addresses may resolve upstream only after a connection starts.
        _ = try? await AddressClient().read(url, direct: true, limit: 1024, timeout: 4)
    }

    private func read(_ url: URL, direct: Bool = false, limit: Int = 4096,
                      accept: String = "text/plain", timeout: TimeInterval = 8,
                      measureErrorResponse: Bool = false) async throws -> Data {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = min(6, timeout)
        config.timeoutIntervalForResource = timeout
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        if direct { config.connectionProxyDictionary = [:] }
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        var request = URLRequest(url: url)
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        request.setValue(accept, forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200 || measureErrorResponse else {
            throw InvalidResponse()
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < limit else { throw InvalidResponse() }
            data.append(byte)
        }
        guard response.statusCode == 200 else { throw InvalidResponse() }
        return data
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didFinishCollecting metrics: URLSessionTaskMetrics) {
        let network = metrics.transactionMetrics.filter { $0.resourceFetchType == .networkLoad }
        guard let transaction = network.last(where: { $0.response != nil }) ?? network.last else { return }
        metricLock.withLock {
            usedProxy = transaction.isProxyConnection
            remoteAddress = transaction.remoteAddress.flatMap(AddressEcho.parse)
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}
