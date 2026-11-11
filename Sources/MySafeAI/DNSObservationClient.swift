import Foundation
import NetworkDiagnostics
import dnssd

enum DNSObservationClient {
    static func check() async -> DNSObservation {
        do {
            let startURL = URL(string: "https://dnsleak.dev/api/new")!
            let data = try await AddressClient.readJSON(startURL)
            let session = try JSONDecoder().decode(DNSObserverSession.self, from: data)
            guard session.isValid else { return .unavailable }
            try Task.checkCancellation()
            await withTaskGroup(of: Void.self) { group in
                for hostname in session.hostnames {
                    group.addTask {
                        async let native = SystemDNSLookup.resolve(
                            hostname, ipv6: hostname.hasPrefix(session.testId.lowercased() + "-q")
                        )
                        async let connection = AddressClient.triggerDNSLookup(hostname)
                        _ = await (native, connection)
                    }
                }
            }
            let resultURL = URL(string: "https://dnsleak.dev/api/result/\(session.testId)")!
            for attempt in 0..<3 {
                try await Task.sleep(for: .seconds(1))
                let result = try await AddressClient.readJSON(resultURL)
                let report = try JSONDecoder().decode(DNSObserverReport.self, from: result)
                if report.lookups >= session.hostnames.count || attempt == 2 {
                    return .observed(report, expected: session.hostnames.count)
                }
            }
        } catch {
            return .unavailable
        }
        return .unavailable
    }
}

/// All service-reference and continuation access runs on this serial queue.
private final class SystemDNSLookup: @unchecked Sendable {
    private static let queue = DispatchQueue(label: "MySafeAI.DNSObservation")
    private var service: DNSServiceRef?
    private var continuation: CheckedContinuation<Void, Never>?

    private init(_ continuation: CheckedContinuation<Void, Never>) {
        self.continuation = continuation
    }

    static func resolve(_ hostname: String, ipv6: Bool) async {
        guard !Task.isCancelled else { return }
        await withCheckedContinuation { continuation in
            let query = SystemDNSLookup(continuation)
            queue.async { query.start(hostname, ipv6: ipv6) }
        }
    }

    private func start(_ hostname: String, ipv6: Bool) {
        let error = DNSServiceQueryRecord(
            &service, 0, 0, hostname,
            UInt16(ipv6 ? kDNSServiceType_AAAA : kDNSServiceType_A), UInt16(kDNSServiceClass_IN),
            { _, _, _, _, _, _, _, _, _, _, context in
                guard let context else { return }
                Unmanaged<SystemDNSLookup>.fromOpaque(context).takeUnretainedValue().finish()
            },
            Unmanaged.passUnretained(self).toOpaque()
        )
        guard error == kDNSServiceErr_NoError, let service,
              DNSServiceSetDispatchQueue(service, Self.queue) == kDNSServiceErr_NoError else {
            finish()
            return
        }
        // Retains the query through its callback or deadline. Each unique name has a bounded lifetime.
        Self.queue.asyncAfter(deadline: .now() + 4) { self.finish() }
    }

    private func finish() {
        if let service {
            DNSServiceRefDeallocate(service)
            self.service = nil
        }
        continuation?.resume()
        continuation = nil
    }
}
