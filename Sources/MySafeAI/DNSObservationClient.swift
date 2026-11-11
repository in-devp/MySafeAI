import Foundation
import NetworkDiagnostics
import dnssd

enum DNSObservationClient {
    static func check() async -> DNSObservation {
        do {
            let token = try await AddressClient.readText(DNSObserverSession.startURL, limit: 128)
            guard let session = DNSObserverSession(response: token) else { return .unavailable }
            try Task.checkCancellation()
            await withTaskGroup(of: Void.self) { group in
                for (index, hostname) in session.hostnames.enumerated() {
                    group.addTask {
                        async let native = SystemDNSLookup.resolve(hostname, ipv6: index % 2 == 1)
                        async let connection = AddressClient.triggerDNSLookup(hostname)
                        _ = await (native, connection)
                    }
                }
            }
            for _ in 0..<3 {
                try await Task.sleep(for: .seconds(1))
                if let data = try? await AddressClient.readJSON(session.resultURL, timeout: 4),
                   let report = try? JSONDecoder().decode(DNSObserverReport.self, from: data),
                   !report.answeringResolvers.isEmpty {
                    return .observed(report.answeringResolvers)
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
