import Testing
@testable import MySafeAI

@Test func directIPLookupRetriesTransientFailureOnlyOnce() throws {
    var attempts: [Int] = []
    let address = try AddressClient.retryDirectLookup { timeout in
        attempts.append(timeout)
        if attempts.count == 1 { throw AddressClient.TransportFailure() }
        return "203.0.113.42"
    }
    #expect(address == "203.0.113.42")
    #expect(attempts == [2, 5])

    attempts = []
    #expect(throws: AddressClient.TransportFailure.self) {
        try AddressClient.retryDirectLookup { timeout in
            attempts.append(timeout)
            throw AddressClient.TransportFailure()
        } as String
    }
    #expect(attempts == [2, 5])
}

@Test func directIPLookupDoesNotRetryRejectedResponse() {
    struct Rejected: Error {}
    var attempts = 0
    #expect(throws: Rejected.self) {
        try AddressClient.retryDirectLookup { _ in
            attempts += 1
            throw Rejected()
        } as String
    }
    #expect(attempts == 1)
}
