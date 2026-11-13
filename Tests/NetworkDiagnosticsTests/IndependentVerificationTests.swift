import Foundation
import Testing
@testable import NetworkDiagnostics

private actor VerificationGate<Value: Sendable> {
    private var continuation: CheckedContinuation<Value?, Never>?
    private var ready: Value??

    func wait() async -> Value? {
        if let ready { return ready }
        return await withCheckedContinuation { continuation = $0 }
    }

    func release(_ value: Value?) {
        if let continuation {
            self.continuation = nil
            continuation.resume(returning: value)
        } else {
            ready = .some(value)
        }
    }
}

@MainActor
@Test func browserVerificationPublishesBeforeUnrelatedSlowApplication() async throws {
    let app = IndependentVerification<String>()
    let browser = IndependentVerification<String>()
    let slow = VerificationGate<String>()
    let browserFinished = VerificationGate<Bool>()
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    app.start(operation: { await slow.wait() }, completed: {})
    browser.start(now: now, operation: { "browser approved" }) {
        Task { await browserFinished.release(true) }
    }
    #expect(await browserFinished.wait() == true)
    #expect(browser.value == "browser approved")
    #expect(browser.startedAt == now)
    #expect(!browser.isRunning)
    #expect(app.isRunning)
    #expect(app.value == nil)
    await slow.release("application checked")
}

@MainActor
@Test func browserVerificationDoesNotStartConcurrentChecksInOneGeneration() async {
    let browser = IndependentVerification<String>()
    let pending = VerificationGate<String>()
    let first = browser.start(operation: { await pending.wait() }, completed: {})
    let duplicate = browser.start(operation: { "must not run" }, completed: {})
    #expect(first)
    #expect(!duplicate)
    await pending.release("checked")
    browser.invalidate()
}

@MainActor
@Test func browserNetworkChangeRejectsLateResultFromPreviousGeneration() async {
    let browser = IndependentVerification<String>()
    let obsolete = VerificationGate<String>()
    let freshFinished = VerificationGate<Bool>()
    browser.start(operation: { await obsolete.wait() }, completed: {})
    browser.invalidate()
    #expect(browser.value == nil)
    #expect(browser.startedAt == nil)
    browser.start(operation: { "new network denied" }) {
        Task { await freshFinished.release(true) }
    }
    _ = await freshFinished.wait()
    await obsolete.release("old network approved")
    // Let the cancelled operation finish; cancellation alone is not the proof
    // because it intentionally ignores cancellation while waiting on its gate.
    for _ in 0..<10 { await Task.yield() }
    #expect(browser.value == "new network denied")
    browser.invalidate()
    #expect(browser.value == nil)
}
