import Foundation

/// A verification lane that publishes its own result without waiting for other lanes.
@MainActor
public final class IndependentVerification<Value: Sendable> {
    public private(set) var value: Value?
    public private(set) var startedAt: Date?
    public var isRunning: Bool { task != nil }

    private var task: Task<Void, Never>?
    private var generation = UUID()

    public init() {}

    @discardableResult
    public func start(now: Date = .now, operation: @escaping @Sendable () async -> Value?,
                      completed: @escaping @MainActor () -> Void) -> Bool {
        guard task == nil else { return false }
        let request = UUID()
        generation = request
        task = Task { [weak self] in
            let result = await operation()
            guard let self, request == self.generation, !Task.isCancelled else { return }
            self.task = nil
            self.value = result
            self.startedAt = result == nil ? nil : now
            completed()
        }
        return true
    }

    public func invalidate() {
        generation = UUID()
        task?.cancel()
        task = nil
        value = nil
        startedAt = nil
    }
}
