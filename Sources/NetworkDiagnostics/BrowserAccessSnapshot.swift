import Foundation

/// A short-lived local permission, without addresses, URLs or browser history.
public struct BrowserAccessSnapshot: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable {
        case trusted, blocked, disabled, paused, unavailable
    }

    public let `protocol`: Int
    public let allowed: Bool
    public let state: State
    public let updatedAt: Int64
    public let validUntil: Int64

    public init(now: Date, protectionActive: Bool, explicitlyDisabled: Bool,
                pausedUntil: Date?, sleeping: Bool, trustedAt: Date?) {
        let timestamp = Self.milliseconds(now)
        var state: State = .blocked
        var deadline = timestamp + 2_500
        if !sleeping {
            if explicitlyDisabled {
                state = .disabled
            } else if let pausedUntil, pausedUntil > now {
                state = .paused
                deadline = min(deadline, Self.milliseconds(pausedUntil))
            } else if protectionActive, let trustedAt,
                      now >= trustedAt, now.timeIntervalSince(trustedAt) < 12 {
                state = .trusted
                // A fresh heartbeat never renews an expired network proof.
                deadline = min(deadline, Self.milliseconds(trustedAt.addingTimeInterval(12)))
            }
        }
        self.protocol = 1
        self.allowed = state == .trusted || state == .disabled || state == .paused
        self.state = state
        self.updatedAt = timestamp
        self.validUntil = deadline
    }

    private static func milliseconds(_ date: Date) -> Int64 {
        Int64((date.timeIntervalSince1970 * 1_000).rounded(.down))
    }
}
