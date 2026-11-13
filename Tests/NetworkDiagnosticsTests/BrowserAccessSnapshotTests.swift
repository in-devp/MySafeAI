import Foundation
import Testing
@testable import NetworkDiagnostics

@Test func browserPermissionRequiresFreshApprovedProof() {
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    func snapshot(_ proof: Date?, active: Bool = true) -> BrowserAccessSnapshot {
        .init(now: now, protectionActive: active, explicitlyDisabled: false,
              pausedUntil: nil, sleeping: false, trustedAt: proof)
    }
    #expect(!snapshot(nil).allowed)
    #expect(!snapshot(now, active: false).allowed)
    #expect(!snapshot(now.addingTimeInterval(1)).allowed)
    #expect(!snapshot(now.addingTimeInterval(-12)).allowed)
    #expect(snapshot(now.addingTimeInterval(-11)).allowed)
    #expect(snapshot(now.addingTimeInterval(-11)).validUntil == 1_700_000_001_000)
    #expect(snapshot(now).validUntil == 1_700_000_002_500)
}

@Test func browserPermissionOnlyAllowsExplicitProtectionSuspension() {
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    func snapshot(disabled: Bool = false, pause: Date? = nil, asleep: Bool = false) -> BrowserAccessSnapshot {
        .init(now: now, protectionActive: false, explicitlyDisabled: disabled,
              pausedUntil: pause, sleeping: asleep, trustedAt: nil)
    }
    #expect(snapshot().state == .blocked)
    #expect(snapshot(disabled: true).state == .disabled)
    #expect(snapshot(disabled: true).allowed)
    #expect(snapshot(pause: now.addingTimeInterval(1)).state == .paused)
    #expect(snapshot(pause: now.addingTimeInterval(1)).validUntil == 1_700_000_001_000)
    #expect(!snapshot(pause: now).allowed)
    #expect(!snapshot(disabled: true, asleep: true).allowed)
}

@Test func browserSnapshotUsesNativeHostWireFormatWithoutPrivateData() throws {
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    let snapshot = BrowserAccessSnapshot(now: now, protectionActive: true, explicitlyDisabled: false,
                                        pausedUntil: nil, sleeping: false, trustedAt: now)
    let data = try JSONEncoder().encode(snapshot)
    let value = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(Set(value.keys) == ["protocol", "allowed", "state", "updatedAt", "validUntil"])
    #expect(value["protocol"] as? Int == 1)
    #expect(value["state"] as? String == "trusted")
    #expect(value["updatedAt"] as? Int64 == 1_700_000_000_000)
    #expect(try JSONDecoder().decode(BrowserAccessSnapshot.self, from: data) == snapshot)
}
