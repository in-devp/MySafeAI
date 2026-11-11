import Foundation
import SystemConfiguration

/// Observes route and DNS changes that can leave NWPath's selected interface unchanged.
final class NetworkSettingsObserver {
    private let store: SCDynamicStore

    private final class Callback: Sendable {
        let changed: @Sendable () -> Void

        init(_ changed: @escaping @Sendable () -> Void) { self.changed = changed }
    }

    init?(changed: @escaping @Sendable () -> Void) {
        let callback = Callback(changed)
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(callback).toOpaque(),
            retain: { pointer in
                _ = Unmanaged<Callback>.fromOpaque(pointer).retain()
                return pointer
            },
            release: { pointer in Unmanaged<Callback>.fromOpaque(pointer).release() },
            copyDescription: nil
        )
        guard let store = SCDynamicStoreCreate(nil, "MySafeAI" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<Callback>.fromOpaque(info).takeUnretainedValue().changed()
        }, &context) else { return nil }

        let patterns = [
            "State:/Network/Global/(IPv4|IPv6|DNS|Proxies)",
            "State:/Network/Service/.*/(IPv4|IPv6|DNS|Proxies|PPP|IPSec)",
            "Setup:/Network/Service/.*/Proxies",
            "State:/Network/Interface/.*/(Link|IPv4|IPv6)"
        ]
        guard SCDynamicStoreSetNotificationKeys(store, nil, patterns as CFArray),
              SCDynamicStoreSetDispatchQueue(store, .main) else { return nil }
        self.store = store
    }

    deinit {
        SCDynamicStoreSetDispatchQueue(store, nil)
    }
}
