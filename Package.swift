// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "MySafeAI",
    defaultLocalization: "en",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "MySafeAI", targets: ["MySafeAI"])],
    targets: [
        .target(name: "NetworkDiagnostics", resources: [.process("Resources")]),
        .executableTarget(name: "MySafeAI", dependencies: ["NetworkDiagnostics"]),
        .testTarget(name: "NetworkDiagnosticsTests", dependencies: ["NetworkDiagnostics"])
    ]
)
