// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "MySafeAI",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "MySafeAI", targets: ["MySafeAI"])],
    targets: [
        .target(name: "NetworkDiagnostics"),
        .executableTarget(name: "MySafeAI", dependencies: ["NetworkDiagnostics"]),
        .testTarget(name: "NetworkDiagnosticsTests", dependencies: ["NetworkDiagnostics"])
    ]
)
