// swift-tools-version: 6.2
// The extension's platform-independent parts (ADR-007): host name peek, flow records, the
// record buffer and the socket client. Built into the filter extension by the Xcode project,
// and tested here with synthetic data only. Apple frameworks only; no package dependencies.

import PackageDescription

let package = Package(
    name: "ThadamNetKit",
    platforms: [.macOS(.v15)],
    products: [.library(name: "ThadamNetKit", targets: ["ThadamNetKit"])],
    targets: [
        .target(
            name: "ThadamNetKit",
            swiftSettings: [.treatAllWarnings(as: .error)]
        ),
        .testTarget(
            name: "ThadamNetKitTests",
            dependencies: ["ThadamNetKit"],
            swiftSettings: [.treatAllWarnings(as: .error)]
        ),
    ],
    swiftLanguageModes: [.v6]
)
