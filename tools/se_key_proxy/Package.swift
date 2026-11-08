// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "se-key-proxy",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "se-key-proxy", targets: ["se-key-proxy"]),
    ],
    targets: [
        .executableTarget(
            name: "se-key-proxy",
            path: ".",
            sources: ["main.swift"]
        ),
    ]
)
