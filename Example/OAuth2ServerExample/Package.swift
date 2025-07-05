// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "OAuth2ServerExample",
    platforms: [
       .macOS(.v13)
    ],
    dependencies: [
        // 💧 A server-side Swift web framework.
        .package(url: "https://github.com/vapor/vapor.git", from: "4.115.0"),
        // 🗄 An ORM for SQL and NoSQL databases.
        .package(url: "https://github.com/vapor/fluent.git", from: "4.9.0"),
        // 🪶 Fluent driver for SQLite.
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.6.0"),
        // 🍃 Leaf templating engine.
        .package(url: "https://github.com/vapor/leaf.git", from: "4.5.0"),
        // 🔵 Non-blocking, event-driven networking for Swift. Used for custom executors
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        // 🔐 OAuth2 implementation for Vapor
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "OAuth2ServerExampleApp",
            dependencies: [
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Leaf", package: "leaf"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "OAuth", package: "vapor-oauth"),
            ],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "OAuth2ServerExampleTests",
            dependencies: [
                .target(name: "OAuth2ServerExampleApp"),
                .product(name: "VaporTesting", package: "vapor"),
            ],
            swiftSettings: swiftSettings
        )
    ]
)

var swiftSettings: [SwiftSetting] { [
    .enableUpcomingFeature("ExistentialAny"),
] }
