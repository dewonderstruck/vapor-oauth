// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "vapor-oauth",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "OAuth",
            targets: ["VaporOAuth"]
        ),
        .library(
            name: "OAuthPAR", 
            targets: ["VaporOAuthPAR"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.106.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.8.1"),
        .package(url: "https://github.com/vapor/redis.git", from: "4.11.0")
    ],
    targets: [
        .target(
            name: "VaporOAuth",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: [
                .enableUpcomingFeature("BareSlashRegexLiterals"),
                .enableExperimentalFeature("StrictConcurrency=complete"),
            ]
        ),
        .target(
            name: "VaporOAuthPAR",
            dependencies: [
                .target(name: "VaporOAuth"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Redis", package: "redis")
            ],
            swiftSettings: [
                .enableUpcomingFeature("BareSlashRegexLiterals"),
                .enableExperimentalFeature("StrictConcurrency=complete"),
            ]
        ),
        .testTarget(
            name: "VaporOAuthTests",
            dependencies: [
                .target(name: "VaporOAuth"),
                .target(name: "VaporOAuthPAR"),
                .product(name: "XCTVapor", package: "vapor")
            ]
        )
    ]
)
