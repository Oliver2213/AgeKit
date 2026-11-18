// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AgeKit",
    // Parts of CryptoKit require macOS 11+, iOS 14+
    platforms: [
        .macOS(.v11),
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "AgeKit",
            targets: ["AgeKit"]),
    ],
    dependencies: [
        // scrypt via BoringSSL. greymass/swift-scrypt (libscrypt) returns wrong,
        // nondeterministic output when compiled with optimization.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.0"),
        .package(url: "https://github.com/swift-extras/swift-extras-base64.git", from: "0.7.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: "AgeKit",
            dependencies: [
                "Bech32",
                .product(name: "CryptoExtras", package: "swift-crypto"),
                .product(name: "ExtrasBase64", package: "swift-extras-base64")
            ]),
        .target(name: "Bech32"),
        .testTarget(
            name: "Bech32Tests",
            dependencies: ["Bech32"]),
        .testTarget(
            name: "AgeKitTests",
            dependencies: ["AgeKit", .product(name: "SwiftASN1", package: "swift-asn1")],
            exclude: [
                "StreamTests/StreamTests.swift.gyb",
            ]),
    ]
)
