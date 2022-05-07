// swift-tools-version:4.2

import PackageDescription

let package = Package(
    name: "SRP",
    products: [
        .library(name: "SRP", targets: ["SRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/IBM-Swift/BlueCryptor.git", from: "2.0.1"),
        .package(url: "https://github.com/PerfectlySoft/Perfect-COpenSSL", from: "4.0.2"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.0.0"),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1")
    ],
    targets: [
        .target(name: "SRP", dependencies: ["Cryptor", "COpenSSL", "BigInt", "Sodium"], path: "Sources")
    ]
)
