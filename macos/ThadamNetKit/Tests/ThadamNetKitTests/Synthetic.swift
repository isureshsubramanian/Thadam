// Synthetic inputs for the tests. Names use the reserved `.test` domain; addresses come from
// the documentation ranges (RFC 5737, RFC 3849).

import Foundation

@testable import ThadamNetKit

/// A TLS 1.3-style ClientHello carrying `name` in its SNI extension, after one other extension.
func clientHello(sni name: String) -> [UInt8] {
    func u16(_ n: Int) -> [UInt8] { [UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)] }
    let nameBytes = Array(name.utf8)
    let serverName = [0x00] + u16(nameBytes.count) + nameBytes
    let sniExtension = u16(0x0000) + u16(serverName.count + 2) + u16(serverName.count) + serverName
    let otherExtension = u16(0x002B) + u16(3) + [0x02, 0x03, 0x04]  // supported_versions
    let extensions = otherExtension + sniExtension
    var hello: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 0xAB, count: 32)
    hello += [0x20] + [UInt8](repeating: 0xCD, count: 32)  // session id
    hello += u16(4) + [0x13, 0x01, 0x13, 0x02]  // cipher suites
    hello += [0x01, 0x00]  // compression: null
    hello += u16(extensions.count) + extensions
    let handshake = [0x01, 0x00] + u16(hello.count) + hello
    return [0x16, 0x03, 0x01] + u16(handshake.count) + handshake
}

/// A fixed-seed generator, so "random" garbage is the same on every run.
struct SeededBytes {
    var state: UInt64

    mutating func next() -> UInt8 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return UInt8(truncatingIfNeeded: state >> 33)
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in next() }
    }
}

let process = FlowProcess(pid: 4211, pidversion: 3, ppids: [4100, 1], exe: "/Users/test/.local/bin/agent")
let remote = Remote(ip: "203.0.113.7", port: 443)
let t0 = Date(timeIntervalSince1970: 1_794_648_780.5)  // 2026-11-14T09:33:00.5Z
let flowA = UUID(uuid: (0x01, 0x92, 0xF3, 0xA4, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1))
let flowB = UUID(uuid: (0x01, 0x92, 0xF3, 0xA4, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2))

func text(_ data: Data) -> String {
    String(decoding: data, as: UTF8.self)
}
