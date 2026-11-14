// A flow's remote endpoint as address text and port, for `remote_ip` and `remote_port`.

import Foundation
import Network

/// The address and port of an address endpoint, or nil for a name endpoint or port 0.
/// IPv4-mapped IPv6 addresses come back as IPv4; scope ids are dropped.
public func remoteAddress(of endpoint: NWEndpoint) -> Remote? {
    guard case let .hostPort(host, port) = endpoint, port.rawValue > 0 else { return nil }
    switch host {
    case let .ipv4(address):
        return Remote(ip: dotted(address.rawValue), port: port.rawValue)
    case let .ipv6(address):
        let bytes = [UInt8](address.rawValue)
        guard bytes.count == 16 else { return nil }
        if let v4 = address.asIPv4 {
            return Remote(ip: dotted(v4.rawValue), port: port.rawValue)
        }
        return Remote(ip: ipv6Text(bytes), port: port.rawValue)
    case .name:
        return nil
    @unknown default:
        return nil
    }
}

private func dotted(_ raw: Data) -> String {
    raw.map(String.init).joined(separator: ".")
}

/// RFC 5952 text: lower-case hex, leading zeros dropped, the longest run of two or more zero
/// groups shortened to `::`.
private func ipv6Text(_ bytes: [UInt8]) -> String {
    let groups = stride(from: 0, to: 16, by: 2).map { Int(bytes[$0]) << 8 | Int(bytes[$0 + 1]) }
    var best = (start: -1, length: 0)
    var run = (start: -1, length: 0)
    for (i, group) in groups.enumerated() {
        if group == 0 {
            run = run.start < 0 ? (i, 1) : (run.start, run.length + 1)
            if run.length > best.length { best = run }
        } else {
            run = (-1, 0)
        }
    }
    let hex = groups.map { String($0, radix: 16) }
    guard best.length >= 2 else { return hex.joined(separator: ":") }
    let head = hex[..<best.start].joined(separator: ":")
    let tail = hex[(best.start + best.length)...].joined(separator: ":")
    return head + "::" + tail
}
