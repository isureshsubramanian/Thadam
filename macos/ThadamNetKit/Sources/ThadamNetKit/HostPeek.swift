// Host names from the first outbound bytes of a TCP flow (ADR-007 Decision 3, amendment 1).
// Used only when the system gives no name. Reads the TLS ClientHello's SNI or the first HTTP
// request's Host header, keeps only the name, and never keeps the bytes or the request line.
// Bounds-checked throughout: any input returns a name or nil, never a crash.

import Foundation

/// Most bytes the extension asks the system for.
public let peekLimit = 4096

/// Longest host name (RFC 1035, as text). Same bound as the collector's.
public let maxHostLength = 253

/// Where a host name came from (`host_from` in `thadam.flow.v1`).
public enum HostFrom: String, Sendable, Equatable {
    case sni, http, api, none
}

/// The host name in `bytes`, from SNI first, then HTTP `Host`.
public func peekHost(_ bytes: [UInt8]) -> (host: String, from: HostFrom)? {
    let bytes = Array(bytes.prefix(peekLimit))
    if let host = sniHost(bytes) {
        return (host, .sni)
    }
    if let host = httpHost(bytes) {
        return (host, .http)
    }
    return nil
}

/// A valid host name, lower case without a trailing dot, or nil. The same rule as the
/// collector's `is_host_name`, so a name sent is never a record rejected; change both.
public func normalizedHost(_ value: String) -> String? {
    let name = value.hasSuffix(".") ? String(value.dropLast()) : value
    guard !name.isEmpty, name.utf8.count <= maxHostLength else { return nil }
    let labelsOK = name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
        (1...63).contains(label.utf8.count)
            && label.utf8.allSatisfy { b in
                (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                    || b == 0x2D || b == 0x5F
            }
    }
    return labelsOK ? name.lowercased() : nil
}

/// Reads big-endian fields from a byte array without ever reading past its end.
private struct Reader {
    let bytes: [UInt8]
    var at = 0
    /// Reading stops here, even if more bytes follow.
    var end: Int

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
        end = bytes.count
    }

    mutating func u8() -> Int? {
        guard at < end else { return nil }
        defer { at += 1 }
        return Int(bytes[at])
    }

    mutating func u16() -> Int? {
        guard let high = u8(), let low = u8() else { return nil }
        return high << 8 | low
    }

    mutating func u24() -> Int? {
        guard let high = u8(), let low = u16() else { return nil }
        return high << 16 | low
    }

    mutating func skip(_ count: Int) -> Bool {
        guard count >= 0, count <= end - at else { return false }
        at += count
        return true
    }

    mutating func take(_ count: Int) -> ArraySlice<UInt8>? {
        guard count >= 0, count <= end - at else { return nil }
        defer { at += count }
        return bytes[at..<at + count]
    }

    /// Narrows reading to the next `count` bytes, or to what is there if fewer arrived.
    mutating func limit(_ count: Int) {
        end = min(end, at + max(0, count))
    }
}

/// The SNI host name from a TLS ClientHello (RFC 8446 4.1.2, RFC 6066 3), or nil.
func sniHost(_ bytes: [UInt8]) -> String? {
    var r = Reader(bytes)
    // Record header: handshake (22), legacy version 3.x, length.
    guard r.u8() == 0x16, r.u8() == 0x03, r.skip(1), let recordLength = r.u16() else { return nil }
    r.limit(recordLength)
    // Handshake header: ClientHello (1), length.
    guard r.u8() == 0x01, let helloLength = r.u24() else { return nil }
    r.limit(helloLength)
    // Version, random, session id, cipher suites, compression methods.
    guard r.skip(2 + 32),
        let sessionID = r.u8(), r.skip(sessionID),
        let suites = r.u16(), r.skip(suites),
        let methods = r.u8(), r.skip(methods),
        let extensionsLength = r.u16()
    else { return nil }
    r.limit(extensionsLength)
    while let type = r.u16(), let length = r.u16() {
        guard type == 0 else {
            guard r.skip(length) else { return nil }
            continue
        }
        r.limit(length)
        guard let listLength = r.u16() else { return nil }
        r.limit(listLength)
        while let nameType = r.u8(), let nameLength = r.u16(), let name = r.take(nameLength) {
            // 0 is host_name; other types are skipped.
            if nameType == 0 {
                return String(bytes: name, encoding: .ascii).flatMap(normalizedHost)
            }
        }
        return nil
    }
    return nil
}

/// Methods a plain HTTP/1 request may start with.
private let httpMethods = ["GET", "POST", "PUT", "HEAD", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"]

/// The `Host` header of an HTTP/1 request, without its port, or nil. The request line, which
/// holds the path, is skipped and never kept.
func httpHost(_ bytes: [UInt8]) -> String? {
    // Header lines end at the first empty line; only complete lines are read.
    let lines = bytes.split(separator: 0x0A, omittingEmptySubsequences: false).dropLast()
    guard let requestLine = lines.first,
        let space = requestLine.firstIndex(of: 0x20),
        let method = String(bytes: requestLine[requestLine.startIndex..<space], encoding: .ascii),
        httpMethods.contains(method)
    else { return nil }
    for raw in lines.dropFirst() {
        let line = raw.last == 0x0D ? raw.dropLast() : raw
        if line.isEmpty { return nil }
        guard let colon = line.firstIndex(of: 0x3A),
            let field = String(bytes: line[line.startIndex..<colon], encoding: .ascii),
            field.lowercased() == "host"
        else { continue }
        guard var value = String(bytes: line[(colon + 1)...], encoding: .ascii) else { return nil }
        value = value.trimmingCharacters(in: .whitespaces)
        // A bracketed address (IPv6 literal) is not a name; a trailing port is dropped.
        if value.hasPrefix("[") { return nil }
        if let portStart = value.lastIndex(of: ":") {
            value = String(value[..<portStart])
        }
        return normalizedHost(value)
    }
    return nil
}
