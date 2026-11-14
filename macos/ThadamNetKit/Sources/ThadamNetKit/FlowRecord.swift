// CONTRACT: `thadam.flow.v1` (ADR-007 Decision 2, amendment 2), one JSON object per line, read
// by the collector's network source. This is the only coupling with the collector. Fields
// are omitted, never sent as null, and a record carries only the fields its kind allows.
// Never in a record: payload bytes, URL paths, header values other than the host name.

import Foundation

/// Most ancestors in a record.
public let maxAncestors = 16

/// Longest executable path, in bytes. Same bound as the collector's.
public let maxExeLength = 4096

public enum FlowProto: String, Sendable, Equatable {
    case tcp, udp
}

public enum FlowDirection: String, Sendable, Equatable {
    case outbound = "out"
    case inbound = "in"
}

/// The far end of a flow. `ip` is plain address text (no scope, IPv4-mapped addresses as IPv4).
public struct Remote: Sendable, Equatable {
    public let ip: String
    public let port: UInt16

    public init(ip: String, port: UInt16) {
        self.ip = ip
        self.port = port
    }
}

/// What the extension knows about a flow's process when the flow starts.
public struct FlowProcess: Sendable, Equatable {
    public let pid: UInt32
    public let pidversion: UInt32
    /// Nearest first, at most `maxAncestors`.
    public let ppids: [UInt32]
    /// Absolute, at most `maxExeLength` bytes; nil if unknown.
    public let exe: String?

    public init(pid: UInt32, pidversion: UInt32, ppids: [UInt32], exe: String?) {
        self.pid = pid
        self.pidversion = pidversion
        self.ppids = Array(ppids.prefix(maxAncestors))
        self.exe = exe.flatMap { $0.hasPrefix("/") && $0.utf8.count <= maxExeLength ? $0 : nil }
    }
}

/// One `thadam.flow.v1` record.
public enum FlowRecord: Sendable, Equatable {
    case open(
        flow: UUID, ts: Date, process: FlowProcess, proto: FlowProto, direction: FlowDirection,
        remote: Remote, host: String?, hostFrom: HostFrom)
    /// Running byte totals for the flow.
    case stats(flow: UUID, ts: Date, bytesOut: UInt64, bytesIn: UInt64)
    case close(flow: UUID, ts: Date, bytesOut: UInt64, bytesIn: UInt64)
    /// Records dropped while the collector was away or slow.
    case gap(ts: Date, missed: UInt64)

    /// The record as one line of JSON, newline included.
    public func jsonLine() -> Data {
        var fields: [(String, JSONValue)] = [("v", .int(1))]
        switch self {
        case let .open(flow, ts, process, proto, direction, remote, host, hostFrom):
            fields += [
                ("kind", .string("open")), ("flow", .string(flow.wireText)), ("ts", .string(ts.wireText)),
                ("pid", .int(UInt64(process.pid))), ("pidversion", .int(UInt64(process.pidversion))),
                ("ppids", .ints(process.ppids.map(UInt64.init))),
                ("proto", .string(proto.rawValue)), ("direction", .string(direction.rawValue)),
                ("remote_ip", .string(remote.ip)), ("remote_port", .int(UInt64(remote.port))),
            ]
            // A name and its origin come together, or neither does.
            if let host, hostFrom != .none {
                fields += [("host", .string(host)), ("host_from", .string(hostFrom.rawValue))]
            } else {
                fields.append(("host_from", .string(HostFrom.none.rawValue)))
            }
            if let exe = process.exe {
                fields.append(("exe", .string(exe)))
            }
        case let .stats(flow, ts, bytesOut, bytesIn), let .close(flow, ts, bytesOut, bytesIn):
            let kind = if case .stats = self { "stats" } else { "close" }
            fields += [
                ("kind", .string(kind)), ("flow", .string(flow.wireText)), ("ts", .string(ts.wireText)),
                ("bytes_out", .int(bytesOut)), ("bytes_in", .int(bytesIn)),
            ]
        case let .gap(ts, missed):
            fields += [("kind", .string("gap")), ("ts", .string(ts.wireText)), ("missed", .int(missed))]
        }
        var out = "{"
        for (i, (key, value)) in fields.enumerated() {
            if i > 0 { out += "," }
            out += jsonString(key) + ":" + value.text
        }
        out += "}\n"
        return Data(out.utf8)
    }
}

private enum JSONValue {
    case int(UInt64)
    case ints([UInt64])
    case string(String)

    var text: String {
        switch self {
        case let .int(n): String(n)
        case let .ints(ns): "[" + ns.map(String.init).joined(separator: ",") + "]"
        case let .string(s): jsonString(s)
        }
    }
}

/// A JSON string literal (RFC 8259 7): quotes, backslashes and control characters escaped.
func jsonString(_ value: String) -> String {
    var out = "\""
    for scalar in value.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        case _ where scalar.value < 0x20:
            out += "\\u" + String(format: "%04x", scalar.value)
        default: out.unicodeScalars.append(scalar)
        }
    }
    return out + "\""
}

extension UUID {
    /// Lower-case hyphenated form.
    var wireText: String { uuidString.lowercased() }
}

extension Date {
    /// RFC 3339 in UTC with milliseconds.
    var wireText: String {
        formatted(Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt))
    }
}
