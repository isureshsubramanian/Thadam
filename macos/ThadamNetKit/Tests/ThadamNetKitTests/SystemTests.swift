// Tests against the running system: this test process, the Network framework's endpoint
// objects, and a Unix socket in a temporary folder. No real traffic.

import Darwin
import Foundation
import Network
import Testing
import os

@testable import ThadamNetKit

struct ProcessLookupTests {
    @Test func identityFromAnAuditToken() {
        var token = audit_token_t()
        token.val.5 = 4211
        token.val.7 = 3
        let data = withUnsafeBytes(of: token) { Data($0) }
        #expect(processIdentity(auditToken: data)?.pid == 4211)
        #expect(processIdentity(auditToken: data)?.pidversion == 3)
        #expect(processIdentity(auditToken: Data([1, 2, 3])) == nil)
        #expect(processIdentity(auditToken: nil) == nil)
    }

    @Test func ancestorsAndPathOfThisProcess() throws {
        let me = UInt32(getpid())
        let chain = ancestors(of: me)
        #expect(chain.first == UInt32(getppid()))
        #expect(chain.count <= maxAncestors && !chain.contains(me))
        let path = try #require(executablePath(of: me))
        #expect(path.hasPrefix("/"))
        #expect(executablePath(of: UInt32(Int32.max)) == nil)
    }
}

struct EndpointTests {
    private func endpoint(_ host: String, _ port: UInt16) -> NWEndpoint {
        .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? .any)
    }

    @Test func addressesAndPorts() {
        #expect(remoteAddress(of: endpoint("203.0.113.7", 443)) == Remote(ip: "203.0.113.7", port: 443))
        #expect(remoteAddress(of: endpoint("2001:db8::1", 53)) == Remote(ip: "2001:db8::1", port: 53))
        #expect(remoteAddress(of: endpoint("2001:db8:0:1:0:0:0:1", 53))?.ip == "2001:db8:0:1::1")
        #expect(remoteAddress(of: endpoint("fe80::1%lo0", 53))?.ip == "fe80::1")
        #expect(remoteAddress(of: endpoint("::ffff:203.0.113.7", 80)) == Remote(ip: "203.0.113.7", port: 80))
        #expect(remoteAddress(of: endpoint("203.0.113.7", 0)) == nil)
        #expect(remoteAddress(of: endpoint("api.example.test", 443)) == nil)
    }
}

/// A listening Unix socket that collects whole lines.
private final class Listener: Sendable {
    let path: String
    private let fd: Int32
    private let lines = LineBox()

    init() throws {
        path = NSTemporaryDirectory() + "thadam-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).sock"
        unlink(path)
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = path
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
        try #require(bound && listen(fd, 4) == 0)
    }

    /// Accepts one connection and reads it to the end on a background thread.
    func acceptOne() {
        let fd = fd
        let lines = lines
        Thread.detachNewThread {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            var pending = Data()
            var chunk = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = read(client, &chunk, chunk.count)
                guard n > 0 else { break }
                pending.append(contentsOf: chunk[0..<n])
                while let newline = pending.firstIndex(of: 0x0A) {
                    lines.append(String(decoding: pending[pending.startIndex..<newline], as: UTF8.self))
                    pending = Data(pending[(newline + 1)...])
                }
            }
            close(client)
        }
    }

    func waitForLines(_ count: Int) -> [String] {
        for _ in 0..<200 where lines.count < count {
            usleep(10_000)
        }
        return lines.all
    }

    func shutdown() {
        close(fd)
        unlink(path)
    }
}

private final class LineBox: Sendable {
    private let lock = OSAllocatedUnfairLock(initialState: [String]())
    func append(_ line: String) { lock.withLock { $0.append(line) } }
    var count: Int { lock.withLock { $0.count } }
    var all: [String] { lock.withLock { $0 } }
}

struct FlowSenderTests {
    @Test func linesQueuedWhileTheCollectorIsAwayArriveAfterAGap() throws {
        let listener = try Listener()
        defer { listener.shutdown() }
        let sender = FlowSender(path: listener.path, capacity: 3, retry: 0.02)
        // Queued before anything connects: two of five are dropped.
        for n in 1...5 {
            sender.send(.stats(flow: flowA, ts: t0, bytesOut: UInt64(n), bytesIn: 0))
        }
        listener.acceptOne()
        sender.start()
        defer { sender.stop() }
        let lines = listener.waitForLines(4)
        #expect(lines.count == 4)
        #expect(lines.first?.contains(#""kind":"gap""#) == true)
        #expect(lines.first?.contains(#""missed":2"#) == true)
        #expect(lines.dropFirst().map { $0.contains(#""bytes_out":3"#) } == [true, false, false])
        #expect(lines.last?.contains(#""bytes_out":5"#) == true)
        #expect(sender.counts.sent == 3 && sender.counts.dropped == 2)
    }

    @Test func aMissingCollectorNeverBlocksSend() {
        let sender = FlowSender(path: "/nonexistent-thadam-test/flow.sock", capacity: 2, retry: 0.02)
        sender.start()
        defer { sender.stop() }
        for n in 1...1000 {
            sender.send(.stats(flow: flowA, ts: t0, bytesOut: UInt64(n), bytesIn: 0))
        }
        #expect(sender.counts.queued == 2)
        #expect(sender.counts.dropped == 998)
        #expect(sender.counts.connected == false)
    }
}
