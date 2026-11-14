// The socket client (ADR-007 Decision 1). The collector listens and the extension connects.
// `send` only appends to the buffer and never waits; one writer thread connects, retries
// every second while the collector is away, and drains the buffer. A dropped count goes out
// as a `gap` record before the next lines.

import Darwin
import Foundation
import os

/// Where the collector listens: the collector's `DEFAULT_SOCKET`; change both.
public let defaultFlowSocket = "/var/run/thadam/flow.sock"

public final class FlowSender: Sendable {
    private let path: String
    private let state: OSAllocatedUnfairLock<State>
    private let wake = DispatchSemaphore(value: 0)
    private let retry: TimeInterval

    private struct State {
        var buffer: RecordBuffer
        var running = false
        var connected = false
        var sent: UInt64 = 0
        var dropped: UInt64 = 0
    }

    /// Counts for diagnostic logs. No content.
    public struct Counts: Sendable, Equatable {
        public let sent: UInt64
        public let dropped: UInt64
        public let queued: Int
        public let connected: Bool
    }

    public init(path: String = defaultFlowSocket, capacity: Int = defaultBufferCapacity, retry: TimeInterval = 1) {
        self.path = path
        self.retry = retry
        state = OSAllocatedUnfairLock(initialState: State(buffer: RecordBuffer(capacity: capacity)))
    }

    /// Queues a record. Never blocks on the collector.
    public func send(_ record: FlowRecord) {
        let line = record.jsonLine()
        state.withLock { $0.buffer.append(line) }
        wake.signal()
    }

    public var counts: Counts {
        state.withLock {
            Counts(
                sent: $0.sent, dropped: $0.dropped + $0.buffer.missed, queued: $0.buffer.count,
                connected: $0.connected)
        }
    }

    /// Starts the writer thread. Calling it again does nothing.
    public func start() {
        let alreadyRunning = state.withLock { s in
            defer { s.running = true }
            return s.running
        }
        guard !alreadyRunning else { return }
        let thread = Thread { [self] in run() }
        thread.name = "thadam.flow-sender"
        thread.start()
    }

    /// Stops the writer thread after its current pass. Queued lines stay queued.
    public func stop() {
        state.withLock { $0.running = false }
        wake.signal()
    }

    private var running: Bool { state.withLock { $0.running } }

    private func run() {
        var fd: Int32 = -1
        while running {
            if fd < 0 {
                fd = connectSocket(path)
                let connected = fd >= 0
                state.withLock { $0.connected = connected }
                if fd < 0 {
                    _ = wake.wait(timeout: .now() + retry)
                    continue
                }
            }
            if !drain(fd) {
                close(fd)
                fd = -1
                state.withLock { $0.connected = false }
                continue
            }
            _ = wake.wait(timeout: .now() + retry)
        }
        if fd >= 0 { close(fd) }
        state.withLock { $0.connected = false }
    }

    /// Writes everything queued, a `gap` record first if lines were dropped. False if the
    /// connection failed; whatever was not written goes back to the buffer.
    private func drain(_ fd: Int32) -> Bool {
        let (lines, missed) = state.withLock { s in (s.buffer.takeAll(), s.buffer.takeMissed()) }
        if missed > 0 {
            guard writeAll(fd, FlowRecord.gap(ts: Date(), missed: missed).jsonLine()) else {
                state.withLock { s in
                    s.buffer.addMissed(missed)
                    s.buffer.prepend(lines)
                }
                return false
            }
            state.withLock { $0.dropped += missed }
        }
        for (i, line) in lines.enumerated() {
            guard writeAll(fd, line) else {
                state.withLock { $0.buffer.prepend(Array(lines[i...])) }
                return false
            }
            state.withLock { $0.sent += 1 }
        }
        return true
    }
}

/// Connects a Unix stream socket, or returns -1. SIGPIPE is off for it.
private func connectSocket(_ path: String) -> Int32 {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    guard path.utf8.count < capacity else { return -1 }
    withUnsafeMutableBytes(of: &address.sun_path) { raw in
        raw.copyBytes(from: path.utf8)
        raw[path.utf8.count] = 0
    }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return -1 }
    var on: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    let ok = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
        }
    }
    if !ok {
        close(fd)
        return -1
    }
    return fd
}

/// Writes all of `data`, retrying short writes and interrupts. False on any other failure.
private func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    data.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return true }
        var offset = 0
        while offset < raw.count {
            let n = write(fd, base + offset, raw.count - offset)
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += n
        }
        return true
    }
}
