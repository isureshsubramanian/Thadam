// Records waiting for the collector (ADR-007 Decision 1): at most `capacity` lines; when full,
// the oldest is dropped and counted, and the count goes out as a `gap` record.

import Foundation

/// The default size. An estimate: a few minutes of a busy session (ADR-007 Decision 1).
public let defaultBufferCapacity = 10_000

public struct RecordBuffer: Sendable {
    public let capacity: Int
    private var slots: [Data?]
    private var head = 0
    public private(set) var count = 0
    /// Lines dropped since the last `takeMissed()`.
    public private(set) var missed: UInt64 = 0

    public init(capacity: Int = defaultBufferCapacity) {
        self.capacity = max(1, capacity)
        slots = Array(repeating: nil, count: self.capacity)
    }

    /// Adds a line at the back, dropping the oldest if full.
    public mutating func append(_ line: Data) {
        if count == capacity {
            head = (head + 1) % capacity
            count -= 1
            missed += 1
        }
        slots[(head + count) % capacity] = line
        count += 1
    }

    /// Puts lines back at the front, oldest first, as if never taken. Lines that no longer fit
    /// are the oldest of them, and are dropped and counted.
    public mutating func prepend(_ lines: [Data]) {
        for line in lines.reversed() {
            if count == capacity {
                missed += 1
                continue
            }
            head = (head - 1 + capacity) % capacity
            slots[head] = line
            count += 1
        }
    }

    /// Removes and returns every line, oldest first.
    public mutating func takeAll() -> [Data] {
        var lines: [Data] = []
        lines.reserveCapacity(count)
        for i in 0..<count {
            let at = (head + i) % capacity
            if let line = slots[at] { lines.append(line) }
            slots[at] = nil
        }
        head = 0
        count = 0
        return lines
    }

    /// Adds back a dropped count that could not be reported.
    public mutating func addMissed(_ n: UInt64) {
        missed += n
    }

    /// Returns the dropped count and resets it.
    public mutating func takeMissed() -> UInt64 {
        defer { missed = 0 }
        return missed
    }
}
