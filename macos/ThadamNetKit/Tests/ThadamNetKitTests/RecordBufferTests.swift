import Foundation
import Testing

@testable import ThadamNetKit

struct RecordBufferTests {
    private func line(_ n: Int) -> Data { Data("\(n)\n".utf8) }

    @Test func dropsTheOldestWhenFullAndCountsThem() {
        var buffer = RecordBuffer(capacity: 3)
        (1...5).forEach { buffer.append(line($0)) }
        #expect(buffer.count == 3)
        #expect(buffer.takeMissed() == 2)
        #expect(buffer.takeMissed() == 0)
        #expect(buffer.takeAll() == [line(3), line(4), line(5)])
        #expect(buffer.count == 0)
    }

    @Test func prependPutsLinesBackInOrder() {
        var buffer = RecordBuffer(capacity: 4)
        buffer.append(line(3))
        buffer.prepend([line(1), line(2)])
        #expect(buffer.takeAll() == [line(1), line(2), line(3)])
    }

    @Test func prependDropsTheOldestThatNoLongerFit() {
        var buffer = RecordBuffer(capacity: 3)
        buffer.append(line(4))
        buffer.append(line(5))
        buffer.prepend([line(1), line(2), line(3)])
        #expect(buffer.takeAll() == [line(3), line(4), line(5)])
        #expect(buffer.takeMissed() == 2)
    }
}
