import Foundation
import Testing

@testable import ThadamNetKit

struct FlowTrackerTests {
    @Test func aNamedFlowIsAnnouncedAtOnce() {
        let tracker = FlowTracker()
        let (verdict, records) = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, systemHost: "API.example.test.")
        #expect(verdict == .allow)
        #expect(
            records == [
                .open(
                    flow: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
                    remote: remote, host: "api.example.test", hostFrom: .api)
            ])
        #expect(tracker.pendingCount == 0)
    }

    @Test func anUnnamedTcpFlowWaitsForItsFirstBytes() {
        let tracker = FlowTracker()
        let (verdict, records) = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, systemHost: nil)
        #expect(verdict == .peekOutbound && records.isEmpty)
        let later = tracker.outboundBytes(id: flowA, bytes: clientHello(sni: "cdn.example.test"), remote: nil)
        #expect(
            later == [
                .open(
                    flow: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
                    remote: remote, host: "cdn.example.test", hostFrom: .sni)
            ])
        // Bytes for a flow no longer waiting are ignored.
        #expect(tracker.outboundBytes(id: flowA, bytes: [1], remote: nil).isEmpty)
    }

    @Test func aSystemNameThatIsNotAHostNameFallsBackToPeeking() {
        let tracker = FlowTracker()
        let (verdict, _) = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, systemHost: "not a name")
        #expect(verdict == .peekOutbound)
    }

    @Test func aFlowClosingBeforeAnyBytesIsAnnouncedUnnamedThenClosed() {
        let tracker = FlowTracker()
        _ = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, systemHost: nil)
        let closeTs = t0.addingTimeInterval(2)
        let records = tracker.report(id: flowA, kind: .closed, ts: closeTs, bytesOut: 0, bytesIn: 0, remote: nil)
        #expect(
            records == [
                .open(
                    flow: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
                    remote: remote, host: nil, hostFrom: .none),
                .close(flow: flowA, ts: closeTs, bytesOut: 0, bytesIn: 0),
            ])
    }

    @Test func theRemoteAddressCanArriveLater() {
        let tracker = FlowTracker()
        let (verdict, records) = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .udp, direction: .outbound,
            remote: nil, systemHost: nil)
        #expect(verdict == .allow && records.isEmpty)
        let later = tracker.report(id: flowA, kind: .statistics, ts: t0, bytesOut: 5, bytesIn: 9, remote: remote)
        #expect(later.count == 2)
        #expect(later.last == .stats(flow: flowA, ts: t0, bytesOut: 5, bytesIn: 9))
        // Later reports carry bytes only.
        #expect(tracker.report(id: flowA, kind: .closed, ts: t0, bytesOut: 5, bytesIn: 9, remote: remote).count == 1)
    }

    @Test func aFlowThatNeverGetsAnAddressIsDroppedAndCounted() {
        let tracker = FlowTracker()
        _ = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .udp, direction: .outbound,
            remote: nil, systemHost: nil)
        #expect(tracker.report(id: flowA, kind: .closed, ts: t0, bytesOut: 0, bytesIn: 0, remote: nil).isEmpty)
        #expect(tracker.counts.noEndpoint == 1)
    }

    @Test func waitingFlowsAreBounded() {
        let tracker = FlowTracker(pendingCapacity: 1)
        _ = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, systemHost: nil)
        _ = tracker.newFlow(
            id: flowB, ts: t0.addingTimeInterval(1), process: process, proto: .tcp,
            direction: .outbound, remote: remote, systemHost: nil)
        #expect(tracker.pendingCount == 1)
        #expect(tracker.counts.pendingDropped == 1)
        #expect(tracker.outboundBytes(id: flowA, bytes: [], remote: nil).isEmpty)
        #expect(tracker.outboundBytes(id: flowB, bytes: [], remote: nil).count == 1)
    }

    @Test func countsCarryNoContent() {
        let tracker = FlowTracker()
        _ = tracker.newFlow(
            id: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, systemHost: "api.example.test")
        let counts = tracker.counts
        #expect(counts.flows == 1 && counts.opens == 1 && counts.named == ["api": 1])
    }
}
