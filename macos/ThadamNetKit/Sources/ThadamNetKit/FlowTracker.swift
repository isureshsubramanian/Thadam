// Turns the filter's callbacks into `thadam.flow.v1` records (ADR-007 Decision 3, amendments 1
// and 2). Free of NetworkExtension types so it can be tested with synthetic flows; the
// provider translates its objects into these calls.
//
// A flow's `open` record goes out at once when its remote address is known and either the
// system named the host or the flow is not outbound TCP. Otherwise the flow waits here until
// its first outbound bytes (outbound TCP with no name: SNI, then HTTP Host) or its first
// report, whichever comes first, and the open record goes out then.

import Foundation
import os

/// Most flows waiting for their first bytes. An estimate: far above the spike's 35 flows a
/// minute machine-wide. Beyond it the oldest is dropped and counted.
public let defaultPendingCapacity = 10_000

public final class FlowTracker: Sendable {
    /// What the provider should answer for a new flow. Every answer lets the flow through.
    public enum Verdict: Sendable, Equatable {
        /// Allow; nothing more to read.
        case allow
        /// Allow, after showing the extension the first `peekLimit` outbound bytes.
        case peekOutbound
    }

    public enum ReportKind: Sendable {
        case statistics, closed
    }

    /// Counts for diagnostic logs. No hosts, addresses or pids.
    public struct Counts: Sendable, Equatable {
        public var flows: UInt64 = 0
        public var opens: UInt64 = 0
        public var named: [String: UInt64] = [:]
        public var noEndpoint: UInt64 = 0
        public var pendingDropped: UInt64 = 0
    }

    private struct Pending: Sendable {
        let ts: Date
        let process: FlowProcess
        let proto: FlowProto
        let direction: FlowDirection
        var remote: Remote?
        let apiHost: String?
    }

    private struct State: Sendable {
        var pending: [UUID: Pending] = [:]
        var counts = Counts()
    }

    private let capacity: Int
    private let state = OSAllocatedUnfairLock(initialState: State())

    public init(pendingCapacity: Int = defaultPendingCapacity) {
        capacity = max(1, pendingCapacity)
    }

    public var counts: Counts { state.withLock { $0.counts } }

    public var pendingCount: Int { state.withLock { $0.pending.count } }

    /// A new flow. `systemHost` is the name the system reported, if any.
    public func newFlow(
        id: UUID, ts: Date, process: FlowProcess, proto: FlowProto, direction: FlowDirection,
        remote: Remote?, systemHost: String?
    ) -> (Verdict, [FlowRecord]) {
        let apiHost = systemHost.flatMap(normalizedHost)
        let wantsPeek = apiHost == nil && proto == .tcp && direction == .outbound
        let flow = Pending(
            ts: ts, process: process, proto: proto, direction: direction, remote: remote, apiHost: apiHost)
        return state.withLock { s in
            s.counts.flows += 1
            if let remote, !wantsPeek {
                return (.allow, [Self.open(id, flow, remote: remote, peeked: nil, counts: &s.counts)])
            }
            if s.pending.count >= capacity, let oldest = s.pending.min(by: { $0.value.ts < $1.value.ts }) {
                s.pending[oldest.key] = nil
                s.counts.pendingDropped += 1
            }
            s.pending[id] = flow
            return (wantsPeek ? .peekOutbound : .allow, [])
        }
    }

    /// The first outbound bytes of a flow that asked for them. The bytes are parsed here and
    /// not kept.
    public func outboundBytes(id: UUID, bytes: [UInt8], remote: Remote?) -> [FlowRecord] {
        state.withLock { s in
            guard var flow = s.pending.removeValue(forKey: id) else { return [] }
            flow.remote = flow.remote ?? remote
            guard let known = flow.remote else {
                s.counts.noEndpoint += 1
                return []
            }
            let peeked = flow.apiHost == nil ? peekHost(bytes) : nil
            return [Self.open(id, flow, remote: known, peeked: peeked, counts: &s.counts)]
        }
    }

    /// A statistics or closed report with the flow's running byte totals. Sends a waiting
    /// open record first, without a peeked name.
    public func report(
        id: UUID, kind: ReportKind, ts: Date, bytesOut: UInt64, bytesIn: UInt64, remote: Remote?
    ) -> [FlowRecord] {
        state.withLock { s in
            var records: [FlowRecord] = []
            if var flow = s.pending.removeValue(forKey: id) {
                flow.remote = flow.remote ?? remote
                guard let known = flow.remote else {
                    // Never announced, so its bytes would be for a flow the collector never saw.
                    s.counts.noEndpoint += 1
                    return []
                }
                records.append(Self.open(id, flow, remote: known, peeked: nil, counts: &s.counts))
            }
            switch kind {
            case .statistics: records.append(.stats(flow: id, ts: ts, bytesOut: bytesOut, bytesIn: bytesIn))
            case .closed: records.append(.close(flow: id, ts: ts, bytesOut: bytesOut, bytesIn: bytesIn))
            }
            return records
        }
    }

    private static func open(
        _ id: UUID, _ flow: Pending, remote: Remote, peeked: (host: String, from: HostFrom)?,
        counts: inout Counts
    ) -> FlowRecord {
        let (host, from): (String?, HostFrom) =
            if let api = flow.apiHost { (api, .api) } else if let peeked { (peeked.host, peeked.from) } else {
                (nil, .none)
            }
        counts.opens += 1
        counts.named[from.rawValue, default: 0] += 1
        return .open(
            flow: id, ts: flow.ts, process: flow.process, proto: flow.proto, direction: flow.direction,
            remote: remote, host: host, hostFrom: from)
    }
}
