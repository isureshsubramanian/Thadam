// The content filter (ADR-007 Decisions 1 and 3, amendments 1 and 2). Observe only: every
// verdict lets the flow through, at once, without waiting for the collector. Flow metadata
// goes to the collector over `thadam.flow.v1`; the first outbound bytes of an unnamed TCP
// flow are parsed for a host name in memory and never kept.
//
// Diagnostic logs carry counts only, never hosts, addresses or pids: this extension sees
// every app's traffic.

import Foundation
import NetworkExtension
import os

private let log = Logger(subsystem: "com.nerttiyana.thadam.net.filter", category: "filter")

/// How often counts go to the diagnostic log.
private let countsInterval: DispatchTimeInterval = .seconds(300)

final class FilterDataProvider: NEFilterDataProvider {
    private let tracker = FlowTracker()
    private let sender = FlowSender()
    private var timer: DispatchSourceTimer?

    override func startFilter() async throws {
        sender.start()
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + countsInterval, repeating: countsInterval)
        timer.setEventHandler { [tracker, sender] in logCounts(tracker, sender) }
        timer.resume()
        self.timer = timer
        // No rules: every new flow comes to handleNewFlow.
        do {
            try await apply(NEFilterSettings(rules: [], defaultAction: .filterData))
        } catch {
            log.error("apply settings failed: \(error.localizedDescription, privacy: .public)")
            throw error
        }
        log.info("filter started")
    }

    override func stopFilter(with reason: NEProviderStopReason) async {
        timer?.cancel()
        timer = nil
        logCounts(tracker, sender)
        sender.stop()
        log.info("filter stopped, reason \(reason.rawValue, privacy: .public)")
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow,
            let proto = flowProto(socketFlow.socketProtocol),
            let identity = processIdentity(auditToken: flow.sourceAppAuditToken)
        else {
            return .allow()
        }
        let process = FlowProcess(
            pid: identity.pid, pidversion: identity.pidversion, ppids: ancestors(of: identity.pid),
            exe: executablePath(of: identity.pid))
        let (verdict, records) = tracker.newFlow(
            id: flow.identifier, ts: Date(), process: process, proto: proto,
            direction: socketFlow.direction == .inbound ? .inbound : .outbound,
            remote: remoteOf(flow), systemHost: socketFlow.remoteHostname)
        records.forEach(sender.send)
        let answer: NEFilterNewFlowVerdict =
            switch verdict {
            case .allow: .allow()
            case .peekOutbound:
                .filterDataVerdict(
                    withFilterInbound: false, peekInboundBytes: 0, filterOutbound: true,
                    peekOutboundBytes: peekLimit)
            }
        answer.shouldReport = true
        answer.statisticsReportFrequency = .medium
        return answer
    }

    override func handleOutboundData(
        from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data
    ) -> NEFilterDataVerdict {
        tracker.outboundBytes(id: flow.identifier, bytes: [UInt8](readBytes.prefix(peekLimit)), remote: remoteOf(flow))
            .forEach(sender.send)
        // Pass the rest of the flow without showing it to the extension.
        let verdict = NEFilterDataVerdict.allow()
        verdict.shouldReport = true
        return verdict
    }

    override func handle(_ report: NEFilterReport) {
        guard let flow = report.flow else { return }
        let kind: FlowTracker.ReportKind
        switch report.event {
        case .statistics: kind = .statistics
        case .flowClosed: kind = .closed
        default: return
        }
        tracker.report(
            id: flow.identifier, kind: kind, ts: Date(), bytesOut: UInt64(report.bytesOutboundCount),
            bytesIn: UInt64(report.bytesInboundCount), remote: remoteOf(flow)
        ).forEach(sender.send)
    }
}

private func flowProto(_ value: Int32) -> FlowProto? {
    switch value {
    case IPPROTO_TCP: .tcp
    case IPPROTO_UDP: .udp
    default: nil
    }
}

private func remoteOf(_ flow: NEFilterFlow) -> Remote? {
    (flow as? NEFilterSocketFlow)?.remoteFlowEndpoint.flatMap(remoteAddress(of:))
}

private func logCounts(_ tracker: FlowTracker, _ sender: FlowSender) {
    let t = tracker.counts
    let s = sender.counts
    log.info(
        """
        flows \(t.flows, privacy: .public) opens \(t.opens, privacy: .public) \
        api \(t.named["api", default: 0], privacy: .public) sni \(t.named["sni", default: 0], privacy: .public) \
        http \(t.named["http", default: 0], privacy: .public) none \(t.named["none", default: 0], privacy: .public) \
        no_endpoint \(t.noEndpoint, privacy: .public) pending_dropped \(t.pendingDropped, privacy: .public) \
        sent \(s.sent, privacy: .public) dropped \(s.dropped, privacy: .public) \
        queued \(s.queued, privacy: .public) connected \(s.connected, privacy: .public)
        """)
}
