import Foundation
import Testing

@testable import ThadamNetKit

/// The exact lines here are also parsed by the collector's test
/// `source::network::tests::lines_the_extension_writes_parse`. Change both together.
struct FlowRecordTests {
    @Test func openLineMatchesTheContract() {
        let line = FlowRecord.open(
            flow: flowA, ts: t0, process: process, proto: .tcp, direction: .outbound,
            remote: remote, host: "api.example.test", hostFrom: .sni
        ).jsonLine()
        #expect(
            text(line)
                == #"{"v":1,"kind":"open","flow":"0192f3a4-0000-7000-8000-000000000001","ts":"2026-11-14T09:33:00.500Z","pid":4211,"pidversion":3,"ppids":[4100,1],"proto":"tcp","direction":"out","remote_ip":"203.0.113.7","remote_port":443,"host":"api.example.test","host_from":"sni","exe":"/Users/test/.local/bin/agent"}"#
                + "\n")
    }

    @Test func openWithoutANameOrExe() {
        let bare = FlowProcess(pid: 9, pidversion: 1, ppids: [], exe: nil)
        let line = text(
            FlowRecord.open(
                flow: flowA, ts: t0, process: bare, proto: .udp, direction: .inbound,
                remote: Remote(ip: "2001:db8::1", port: 53), host: nil, hostFrom: .none
            ).jsonLine())
        #expect(line.contains(#""host_from":"none""#))
        #expect(!line.contains(#""host""#) && !line.contains("exe"))
        #expect(line.contains(#""ppids":[]"#) && line.contains(#""direction":"in""#))
        // A name with origin `none` is never sent.
        let mismatched = text(
            FlowRecord.open(
                flow: flowA, ts: t0, process: bare, proto: .tcp, direction: .outbound,
                remote: remote, host: "x.test", hostFrom: .none
            ).jsonLine())
        #expect(!mismatched.contains("x.test"))
    }

    @Test func byteAndGapLines() {
        #expect(
            text(FlowRecord.stats(flow: flowA, ts: t0, bytesOut: 10, bytesIn: 2000).jsonLine())
                == #"{"v":1,"kind":"stats","flow":"0192f3a4-0000-7000-8000-000000000001","ts":"2026-11-14T09:33:00.500Z","bytes_out":10,"bytes_in":2000}"#
                + "\n")
        #expect(text(FlowRecord.close(flow: flowA, ts: t0, bytesOut: 0, bytesIn: 0).jsonLine()).contains(#""kind":"close""#))
        #expect(
            text(FlowRecord.gap(ts: t0, missed: 42).jsonLine())
                == #"{"v":1,"kind":"gap","ts":"2026-11-14T09:33:00.500Z","missed":42}"# + "\n")
    }

    @Test func processFieldsAreBounded() {
        let long = FlowProcess(pid: 1, pidversion: 1, ppids: Array(1...40), exe: "relative/agent")
        #expect(long.ppids.count == maxAncestors)
        #expect(long.exe == nil)
        #expect(FlowProcess(pid: 1, pidversion: 1, ppids: [], exe: "/" + String(repeating: "a", count: maxExeLength)).exe == nil)
    }

    @Test func stringsAreEscaped() {
        #expect(jsonString("a\"b\\c\nd\u{01}é") == #""a\"b\\c\nd\u0001é""#)
    }
}
