// What a flow's audit token says about its process: pid and pidversion from the token, then
// the ancestor chain and executable path read from the live process table (ADR-007 Decision 2,
// amendment 2). Read once, when the flow starts.

import Darwin
import Foundation

/// pid and pidversion from an audit token, as `audit_token_to_pid` and
/// `audit_token_to_pidversion` read them (val[5] and val[7]). Nil if the data is not a token.
public func processIdentity(auditToken data: Data?) -> (pid: UInt32, pidversion: UInt32)? {
    guard let data, data.count == MemoryLayout<audit_token_t>.size else { return nil }
    var token = audit_token_t()
    withUnsafeMutableBytes(of: &token) { $0.copyBytes(from: data) }
    let pid = token.val.5
    return pid > 0 ? (pid, token.val.7) : nil
}

/// The process's ancestors, nearest first, up to `maxAncestors`. Stops at launchd (pid 1),
/// at a process that is gone, or at a loop.
public func ancestors(of pid: UInt32) -> [UInt32] {
    var chain: [UInt32] = []
    var current = pid
    while chain.count < maxAncestors, current > 1, let parent = parentPID(of: current) {
        guard parent > 0, parent != pid, !chain.contains(parent) else { break }
        chain.append(parent)
        current = parent
    }
    return chain
}

private func parentPID(of pid: UInt32) -> UInt32? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(Int32(bitPattern: pid), PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
    return info.pbi_ppid
}

/// The process's executable path, or nil.
public func executablePath(of pid: UInt32) -> String? {
    // PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN) is a macro Swift does not import.
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    let length = proc_pidpath(Int32(bitPattern: pid), &buffer, UInt32(buffer.count))
    guard length > 0 else { return nil }
    let bytes = buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }
    return String(bytes: bytes, encoding: .utf8)
}
