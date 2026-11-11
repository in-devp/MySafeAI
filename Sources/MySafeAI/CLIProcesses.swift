import Darwin
import Foundation
import NetworkDiagnostics

enum CLIProcesses {
    static func roots(for targets: Set<CLIProtectionTarget>) -> [ProcessIdentity: CLIProtectionTarget] {
        guard !targets.isEmpty else { return [:] }
        var result: [ProcessIdentity: CLIProtectionTarget] = [:]
        for pid in processIDs() {
            guard let executable = executablePath(pid) else { continue }
            let name = (executable as NSString).lastPathComponent
            guard name == "node" || name == "claude" || name.hasPrefix("codex")
                    || executable.contains("/.local/share/claude/versions/"),
                  let info = ProcessIdentity.info(pid),
                  let target = CLIProtectionTarget.identify(
                    executable: executable,
                    firstArgument: name == "node" || name.hasPrefix("codex") ? firstArgument(pid) : nil
                  ),
                  targets.contains(target) else { continue }
            let identity = ProcessIdentity(info)
            guard ProcessIdentity.info(pid).map(ProcessIdentity.init) == identity else { continue }
            result[identity] = target
        }
        return result
    }

    private static func processIDs() -> [pid_t] {
        var pids = [pid_t](repeating: 0, count: max(256, Int(proc_listallpids(nil, 0)) + 32))
        while true {
            let capacity = pids.count
            let count = pids.withUnsafeMutableBufferPointer {
                Int(proc_listallpids($0.baseAddress, Int32(capacity * MemoryLayout<pid_t>.stride)))
            }
            if count < capacity { return Array(pids.prefix(max(0, count))).filter { $0 > 1 } }
            pids = [pid_t](repeating: 0, count: capacity * 2)
        }
    }

    private static func executablePath(_ pid: pid_t) -> String? {
        var bytes = [UInt8](repeating: 0, count: 4096)
        let length = bytes.withUnsafeMutableBytes { proc_pidpath(pid, $0.baseAddress, UInt32($0.count)) }
        guard length > 0 else { return nil }
        return String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
    }

    private static func firstArgument(_ pid: pid_t) -> String? {
        var mib = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, u_int(mib.count), &bytes, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size else { return nil }
        let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc > 1 else { return "" }
        // Darwin stores argc, the executable path, padding, then argv and the environment.
        let body = bytes.prefix(size).dropFirst(MemoryLayout<Int32>.size)
        guard let pathEnd = body.firstIndex(of: 0),
              let argvStart = body.dropFirst(pathEnd - body.startIndex + 1).firstIndex(where: { $0 != 0 }),
              let argvEnd = body[argvStart...].firstIndex(of: 0) else { return nil }
        return String(decoding: body[body.index(after: argvEnd)...].prefix(while: { $0 != 0 }), as: UTF8.self)
    }
}
