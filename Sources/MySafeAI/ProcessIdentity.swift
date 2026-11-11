import Darwin
import Foundation

struct ProcessIdentity: Codable, Hashable {
    let pid: pid_t
    let startedSeconds: UInt64
    let startedMicroseconds: UInt64

    init(_ info: proc_bsdinfo) {
        pid = pid_t(info.pbi_pid)
        startedSeconds = info.pbi_start_tvsec
        startedMicroseconds = info.pbi_start_tvusec
    }

    static func info(_ pid: pid_t) -> proc_bsdinfo? {
        guard pid != getpid() else { return nil }
        return readInfo(pid)
    }

    static func current() throws -> Self {
        guard let info = readInfo(getpid()) else { throw POSIXError(.ESRCH) }
        return Self(info)
    }

    var isRunning: Bool { Self.readInfo(pid).map(Self.init) == self }

    private static func readInfo(_ pid: pid_t) -> proc_bsdinfo? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
              info.pbi_uid == getuid(), info.pbi_ruid == getuid(),
              info.pbi_status != SZOMB else { return nil }
        return info
    }

    func resume() -> Bool {
        guard let info = Self.info(pid), Self(info) == self else { return true }
        return kill(pid, SIGCONT) == 0 || errno == ESRCH
    }
}
