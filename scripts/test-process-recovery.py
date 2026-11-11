#!/usr/bin/env python3
"""Exercise crash recovery using disposable processes and an isolated journal."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

REPOSITORY = Path(__file__).resolve().parents[1]


def wait_for(check, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for recovery")


def process_state(pid):
    result = subprocess.run(["/bin/ps", "-o", "state=", "-p", str(pid)],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip()


def fixture_processes(executable):
    output = subprocess.check_output(["/bin/ps", "-axww", "-o", "pid=,command="], text=True)
    return [(int(parts[0]), parts[1]) for line in output.splitlines()
            if len(parts := line.strip().split(maxsplit=1)) == 2
            and Path(parts[1].split(maxsplit=1)[0]).resolve() == executable]


class Scenario:
    def __init__(self, directory, executable, tree, *, trusted=False, scoped=False):
        self.directory = directory
        self.executable = executable
        directory.mkdir()
        tree_ids = directory / "tree"
        self.target = subprocess.Popen([str(tree), str(tree_ids)], start_new_session=True)
        self.external = subprocess.Popen([str(tree)])
        self.monitor = None
        try:
            wait_for(lambda: tree_ids.exists() and tree_ids.read_text().strip())
            self.owned = [self.target.pid, *map(int, tree_ids.read_text().split())]
            os.kill(self.external.pid, signal.SIGSTOP)
            self.targets = [*self.owned, self.external.pid]
            (directory / "targets.json").write_text(json.dumps([self.target.pid, self.external.pid]))
            self.environment = {**os.environ, "RECOVERY_FIXTURE_DIRECTORY": str(directory),
                                "RECOVERY_FIXTURE_TRUSTED": "1" if trusted else "0",
                                "RECOVERY_FIXTURE_SCOPED": "1" if scoped else "0"}
            self.monitor = subprocess.Popen([str(executable)], env=self.environment,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_for(lambda: self.ready().get("phase") == "ready")
        except BaseException:
            self.cleanup()
            raise

    def ready(self):
        try:
            return json.loads((self.directory / "ready.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def command(self, value):
        (self.directory / "command").write_text(value)

    def assert_paused(self):
        assert all(process_state(pid).startswith("T") for pid in self.targets)

    def crash(self):
        self.monitor.kill()
        self.monitor.wait(timeout=3)
        original = self.monitor.pid

        def recovered():
            self.assert_paused()
            value = self.ready()
            return value if value.get("pid") != original and value.get("phase") == "restored" else None

        return wait_for(recovered)

    def cleanup(self):
        # Stop monitors before their watchdogs, so cleanup cannot start another monitor.
        processes = fixture_processes(self.executable)
        for pid, command in processes:
            if "--recover-paused" not in command:
                try:
                    os.kill(pid, signal.SIGSTOP)
                except ProcessLookupError:
                    pass
        processes.sort(key=lambda value: "--recover-paused" not in value[1])
        for pid, _ in processes:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            os.killpg(self.target.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.external.kill()
        if self.monitor:
            self.monitor.wait(timeout=3)
        self.target.wait(timeout=3)
        self.external.wait(timeout=3)


def run():
    with tempfile.TemporaryDirectory(prefix="MySafeAI-recovery-") as temporary:
        root = Path(temporary).resolve()
        executable = root / "recovery-fixture"
        tree = root / "tree-fixture"
        sources = ["ProcessIdentity.swift", "PauseRecoveryStore.swift",
                   "ProcessPauser.swift", "ProcessWatchdog.swift"]
        subprocess.run(["swiftc", "-swift-version", "6", "-parse-as-library",
                        *[str(REPOSITORY / "Sources/MySafeAI" / name) for name in sources],
                        str(REPOSITORY / "Tests/ProcessRecoveryFixtures/main.swift"),
                        "-o", str(executable)], check=True)
        subprocess.run(["cc", str(REPOSITORY / "Tests/ProcessRecoveryFixtures/tree.c"),
                        "-o", str(tree)], check=True)

        case = Scenario(root / "crash-paused", executable, tree)
        try:
            case.assert_paused()
            restored = case.crash()
            assert restored["restored"]
            case.command("trust")
            wait_for(lambda: case.ready().get("phase") == "trusted")
            assert all(process_state(pid) and not process_state(pid).startswith("T") for pid in case.owned)
            assert process_state(case.external.pid).startswith("T")
            case.command("stop")
            wait_for(lambda: case.ready().get("phase") == "stopped")
            time.sleep(0.3)
            assert not (case.directory / "paused.json").exists()
            assert not fixture_processes(executable)
            print("PASS crash keeps the tree paused, relaunch adopts pauses, verified recovery resumes owned processes")
        finally:
            case.cleanup()

        case = Scenario(root / "crash-trusted", executable, tree, trusted=True)
        try:
            assert all(not process_state(pid).startswith("T") for pid in case.owned)
            case.monitor.kill()
            case.monitor.wait(timeout=3)
            wait_for(lambda: case.ready().get("phase") == "restored")
            case.assert_paused()
            print("PASS crash during a trusted connection relaunches and freezes before revalidation")
        finally:
            case.cleanup()

        case = Scenario(root / "watchdog-exit", executable, tree)
        try:
            watchdog = wait_for(lambda: next((pid for pid, command in fixture_processes(executable)
                                             if "--recover-paused" in command), None))
            os.kill(watchdog, signal.SIGKILL)
            wait_for(lambda: case.ready().get("phase") == "watchdog-rearmed")
            case.assert_paused()
            assert case.monitor.poll() is None
            duplicate = subprocess.run([str(executable)], env=case.environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            assert duplicate.returncode != 0
            case.assert_paused()
            print("PASS a failed watchdog is replaced, and a second controller cannot claim the journal")
        finally:
            case.cleanup()

        case = Scenario(root / "scoped", executable, tree, scoped=True)
        try:
            case.assert_paused()
            case.crash()
            case.command("trust-parent")
            wait_for(lambda: case.ready().get("phase") == "parent-trusted")
            assert not process_state(case.target.pid).startswith("T")
            assert all(process_state(pid).startswith("T") for pid in case.owned[1:])
            case.command("close-child")
            wait_for(lambda: case.ready().get("phase") == "child-closed")
            wait_for(lambda: all(not process_state(pid) or process_state(pid).startswith("Z")
                                 for pid in case.owned[1:]))
            assert case.target.poll() is None
            assert process_state(case.external.pid).startswith("T")
            print("PASS overlapping owners survive recovery; targeted shutdown leaves the allowed parent and external pause alone")
        finally:
            case.cleanup()

        case = Scenario(root / "corrupt-journal", executable, tree)
        try:
            (case.directory / "paused.json").write_text("incomplete-json")
            case.monitor.kill()
            case.monitor.wait(timeout=3)
            time.sleep(0.4)
            case.assert_paused()
            assert (case.directory / "paused.json").read_text() == "incomplete-json"
            print("PASS an unreadable journal preserves paused processes and the recovery evidence")
        finally:
            case.cleanup()


if __name__ == "__main__":
    run()
