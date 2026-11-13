#!/usr/bin/env python3
"""Operate the installed app's real settings controls in the isolated CI desktop.

Requires python-gobject + at-spi2-core. No application test endpoints, JavaScript
injection, fixed startup delay, or writes to MySafeAI's settings are used.
"""

import os
import sys
import time
from collections import deque

import gi

gi.require_version("Atspi", "2.0")
from gi.repository import Atspi, GLib

TARGET_PID = int(sys.argv[1])
Atspi.init()
Atspi.set_timeout(1000, 1000)


def belongs_to_target(pid):
    """WebKit may export its document from a separate child process."""
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == TARGET_PID:
            return True
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as source:
                stat = source.read()
            pid = int(stat[stat.rfind(")") + 2 :].split()[1])
        except (OSError, ValueError, IndexError):
            return False
    return False


def app_roots():
    desktop = Atspi.get_desktop(0)
    result = []
    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        try:
            if app is not None and belongs_to_target(app.get_process_id()):
                app.clear_cache()
                result.append(app)
        except GLib.Error:
            continue
    return result


def nodes(roots, deadline=None):
    pending = deque((root, 0) for root in roots)
    count = 0
    while pending and count < 3000 and (deadline is None or time.monotonic() < deadline):
        node, depth = pending.popleft()
        if node is None or depth > 30:
            continue
        count += 1
        yield node, depth
        try:
            pending.extend((node.get_child_at_index(i), depth + 1)
                           for i in range(min(node.get_child_count(), 500)))
        except GLib.Error:
            continue


def find_control(roles, names, deadline):
    for node, _ in nodes(app_roots(), deadline):
        try:
            if node.get_role() not in roles or (node.get_name() or "").strip() not in names:
                continue
            state = node.get_state_set()
            if state.contains(Atspi.StateType.VISIBLE) and state.contains(Atspi.StateType.ENABLED):
                action = node.get_action_iface()
                if action is not None and action.get_n_actions() > 0:
                    return node
        except GLib.Error:
            continue
    return None


def wait_control(roles, names):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        os.kill(TARGET_PID, 0)
        context = GLib.MainContext.default()
        while context.pending():
            context.iteration(False)
        try:
            control = find_control(roles, names, deadline)
            if control is not None:
                return control
        except GLib.Error:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for accessible control {sorted(names)}")


def activate(node):
    action = node.get_action_iface()
    if action is None or action.get_n_actions() == 0 or not action.do_action(0):
        raise RuntimeError("The application refused its accessibility action")


def dump_tree():
    print("AT-SPI application tree after failure:", file=sys.stderr)
    try:
        desktop = Atspi.get_desktop(0)
        for i in range(min(desktop.get_child_count(), 30)):
            app = desktop.get_child_at_index(i)
            if app is not None:
                print(f"  application pid={app.get_process_id()} name={app.get_name()!r}", file=sys.stderr)
        for count, (node, depth) in enumerate(nodes(app_roots(), time.monotonic() + 5)):
            if count >= 120:
                print("  [tree truncated]", file=sys.stderr)
                break
            try:
                # Only control labels are printed; paragraphs/entries can hold
                # addresses or user input and are unnecessary for this diagnosis.
                role = node.get_role()
                name = (node.get_name() or "")[:80] if role in {
                    Atspi.Role.APPLICATION, Atspi.Role.FRAME, Atspi.Role.PUSH_BUTTON,
                    Atspi.Role.TOGGLE_BUTTON, Atspi.Role.CHECK_BOX, Atspi.Role.COMBO_BOX, Atspi.Role.HEADING,
                    Atspi.Role.LINK,
                } else ""
                states = [state.value_nick for state in node.get_state_set().get_states()]
                print(f"{'  ' * min(depth, 8)}{node.get_role_name()} {name!r} {states}", file=sys.stderr)
            except GLib.Error as error:
                print(f"  [inaccessible node: {error.message}]", file=sys.stderr)
    except Exception as error:
        print(f"  [tree unavailable: {error}]", file=sys.stderr)


try:
    # Hide is initially [hidden] in the HTML. refresh() exposes it only after
    # bootstrap has fetched API state and confirmed that a tray host exists.
    # Seeing it proves JS/data readiness, not just a mapped GTK window.
    wait_control({Atspi.Role.PUSH_BUTTON}, {"Hide", "Скрыть"})
    print("Confirmed loaded panel and tray state through the visible Hide control", flush=True)
    settings = wait_control({Atspi.Role.PUSH_BUTTON, Atspi.Role.TOGGLE_BUTTON}, {"Settings", "Настройки"})
    activate(settings)
    print("Activated the loaded Settings button through AT-SPI", flush=True)
    toggle = wait_control({Atspi.Role.CHECK_BOX}, {"Tray only", "Только в трее"})
    if toggle.get_state_set().contains(Atspi.StateType.CHECKED):
        raise RuntimeError("Tray-only was already enabled in the clean test profile")
    activate(toggle)
    print("Activated the enabled tray-only checkbox through AT-SPI", flush=True)
except Exception:
    dump_tree()
    raise
finally:
    Atspi.exit()
