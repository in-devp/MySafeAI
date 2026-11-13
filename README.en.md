<p align="center"><img src="docs/screenshots/logo.png" alt="MySafeAI" width="110"></p>
<h1 align="center">MySafeAI</h1>
<p align="center"><strong>Local protection for AI apps and websites</strong><br>Verify your connection, pause selected apps, and protect AI sites without freezing your browser.</p>
<p align="center"><a href="README.md">Русский</a> · English · <a href="https://github.com/in-devp/MySafeAI/releases/latest">Download</a> · <a href="docs/browser-extension.en.md">Browser setup</a> · <a href="https://pay.oxapay.com/10596841">Donate</a></p>

MySafeAI is free, open source, and runs locally. No account or hosted control service is required. Both Russian and English are available in the application and browser extension settings.

## Download

| Platform | ARM64 | x64 |
| --- | --- | --- |
| macOS 14+ | [ZIP](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-macOS-arm64.zip) | [ZIP](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-macOS-x64.zip) |
| Windows 10+ | [ZIP](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Windows-arm64.zip) | [ZIP](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Windows-x64.zip) |
| Ubuntu 26.04 | [DEB](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Linux-arm64.deb) · [TAR.GZ](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Linux-arm64.tar.gz) | [DEB](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Linux-x64.deb) · [TAR.GZ](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Linux-x64.tar.gz) |
| Arch Linux | — | [Package](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Arch-x64.pkg.tar.zst) |
| FreeBSD 15.1 | — | [TAR.GZ](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-FreeBSD-amd64.tar.gz) |

[All releases](https://github.com/in-devp/MySafeAI/releases) · [SHA-256 checksums](https://github.com/in-devp/MySafeAI/releases/latest/download/SHA256SUMS.txt)

Browser extensions: [Chrome / Edge / Brave / Chromium](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Browser-Chromium.zip) · [Firefox](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Browser-Firefox.zip). Installation is currently manual. The unsigned Firefox build can be loaded temporarily for one browser session; permanent installation in regular Firefox requires Mozilla signing.

## How it works

- **Approve your connection.** At least two independent IP services verify the public address, on a VPN or direct Wi-Fi/Ethernet connection. New direct addresses require separate approval.
- **Pause, then resume.** Selected Codex CLI, Claude Code, Cursor, desktop apps and their child processes pause while the connection is untrusted, then resume after verification. `mysafeai run -- codex` checks the connection before starting a command.
- **Protect websites.** The browser extension blocks new requests to selected AI domains, including your own domains. Other sites keep working. Open protected tabs move to a local pause page when access is revoked. [Setup and limitations](docs/browser-extension.en.md).
- **Choose a policy.** App-specific IP/CIDR/country rules, trusted local networks, VPN-only routes, service route checks, and system proxy/PAC diagnostics are available.
- **Stay in control.** Disable protection without quitting, pause it for 15 minutes, use tray-only mode, and review the local event log. IP, IPv6 and DNS diagnostics are built in; the external bash.ws DNS test is optional.

MySafeAI does not create a VPN or change system routing. Process suspension and browser request filtering are **not an operating-system packet firewall**. For a strict no-packets-outside-the-VPN requirement, enable your VPN client's kill switch. Already queued packets, WebRTC and some existing browser streams are outside the extension's guarantees. A crashed extension worker can retain a session allow rule until the browser restarts it. Navigating to a pause page can discard unsaved site input.

## Install

- **macOS:** move `MySafeAI.app` into Applications. The build is ad-hoc signed, so macOS may require confirmation in Privacy & Security.
- **Windows:** unpack the entire archive and run `MySafeAI-Desktop.exe`. Microsoft WebView2 Runtime is required.
- **Ubuntu:** run `sudo apt install ./MySafeAI-Linux-*.deb`.
- **Arch:** run `sudo pacman -U ./MySafeAI-Arch-x64.pkg.tar.zst`.
- **FreeBSD:** install `gtk4 webkit2-gtk_60 glib-networking`, unpack the archive, then run `./mysafeai` in a desktop session.

For browser integration, keep the included `mysafeai-browser-host` helper alongside the executable. It is already bundled inside the macOS app and installed by Linux packages. Connect it from the application's settings, then install the extension.

## Build

macOS uses SwiftUI and Xcode 26.3. The browser bridge and Windows/Linux/FreeBSD app use Go 1.26.

```sh
swift test
python3 scripts/test-process-recovery.py
./scripts/build-macos.sh

cd portable
go test ./...
go build -tags production -o mysafeai .
go build -o mysafeai-browser-host ./cmd/browser-host
```

Linux desktop builds require GTK4, WebKitGTK 6.0 and their development packages. Extension tests and packaging use Node.js without runtime npm dependencies:

```sh
node --test browser-extension/tests/*.test.cjs
node browser-extension/package.mjs dist/browser-extension
```

The project is distributed under the [MIT license](LICENSE). [Donate through OxaPay](https://pay.oxapay.com/10596841) or [report an issue](https://github.com/in-devp/MySafeAI/issues/new).
