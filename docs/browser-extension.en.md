# Browser protection

[Русский](browser-extension.md) · English

MySafeAI 0.4.0 can protect selected AI websites without freezing the whole browser. The extension blocks new requests to selected domains until the desktop app confirms your connection. Other websites keep working, and your browser's proxy and VPN settings remain unchanged.

Supported browsers are Chrome, Edge, Brave, Chromium and Firefox on macOS, Windows, Linux/Arch and FreeBSD. Safari and sandboxed Snap/Flatpak native-host integration are not covered by this release.

## Install

1. Install the complete MySafeAI 0.4.0 build. On macOS, move the app into Applications first. Keep all archive files together on Windows/FreeBSD, including `mysafeai-browser-host` or `mysafeai-browser-host.exe`.
2. Open MySafeAI settings and connect the browser extension. This registers a local component for your user account, without administrator access.
3. Install the extension using the steps below, then open its toolbar menu and choose sites.
4. Approve your current IP in MySafeAI. Selected sites remain blocked until verification completes.

If you move the desktop app, reconnect the browser component from settings. The app and browser must run under the same operating-system user.

### Chromium browsers

Download and unpack [MySafeAI-Browser-Chromium.zip](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Browser-Chromium.zip) into a permanent folder. Open `chrome://extensions`, `edge://extensions` or `brave://extensions`, enable Developer mode, choose **Load unpacked**, and select the folder containing `manifest.json`.

Do not delete this folder. To update, replace its files and reload the extension. It is not published in a browser store yet. The fixed extension ID is `akehebbcjgcamdjgjpmhepmgjjlldbik`.

### Firefox

Download and unpack [MySafeAI-Browser-Firefox.zip](https://github.com/in-devp/MySafeAI/releases/latest/download/MySafeAI-Browser-Firefox.zip). Open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select `manifest.json`.

**The archive is not signed by Mozilla yet.** In regular Firefox this temporary installation lasts until the browser restarts. Permanent installation requires a signed XPI, which is not included in this release. Do not disable signature verification in your regular browser. Add-on ID: `mysafeai@in-devp`.

## Choose sites and language

The extension includes ChatGPT/OpenAI, Claude/Anthropic, Cursor and Gemini/AI Studio groups. You can turn groups off independently and add your own domains in its menu. A custom domain also covers its subdomains; it does not include unrelated suffix lookalikes. Custom entries are stored only in your browser, and their blocking rules persist across browser restarts.

Select **System**, **Русский**, or **English** in the app and extension settings. Their preferences are independent so you can use a different language in your browser.

The desktop app receives no site addresses, history, cookies or page contents. Native Messaging communicates over local process pipes and opens no network port.

## What happens when access is blocked

New HTTP(S) requests and new WebSocket handshakes to selected domains are blocked from any tab. An AI integration embedded in an unrelated site may therefore stop working too.

An open protected AI tab moves to a local pause page to terminate its connections. **Unsaved text on the site can be lost.** After verification, explicitly choose to return to the site. Its return URL is stored only in browser session storage, removed after return/tab close, and never sent to the native app.

Without a running desktop app, or if the local bridge is missing, selected sites are blocked. The extension checks the bridge every second. The app's snapshot expires within 3 seconds; a native reply is considered fresh for at most 2.5 seconds. These are sequential checks, not a promise of instantaneous packet cutoff.

Explicitly disabling protection or pausing it for 15 minutes in MySafeAI permits the selected sites while the app remains alive and reports that setting. When the pause ends, a new verified connection is required. Disabling/removing the extension removes its browser rules. Private/incognito windows require separate permission in the browser's extension settings.

## Limits

This is browser request filtering, **not an OS packet firewall**. It does not guarantee control of WebRTC/UDP, unknown extra service domains, already established streams from other tabs, site service workers or packets already queued by the OS.

Chromium's session rules have no built-in expiry. If the extension's background worker crashes while the browser keeps running, an allow rule may remain until the worker starts again. An alarm requests a restart, but the browser may delay it. Restarting the browser clears session rules.

The extension uses MySafeAI's **global public-IP policy**. It does not attest the exit of each browser request under split routing or PAC. Configure your VPN so protected sites follow the verified connection. Use your VPN client's own kill switch when strict packet blocking is required.

## Remove the bridge

Disable or uninstall the extension first. If needed, remove the bridge's user registrations:

```sh
# macOS
/Applications/MySafeAI.app/Contents/MacOS/mysafeai-browser-host --uninstall all

# Linux / Arch / FreeBSD
mysafeai-browser-host --uninstall all

# Windows PowerShell, from the application folder
.\mysafeai-browser-host.exe --uninstall all
```

Only this helper's registrations are removed. Other extensions, proxies, VPNs and firewall settings are untouched.
