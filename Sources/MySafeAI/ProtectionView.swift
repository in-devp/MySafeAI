import AppKit
import NetworkDiagnostics
import SwiftUI

extension ProtectionController.Status {
    var title: String {
        switch self {
        case .off: L10n.text("Защита приложений выключена")
        case .checking: L10n.text("Проверяем маршрут и IP")
        case .trusted: L10n.text("Маршрут и IP подтверждены")
        case .paused(.noTunnel): L10n.text("Требуемый маршрут не найден")
        case .paused(.unsafeIPv6): L10n.text("Маршрут IPv6 не подтверждён")
        case .paused(.unsafeDNS): L10n.text("Маршрут DNS не подтверждён")
        case .paused(.noResponse): L10n.text("Не удалось подтвердить IP")
        case .paused(.disagreement): L10n.text("Источники вернули разные адреса")
        case .paused(.unexpectedAddress): L10n.text("IP вне списка доверенных")
        case .paused(.serviceUnverified): L10n.text("Маршрут к сервису не подтверждён")
        case .paused(.proxyUnverified): L10n.text("Системный прокси для сервиса не подтверждён")
        case .failed: L10n.text("Ошибка защиты приложений")
        }
    }
}

struct ProtectionView: View {
    let model: MonitorModel
    var showRules: (() -> Void)?
    @State private var addressInput = ""
    @State private var showsAddressInput = false
    @FocusState private var addressInputFocused: Bool

    private var protection: ProtectionController { model.protection }
    var body: some View {
        VStack(alignment: .leading, spacing: 15) {
            if protection.status == .failed {
                Label(L10n.text("Ошибка защиты. Остановленные процессы сохраняют паузу. Повторите запуск защиты или отключите её."),
                      systemImage: "exclamationmark.circle")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }

            addressRules
            if let showRules {
                Button(action: showRules) {
                    Label(L10n.text("Правила IP и маршрутов"), systemImage: "list.bullet.rectangle")
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
            }
            applicationRules
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var applicationRules: some View {
        let targets = CLIProtectionTarget.allCases.filter {
            !protection.isEnabled || protection.cliTargets.contains($0)
        }
        let desktops = DesktopProtectionTarget.allCases.filter {
            !protection.isEnabled || protection.desktopTargets.contains($0)
        }

        return VStack(alignment: .leading, spacing: 7) {
            Text(protection.isEnabled ? L10n.text("Правила защиты") : L10n.text("Что защищать"))
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.secondary)
                .padding(.leading, 10)
                .accessibilityAddTraits(.isHeader)

            VStack(spacing: 0) {
                ForEach(targets, id: \.self) { target in
                    if target != targets.first { targetDivider }
                    cliRow(target)
                }
                ForEach(desktops, id: \.self) { target in
                    if !targets.isEmpty || target != desktops.first { targetDivider }
                    desktopRow(target)
                }
                ForEach(protection.applications) { app in
                    if !targets.isEmpty || !desktops.isEmpty || app != protection.applications.first { targetDivider }
                    applicationRow(app)
                }
                if !protection.isEnabled {
                    targetDivider
                    Button(action: protection.selectApplication) {
                        targetRow(L10n.text("Добавить приложение…")) {
                            PanelIconTile(symbol: "plus")
                        } accessory: {
                            Image(systemName: "chevron.right")
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundStyle(.secondary)
                                .frame(width: 20)
                        }
                    }
                    .buttonStyle(PanelButtonStyle(.quiet, size: .row, fullWidth: true))
                }
            }
            .panelGroup()

            if protection.selectionError {
                Text(L10n.text("Выберите другой пакет .app с исполняемым файлом."))
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var targetDivider: some View {
        PanelGroupDivider(inset: 44)
    }

    private func cliRow(_ target: CLIProtectionTarget) -> some View {
        let selected = protection.cliTargets.contains(target)
        return selectableTarget(target.title, selected: selected) {
            PanelIconTile(symbol: target == .codex ? "terminal" : "sparkle")
        } change: {
            protection.setCLITarget(target, enabled: !selected)
        }
    }

    private func desktopRow(_ target: DesktopProtectionTarget) -> some View {
        let selected = protection.desktopTargets.contains(target)
        return selectableTarget(target.title, selected: selected) {
            if let url = target.installedURL {
                appIcon(path: url.path)
            } else {
                PanelIconTile(symbol: target.symbol)
            }
        } change: {
            protection.setDesktopTarget(target, enabled: !selected)
        }
    }

    @ViewBuilder private func selectableTarget<Icon: View>(
        _ title: String, selected: Bool, @ViewBuilder icon: () -> Icon, change: @escaping () -> Void
    ) -> some View {
        let row = targetRow(title, icon: icon) { PanelSelectionMark(selected: selected) }
        if protection.isEnabled {
            row.padding(.horizontal, 10)
        } else {
            Button(action: change) { row }
            .buttonStyle(PanelButtonStyle(.quiet, size: .row, fullWidth: true))
            .accessibilityValue(selected ? L10n.text("Выбрано") : L10n.text("Не выбрано"))
            .accessibilityAddTraits(selected ? .isSelected : [])
        }
    }

    private func applicationRow(_ app: ProtectedApplication) -> some View {
        targetRow(app.name) {
            appIcon(path: app.path)
        } accessory: {
            if !protection.isEnabled {
                Button { protection.removeApplication(app) } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(PanelButtonStyle(.quiet, size: .icon))
                .accessibilityLabel(L10n.text("Убрать \(app.name) из защиты"))
                .help(L10n.text("Убрать из защиты"))
            }
            PanelSelectionMark(selected: true)
        }
        .padding(.horizontal, 10)
    }

    private func targetRow<Icon: View, Accessory: View>(
        _ title: String, @ViewBuilder icon: () -> Icon, @ViewBuilder accessory: () -> Accessory
    ) -> some View {
        HStack(spacing: 10) {
            icon().frame(width: 24, height: 24).accessibilityHidden(true)
            Text(title).font(.system(size: 13, weight: .medium)).lineLimit(1)
            Spacer(minLength: 4)
            HStack(spacing: 4, content: accessory)
        }
        .frame(minHeight: 38)
    }

    private func appIcon(path: String) -> some View {
        Image(nsImage: NSWorkspace.shared.icon(forFile: path))
            .resizable()
            .scaledToFit()
            .frame(width: 24, height: 24)
    }

    private var addressRules: some View {
        let current = protection.currentAddresses
        let other = protection.trustedAddresses.filter { !current.contains($0) }
        let showsDecision = protection.isEnabled && !protection.pendingAddresses.isEmpty
        return VStack(alignment: .leading, spacing: 8) {
            Text(L10n.text("Доверенные IP"))
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.secondary)
                .accessibilityAddTraits(.isHeader)

            VStack(alignment: .leading, spacing: 10) {
                Text(L10n.text("Текущее подключение"))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                if current.isEmpty {
                    VPNAddressApproval(model: model, embedded: true)
                } else {
                    ForEach(showsDecision ? Array(current.prefix(1)) : current, id: \.self) { address in
                        currentAddressRow(address)
                    }
                    if showsDecision {
                        VPNAddressApproval(model: model, showsPrimaryAddress: false, embedded: true)
                    } else if !protection.isEnabled && protection.assessment?.base.direct != true && current.contains(where: {
                        !protection.isGloballyTrusted($0)
                    }) {
                        Button {
                            for address in current { _ = protection.addAddress(address) }
                        } label: {
                            Label(current.count == 1 ? L10n.text("Разрешить этот IP") : L10n.text("Разрешить эти IP"),
                                  systemImage: "checkmark.shield")
                        }
                        .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
                    }
                }
            }
            .padding(10)
            .panelGroup()

            if !other.isEmpty {
                VStack(spacing: 0) {
                    ForEach(other, id: \.self) { ip in
                        if ip != other.first { PanelGroupDivider() }
                        removableAddressRow(ip)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                    }
                }
                .panelGroup()
            }

            if !protection.isEnabled {
                if showsAddressInput {
                    manualAddressEntry
                } else {
                    Button {
                        showsAddressInput = true
                        addressInputFocused = true
                    } label: {
                        Label(L10n.text("Добавить другой IP"), systemImage: "plus")
                    }
                    .buttonStyle(PanelButtonStyle(fullWidth: true))
                }
            }
        }
    }

    private var manualAddressEntry: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField(L10n.text("IPv4 или IPv6"), text: $addressInput)
                .textFieldStyle(.plain)
                .padding(9)
                .background(.white.opacity(0.05), in: .rect(cornerRadius: 7))
                .accessibilityLabel(L10n.text("Другой доверенный IP"))
                .focused($addressInputFocused)
                .onSubmit(addAddress)
            HStack(spacing: 8) {
                Button(L10n.text("Отмена")) {
                    addressInput = ""
                    showsAddressInput = false
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
                Button(L10n.text("Сохранить IP"), action: addAddress)
                    .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
                    .disabled(AddressEcho.parse(addressInput) == nil)
            }
        }
        .padding(10)
        .panelGroup()
    }

    private func addAddress() {
        if protection.addAddress(addressInput) {
            addressInput = ""
            showsAddressInput = false
        }
    }

    private func currentAddressRow(_ address: String) -> some View {
        let trusted = (protection.assessment?.base.direct == true
            ? protection.globalAddressPolicy.allowsDirect(address)
            : protection.isGloballyTrusted(address)) || protection.assessment?.trustedNetwork != nil
        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Label(trusted ? L10n.text("Разрешён") : L10n.text("Ждёт разрешения"),
                      systemImage: trusted ? "checkmark.circle.fill" : "questionmark.circle")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(trusted ? PanelButtonStyle.accent : .secondary)
                Spacer(minLength: 0)
                if protection.trustedAddresses.contains(address) && !protection.isEnabled { removeAddressButton(address) }
            }
            Text(address)
                .font(.system(size: address.contains(":") ? 16 : 23, weight: .medium))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .textSelection(.enabled)
        }
    }

    private func removableAddressRow(_ address: String) -> some View {
        HStack {
            Text(address)
                .monospacedDigit()
                .lineLimit(1)
                .textSelection(.enabled)
            Spacer()
            if !protection.isEnabled {
                removeAddressButton(address)
            }
        }
    }

    private func removeAddressButton(_ address: String) -> some View {
        Button { protection.removeAddress(address) } label: {
            Image(systemName: "trash")
        }
        .buttonStyle(PanelButtonStyle(.quiet, size: .icon))
        .accessibilityLabel(L10n.text("Убрать \(address) из доверенных"))
        .help(L10n.text("Убрать из доверенных"))
    }
}

struct ProtectionActions: View {
    let model: MonitorModel

    private var setupHint: String {
        if model.addressSettings.enabledSources.isEmpty {
            return L10n.text("Включите два источника проверки IP в настройках.")
        }
        if !model.protection.hasTargets {
            return L10n.text("Защита будет действовать для команд mysafeai run.")
        }
        return L10n.text("Приложения будут на паузе до подтверждения IP.")
    }

    var body: some View {
        if model.protection.status == .off {
            VStack(alignment: .leading, spacing: 6) {
                Text(model.protection.protectionPausedUntil.map {
                    L10n.text("Пауза защиты до \($0.formatted(Date.FormatStyle(date: .omitted, time: .shortened).locale(L10n.locale))).")
                } ?? setupHint)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Button(action: model.enableProtection) {
                    Label(model.protection.protectionPausedUntil == nil ? L10n.text("Включить защиту") : L10n.text("Возобновить защиту"),
                          systemImage: "shield")
                }
                .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
            }
        } else if model.protection.status == .failed {
            VStack(spacing: 7) {
                Button(action: model.enableProtection) {
                    Label(L10n.text("Восстановить защиту"), systemImage: "arrow.clockwise.shield")
                }
                .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
                Button(action: model.disableProtection) {
                    Text(L10n.text("Отключить и снять паузу"))
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
            }
        } else {
            HStack(spacing: 7) {
                Button(action: model.pauseProtection) {
                    Label(L10n.text("Пауза на 15 минут"), systemImage: "pause.circle")
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
                Button(action: model.disableProtection) {
                    Label(L10n.text("Отключить защиту"), systemImage: "shield.slash")
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
            }
        }
    }
}

struct VPNAddressApproval: View {
    let model: MonitorModel
    var showsPrimaryAddress = true
    var embedded = false

    private var protection: ProtectionController { model.protection }

    var body: some View {
        let pending = protection.pendingAddresses
        let declined = pending == protection.declinedAddresses

        VStack(alignment: .leading, spacing: 7) {
            if protection.pausedCount > 0 && !embedded {
                Label(L10n.text("На паузе: \(protection.pausedCount)"), systemImage: "pause.circle.fill")
                    .foregroundStyle(Color(red: 1.0, green: 0.79, blue: 0.52))
                    .fontWeight(.medium)
            }
            switch protection.addressState {
            case .checking:
                Label(L10n.text("Определяем внешний IP…"), systemImage: "ellipsis.circle")
            case .noTunnel:
                Label(L10n.text("Нет подтверждённого маршрута IPv4"), systemImage: "network")
            case .unsafeIPv6:
                Label(L10n.text("Маршрут IPv6 не подтверждён"), systemImage: "exclamationmark.circle")
            case .unverifiedIPv6:
                Label(L10n.text("Два источника должны подтвердить IPv6"), systemImage: "exclamationmark.circle")
            case .unavailable:
                Label(L10n.text("Два источника должны подтвердить IP"), systemImage: "exclamationmark.circle")
            case .disagreement:
                Label(L10n.text("Сервисы проверки видят разные IP"), systemImage: "exclamationmark.circle")
            case .serviceUnverified:
                Label(L10n.text("Путь к сервису через туннель не подтверждён"), systemImage: "point.3.connected.trianglepath.dotted")
            case .proxyUnverified:
                Label(L10n.text("Сервис не подтвердил выход через системный прокси"), systemImage: "network")
            case .current(let addresses):
                Text(pending.isEmpty ? protection.status.title
                     : declined ? L10n.text("Текущий IP отклонён") : L10n.text("Разрешить текущий IP?"))
                    .fontWeight(.semibold)
                if let target = protection.pendingDirectTarget {
                    Text(protection.policyTargets.first { $0.id == target }
                        .map { L10n.text("Прямое подключение · \($0.title)") } ?? L10n.text("Прямое подключение · без VPN"))
                        .foregroundStyle(.secondary)
                }
                if !pending.isEmpty && protection.status == .paused(.unsafeDNS) {
                    Text(L10n.text("Приложения останутся на паузе, пока маршрут DNS не подтвердится."))
                        .foregroundStyle(.secondary)
                }
                ForEach(showsPrimaryAddress ? addresses : Array(addresses.dropFirst()), id: \.self) { address in
                    Text(address)
                        .fontWeight(.medium)
                        .monospacedDigit()
                        .textSelection(.enabled)
                }
                if !pending.isEmpty {
                    HStack(spacing: 7) {
                        Button {
                            model.approveVPNAddress(pending)
                        } label: {
                            Label(pending.count == 1 ? L10n.text("Разрешить IP") : L10n.text("Разрешить эти IP"),
                                  systemImage: "checkmark")
                        }
                        .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
                        if !declined {
                            Button(L10n.text("Не разрешать")) { protection.declineCurrentAddresses(pending) }
                                .buttonStyle(PanelButtonStyle(fullWidth: true))
                        }
                    }
                }
            }
        }
        .font(.system(size: 12))
        .padding(.horizontal, embedded ? 0 : 10)
        .padding(.vertical, embedded ? 0 : 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.white.opacity(embedded ? 0 : 0.055), in: .rect(cornerRadius: 12))
    }
}

struct ProtectionJournalView: View {
    let journal: ProtectionJournal

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if journal.writeFailed {
                Label(L10n.text("Не удалось сохранить события на диск"), systemImage: "exclamationmark.circle")
                    .foregroundStyle(.orange)
            }
            if journal.events.isEmpty {
                Text(L10n.text("Здесь появятся события защиты."))
                    .foregroundStyle(.secondary)
            }
            if !journal.events.isEmpty {
                LazyVStack(spacing: 0) {
                    ForEach(journal.events) { event in
                        if event.id != journal.events.first?.id { PanelGroupDivider(inset: 43) }
                        eventRow(event)
                    }
                }
                .panelGroup()
            }
        }
        .font(.system(size: 12))
    }

    private func eventRow(_ event: ProtectionEvent) -> some View {
        HStack(alignment: .top, spacing: 9) {
            PanelIconTile(symbol: event.kind.icon)
            VStack(alignment: .leading, spacing: 3) {
                Text(event.kind.title).fontWeight(.medium)
                if !event.detail.isEmpty {
                    Text(event.localizedDetail).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Spacer(minLength: 6)
            Text(event.date.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(L10n.locale)))
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
    }
}
