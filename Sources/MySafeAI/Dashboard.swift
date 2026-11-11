import SwiftUI
import NetworkDiagnostics

private let surface = Color.white.opacity(0.055)
private let ink = Color.primary
private let muted = Color.secondary
private let mint = PanelButtonStyle.accent
private let amber = Color(red: 1.0, green: 0.79, blue: 0.52)

struct Dashboard: View {
    static let size = CGSize(width: 370, height: 448)

    let model: MonitorModel
    let inWindow: Bool
    let windowAction: @MainActor () -> Void
    let setTrayOnly: @MainActor @Sendable (Bool) -> Void

    private enum Page { case overview, protection, routes, addresses, settings, journal, leaks, policies, serviceRoutes }
    @State private var history: [Page] = []

    private var page: Page { history.last ?? .overview }

    var body: some View {
        VStack(spacing: 0) {
            header.padding(.horizontal, 14)
            Divider().padding(.horizontal, 16)
            if page != .overview && page != .protection && !model.protection.pendingAddresses.isEmpty {
                Button {
                    history = []
                } label: {
                    Label("VPN ждёт подтверждения IP", systemImage: "exclamationmark.shield")
                }
                .buttonStyle(PanelButtonStyle(size: .compact, fullWidth: true))
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }
            ScrollView {
                pageContent
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
            }
            .id(page)
            Divider().padding(.horizontal, 16)
            if page == .protection {
                ProtectionActions(model: model)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
            } else if page == .leaks {
                Button(action: model.checkLeaks) {
                    Label(model.checkingLeaks ? "Проверяем…" : "Проверить утечки",
                          systemImage: "arrow.clockwise")
                }
                .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
                .disabled(model.checkingLeaks)
                .padding(.horizontal, 16)
                .padding(.vertical, 9)
            } else {
                footer.padding(.horizontal, 16)
            }
        }
        .frame(minWidth: Self.size.width, maxWidth: inWindow ? .infinity : Self.size.width,
               minHeight: inWindow ? 410 : Self.size.height, maxHeight: inWindow ? .infinity : Self.size.height)
        .font(.system(size: 13))
        .foregroundStyle(ink)
        .tint(mint)
        .environment(\.colorScheme, .dark)
    }

    @ViewBuilder private var pageContent: some View {
        switch page {
        case .overview:
            overview
        case .protection:
            ProtectionView(model: model, showRules: { history.append(.policies) })
        case .routes:
            VStack(spacing: 10) {
                Button {
                    history.append(.serviceRoutes)
                    model.checkServicePaths()
                } label: {
                    Label("Маршруты ИИ", systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                }
                .buttonStyle(PanelButtonStyle(fullWidth: true))
                RouteDetails(snapshot: model.snapshot, lastCheck: model.lastCheck, refresh: model.refresh)
            }
        case .addresses:
            AddressResults(results: model.addressResults)
        case .settings:
            AddressSettings(model: model, setTrayOnly: setTrayOnly)
        case .journal:
            ProtectionJournalView(journal: model.protection.journal)
        case .leaks:
            LeakCheckView(model: model)
        case .policies:
            PolicySettingsView(model: model)
        case .serviceRoutes:
            ServiceRoutesView(model: model)
        }
    }

    private var header: some View {
        HStack(spacing: 7) {
            if page == .overview {
                Image(nsImage: BrandMark.badge)
                    .frame(width: 28, height: 28)
                    .accessibilityHidden(true)
            } else {
                iconButton("chevron.left", label: "Назад") { _ = history.popLast() }
            }

            Text(pageTitle)
                .font(.system(size: 15, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
            Spacer()
            if page == .overview || page == .protection {
                iconButton("clock.arrow.circlepath", label: "Журнал") { history.append(.journal) }
            }
            if page != .settings {
                iconButton("gearshape", label: "Настройки") { history.append(.settings) }
            }
            iconButton(inWindow ? "menubar.arrow.up.rectangle" : "macwindow",
                       label: inWindow ? "Скрыть окно" : "Открыть в отдельном окне") {
                windowAction()
            }
        }
        .frame(height: 46)
    }

    private var pageTitle: String {
        switch page {
        case .overview: "MySafeAI"
        case .protection: "Защита приложений"
        case .routes: "Маршруты"
        case .addresses: "Проверка IP"
        case .settings: "Настройки"
        case .journal: "Журнал защиты"
        case .leaks: "Проверка утечек"
        case .policies: "Правила IP и маршрутов"
        case .serviceRoutes: "Маршруты ИИ"
        }
    }

    private var overview: some View {
        let results = model.addressResults
        let summary = AddressCheckSummary(results)
        return VStack(alignment: .leading, spacing: 12) {
            NetworkCard(model: model,
                        address: model.protection.currentAddresses.first ?? summary.preferredAddress)

            if model.protection.isEnabled {
                let paused = !model.protection.pausedApplications.isEmpty
                let names = paused ? model.protection.pausedApplications : model.protection.protectedApplications
                VStack(alignment: .leading, spacing: 7) {
                    Text(paused ? "На паузе" : "Под защитой")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(muted)
                        .accessibilityAddTraits(.isHeader)
                    FlowLayout(spacing: 6) {
                        ForEach(names, id: \.self) { title in
                            Label(title, systemImage: paused ? "pause.fill" : "checkmark.shield")
                                .font(.system(size: 12, weight: .medium))
                                .lineLimit(1)
                                .help(title)
                                .padding(.horizontal, 9)
                                .padding(.vertical, 6)
                                .background((paused ? amber : mint).opacity(0.09), in: .capsule)
                        }
                    }
                    if names.isEmpty {
                        Text("Ожидаем запуска выбранных приложений")
                            .font(.system(size: 12))
                            .foregroundStyle(muted)
                    }
                }
                if paused && !model.protection.protectedApplications.isEmpty {
                    Text("Работают: \(model.protection.protectedApplications.joined(separator: ", "))")
                        .font(.system(size: 11)).foregroundStyle(muted)
                }
            }

            if model.protection.status == .off {
                Button {
                    history.append(.protection)
                } label: {
                    Label("Настроить защиту", systemImage: "shield")
                }
                .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
            } else if model.protection.status == .failed {
                Button(action: model.enableProtection) {
                    Label("Восстановить защиту", systemImage: "arrow.clockwise.shield")
                }
                .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
            }

            HStack(spacing: 8) {
                actionButton(
                    model.checkingLeaks ? "Проверяем…" : "Проверить утечки",
                    icon: "network.badge.shield.half.filled"
                ) {
                    history.append(.leaks)
                    model.checkLeaks()
                }
                actionButton("Маршруты", icon: "point.topleft.down.to.point.bottomright.curvepath") {
                    history.append(.routes)
                }
            }

            if let report = model.leakReport {
                Button {
                    history.append(.leaks)
                } label: {
                    HStack {
                        Image(systemName: report.hasWarnings ? "exclamationmark.circle" : "list.bullet.clipboard")
                        Text(report.summary)
                            .foregroundStyle(report.hasWarnings ? amber : ink)
                        Spacer(minLength: 4)
                        Image(systemName: "chevron.right")
                    }
                }
                .buttonStyle(PanelButtonStyle(size: .row, fullWidth: true))
            } else if let message = model.leakMessage {
                Text(message)
                    .font(.system(size: 11))
                    .foregroundStyle(muted)
            }

            if !results.isEmpty && model.leakReport == nil {
                Button {
                    history.append(.addresses)
                } label: {
                    HStack(spacing: 7) {
                        Text(addressResultLabel(summary))
                            .foregroundStyle(summary.hasDisagreement || summary.responseCount == 0 ? amber : ink)
                        Spacer()
                        Text("\(summary.responseCount) из \(results.count)")
                        Image(systemName: "chevron.right")
                            .accessibilityHidden(true)
                    }
                }
                .buttonStyle(PanelButtonStyle(size: .row, fullWidth: true))
                .accessibilityHint("Показывает ответы отдельных источников")
            }

        }
    }

    private func addressResultLabel(_ summary: AddressCheckSummary) -> String {
        if summary.hasDisagreement { return "Источники вернули разные IP" }
        if summary.responseCount == 0 { return "Не удалось определить IP" }
        return "Ответы источников"
    }

    private var footer: some View {
        HStack {
            Button { history.append(.protection) } label: {
                Label("Приложения", systemImage: "square.grid.2x2")
            }
            .buttonStyle(PanelButtonStyle(.quiet, size: .compact))
            .accessibilityHint("Открывает правила защиты приложений")
            if model.protection.status == .failed {
                Image(systemName: "exclamationmark.shield")
                    .foregroundStyle(amber)
                    .help(model.protection.status.title)
            }
            Spacer()
            iconButton("power", label: "Выйти из MySafeAI") {
                NSApplication.shared.terminate(nil)
            }
        }
        .frame(height: 37)
        .foregroundStyle(muted)
    }

    private func iconButton(_ icon: String, label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
        }
        .buttonStyle(PanelButtonStyle(.quiet, size: .icon))
        .accessibilityLabel(label)
        .help(label)
    }

    private func actionButton(_ title: String, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon)
        }
        .buttonStyle(PanelButtonStyle(fullWidth: true))
    }
}

private struct NetworkCard: View {
    let model: MonitorModel
    let address: String?

    private var snapshot: NetworkSnapshot? { model.snapshot }

    private var status: (title: String, icon: String, color: Color) {
        switch model.protection.status {
        case .trusted: ("Защита активна", "checkmark.shield.fill", mint)
        case .off: ("Защита выключена", "shield", muted)
        case .checking, .paused:
            model.protection.pausedCount > 0
                ? ("Приложения на паузе", "pause.circle.fill", amber)
                : ("Ожидаем безопасный маршрут", "shield", amber)
        case .failed: ("Ошибка защиты", "exclamationmark.shield.fill", amber)
        }
    }

    var body: some View {
        let state = status
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(state.title, systemImage: state.icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(state.color)
                Spacer(minLength: 5)
            }

            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(addressLabel)
                        .font(.system(size: 12))
                        .foregroundStyle(muted)

                    Text(address ?? "—")
                        .font(.system(size: address?.contains(":") == true ? 19 : 33, weight: .semibold))
                        .monospacedDigit()
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .textSelection(.enabled)
                    if let address, let code = model.protection.assessment?.countries[address] {
                        Text(Locale(identifier: "ru").localizedString(forRegionCode: code) ?? code)
                            .font(.system(size: 11)).foregroundStyle(muted)
                    }
                }
                Spacer(minLength: 0)
                if let deadline = model.protection.closeDeadline {
                    PauseCountdown(deadline: deadline)
                }
            }

            FlowLayout(spacing: 6) {
                chip(ipv4Summary, icon: "network")
                chip(ipv6Summary, icon: "arrow.triangle.branch", color: ipv6Color)
                chip(dnsSummary, icon: "server.rack", color: snapshot?.dnsRoute == .outsideTunnel ? amber : ink)
            }
            if let network = model.protection.assessment?.trustedNetwork {
                Label("Доверенная сеть: \(network)", systemImage: "house")
                    .font(.system(size: 11)).foregroundStyle(mint)
            }

            if model.protection.isEnabled && model.protection.status != .trusted {
                PanelGroupDivider(inset: 0).padding(.vertical, 3)
                VPNAddressApproval(model: model, showsPrimaryAddress: false, embedded: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 12)
                .fill(.linearGradient(
                    colors: [state.color.opacity(0.10), surface],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                ))
        }
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(state.color.opacity(0.18))
        }
    }

    private var addressLabel: String {
        guard let address else { return "Внешний IP" }
        return address.contains(":") ? "Внешний IPv6" : "Внешний IPv4"
    }

    private var ipv4Summary: String {
        switch snapshot?.ipv4 {
        case .tunnel: "IPv4 · туннель"
        case .other: "IPv4 · вне туннеля"
        case .missing: "IPv4 · нет маршрута"
        case .unavailable, nil: "IPv4 · неизвестно"
        }
    }

    private var ipv6Summary: String {
        switch snapshot?.ipv6 {
        case .tunnel: "IPv6 · туннель"
        case .other: "IPv6 · вне туннеля"
        case .missing: "IPv6 · нет маршрута"
        case .unavailable, nil: "IPv6 · неизвестно"
        }
    }

    private var ipv6Color: Color {
        if case .other = snapshot?.ipv6 { return amber }
        return ink
    }

    private var dnsSummary: String {
        switch snapshot?.dnsRoute {
        case .viaTunnel: "DNS · через туннель"
        case .outsideTunnel: "DNS · вне VPN"
        case .unknown, nil: "DNS · путь неизвестен"
        }
    }

    private func chip(_ title: String, icon: String, color: Color = ink) -> some View {
        Label(title, systemImage: icon)
            .font(.system(size: 11))
            .padding(.horizontal, 7)
            .padding(.vertical, 5)
            .foregroundStyle(color)
            .background(surface, in: .capsule)
    }
}

private struct PauseCountdown: View {
    let deadline: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.25)) { context in
            let remaining = max(0, min(20, deadline.timeIntervalSince(context.date)))
            let seconds = Int(remaining.rounded(.up))
            ZStack {
                Circle().strokeBorder(amber.opacity(0.20), lineWidth: 3)
                Circle()
                    .trim(from: 0, to: remaining / 20)
                    .stroke(amber, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                VStack(spacing: 0) {
                    Text(seconds.formatted()).font(.system(size: 16, weight: .semibold)).monospacedDigit()
                    Text("сек").font(.system(size: 9)).foregroundStyle(muted)
                }
            }
            .frame(width: 45, height: 45)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("До закрытия приложений")
            .accessibilityValue("\(seconds) сек")
        }
    }
}

private struct RouteDetails: View {
    let snapshot: NetworkSnapshot?
    let lastCheck: Date?
    let refresh: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(spacing: 0) {
                row("Маршрут IPv4", value: label(snapshot?.ipv4))
                PanelGroupDivider()
                row("Маршрут IPv6", value: label(snapshot?.ipv6))
                PanelGroupDivider()
                row("Маршрут DNS", value: dnsRouteLabel)
                PanelGroupDivider()
                row("DNS для интерфейсов", value: dnsLabel(scoped: true))
            }
            .panelGroup()

            Text("Системные маршруты по умолчанию. При раздельной маршрутизации путь конкретного приложения может отличаться.")
                .font(.system(size: 12))
                .foregroundStyle(muted)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                if let lastCheck {
                    Text("Обновлено в \(lastCheck.formatted(date: .omitted, time: .standard))")
                        .font(.system(size: 11))
                        .foregroundStyle(muted)
                }
                Spacer()
                Button(action: refresh) { Label("Обновить", systemImage: "arrow.clockwise") }
                    .buttonStyle(PanelButtonStyle(size: .compact))
            }
        }
    }

    private var dnsRouteLabel: String {
        switch snapshot?.dnsRoute {
        case .viaTunnel: "Через туннель"
        case .outsideTunnel: "Вне VPN"
        case .unknown, nil: "Не определён"
        }
    }

    private func dnsLabel(scoped: Bool) -> String {
        guard case .available(let entries) = snapshot?.dns else { return "Неизвестно" }
        let resolvers = entries.filter { $0.isScoped == scoped }
        guard !resolvers.isEmpty else { return "Нет записей" }
        var interfaces = Set(resolvers.compactMap(\.interface)).sorted()
        if resolvers.contains(where: { $0.interface == nil }) {
            interfaces.append("без привязки")
        }
        return interfaces.joined(separator: ", ")
    }

    private func label(_ route: DefaultRoute?) -> String {
        switch route {
        case .tunnel(let name): "Туннель · \(name)"
        case .other(let name): "Вне туннеля · \(name)"
        case .missing: "Нет маршрута"
        case .unavailable, nil: "Неизвестно"
        }
    }

    private func row(_ title: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).foregroundStyle(muted)
            Spacer(minLength: 12)
            Text(value)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }
}

struct AddressResults: View {
    let results: [AddressCheckResult]

    var body: some View {
        if results.isEmpty {
            Text("Запустите проверку IP из обзора.")
                .font(.system(size: 12))
                .foregroundStyle(muted)
        } else {
            VStack(spacing: 0) {
                ForEach(results) { result in
                    if result.id != results.first?.id {
                        PanelGroupDivider()
                    }
                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 12) {
                            source(result.source).frame(minWidth: 112, alignment: .leading)
                            Spacer(minLength: 0)
                            outcome(for: result.outcome).fixedSize(horizontal: true, vertical: false)
                        }
                        VStack(alignment: .leading, spacing: 5) {
                            source(result.source)
                            outcome(for: result.outcome)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .panelGroup()
        }
    }

    private func source(_ source: AddressSource) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(source.name)
                .fontWeight(.medium)
                .lineLimit(1)
            Text((source.url.host ?? "") + (source.url.path == "/" ? "" : source.url.path))
                .font(.system(size: 12))
                .foregroundStyle(muted)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(source.url.absoluteString)
        }
    }

    @ViewBuilder private func outcome(for result: AddressCheckResult.Outcome) -> some View {
        switch result {
        case .address(let ip):
            Text(ip)
                .fontWeight(.medium)
                .monospacedDigit()
                .textSelection(.enabled)
        case .invalidResponse:
            Text("Некорректный ответ").foregroundStyle(amber)
        case .unavailable:
            Text("Нет ответа").foregroundStyle(amber)
        }
    }
}

private struct AddressSettings: View {
    let model: MonitorModel
    let setTrayOnly: @MainActor @Sendable (Bool) -> Void
    @State private var draft = ""
    @AppStorage("trayOnly") private var trayOnly = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            section("Поведение защиты") {
                switchRow("Включать при запуске", icon: "power",
                          value: model.protection.enablesOnLaunch, change: model.protection.setEnablesOnLaunch)
                PanelGroupDivider(inset: 44)
                switchRow("Закрывать после 20 секунд", icon: "timer",
                          value: model.protection.closesAfterTimeout, change: model.protection.setClosesAfterTimeout)
                PanelGroupDivider(inset: 44)
                switchRow("Ставить на паузу при DNS вне VPN", icon: "network",
                          value: model.protection.blocksOutsideDNS, change: model.setBlocksOutsideDNS)
            } hint: {
                Text("После потери доверенного подключения MySafeAI сначала запросит выход, а через 5 секунд завершит оставшиеся процессы.")
            }

            section("Работа в фоне") {
                switchRow("Только в трее", icon: "menubar.rectangle", value: trayOnly, change: setTrayOnly)
                PanelGroupDivider(inset: 44)
                switchRow("Запускать при входе в macOS", icon: "person.crop.circle",
                          value: model.background.loginStatus == .enabled, change: model.background.setLaunchAtLogin)
                if model.background.loginStatus == .requiresApproval {
                    Button("Открыть объекты входа", action: model.background.openLoginSettings)
                        .buttonStyle(PanelButtonStyle(size: .compact))
                }
                PanelGroupDivider(inset: 44)
                switchRow("Системные уведомления", icon: "bell",
                          value: model.background.notifications, change: model.background.setNotifications)
            } hint: {
                if let message = model.background.message { Text(message) }
            }

            section("Источники проверки IP") {
                let providers = BuiltInAddressSource.allCases
                ForEach(providers, id: \.self) { provider in
                    if provider != providers.first { PanelGroupDivider(inset: 44) }
                    switchRow(provider.source.name, icon: provider.source.isIPv6Only ? "6.circle" : "4.circle",
                              value: model.addressSettings.enabledBuiltIns.contains(provider)) {
                        model.enableAddressSource(provider, enabled: $0)
                    }
                    .help(provider.source.url.absoluteString)
                }
            } hint: {
                Text("Защита сверяет IP у двух источников. Включённые сервисы видят IP входящего запроса.")
            }

            section("Активная проверка DNS") {
                switchRow("Проверять резолверы извне", icon: "server.rack",
                          value: model.observesDNSExternally, change: model.setObservesDNSExternally)
            } hint: {
                Text("По кнопке «Проверить утечки» dnsleak.dev увидит IP устройства и DNS-серверов. Тест использует случайные имена и системный резолвер macOS.")
            }

            section("Свои HTTPS-источники") {
                customSources
            } hint: {
                if !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                    !model.addressSettings.canAdd(draft) {
                    Text("Введите новый HTTPS-адрес без учётных данных и параметров.").foregroundStyle(amber)
                } else {
                    Text("Источник должен возвращать один IP обычным текстом.")
                }
            }
        }
        .onAppear { model.background.refresh() }
    }

    private func section<Content: View, Hint: View>(
        _ title: String, @ViewBuilder content: () -> Content, @ViewBuilder hint: () -> Hint
    ) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.system(size: 12, weight: .semibold))
                .accessibilityAddTraits(.isHeader)
            VStack(spacing: 0, content: content).panelGroup()
            hint()
                .font(.system(size: 11))
                .foregroundStyle(muted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func switchRow(
        _ title: String, icon: String, value: Bool, change: @escaping @MainActor @Sendable (Bool) -> Void
    ) -> some View {
        HStack(spacing: 9) {
            PanelIconTile(symbol: icon)
            Text(title).accessibilityHidden(true)
            Spacer(minLength: 4)
            Toggle(title, isOn: Binding(get: { value }, set: { enabled in
                Task { @MainActor in change(enabled) }
            }))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
        }
        .padding(.horizontal, 9)
        .frame(minHeight: 37)
    }

    private var customSources: some View {
        VStack(spacing: 0) {
            ForEach(model.addressSettings.customURLs, id: \.self) { url in
                HStack(spacing: 9) {
                    PanelIconTile(symbol: "link")
                    Text(url.absoluteString)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(url.absoluteString)
                    Spacer(minLength: 0)
                    Button {
                        model.removeAddressSource(url)
                    } label: {
                        Image(systemName: "minus")
                    }
                    .buttonStyle(PanelButtonStyle(.quiet, size: .icon))
                    .accessibilityLabel("Удалить \(url.absoluteString)")
                }
                .padding(.horizontal, 9)
                .frame(minHeight: 36)
                PanelGroupDivider(inset: 44)
            }

            HStack(spacing: 8) {
                TextField("https://example.com/ip", text: $draft)
                    .textFieldStyle(.plain)
                    .padding(.horizontal, 8)
                    .frame(height: 29)
                    .background(.black.opacity(0.18), in: .rect(cornerRadius: 7))
                    .accessibilityLabel("HTTPS-адрес источника IP")
                    .onSubmit(addSource)
                Button("Добавить", action: addSource)
                    .buttonStyle(PanelButtonStyle(size: .compact))
                    .disabled(!model.addressSettings.canAdd(draft))
            }
            .padding(7)
        }
    }

    private func addSource() {
        if model.addAddressSource(draft) { draft = "" }
    }
}
