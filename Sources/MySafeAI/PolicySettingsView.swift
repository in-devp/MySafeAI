import NetworkDiagnostics
import SwiftUI

struct PolicySettingsView: View {
    let model: MonitorModel
    @State private var selection = ""
    @State private var rule = ApplicationAccessRule()
    @State private var separate = false
    @State private var addresses = ""
    @State private var subnets = ""
    @State private var countries = ""
    @State private var host = ""
    @State private var feedback: String?
    @State private var networkName = ""

    private var target: ProtectionTarget? { model.protection.policyTargets.first { $0.id == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Picker("Правило", selection: $selection) {
                Text("Общее").tag("")
                ForEach(model.protection.policyTargets) { item in
                    Text(item.title).tag(item.id)
                }
            }
            .onChange(of: selection) { load() }

            if let target {
                VStack(alignment: .leading, spacing: 9) {
                    Picker("Подключение", selection: $rule.transport) {
                        Text("Туннель VPN").tag(ProtectionTransport.tunnel)
                        if target.id != ProtectionTarget.managed.id {
                            Text("Туннель до сервисов").tag(ProtectionTransport.serviceTunnel)
                        }
                        if target.supportsSystemProxy {
                            Text("Системный прокси / PAC").tag(ProtectionTransport.systemProxy)
                        }
                    }
                    if rule.transport == .systemProxy {
                        Text("Для приложений, настроенных на системный прокси. MySafeAI проверяет выход к указанным сервисам.")
                            .foregroundStyle(.secondary).font(.system(size: 11))
                        if model.protection.blocksOutsideDNS {
                            Text("Включена проверка DNS. Без подтверждённого туннеля для DNS приложение останется на паузе.")
                                .foregroundStyle(.secondary).font(.system(size: 11))
                        }
                    }
                    if rule.transport != .tunnel && target.hosts.isEmpty {
                        field("Хост сервиса", "example.com", $host)
                    }
                    Toggle("Отдельный список IP, подсетей и стран", isOn: $separate)
                    Toggle("Разрешать в доверенных сетях", isOn: $rule.allowsTrustedNetworks)
                    if let proof = model.protection.assessment?.decisions[target.id], !proof.addresses.isEmpty {
                        Text(proof.addresses.joined(separator: ", "))
                            .monospacedDigit().textSelection(.enabled)
                            .foregroundStyle(.secondary)
                        if separate && proof.issue == .unexpectedAddress {
                            Button("Добавить проверенные IP") {
                                addresses = (tokens(addresses) + proof.addresses).joined(separator: ", ")
                                feedback = nil
                            }
                            .buttonStyle(PanelButtonStyle(size: .compact))
                        }
                    }
                }
                .padding(9).panelGroup()
            }
            if target == nil || separate {
                VStack(alignment: .leading, spacing: 8) {
                    field("Отдельные IP", "203.0.113.8, 2001:db8::8", $addresses)
                    field("Подсети", "203.0.113.0/24, 2001:db8::/48", $subnets)
                    field("Коды стран", "NL, DE", $countries)
                    if !countries.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        Text("Страну определяем по ответу сервиса или через country.is для общего VPN.")
                            .foregroundStyle(.secondary).font(.system(size: 11))
                    }
                }
                .padding(9).panelGroup()
            }
            Button("Сохранить правило", action: save)
                .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
            if let feedback { Text(feedback).font(.system(size: 11)).foregroundStyle(.secondary) }
            trustedNetworks
        }
        .onAppear(perform: load)
    }

    private var trustedNetworks: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Доверенные сети").font(.system(size: 12, weight: .semibold))
            if let current = model.protection.assessment?.trustedNetwork {
                Label("Активна сеть «\(current)»", systemImage: "checkmark.circle")
                    .foregroundStyle(PanelButtonStyle.accent)
            }
            ForEach(model.protection.trustedNetworks) { network in
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(network.name)
                        Text(network.addresses.sorted().joined(separator: ", "))
                            .font(.system(size: 11)).monospacedDigit().foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        model.protection.removeTrustedNetwork(network)
                        model.refresh()
                    } label: { Image(systemName: "trash") }
                        .buttonStyle(PanelButtonStyle(.quiet, size: .icon))
                        .accessibilityLabel("Удалить сеть \(network.name)")
                }
                .padding(8).panelGroup()
            }
            field("Название текущей сети", "Дом или офис", $networkName)
            Button(model.checkingTrustedNetwork ? "Проверяем сеть…" : "Доверять этой сети без VPN") {
                model.rememberTrustedNetwork(networkName)
            }
            .buttonStyle(PanelButtonStyle(fullWidth: true))
            .disabled(model.checkingTrustedNetwork || networkName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || networkName.count > 60)
            if let message = model.trustedNetworkMessage {
                Text(message).font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
    }

    private func field(_ title: String, _ placeholder: String, _ value: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary)
            TextField(placeholder, text: value)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(title)
        }
    }

    private func load() {
        rule = model.protection.applicationRules[selection] ?? .init()
        separate = rule.addressPolicy != nil
        let access = rule.addressPolicy ?? model.protection.globalAddressPolicy
        addresses = access.addresses.sorted().joined(separator: ", ")
        subnets = access.subnets.map(\.notation).sorted().joined(separator: ", ")
        countries = access.countries.sorted().joined(separator: ", ")
        host = rule.customHost ?? ""
        feedback = nil
    }

    private func tokens(_ value: String) -> [String] {
        value.split { $0.isWhitespace || $0 == "," || $0 == ";" }.map(String.init)
    }

    private func save() {
        var access = AddressAccessPolicy()
        if target == nil || separate {
            let ips = tokens(addresses)
            let ranges = tokens(subnets)
            let codes = tokens(countries)
            let validIPs = ips.compactMap(AddressEcho.parse)
            let validRanges = ranges.compactMap(IPSubnet.init)
            let validCodes = codes.compactMap(AddressAccessPolicy.countryCode)
            guard validIPs.count == ips.count, validRanges.count == ranges.count,
                  validCodes.count == codes.count else {
                feedback = "Проверьте формат IP, подсетей CIDR и двухбуквенных кодов стран."
                return
            }
            access = AddressAccessPolicy(addresses: Set(validIPs), subnets: Set(validRanges), countries: Set(validCodes))
        }
        if let target {
            if rule.transport != .tunnel && target.hosts.isEmpty {
                guard let value = ServicePath.validatedHost(host) else {
                    feedback = "Введите имя HTTPS-хоста сервиса."
                    return
                }
                rule.customHost = value
            }
            rule.addressPolicy = separate ? access : nil
            model.protection.setApplicationRule(rule, target: target)
        } else {
            model.protection.setGlobalAddressPolicy(access)
        }
        model.refresh()
        feedback = "Правило сохранено. Проверяем подключение."
    }
}

struct ServiceRoutesView: View {
    let model: MonitorModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button(model.checkingServicePaths ? "Проверяем…" : "Проверить маршруты ИИ") {
                model.checkServicePaths()
            }
            .buttonStyle(PanelButtonStyle(.primary, fullWidth: true))
            .disabled(model.checkingServicePaths)
            Text("Проверяем HTTPS-путь до конкретных сервисов и IP, который сервис сообщил в ответе.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            let paths = model.servicePaths.isEmpty ? model.protection.assessment?.servicePaths ?? [] : model.servicePaths
            ForEach(paths) { path in
                VStack(alignment: .leading, spacing: 4) {
                    Text(path.host).fontWeight(.semibold)
                    Text(label(path)).foregroundStyle(.secondary)
                    if let address = path.observedAddress {
                        let code = model.serviceCountries[address] ?? model.protection.assessment?.countries[address]
                        Text([address, code].compactMap { $0 }.joined(separator: " · "))
                            .monospacedDigit().textSelection(.enabled)
                    } else {
                        Text("Сервис не сообщил внешний IP").foregroundStyle(.secondary)
                    }
                }
                .font(.system(size: 12)).padding(8).panelGroup()
            }
        }
    }

    private func label(_ path: ServicePath) -> String {
        if path.usedProxy == true { return "Проба через прокси" }
        if path.systemProxy && path.usedProxy == false { return "Системная проба обошла прокси" }
        switch path.route {
        case .tunnel(let interface): return "Проба через \(interface)"
        case .other(let interface): return "Прямой выход · \(interface)"
        default: return "Путь не определён"
        }
    }
}
