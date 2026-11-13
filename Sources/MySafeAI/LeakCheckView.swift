import NetworkDiagnostics
import SwiftUI

extension LeakFinding.Level {
    var color: Color {
        switch self {
        case .good: PanelButtonStyle.accent
        case .warning: Color(red: 1, green: 0.79, blue: 0.52)
        case .unknown, .info: .secondary
        }
    }

    var symbol: String {
        switch self {
        case .good: "checkmark.circle.fill"
        case .warning: "exclamationmark.circle.fill"
        case .unknown: "questionmark.circle"
        case .info: "info.circle"
        }
    }
}

struct LeakCheckView: View {
    let model: MonitorModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if model.checkingLeaks {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(L10n.text("Проверяем прямой выход, прокси, IPv6 и DNS…"))
                        .font(.system(size: 12))
                }
                .padding(12)
                .panelGroup()
            } else if let report = model.leakReport {
                VStack(alignment: .leading, spacing: 4) {
                    Text(report.summary)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(report.hasWarnings ? Color.orange : Color.primary)
                    Text(L10n.text("Проверено в \(report.date.formatted(Date.FormatStyle(date: .omitted, time: .standard).locale(L10n.locale)))"))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }

                VStack(spacing: 0) {
                    ForEach(report.findings) { finding in
                        if finding.id != report.findings.first?.id { PanelGroupDivider(inset: 36) }
                        findingRow(finding)
                    }
                }
                .panelGroup()

                if case .observed(let resolvers) = report.dns {
                    resolverList(resolvers)
                }

                DisclosureGroup(L10n.text("Ответы HTTPS-источников")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(L10n.text("Прямой IPv4 · CLI")).fontWeight(.medium)
                        AddressResults(results: report.direct)
                        Text(L10n.text("Системный IPv4")).fontWeight(.medium)
                        AddressResults(results: report.system)
                        Text(L10n.text("Прямой IPv6")).fontWeight(.medium)
                        AddressResults(results: report.ipv6)
                    }
                    .padding(.top, 8)
                }
                .font(.system(size: 12))
            } else {
                Label(model.leakMessage ?? L10n.text("Сравните выход CLI и системного прокси, проверьте IPv6 и DNS."),
                      systemImage: "network.badge.shield.half.filled")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }

            Text(model.observesDNSExternally
                 ? L10n.text("IP проверяют выбранные HTTPS-источники. При внешнем DNS-тесте bash.ws видит IP устройства и резолверов.")
                 : L10n.text("Маршруты к DNS-серверам проверяются локально. Для проверки внешнего IP используются выбранные HTTPS-источники."))
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func findingRow(_ finding: LeakFinding) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: finding.level.symbol)
                .foregroundStyle(finding.level.color)
                .frame(width: 17)
                .padding(.top, 2)
                .accessibilityHidden(true)
            DisclosureGroup {
                Text(finding.detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .padding(.top, 4)
            } label: {
                VStack(alignment: .leading, spacing: 3) {
                    Text(finding.title)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                    Text(finding.value)
                        .font(.system(size: 13, weight: .medium))
                        .lineLimit(2)
                        .textSelection(.enabled)
                        .help(finding.value)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .fixedSize(horizontal: false, vertical: true)
        .padding(10)
    }

    private func resolverList(_ resolvers: [ObservedDNSResolver]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(L10n.text("Кто обработал DNS-запросы"))
                .font(.system(size: 12, weight: .semibold))
            VStack(spacing: 0) {
                ForEach(resolvers) { resolver in
                    if resolver.id != resolvers.first?.id { PanelGroupDivider() }
                    VStack(alignment: .leading, spacing: 3) {
                        Text(resolver.label).fontWeight(.medium)
                        Text(resolver.ip).monospacedDigit().textSelection(.enabled)
                        if let country = resolver.country, !country.isEmpty {
                            Text(String(country.prefix(60))).foregroundStyle(.secondary)
                        }
                    }
                    .font(.system(size: 12))
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .panelGroup()
        }
    }
}
