import Foundation
import Testing
@testable import NetworkDiagnostics

@Test func proxyConfigurationUsesLanguageIndependentModeIdentifiers() {
    let settings: [String: Any] = ["ProxyAutoDiscoveryEnable": NSNumber(value: true)]
    let configuration = SystemProxyConfiguration.parse(settings: settings)
    #expect(configuration.modes == ["WPAD"])
    #expect(configuration == SystemProxyConfiguration.parse(settings: settings))
    #expect(configuration.isEnabled)
}

@Test func languagePreferenceSupportsAutomaticRussianAndEnglish() {
    #expect(L10n.resolvedLanguage(preference: "en", preferredLanguages: ["ru-RU"]) == "en")
    #expect(L10n.resolvedLanguage(preference: "ru", preferredLanguages: ["en-US"]) == "ru")
    #expect(L10n.resolvedLanguage(preference: "system", preferredLanguages: ["ru-RU"]) == "ru")
    #expect(L10n.resolvedLanguage(preference: nil, preferredLanguages: ["de-DE", "ru-RU"]) == "en")
    #expect(L10n.resolvedLanguage(preference: "invalid", preferredLanguages: []) == "en")
}

@Test func bundledTranslationsCoverBothLanguagesAndKeepPlaceholders() throws {
    let russian = L10n.catalog(language: "ru")
    let english = L10n.catalog(language: "en")
    #expect(russian.count >= 312)
    #expect(Set(russian.keys) == Set(english.keys))
    let expression = try NSRegularExpression(pattern: #"\{[0-9]+\}"#)
    func placeholders(_ value: String) -> [String] {
        let source = value as NSString
        return expression.matches(in: value, range: NSRange(location: 0, length: source.length))
            .map { source.substring(with: $0.range) }.sorted()
    }
    for (key, translation) in english {
        #expect(!translation.isEmpty)
        #expect(placeholders(key) == placeholders(translation), "Placeholder mismatch: \(key)")
        #expect(russian[key] == key)
    }
    #expect(L10n.text("Защита активна", language: "en") == "Protection active")
    #expect(L10n.text("Защита активна", language: "ru") == "Защита активна")
}

@Test func localizedInterpolationDoesNotInterpretUserContent() {
    let network = #"Office {1} 100% $HOME \n"#
    #expect(L10n.text("Сеть «\(network)» сохранена.", language: "en") == "Network “\(network)” saved.")
    #expect(L10n.text("\(2) из \(3)", language: "en") == "2 of 3")
    #expect(L10n.interpolate("{1}, {0}", arguments: ["{1}", "B"]) == "B, {1}")
    #expect(L10n.text("Unknown \(network)", language: "en") == "Unknown \(network)")
}
