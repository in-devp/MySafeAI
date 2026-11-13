import Foundation

/// One language preference shared by the menu, SwiftUI views, diagnostics and CLI.
public enum L10n {
    public static let preferenceKey = "appLanguage"

    public static var language: String {
        resolvedLanguage(preference: UserDefaults.standard.string(forKey: preferenceKey),
                         preferredLanguages: Locale.preferredLanguages)
    }

    public static var locale: Locale { Locale(identifier: language) }

    public static func resolvedLanguage(preference: String?, preferredLanguages: [String]) -> String {
        if let preference, ["ru", "en"].contains(preference) { return preference }
        return preferredLanguages.first?.lowercased().hasPrefix("ru") == true ? "ru" : "en"
    }

    public static func text(_ value: Value, language: String? = nil) -> String {
        let selectedLanguage = language ?? self.language
        let bundle = localizedBundles[selectedLanguage] ?? localizedBundles["en"]!
        let template = bundle.localizedString(forKey: value.key, value: value.key, table: "Localizable")
        return interpolate(template, arguments: value.arguments)
    }

    /// Values are substituted once: braces, percent signs and user-supplied paths
    /// inside an argument are never interpreted as another formatting instruction.
    static func interpolate(_ template: String, arguments: [String]) -> String {
        guard !arguments.isEmpty else { return template }
        let source = template as NSString
        var output = ""
        var position = 0
        for match in placeholderExpression.matches(in: template, range: NSRange(location: 0, length: source.length)) {
            output += source.substring(with: NSRange(location: position, length: match.range.location - position))
            let index = Int(source.substring(with: match.range(at: 1)))!
            output += arguments.indices.contains(index) ? arguments[index] : source.substring(with: match.range)
            position = match.range.location + match.range.length
        }
        output += source.substring(from: position)
        return output
    }

    private static let placeholderExpression = try! NSRegularExpression(pattern: #"\{([0-9]+)\}"#)

    private static let resourceBundle: Bundle = {
        // SwiftPM's generated accessor cannot find a resource bundle relocated
        // inside a distributed .app; keep that supported layout explicit.
        if let url = Bundle.main.resourceURL?.appendingPathComponent("MySafeAI_NetworkDiagnostics.bundle"),
           let bundle = Bundle(url: url) { return bundle }
        return Bundle.module
    }()

    private static let localizedBundles: [String: Bundle] = {
        Dictionary(uniqueKeysWithValues: ["ru", "en"].map { language in
            let path = resourceBundle.path(forResource: language, ofType: "lproj")!
            return (language, Bundle(path: path)!)
        })
    }()

    static func catalog(language: String) -> [String: String] {
        guard let url = localizedBundles[language]?.url(forResource: "Localizable", withExtension: "strings"),
              let data = try? Data(contentsOf: url),
              let value = try? PropertyListSerialization.propertyList(from: data, format: nil)
        else { return [:] }
        return value as? [String: String] ?? [:]
    }

    public struct Value: ExpressibleByStringLiteral, ExpressibleByStringInterpolation, Sendable {
        let key: String
        let arguments: [String]

        public init(stringLiteral value: String) { key = value; arguments = [] }
        public init(stringInterpolation: StringInterpolation) {
            key = stringInterpolation.key
            arguments = stringInterpolation.arguments
        }

        public struct StringInterpolation: StringInterpolationProtocol {
            var key = ""
            var arguments: [String] = []
            public init(literalCapacity: Int, interpolationCount: Int) {
                key.reserveCapacity(literalCapacity)
                arguments.reserveCapacity(interpolationCount)
            }
            public mutating func appendLiteral(_ literal: String) { key += literal }
            public mutating func appendInterpolation<T>(_ value: T) {
                key += "{\(arguments.count)}"
                arguments.append(String(describing: value))
            }
        }
    }
}
