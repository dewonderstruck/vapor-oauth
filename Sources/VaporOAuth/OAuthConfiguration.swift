import Vapor

public struct OAuthConfiguration: Sendable {
    public let deviceVerificationURI: String
    
    public init(deviceVerificationURI: String) {
        self.deviceVerificationURI = deviceVerificationURI
    }
}

extension Application {
    private struct OAuthConfigurationKey: StorageKey {
        typealias Value = OAuthConfiguration
    }
    
    public var oauth: OAuthConfiguration {
        get {
            guard let config = storage[OAuthConfigurationKey.self] else {
                fatalError("OAuth configuration not set. Use app.oauth = OAuthConfiguration(...)")
            }
            return config
        }
        set {
            storage[OAuthConfigurationKey.self] = newValue
        }
    }
}