import Vapor

public struct OAuthConfiguration: Sendable {
    public let deviceVerificationURI: String
    /// Optional JWT configuration for JWT access/refresh tokens (RFC 7519/9068)
    public let jwt: JWTConfiguration?
    public init(deviceVerificationURI: String, jwt: JWTConfiguration? = nil) {
        self.deviceVerificationURI = deviceVerificationURI
        self.jwt = jwt
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
