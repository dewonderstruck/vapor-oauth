import Vapor
import Fluent
import VaporOAuth

// MARK: - Application Extensions

extension Application {
    /// OAuth token manager service
    var oauthTokenManager: FluentTokenManager {
        get {
            guard let manager = storage[OAuthTokenManagerKey.self] else {
                fatalError("OAuth token manager not configured. Use app.oauthTokenManager = ...")
            }
            return manager
        }
        set {
            storage[OAuthTokenManagerKey.self] = newValue
        }
    }
    
    /// OAuth client retriever service
    var oauthClientRetriever: FluentClientRetriever {
        get {
            guard let retriever = storage[OAuthClientRetrieverKey.self] else {
                fatalError("OAuth client retriever not configured. Use app.oauthClientRetriever = ...")
            }
            return retriever
        }
        set {
            storage[OAuthClientRetrieverKey.self] = newValue
        }
    }
    
    /// OAuth code manager service
    var oauthCodeManager: FluentCodeManager {
        get {
            guard let manager = storage[OAuthCodeManagerKey.self] else {
                fatalError("OAuth code manager not configured. Use app.oauthCodeManager = ...")
            }
            return manager
        }
        set {
            storage[OAuthCodeManagerKey.self] = newValue
        }
    }
    
    /// OAuth device code manager service
    var oauthDeviceCodeManager: FluentDeviceCodeManager {
        get {
            guard let manager = storage[OAuthDeviceCodeManagerKey.self] else {
                fatalError("OAuth device code manager not configured. Use app.oauthDeviceCodeManager = ...")
            }
            return manager
        }
        set {
            storage[OAuthDeviceCodeManagerKey.self] = newValue
        }
    }
    
    /// OAuth resource server retriever service
    var oauthResourceServerRetriever: FluentResourceServerRetriever {
        get {
            guard let retriever = storage[OAuthResourceServerRetrieverKey.self] else {
                fatalError("OAuth resource server retriever not configured. Use app.oauthResourceServerRetriever = ...")
            }
            return retriever
        }
        set {
            storage[OAuthResourceServerRetrieverKey.self] = newValue
        }
    }
}

// MARK: - Request Extensions

extension Request {
    /// OAuth token manager service for this request
    var oauthTokenManager: FluentTokenManager {
        application.oauthTokenManager
    }
    
    /// OAuth client retriever service for this request
    var oauthClientRetriever: FluentClientRetriever {
        application.oauthClientRetriever
    }
    
    /// OAuth code manager service for this request
    var oauthCodeManager: FluentCodeManager {
        application.oauthCodeManager
    }
    
    /// OAuth device code manager service for this request
    var oauthDeviceCodeManager: FluentDeviceCodeManager {
        application.oauthDeviceCodeManager
    }
    
    /// OAuth resource server retriever service for this request
    var oauthResourceServerRetriever: FluentResourceServerRetriever {
        application.oauthResourceServerRetriever
    }
}

// MARK: - Storage Keys

private struct OAuthTokenManagerKey: StorageKey {
    typealias Value = FluentTokenManager
}

private struct OAuthClientRetrieverKey: StorageKey {
    typealias Value = FluentClientRetriever
}

private struct OAuthCodeManagerKey: StorageKey {
    typealias Value = FluentCodeManager
}

private struct OAuthDeviceCodeManagerKey: StorageKey {
    typealias Value = FluentDeviceCodeManager
}

private struct OAuthResourceServerRetrieverKey: StorageKey {
    typealias Value = FluentResourceServerRetriever
} 