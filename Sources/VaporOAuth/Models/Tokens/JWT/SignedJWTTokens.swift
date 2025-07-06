import JWTKit
import Vapor

// MARK: - Signed Token Wrappers

/// Wrapper for signed JWT access tokens
public struct SignedJWTAccessToken: AccessToken {
    public let token: String
    public let payload: JWTAccessToken

    public var tokenString: String { token }
    public var clientID: String { payload.clientID }
    public var userID: String? { payload.userID }
    public var scopes: [String]? { payload.scopes }
    public var expiryTime: Date { payload.expiryTime }
}

/// Wrapper for signed JWT refresh tokens
public struct SignedJWTRefreshToken: RefreshToken {
    public let token: String
    public let payload: JWTRefreshToken

    public var tokenString: String {
        get { token }
        set {  // JWT tokens are immutable
        }
    }
    public var clientID: String {
        get { payload.clientID }
        set {  // JWT tokens are immutable
        }
    }
    public var userID: String? {
        get { payload.userID }
        set {  // JWT tokens are immutable
        }
    }
    public var scopes: [String]? {
        get { payload.scopes }
        set {  // JWT tokens are immutable
        }
    }
}
