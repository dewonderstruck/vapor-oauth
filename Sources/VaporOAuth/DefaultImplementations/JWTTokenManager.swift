import JWTKit
import Vapor

/// JWT Token Manager implementation that generates and validates JWT tokens
public struct JWTTokenManager: TokenManager {

    private let configuration: JWTConfiguration
    private let storage: TokenStorage

    /// Initialize JWT Token Manager
    /// - Parameters:
    ///   - configuration: JWT configuration settings
    ///   - storage: Token storage implementation
    public init(configuration: JWTConfiguration, storage: TokenStorage) {
        self.configuration = configuration
        self.storage = storage
    }

    // MARK: - TokenManager Protocol Implementation

    public func generateAccessRefreshTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int
    ) async throws -> (any AccessToken, any RefreshToken) {
        let expiryTime = Date().addingTimeInterval(TimeInterval(accessTokenExpiryTime))

        // Generate JWT Access Token
        let accessToken = JWTAccessToken(
            issuer: configuration.issuer,
            subject: userID ?? "",
            audience: clientID,
            expirationTime: expiryTime,
            scope: scopes?.joined(separator: " "),
            clientID: clientID
        )

        // Generate JWT Refresh Token
        let refreshTokenExpiryTime: Date?
        if let refreshExpiry = configuration.defaultRefreshTokenExpiration {
            refreshTokenExpiryTime = Date().addingTimeInterval(TimeInterval(refreshExpiry))
        } else {
            refreshTokenExpiryTime = nil
        }

        let refreshToken = JWTRefreshToken(
            issuer: configuration.issuer,
            subject: userID ?? "",
            audience: clientID,
            expirationTime: refreshTokenExpiryTime,
            scope: scopes?.joined(separator: " "),
            clientID: clientID
        )

        // Sign the tokens
        let signedAccessToken = try await signAccessToken(accessToken)
        let signedRefreshToken = try await signRefreshToken(refreshToken)

        // Store tokens for revocation support
        try await storage.storeAccessToken(signedAccessToken, for: clientID)
        try await storage.storeRefreshToken(signedRefreshToken, for: clientID)

        return (signedAccessToken, signedRefreshToken)
    }

    public func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) async throws -> any AccessToken {
        let expirationTime = Date().addingTimeInterval(TimeInterval(expiryTime))

        let accessToken = JWTAccessToken(
            issuer: configuration.issuer,
            subject: userID ?? "",
            audience: clientID,
            expirationTime: expirationTime,
            scope: scopes?.joined(separator: " "),
            clientID: clientID
        )

        let signedToken = try await signAccessToken(accessToken)
        try await storage.storeAccessToken(signedToken, for: clientID)

        return signedToken
    }

    public func getRefreshToken(_ refreshToken: String) async throws -> (any RefreshToken)? {
        // First try to get from storage (for revocation support)
        if let storedToken = try await storage.getRefreshToken(refreshToken) {
            return storedToken
        }

        // If not in storage, try to verify the JWT
        return try await verifyAndDecodeRefreshToken(refreshToken)
    }

    public func getAccessToken(_ accessToken: String) async throws -> (any AccessToken)? {
        // First try to get from storage (for revocation support)
        if let storedToken = try await storage.getAccessToken(accessToken) {
            return storedToken
        }

        // If not in storage, try to verify the JWT
        return try await verifyAndDecodeAccessToken(accessToken)
    }

    public func updateRefreshToken(_ refreshToken: any RefreshToken, scopes: [String]) async throws {
        // For JWT tokens, we need to create a new token with updated scopes
        if let signedJWTRefreshToken = refreshToken as? SignedJWTRefreshToken {
            let updatedToken = JWTRefreshToken(
                issuer: configuration.issuer,
                subject: signedJWTRefreshToken.userID ?? "",
                audience: signedJWTRefreshToken.clientID,
                scope: scopes.joined(separator: " "),
                clientID: signedJWTRefreshToken.clientID
            )

            let signedToken = try await signRefreshToken(updatedToken)
            // Remove the old token and store the new one
            try await storage.revokeRefreshToken(signedJWTRefreshToken.tokenString)
            try await storage.storeRefreshToken(signedToken, for: signedJWTRefreshToken.clientID)
        } else {
            // For non-JWT tokens, delegate to storage
            try await storage.updateRefreshToken(refreshToken, scopes: scopes)
        }
    }

    public func revokeAccessToken(_ token: String) async throws {
        try await storage.revokeAccessToken(token)
    }

    public func revokeRefreshToken(_ token: String) async throws {
        try await storage.revokeRefreshToken(token)
    }

    // MARK: - Private Methods

    private func signAccessToken(_ payload: JWTAccessToken) async throws -> SignedJWTAccessToken {
        let token = try await configuration.keyCollection.sign(payload)
        return SignedJWTAccessToken(token: token, payload: payload)
    }

    private func signRefreshToken(_ payload: JWTRefreshToken) async throws -> SignedJWTRefreshToken {
        let token = try await configuration.keyCollection.sign(payload)
        return SignedJWTRefreshToken(token: token, payload: payload)
    }

    private func verifyAndDecodeAccessToken(_ tokenString: String) async throws -> (any AccessToken)? {
        do {
            let payload = try await configuration.keyCollection.verify(tokenString, as: JWTAccessToken.self)
            return SignedJWTAccessToken(token: tokenString, payload: payload)
        } catch {
            // Return nil for malformed or invalid tokens
            return nil
        }
    }

    private func verifyAndDecodeRefreshToken(_ tokenString: String) async throws -> (any RefreshToken)? {
        do {
            let payload = try await configuration.keyCollection.verify(tokenString, as: JWTRefreshToken.self)
            return SignedJWTRefreshToken(token: tokenString, payload: payload)
        } catch {
            // Return nil for malformed or invalid tokens
            return nil
        }
    }
}
