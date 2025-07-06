import Vapor

/// In-memory token storage implementation
public final class InMemoryTokenStorage: TokenStorage, @unchecked Sendable {

    private let storage = TokenStorageActor()

    public init() {}

    public func storeAccessToken(_ token: any AccessToken, for clientID: String) async throws {
        await storage.storeAccessToken(token, for: clientID)
    }

    public func storeRefreshToken(_ token: any RefreshToken, for clientID: String) async throws {
        await storage.storeRefreshToken(token, for: clientID)
    }

    public func getAccessToken(_ token: String) async throws -> (any AccessToken)? {
        await storage.getAccessToken(token)
    }

    public func getRefreshToken(_ token: String) async throws -> (any RefreshToken)? {
        await storage.getRefreshToken(token)
    }

    public func updateRefreshToken(_ token: any RefreshToken, scopes: [String]) async throws {
        await storage.updateRefreshToken(token, scopes: scopes)
    }

    public func revokeAccessToken(_ token: String) async throws {
        await storage.revokeAccessToken(token)
    }

    public func revokeRefreshToken(_ token: String) async throws {
        await storage.revokeRefreshToken(token)
    }

    // MARK: - Additional Methods for Testing

    /// Clear all stored tokens (useful for testing)
    public func clearAllTokens() async {
        await storage.clearAllTokens()
    }

    /// Get the count of stored access tokens
    public var accessTokenCount: Int {
        get async {
            await storage.accessTokenCount
        }
    }

    /// Get the count of stored refresh tokens
    public var refreshTokenCount: Int {
        get async {
            await storage.refreshTokenCount
        }
    }

    /// Internal accessor for all refresh tokens (for testing only)
    var allRefreshTokens: [String: any RefreshToken] {
        get async {
            await storage.allRefreshTokens
        }
    }
}

// MARK: - Private Actor for Thread-Safe Storage

private actor TokenStorageActor {
    private var accessTokens: [String: any AccessToken] = [:]
    private var refreshTokens: [String: any RefreshToken] = [:]

    func storeAccessToken(_ token: any AccessToken, for clientID: String) {
        accessTokens[token.tokenString] = token
    }

    func storeRefreshToken(_ token: any RefreshToken, for clientID: String) {
        refreshTokens[token.tokenString] = token
    }

    func getAccessToken(_ token: String) -> (any AccessToken)? {
        return accessTokens[token]
    }

    func getRefreshToken(_ token: String) -> (any RefreshToken)? {
        return refreshTokens[token]
    }

    func updateRefreshToken(_ token: any RefreshToken, scopes: [String]) {
        var updatedToken = token
        updatedToken.scopes = scopes
        refreshTokens[token.tokenString] = updatedToken
    }

    func revokeAccessToken(_ token: String) {
        accessTokens.removeValue(forKey: token)
    }

    func revokeRefreshToken(_ token: String) {
        refreshTokens.removeValue(forKey: token)
    }

    func clearAllTokens() {
        accessTokens.removeAll()
        refreshTokens.removeAll()
    }

    var accessTokenCount: Int {
        return accessTokens.count
    }

    var refreshTokenCount: Int {
        return refreshTokens.count
    }

    var allRefreshTokens: [String: any RefreshToken] {
        return refreshTokens
    }
}
