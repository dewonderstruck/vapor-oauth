import Vapor

public protocol TokenManager: Sendable {
    func generateAccessRefreshTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int
    ) async throws -> (any AccessToken, any RefreshToken)

    func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) async throws -> any AccessToken

    func getRefreshToken(_ refreshToken: String) async throws -> (any RefreshToken)?
    func getAccessToken(_ accessToken: String) async throws -> (any AccessToken)?
    func updateRefreshToken(_ refreshToken: any RefreshToken, scopes: [String]) async throws

    func revokeAccessToken(_ token: String) async throws
    func revokeRefreshToken(_ token: String) async throws
}
