public protocol TokenStorage: Sendable {
    func storeAccessToken(_ token: any AccessToken, for clientID: String) async throws
    func storeRefreshToken(_ token: any RefreshToken, for clientID: String) async throws
    func getAccessToken(_ token: String) async throws -> (any AccessToken)?
    func getRefreshToken(_ token: String) async throws -> (any RefreshToken)?
    func updateRefreshToken(_ token: any RefreshToken, scopes: [String]) async throws
    func revokeAccessToken(_ token: String) async throws
    func revokeRefreshToken(_ token: String) async throws
}
