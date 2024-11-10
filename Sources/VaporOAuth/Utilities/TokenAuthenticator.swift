public struct TokenAuthenticator: Sendable {

    public init() {}

    func validateRefreshToken(_ refreshToken: any RefreshToken, clientID: String) -> Bool {
        guard refreshToken.clientID  == clientID else {
            return false
        }

        return true
    }

    func validateAccessToken(_ accessToken: any AccessToken, requiredScopes: [String]?) -> Bool {
        guard let scopes = requiredScopes else {
            return true
        }

        guard let accessTokenScopes = accessToken.scopes else {
            return false
        }

        for scope in scopes {
            if !accessTokenScopes.contains(scope) {
                return false
            }
        }

        return true
    }
}
