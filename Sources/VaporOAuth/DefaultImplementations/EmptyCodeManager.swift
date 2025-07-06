public struct EmptyCodeManager: CodeManager {
    public init() {}

    public func getCode(_ code: String) async throws -> OAuthCode? {
        return nil
    }

    public func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) async throws -> String {
        return ""
    }

    public func codeUsed(_ code: OAuthCode) async throws {}
}
