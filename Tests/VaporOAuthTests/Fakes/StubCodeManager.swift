import VaporOAuth

class StubCodeManager: CodeManager, @unchecked Sendable {

    func generateCode(
        userID: String, clientID: String, redirectURI: String, scopes: [String]?, codeChallenge: String?, codeChallengeMethod: String?
    ) async throws -> String {
        return codeToReturn
    }

    var codeToReturn = "ABCDEFHIJKLMNO"

    func getCode(_ code: String) -> OAuthCode? {
        return nil
    }

    func codeUsed(_ code: OAuthCode) {

    }
}
