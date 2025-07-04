import Foundation
import VaporOAuth

class FakeCodeManager: CodeManager, @unchecked Sendable {

    private(set) var usedCodes: [String] = []
    var codes: [String: OAuthCode] = [:]
    var generatedCode = UUID().uuidString

    func getCode(_ code: String) -> OAuthCode? {
        // Don't return codes that have been used
        guard !usedCodes.contains(code) else {
            return nil
        }
        return codes[code]
    }

    func generateCode(
        userID: String, clientID: String, redirectURI: String, scopes: [String]?, codeChallenge: String?, codeChallengeMethod: String?
    ) throws -> String {
        let code = OAuthCode(
            codeID: generatedCode,
            clientID: clientID,
            redirectURI: redirectURI,
            userID: userID,
            expiryDate: Date().addingTimeInterval(60),
            scopes: scopes,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod
        )
        codes[generatedCode] = code
        return generatedCode
    }

    func codeUsed(_ code: OAuthCode) {
        usedCodes.append(code.codeID)
        codes.removeValue(forKey: code.codeID)
    }
}
