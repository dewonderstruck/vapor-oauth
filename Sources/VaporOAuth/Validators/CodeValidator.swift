import Foundation
import Crypto

struct CodeValidator {
    func validateCode(_ code: OAuthCode, clientID: String, redirectURI: String, codeVerifier: String?) -> Bool {
        guard code.clientID == clientID else {
            return false
        }

        guard code.expiryDate >= Date() else {
            return false
        }

        guard code.redirectURI == redirectURI else {
            return false
        }

        if let codeChallenge = code.codeChallenge, let codeChallengeMethod = code.codeChallengeMethod, let verifier = codeVerifier {
            return PKCEValidator().validate(codeVerifier: verifier, codeChallenge: codeChallenge, codeChallengeMethod: codeChallengeMethod)
        }

        return true
    }
}
