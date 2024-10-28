import Foundation
import Vapor
import Crypto

struct PKCEValidator {

    // Validates the code_verifier against the code_challenge and the method (plain or S256)
    func validate(codeVerifier: String, codeChallenge: String?, codeChallengeMethod: String?) -> Bool {
        guard let challengeMethod = codeChallengeMethod else {
            return false
        }

        switch challengeMethod {
        case "S256":
            return validateS256(codeVerifier: codeVerifier, codeChallenge: codeChallenge)
        case "plain":
            return validatePlain(codeVerifier: codeVerifier, codeChallenge: codeChallenge)
        default:
            return false
        }
    }

    // Validates using the plain method: code_verifier === code_challenge
    private func validatePlain(codeVerifier: String, codeChallenge: String?) -> Bool {
        return codeVerifier == codeChallenge
    }

    // Validates using the S256 method: code_challenge === BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    private func validateS256(codeVerifier: String, codeChallenge: String?) -> Bool {
        guard let challenge = codeChallenge else {
            return false
        }

        let hashedVerifier = sha256(codeVerifier).base64URLEncodedString()
        return hashedVerifier == challenge
    }

    // SHA256 hash function for the code_verifier
    private func sha256(_ input: String) -> Data {
        let data = Data(input.utf8)
        return Data(SHA256.hash(data: data))
    }
}

extension Data {
    // Extension to provide a BASE64 URL encoding as required by PKCE
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
