import Foundation
import Crypto

struct CodeValidator {
    /// Validates the basic OAuth code requirements (mandatory)
    func validateBasicRequirements(_ code: OAuthCode, clientID: String, redirectURI: String) -> Bool {
        return code.clientID == clientID &&
               code.redirectURI == redirectURI &&
               code.expiryDate >= Date()
    }
    
    /// Validates PKCE if used (optional enhancement)
    func validatePKCE(_ code: OAuthCode, codeVerifier: String?) -> Bool {
        // If code challenge was used in authorization request
        if let codeChallenge = code.codeChallenge,
           let codeChallengeMethod = code.codeChallengeMethod {
            // Code verifier is required when code challenge was used
            guard let verifier = codeVerifier else {
                return false
            }
            
            return PKCEValidator().validate(
                codeVerifier: verifier,
                codeChallenge: codeChallenge,
                codeChallengeMethod: codeChallengeMethod
            )
        }
        
        // PKCE wasn't used in authorization request, so no verification needed
        return true
    }
}
