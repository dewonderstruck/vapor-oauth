import Vapor 
import VaporOAuth 

public struct PARRequestValidator: Sendable { 
    public init() {} 
    
    public func validateRequest(_ req: Request) async throws -> PARRequest { 
        // Validate required parameters 
        guard let responseType = req.content[String.self, at: OAuthRequestParameters.responseType], let clientID = req.content[String.self, at: OAuthRequestParameters.clientID], let redirectURI = req.content[String.self, at: OAuthRequestParameters.redirectURI] else { 
            throw PARError.invalidRequest(reason: "Missing required parameters") 
            } // Validate response type 
            guard responseType == "code" || responseType == "token" else {
            throw PARError.invalidRequest(reason: "Invalid response_type") 
        } 
        // Parse scopes 
        let scopeString = req.content[String.self, at: OAuthRequestParameters.scope] ?? ""
        let scopes = scopeString.split(separator: " ").map(String.init) 
        // Create PAR request 
        return PARRequest(
            responseType: responseType, 
            clientID: clientID, 
            redirectURI: redirectURI, 
            scope: scopes, 
            state: req.content[String.self, at: OAuthRequestParameters.state], 
            codeChallenge: req.content[String.self, at: OAuthRequestParameters.codeChallenge], 
            codeChallengeMethod: req.content[String.self, at: OAuthRequestParameters.codeChallengeMethod] 
        ) 
    }
}
