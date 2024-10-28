import Vapor
import VaporOAuth

public struct PARRequest: Content, Sendable {
    public let responseType: String
    public let clientID: String
    public let redirectURI: String
    public let scope: [String]
    public let state: String?
    public let codeChallenge: String?
    public let codeChallengeMethod: String?
    public let createdAt: Date

    public init(
        responseType: String,
        clientID: String,
        redirectURI: String,
        scope: [String],
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil,
        createdAt: Date = Date()
    ) {
        self.responseType = responseType
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scope = scope
        self.state = state
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.createdAt = createdAt
    }
}
    
