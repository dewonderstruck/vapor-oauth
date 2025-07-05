import Vapor
import Fluent
import VaporOAuth

final class OAuthCode: Model, @unchecked Sendable {
    static let schema = "oauth_codes"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "code_id")
    var codeID: String
    
    @Field(key: "client_id")
    var clientID: String
    
    @Field(key: "redirect_uri")
    var redirectURI: String
    
    @Field(key: "user_id")
    var userID: String
    
    @Field(key: "scopes")
    var scopes: [String]?
    
    @Field(key: "expiry_date")
    var expiryDate: Date
    
    @Field(key: "code_challenge")
    var codeChallenge: String?
    
    @Field(key: "code_challenge_method")
    var codeChallengeMethod: String?
    
    @Field(key: "used")
    var used: Bool
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        codeID: String,
        clientID: String,
        redirectURI: String,
        userID: String,
        scopes: [String]? = nil,
        expiryDate: Date,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil,
        used: Bool = false
    ) {
        self.id = id
        self.codeID = codeID
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.userID = userID
        self.scopes = scopes
        self.expiryDate = expiryDate
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.used = used
    }
    
    // Convert to library's OAuthCode
    func toOAuthCode() -> VaporOAuth.OAuthCode {
        return VaporOAuth.OAuthCode(
            codeID: self.codeID,
            clientID: self.clientID,
            redirectURI: self.redirectURI,
            userID: self.userID,
            expiryDate: self.expiryDate,
            scopes: self.scopes,
            codeChallenge: self.codeChallenge,
            codeChallengeMethod: self.codeChallengeMethod
        )
    }
    
    // Create from library's OAuthCode
    static func from(_ oauthCode: VaporOAuth.OAuthCode, used: Bool = false) -> OAuthCode {
        return OAuthCode(
            codeID: oauthCode.codeID,
            clientID: oauthCode.clientID,
            redirectURI: oauthCode.redirectURI,
            userID: oauthCode.userID,
            scopes: oauthCode.scopes,
            expiryDate: oauthCode.expiryDate,
            codeChallenge: oauthCode.codeChallenge,
            codeChallengeMethod: oauthCode.codeChallengeMethod,
            used: used
        )
    }
} 