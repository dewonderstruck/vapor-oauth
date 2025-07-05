import Vapor
import Fluent
import VaporOAuth

final class OAuthClientModel: Model, @unchecked Sendable {
    static let schema = "oauth_clients"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "client_id")
    var clientID: String
    
    @Field(key: "client_secret")
    var clientSecret: String
    
    @Field(key: "redirect_uris")
    var redirectURIs: [String]
    
    @Field(key: "valid_scopes")
    var validScopes: [String]
    
    @Field(key: "confidential_client")
    var confidentialClient: Bool
    
    @Field(key: "first_party")
    var firstParty: Bool
    
    @Field(key: "allowed_grant_type")
    var allowedGrantType: String
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        clientID: String,
        clientSecret: String,
        redirectURIs: [String],
        validScopes: [String],
        confidentialClient: Bool,
        firstParty: Bool,
        allowedGrantType: String
    ) {
        self.id = id
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURIs = redirectURIs
        self.validScopes = validScopes
        self.confidentialClient = confidentialClient
        self.firstParty = firstParty
        self.allowedGrantType = allowedGrantType
    }
    
    func toOAuthClient() -> OAuthClient {
        return OAuthClient(
            clientID: self.clientID,
            redirectURIs: self.redirectURIs,
            clientSecret: self.clientSecret,
            validScopes: self.validScopes,
            confidential: self.confidentialClient,
            firstParty: self.firstParty,
            allowedGrantType: OAuthFlowType(rawValue: self.allowedGrantType) ?? .authorization
        )
    }
} 
