import Vapor

/// Default implementation that automatically derives OAuth 2.0 server metadata from configuration
public struct DefaultServerMetadataProvider: ServerMetadataProvider {
    private let issuer: String
    private let validScopes: [String]?
    private let clientRetriever: any ClientRetriever
    private let hasCodeManager: Bool
    private let hasDeviceCodeManager: Bool
    private let hasTokenIntrospection: Bool
    private let hasUserManager: Bool
    private let jwksEndpoint: String
    
    /// Initialize the metadata provider with OAuth 2.0 server configuration
    /// - Parameters:
    ///   - issuer: The issuer identifier for the OAuth 2.0 authorization server
    ///   - validScopes: List of supported OAuth scopes, if any
    ///   - clientRetriever: Service for retrieving OAuth client information
    ///   - hasCodeManager: Whether authorization code flow is supported
    ///   - hasDeviceCodeManager: Whether device authorization flow is supported
    ///   - hasTokenIntrospection: Whether token introspection is supported
    ///   - hasUserManager: Whether resource owner password credentials flow is supported
    ///   - jwksEndpoint: Optional custom JWKS endpoint URL. If nil, defaults to /.well-known/jwks.json
    init(
        issuer: String = "vapor-oauth",
        validScopes: [String]?,
        clientRetriever: any ClientRetriever,
        hasCodeManager: Bool,
        hasDeviceCodeManager: Bool,
        hasTokenIntrospection: Bool,
        hasUserManager: Bool,
        jwksEndpoint: String? = nil
    ) {
        self.issuer = issuer
        self.validScopes = validScopes
        self.clientRetriever = clientRetriever
        self.hasCodeManager = hasCodeManager
        self.hasDeviceCodeManager = hasDeviceCodeManager
        self.hasTokenIntrospection = hasTokenIntrospection
        self.hasUserManager = hasUserManager
        
        let baseURL = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        self.jwksEndpoint = jwksEndpoint ?? "\(baseURL)/.well-known/jwks.json"
    }
    
    public func getMetadata() async throws -> OAuthServerMetadata {
        let baseURL = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        
        // Build list of supported grant types based on configuration
        var supportedGrantTypes = [
            OAuthFlowType.clientCredentials.rawValue,
            OAuthFlowType.refresh.rawValue
        ]
        
        if hasCodeManager {
            supportedGrantTypes.append(OAuthFlowType.authorization.rawValue)
        }
        
        if hasDeviceCodeManager {
            supportedGrantTypes.append(OAuthFlowType.deviceCode.rawValue)
        }
        
        if hasUserManager {
            supportedGrantTypes.append(OAuthFlowType.password.rawValue)
        }
        
        // Configure supported response types per OAuth 2.0 spec
        var responseTypes = ["code"]
        if hasCodeManager {
            responseTypes.append("token")
        }
        
        return OAuthServerMetadata(
            // Required metadata fields per RFC 8414
            issuer: issuer,
            authorizationEndpoint: "\(baseURL)/oauth/authorize",
            tokenEndpoint: "\(baseURL)/oauth/token", 
            jwksUri: jwksEndpoint,
            responseTypesSupported: responseTypes,
            subjectTypesSupported: ["public"],
            idTokenSigningAlgValuesSupported: ["RS256"],
            
            // Recommended metadata fields
            scopesSupported: validScopes,
            tokenEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
            grantTypesSupported: supportedGrantTypes,
            userinfoEndpoint: nil,
            registrationEndpoint: nil,
            claimsSupported: nil,
            
            // Optional metadata fields
            tokenIntrospectionEndpoint: hasTokenIntrospection ? "\(baseURL)/oauth/token_info" : nil,
            tokenRevocationEndpoint: "\(baseURL)/oauth/revoke",
            serviceDocumentation: nil,
            uiLocalesSupported: nil,
            opPolicyUri: nil,
            opTosUri: nil,
            revocationEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
            revocationEndpointAuthSigningAlgValuesSupported: nil,
            introspectionEndpointAuthMethodsSupported: hasTokenIntrospection ? ["client_secret_basic"] : nil,
            introspectionEndpointAuthSigningAlgValuesSupported: nil,
            codeChallengeMethodsSupported: hasCodeManager ? ["S256", "plain"] : nil,
            deviceAuthorizationEndpoint: hasDeviceCodeManager ? "\(baseURL)/oauth/device_authorization" : nil
        )
    }
}
