import Vapor

/// RFC 8414 compliant Authorization Server Metadata
/// https://datatracker.ietf.org/doc/html/rfc8414#section-2
public struct OAuthServerMetadata: Content, Sendable {
    // Required fields per RFC 8414
    public let issuer: String
    public let authorizationEndpoint: String
    public let tokenEndpoint: String
    public let jwksUri: String
    public let responseTypesSupported: [String]
    public let subjectTypesSupported: [String]
    public let idTokenSigningAlgValuesSupported: [String]
    
    // Recommended fields
    public let scopesSupported: [String]?
    public let tokenEndpointAuthMethodsSupported: [String]?
    public let grantTypesSupported: [String]?
    public let userinfoEndpoint: String?
    public let registrationEndpoint: String?
    public let claimsSupported: [String]?
    
    // Optional fields
    public let tokenIntrospectionEndpoint: String?
    public let tokenRevocationEndpoint: String?
    public let serviceDocumentation: String?
    public let uiLocalesSupported: [String]?
    public let opPolicyUri: String?
    public let opTosUri: String?
    public let revocationEndpointAuthMethodsSupported: [String]?
    public let revocationEndpointAuthSigningAlgValuesSupported: [String]?
    public let introspectionEndpointAuthMethodsSupported: [String]?
    public let introspectionEndpointAuthSigningAlgValuesSupported: [String]?
    public let codeChallengeMethodsSupported: [String]?
    public let deviceAuthorizationEndpoint: String?
    
    // Public initializer
    public init(
        issuer: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        jwksUri: String,
        responseTypesSupported: [String],
        subjectTypesSupported: [String],
        idTokenSigningAlgValuesSupported: [String],
        scopesSupported: [String]? = nil,
        tokenEndpointAuthMethodsSupported: [String]? = nil,
        grantTypesSupported: [String]? = nil,
        userinfoEndpoint: String? = nil,
        registrationEndpoint: String? = nil,
        claimsSupported: [String]? = nil,
        tokenIntrospectionEndpoint: String? = nil,
        tokenRevocationEndpoint: String? = nil,
        serviceDocumentation: String? = nil,
        uiLocalesSupported: [String]? = nil,
        opPolicyUri: String? = nil,
        opTosUri: String? = nil,
        revocationEndpointAuthMethodsSupported: [String]? = nil,
        revocationEndpointAuthSigningAlgValuesSupported: [String]? = nil,
        introspectionEndpointAuthMethodsSupported: [String]? = nil,
        introspectionEndpointAuthSigningAlgValuesSupported: [String]? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        deviceAuthorizationEndpoint: String? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.jwksUri = jwksUri
        self.responseTypesSupported = responseTypesSupported
        self.subjectTypesSupported = subjectTypesSupported
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
        self.scopesSupported = scopesSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
        self.grantTypesSupported = grantTypesSupported
        self.userinfoEndpoint = userinfoEndpoint
        self.registrationEndpoint = registrationEndpoint
        self.claimsSupported = claimsSupported
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.tokenRevocationEndpoint = tokenRevocationEndpoint
        self.serviceDocumentation = serviceDocumentation
        self.uiLocalesSupported = uiLocalesSupported
        self.opPolicyUri = opPolicyUri
        self.opTosUri = opTosUri
        self.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported
        self.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported
        self.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported
        self.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
    }
    
    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksUri = "jwks_uri"
        case responseTypesSupported = "response_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case scopesSupported = "scopes_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case grantTypesSupported = "grant_types_supported"
        case userinfoEndpoint = "userinfo_endpoint"
        case registrationEndpoint = "registration_endpoint"
        case claimsSupported = "claims_supported"
        case tokenIntrospectionEndpoint = "introspection_endpoint"
        case tokenRevocationEndpoint = "revocation_endpoint"
        case serviceDocumentation = "service_documentation"
        case uiLocalesSupported = "ui_locales_supported"
        case opPolicyUri = "op_policy_uri"
        case opTosUri = "op_tos_uri"
        case revocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported"
        case revocationEndpointAuthSigningAlgValuesSupported = "revocation_endpoint_auth_signing_alg_values_supported"
        case introspectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported"
        case introspectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case deviceAuthorizationEndpoint = "device_authorization_endpoint"
    }
}