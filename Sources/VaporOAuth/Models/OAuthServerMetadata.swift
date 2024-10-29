import Vapor

/// RFC 8414 compliant Authorization Server Metadata
/// https://datatracker.ietf.org/doc/html/rfc8414#section-2
public struct OAuthServerMetadata: Content, Sendable {
    // Required fields per RFC 8414
    let issuer: String
    let authorizationEndpoint: String
    let tokenEndpoint: String
    let jwksUri: String
    let responseTypesSupported: [String]
    let subjectTypesSupported: [String]
    let idTokenSigningAlgValuesSupported: [String]
    
    // Recommended fields
    let scopesSupported: [String]?
    let tokenEndpointAuthMethodsSupported: [String]?
    let grantTypesSupported: [String]?
    let userinfoEndpoint: String?
    let registrationEndpoint: String?
    let claimsSupported: [String]?
    
    // Optional fields
    let tokenIntrospectionEndpoint: String?
    let tokenRevocationEndpoint: String?
    let serviceDocumentation: String?
    let uiLocalesSupported: [String]?
    let opPolicyUri: String?
    let opTosUri: String?
    let revocationEndpointAuthMethodsSupported: [String]?
    let revocationEndpointAuthSigningAlgValuesSupported: [String]?
    let introspectionEndpointAuthMethodsSupported: [String]?
    let introspectionEndpointAuthSigningAlgValuesSupported: [String]?
    let codeChallengeMethodsSupported: [String]?
    let deviceAuthorizationEndpoint: String?
    
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