public enum OAuthFlowType: String, Sendable {
    case authorization = "authorization_code"
    
    @available(*, deprecated, message: "The Implicit Grant flow is deprecated and not recommended for security reasons. Use Authorization Code flow with PKCE instead.")
    case implicit = "implicit"
    
    case password = "password"
    case clientCredentials = "client_credentials"
    case refresh = "refresh_token"
    case tokenIntrospection = "token_introspection"
}
