public struct StaticClientRetriever: ClientRetriever {

    let clients: [String: OAuthClient]

    public init(clients: [OAuthClient]) {
        self.clients = clients.reduce([String: OAuthClient]()) { (dict, client) -> [String: OAuthClient] in
            var dict = dict
            dict[client.clientID] = client
            return dict
        }
    }

    public func getClient(clientID: String) async throws -> OAuthClient? {
        return clients[clientID]
    }
}

// MARK: - Example Configurations

extension StaticClientRetriever {
    
    /// Creates a StaticClientRetriever with example client configurations demonstrating authorized origins usage
    ///
    /// This provides common patterns for configuring clients with origin validation:
    /// - Web application with multiple environments
    /// - Single-page application with wildcard subdomain support
    /// - Mobile application with custom scheme
    /// - Legacy client without origin restrictions (backward compatibility)
    ///
    /// - Returns: A configured StaticClientRetriever with example clients
    public static func withExampleClients() -> StaticClientRetriever {
        let clients = [
            // Web application with multiple environments
            OAuthClient(
                clientID: "web-app-client",
                redirectURIs: [
                    "https://myapp.com/oauth/callback",
                    "https://staging.myapp.com/oauth/callback",
                    "http://localhost:3000/oauth/callback"
                ],
                clientSecret: "web-app-secret",
                validScopes: ["read", "write", "admin"],
                confidential: true,
                firstParty: true,
                allowedGrantType: .authorization,
                authorizedOrigins: [
                    "https://myapp.com",
                    "https://staging.myapp.com",
                    "http://localhost:3000"
                ]
            ),
            
            // Single-page application with wildcard subdomain support
            OAuthClient(
                clientID: "spa-client",
                redirectURIs: [
                    "https://app.example.com/callback",
                    "https://admin.example.com/callback",
                    "https://dashboard.example.com/callback"
                ],
                validScopes: ["read", "write"],
                confidential: false,
                firstParty: false,
                allowedGrantType: .authorization,
                authorizedOrigins: [
                    "*.example.com",  // Allows any subdomain of example.com
                    "https://example.com"  // Also allow the root domain
                ]
            ),
            
            // Development client with localhost support
            OAuthClient(
                clientID: "dev-client",
                redirectURIs: [
                    "http://localhost:8080/callback",
                    "http://127.0.0.1:8080/callback",
                    "http://localhost:3000/callback"
                ],
                validScopes: ["read"],
                confidential: false,
                firstParty: true,
                allowedGrantType: .authorization,
                authorizedOrigins: [
                    "http://localhost:8080",
                    "http://127.0.0.1:8080",
                    "http://localhost:3000"
                ]
            ),
            
            // Mobile application with custom scheme (no origin validation needed)
            OAuthClient(
                clientID: "mobile-app-client",
                redirectURIs: [
                    "myapp://oauth/callback"
                ],
                validScopes: ["read", "write"],
                confidential: false,
                firstParty: true,
                allowedGrantType: .authorization,
                authorizedOrigins: nil  // No origin validation for mobile apps
            ),
            
            // Legacy client without origin restrictions (backward compatibility)
            OAuthClient(
                clientID: "legacy-client",
                redirectURIs: [
                    "https://legacy.example.com/callback"
                ],
                clientSecret: "legacy-secret",
                validScopes: ["read"],
                confidential: true,
                firstParty: false,
                allowedGrantType: .authorization,
                authorizedOrigins: nil  // Maintains backward compatibility
            ),
            
            // Client credentials flow client (server-to-server)
            OAuthClient(
                clientID: "service-client",
                redirectURIs: nil,
                clientSecret: "service-secret",
                validScopes: ["api:read", "api:write"],
                confidential: true,
                firstParty: true,
                allowedGrantType: .clientCredentials,
                authorizedOrigins: nil  // Not applicable for server-to-server flows
            )
        ]
        
        return StaticClientRetriever(clients: clients)
    }
    
    /// Creates a StaticClientRetriever with a single client configured for common development scenarios
    ///
    /// This is useful for quick setup during development and testing.
    /// The client supports both localhost and common development domains.
    ///
    /// - Returns: A configured StaticClientRetriever with a development client
    public static func forDevelopment() -> StaticClientRetriever {
        let developmentClient = OAuthClient(
            clientID: "development-client",
            redirectURIs: [
                "http://localhost:3000/callback",
                "http://localhost:8080/callback",
                "https://dev.localhost/callback"
            ],
            validScopes: ["read", "write", "admin"],
            confidential: false,
            firstParty: true,
            allowedGrantType: .authorization,
            authorizedOrigins: [
                "http://localhost:3000",
                "http://localhost:8080",
                "https://dev.localhost",
                "*.dev.localhost"  // Support for subdomain development
            ]
        )
        
        return StaticClientRetriever(clients: [developmentClient])
    }
}
