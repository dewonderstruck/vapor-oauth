import Vapor
import VaporOAuth

struct OAuthController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let oauth = routes.grouped("oauth")
        
        // Additional endpoints for the example
        
        oauth.get("info") { req async throws -> OAuthInfoResponse in
            // Return OAuth server information
            return OAuthInfoResponse(
                issuer: "http://localhost:8080",
                authorizationEndpoint: "/oauth/authorize",
                tokenEndpoint: "/oauth/token",
                userinfoEndpoint: "/oauth/userinfo",
                jwksUri: "/oauth/jwks",
                scopesSupported: ["read", "write", "admin"],
                responseTypesSupported: ["code", "token"],
                grantTypesSupported: ["authorization_code", "refresh_token", "client_credentials"],
                tokenEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"]
            )
        }
        
        oauth.get("userinfo") { req async throws -> UserInfoResponse in
            // This endpoint requires a valid access token
            let token = try extractToken(from: req)
            
            // In a real application, you would validate the token and get user info
            // For this example, we'll return mock user data
            return UserInfoResponse(
                sub: "user123",
                name: "John Doe",
                email: "john@example.com",
                emailVerified: true
            )
        }
        
        oauth.get("clients") { req async throws -> [OAuthClientInfo] in
            // Return list of registered clients using the service
            let clients = try await req.oauthClientRetriever.getAllClients()
            return clients.map { client in
                OAuthClientInfo(
                    clientId: client.clientID,
                    clientType: client.confidentialClient == true ? "confidential" : "public",
                    scopes: client.validScopes ?? [],
                    grantTypes: [client.allowedGrantType.rawValue]
                )
            }
        }
    }
    
    private func extractToken(from req: Request) throws -> String {
        guard let authHeader = req.headers.first(name: .authorization) else {
            throw Abort(.forbidden, reason: "Missing Authorization header")
        }

        guard authHeader.lowercased().hasPrefix("bearer ") else {
            throw Abort(.forbidden, reason: "Invalid Authorization header format")
        }

        let token = String(authHeader[authHeader.index(authHeader.startIndex, offsetBy: 7)...])

        guard !token.isEmpty else {
            throw Abort(.forbidden, reason: "Empty token")
        }

        return token
    }
}

// Response models
struct OAuthInfoResponse: Content {
    let issuer: String
    let authorizationEndpoint: String
    let tokenEndpoint: String
    let userinfoEndpoint: String
    let jwksUri: String
    let scopesSupported: [String]
    let responseTypesSupported: [String]
    let grantTypesSupported: [String]
    let tokenEndpointAuthMethodsSupported: [String]
}

struct UserInfoResponse: Content {
    let sub: String
    let name: String
    let email: String
    let emailVerified: Bool
}

struct OAuthClientInfo: Content {
    let clientId: String
    let clientType: String
    let scopes: [String]
    let grantTypes: [String]
}