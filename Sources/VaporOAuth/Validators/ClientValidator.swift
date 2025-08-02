import Vapor
import Logging

struct ClientValidator: Sendable {

    let clientRetriever: any ClientRetriever
    let scopeValidator: ScopeValidator
    let environment: Environment
    let originValidator: OriginValidator
    let securityLogger: SecurityLogger?

    func validateClient(clientID: String, responseType: String, redirectURI: String, scopes: [String]?, request: Request) async throws {
        guard let client = try await clientRetriever.getClient(clientID: clientID) else {
            throw AuthorizationError.invalidClientID
        }

        if client.confidentialClient ?? false {
            guard responseType == ResponseType.code else {
                throw AuthorizationError.confidentialClientTokenGrant
            }
        }

        guard client.validateRedirectURI(redirectURI) else {
            throw AuthorizationError.invalidRedirectURI
        }

        if responseType == ResponseType.code {
            guard client.allowedGrantType == .authorization else {
                throw Abort(.forbidden)
            }
        } else {
            guard client.allowedGrantType == .implicit else {
                throw Abort(.forbidden)
            }
        }

        try await scopeValidator.validateScope(clientID: clientID, scopes: scopes)

        // Perform origin validation
        try validateOrigin(for: client, request: request)

        let redirectURI = URI(stringLiteral: redirectURI)

        if environment == .production {
            if redirectURI.scheme != "https" {
                throw AuthorizationError.httpRedirectURI
            }
        }
    }
    
    /// Validates the origin for the given client and request
    /// - Parameters:
    ///   - client: The OAuth client to validate against
    ///   - request: The request containing the origin header
    /// - Throws: AuthorizationError.unauthorizedOrigin or AuthorizationError.missingOrigin
    private func validateOrigin(for client: OAuthClient, request: Request) throws {
        // Skip origin validation if no authorized origins are configured (backward compatibility)
        guard let authorizedOrigins = client.authorizedOrigins, !authorizedOrigins.isEmpty else {
            return
        }
        
        // Extract origin from request
        guard let origin = originValidator.extractOrigin(from: request) else {
            securityLogger?.logOriginValidationFailure(
                clientID: client.clientID,
                attemptedOrigin: nil,
                authorizedOrigins: authorizedOrigins,
                request: request
            )
            throw AuthorizationError.missingOrigin
        }
        
        // Validate origin against authorized origins
        guard originValidator.validateOrigin(origin, against: authorizedOrigins) else {
            securityLogger?.logOriginValidationFailure(
                clientID: client.clientID,
                attemptedOrigin: origin,
                authorizedOrigins: authorizedOrigins,
                request: request
            )
            throw AuthorizationError.unauthorizedOrigin
        }
        
        // Log successful validation
        securityLogger?.logOriginValidationSuccess(
            clientID: client.clientID,
            validatedOrigin: origin,
            request: request
        )
    }

    func authenticateClient(
        clientID: String, clientSecret: String?, grantType: OAuthFlowType?,
        checkConfidentialClient: Bool = false
    ) async throws {
        guard let client = try await clientRetriever.getClient(clientID: clientID) else {
            throw ClientError.unauthorized
        }

        guard clientSecret == client.clientSecret else {
            throw ClientError.unauthorized
        }

        if let grantType = grantType {
            guard client.allowedGrantType == grantType else {
                throw Abort(.forbidden)
            }

            if grantType == .password {
                guard client.firstParty else {
                    throw ClientError.notFirstParty
                }
            }
        }

        if checkConfidentialClient {
            guard client.confidentialClient ?? false else {
                throw ClientError.notConfidential
            }
        }
    }
}

public enum ClientError: Error, Sendable {
    case unauthorized
    case notFirstParty
    case notConfidential
}
