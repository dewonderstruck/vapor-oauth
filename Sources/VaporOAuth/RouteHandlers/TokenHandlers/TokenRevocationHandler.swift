import Vapor

struct TokenRevocationHandler: Sendable {
    let clientValidator: ClientValidator
    let tokenManager: any TokenManager
    
    @Sendable
    func handleRequest(_ request: Request) async throws -> Response {
        
        // Validate content type
        guard request.headers.contentType == .urlEncodedForm else {
            return try createErrorResponse(
                status: .badRequest,
                errorMessage: OAuthResponseParameters.ErrorType.invalidRequest,
                errorDescription: "Content-Type must be application/x-www-form-urlencoded"
            )
        }
        
        let (errorResponse, requestObject) = try await validateRequest(request)
        
        if let errorResponse = errorResponse {
            return errorResponse
        }
        
        guard let requestObject = requestObject else {
            throw Abort(.internalServerError)
        }
        
        // Client authentication
        do {
            try await clientValidator.authenticateClient(
                clientID: requestObject.clientID,
                clientSecret: request.content[String.self, at: OAuthRequestParameters.clientSecret],
                grantType: nil
            )
        } catch {
            return try createErrorResponse(
                status: .unauthorized,
                errorMessage: OAuthResponseParameters.ErrorType.invalidClient,
                errorDescription: "Request had invalid client credentials"
            )
        }
        
        // Attempt token revocation based on type hint
        try await revokeToken(
            token: requestObject.token,
            typeHint: requestObject.tokenTypeHint,
            clientID: requestObject.clientID
        )
        
        // RFC 7009 specifies returning 200 OK even for non-existent tokens
        return createResponse()
    }
    
    private func validateRequest(_ request: Request) async throws -> (Response?, TokenRevocationRequest?) {
        guard let token: String = request.content[OAuthRequestParameters.token] else {
            return (try createErrorResponse(
                status: .badRequest,
                errorMessage: OAuthResponseParameters.ErrorType.invalidRequest,
                errorDescription: "Request was missing the 'token' parameter"
            ), nil)
        }
        
        guard let clientID: String = request.content[OAuthRequestParameters.clientID] else {
            return (try createErrorResponse(
                status: .badRequest,
                errorMessage: OAuthResponseParameters.ErrorType.invalidRequest,
                errorDescription: "Request was missing the 'client_id' parameter"
            ), nil)
        }
        
        let tokenTypeHint: String? = request.content[OAuthRequestParameters.tokenTypeHint]
        
        let requestObject = TokenRevocationRequest(
            token: token,
            tokenTypeHint: tokenTypeHint,
            clientID: clientID
        )
        
        return (nil, requestObject)
    }
    
    private func revokeToken(token: String, typeHint: String?, clientID: String) async throws {
        switch typeHint {
        case "refresh_token":
            if let refreshToken = try await tokenManager.getRefreshToken(token),
               refreshToken.clientID == clientID {
                try await tokenManager.revokeRefreshToken(token)
            }
            
        case "access_token", .none:
            if let accessToken = try await tokenManager.getAccessToken(token),
               accessToken.clientID == clientID {
                try await tokenManager.revokeAccessToken(token)
            }
            
        default:
            // RFC 7009: Unsupported token type hints are ignored
            break
        }
    }
    
    private func createErrorResponse(
        status: HTTPStatus,
        errorMessage: String,
        errorDescription: String
    ) throws -> Response {
        let response = Response(status: status)
        try response.content.encode(ErrorResponse(
            error: errorMessage,
            errorDescription: errorDescription
        ))
        return response
    }
    
    private func createResponse(status: HTTPStatus = .ok) -> Response {
        let response = Response(status: status)
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: .pragma, value: "no-cache")
        return response
    }
}

// MARK: - Request/Response Models
extension TokenRevocationHandler {
    struct TokenRevocationRequest: Sendable {
        let token: String
        let tokenTypeHint: String?
        let clientID: String
    }
    
    struct ErrorResponse: Content, Sendable {
        let error: String
        let errorDescription: String
        
        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }
}
