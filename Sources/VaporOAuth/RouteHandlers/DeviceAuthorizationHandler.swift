import Vapor

struct DeviceAuthorizationHandler: Sendable {
    let deviceCodeManager: any DeviceCodeManager
    let clientValidator: ClientValidator
    let scopeValidator: ScopeValidator
    
    @Sendable
    func handleRequest(_ request: Request) async throws -> Response {
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
                clientSecret: requestObject.clientSecret,
                grantType: .deviceCode
            )
        } catch {
            return try createErrorResponse(
                status: .unauthorized,
                errorMessage: OAuthResponseParameters.ErrorType.invalidClient,
                errorDescription: "Request had invalid client credentials"
            )
        }
        
        // Validate scopes if present
        if let scopeString = request.content[String.self, at: OAuthRequestParameters.scope] {
            let scopes = scopeString.components(separatedBy: " ")
            do {
                try await scopeValidator.validateScope(clientID: requestObject.clientID, scopes: scopes)
            } catch ScopeError.invalid {
                return try createErrorResponse(
                    status: .badRequest,
                    errorMessage: OAuthResponseParameters.ErrorType.invalidScope,
                    errorDescription: "The requested scope is invalid, unknown, or malformed"
                )
            } catch ScopeError.unknown {
                return try createErrorResponse(
                    status: .badRequest,
                    errorMessage: OAuthResponseParameters.ErrorType.invalidScope,
                    errorDescription: "The requested scope is invalid, unknown, or malformed"
                )
            }
        }
        
        // Generate device and user codes
        guard let deviceCode = try await deviceCodeManager.generateDeviceCode(
            clientID: requestObject.clientID,
            scopes: requestObject.scopes,
            verificationURI: request.application.oauth.deviceVerificationURI,
            verificationURIComplete: nil
        ) else {
            return try createErrorResponse(
                status: .internalServerError,
                errorMessage: OAuthResponseParameters.ErrorType.serverError,
                errorDescription: "Failed to generate device code"
            )
        }
        
        return try createDeviceResponse(deviceCode: deviceCode)
    }
    
    private func validateRequest(_ request: Request) async throws -> (Response?, DeviceAuthorizationRequest?) {
        guard let clientID: String = request.content[OAuthRequestParameters.clientID] else {
            return (try createErrorResponse(
                status: .badRequest,
                errorMessage: OAuthResponseParameters.ErrorType.invalidRequest,
                errorDescription: "Request was missing the 'client_id' parameter"
            ), nil)
        }
        
        let clientSecret: String? = request.content[OAuthRequestParameters.clientSecret]
        
        let scopes: [String]?
        if let scopeString: String = request.content[OAuthRequestParameters.scope] {
            scopes = scopeString.components(separatedBy: " ")
        } else {
            scopes = nil
        }
        
        let requestObject = DeviceAuthorizationRequest(
            clientID: clientID,
            clientSecret: clientSecret,
            scopes: scopes
        )
        
        return (nil, requestObject)
    }
    
    private func createDeviceResponse(deviceCode: OAuthDeviceCode) throws -> Response {
        let response = Response(status: .ok)
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: .pragma, value: "no-cache")
        
        try response.content.encode(DeviceResponse(
            deviceCode: deviceCode.deviceCode,
            userCode: deviceCode.userCode,
            verificationURI: deviceCode.verificationURI,
            verificationURIComplete: deviceCode.verificationURIComplete,
            expiresIn: Int(deviceCode.expiryDate.timeIntervalSinceNow),
            interval: deviceCode.interval
        ))
        
        return response
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
}

// MARK: - Request/Response Models
extension DeviceAuthorizationHandler {
    struct DeviceAuthorizationRequest: Sendable {
        let clientID: String
        let clientSecret: String?
        let scopes: [String]?
    }
    
    struct DeviceResponse: Content, Sendable {
        let deviceCode: String
        let userCode: String
        let verificationURI: String
        let verificationURIComplete: String?
        let expiresIn: Int
        let interval: Int
        
        enum CodingKeys: String, CodingKey {
            case deviceCode = "device_code"
            case userCode = "user_code"
            case verificationURI = "verification_uri"
            case verificationURIComplete = "verification_uri_complete"
            case expiresIn = "expires_in"
            case interval
        }
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
