import Vapor

struct DeviceCodeTokenHandler {
    let clientValidator: ClientValidator
    let scopeValidator: ScopeValidator
    let deviceCodeManager: any DeviceCodeManager
    let tokenManager: any TokenManager
    let tokenResponseGenerator: TokenResponseGenerator
    
    func handleDeviceCodeTokenRequest(_ request: Request) async throws -> Response {
        // Validate device_code parameter
        guard let deviceCodeString = request.content[String.self, at: OAuthRequestParameters.deviceCode] else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'device_code' parameter",
                status: .badRequest
            )
        }
        
        // Validate client
        guard let clientID = request.content[String.self, at: OAuthRequestParameters.clientID] else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'client_id' parameter",
                status: .badRequest
            )
        }
        
        // Authenticate client
        do {
            try await clientValidator.authenticateClient(
                clientID: clientID,
                clientSecret: request.content[String.self, at: OAuthRequestParameters.clientSecret],
                grantType: .deviceCode
            )
        } catch {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidClient,
                description: "Request had invalid client credentials",
                status: .unauthorized
            )
        }
        
        // If device code is not found (invalid, used, or expired), return 'expired_token' per RFC 8628
        guard let deviceCode = try await deviceCodeManager.getDeviceCode(deviceCodeString) else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.expiredToken,
                description: "The device code is invalid, expired, or already used",
                status: .badRequest
            )
        }
        
        // Check if expired
        if deviceCode.expiryDate < Date() {
            // Remove expired code
            try? await deviceCodeManager.removeDeviceCode(deviceCode)
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.expiredToken,
                description: "The device code has expired",
                status: .badRequest
            )
        }
        
        // Validate scopes if present
        if let scopeString = request.content[String.self, at: OAuthRequestParameters.scope] {
            let scopes = scopeString.components(separatedBy: " ")
            do {
                try await scopeValidator.validateScope(clientID: clientID, scopes: scopes)
            } catch ScopeError.invalid {
                return try tokenResponseGenerator.createResponse(
                    error: OAuthResponseParameters.ErrorType.invalidScope,
                    description: "Request contained an invalid scope",
                    status: .badRequest
                )
            } catch ScopeError.unknown {
                return try tokenResponseGenerator.createResponse(
                    error: OAuthResponseParameters.ErrorType.invalidScope,
                    description: "Request contained an unknown scope",
                    status: .badRequest
                )
            }
            
            // Validate against original device code scopes
            if let deviceCodeScopes = deviceCode.scopes {
                for scope in scopes {
                    if !deviceCodeScopes.contains(scope) {
                        return try tokenResponseGenerator.createResponse(
                            error: OAuthResponseParameters.ErrorType.invalidScope,
                            description: "Request contained elevated scopes",
                            status: .badRequest
                        )
                    }
                }
            }
        }
        
        // Check polling frequency
        if deviceCode.shouldIncreasePollInterval {
            try await deviceCodeManager.increaseInterval(deviceCodeString, by: 5)
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.slowDown,
                description: "Polling too frequently",
                status: .badRequest
            )
        }
        
        try await deviceCodeManager.updateLastPolled(deviceCodeString)
        
        // Check authorization status
        switch deviceCode.status {
        case .declined:
            // Remove declined code
            try? await deviceCodeManager.removeDeviceCode(deviceCode)
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.accessDenied,
                description: "The end-user denied the authorization request",
                status: .badRequest
            )
        case .pending, .unauthorized:
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.authorizationPending,
                description: "The authorization request is still pending",
                status: .badRequest
            )
        case .authorized:
            // Remove code after successful use (replay protection)
            try? await deviceCodeManager.removeDeviceCode(deviceCode)
            // Generate tokens
            let expiryTime = 3600
            let (accessToken, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
                clientID: clientID,
                userID: deviceCode.userID!,
                scopes: deviceCode.scopes,
                accessTokenExpiryTime: expiryTime
            )
            return try tokenResponseGenerator.createResponse(
                accessToken: accessToken,
                refreshToken: refreshToken,
                expires: expiryTime,
                scope: deviceCode.scopes?.joined(separator: " ")
            )
        }
    }
}
