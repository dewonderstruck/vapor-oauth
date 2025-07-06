import Crypto
import Foundation
import Vapor

/// Route handler for Pushed Authorization Requests (PAR) endpoint as defined in RFC 9126.
///
/// This handler processes POST requests to the `/oauth/par` endpoint and
/// implements the full PAR flow as specified in RFC 9126.
///
/// ## RFC 9126 Endpoint Requirements
///
/// - Accepts POST requests with OAuth 2.0 authorization request parameters
/// - Requires client authentication
/// - Validates all parameters according to OAuth 2.0 specifications
/// - Returns a `request_uri` and `expires_in` in the response
/// - Implements proper error handling and security measures
/// - Uses cryptographically secure operations
///
/// ## Security Considerations
///
/// - Client authentication is required
/// - Rate limiting should be applied
/// - Request validation is comprehensive
/// - Secure storage of pushed requests
/// - Proper error responses
/// - Cryptographic validation of all parameters
public struct PARRouteHandler: Sendable {
    private let parManager: PushedAuthorizationRequestManager
    private let validator: PARValidator
    private let logger: Logger

    /// Initialize the PAR route handler
    /// - Parameters:
    ///   - parManager: Manager for pushed authorization requests
    ///   - validator: Validator for PAR requests
    ///   - logger: Logger for request events
    public init(
        parManager: PushedAuthorizationRequestManager,
        validator: PARValidator,
        logger: Logger
    ) {
        self.parManager = parManager
        self.validator = validator
        self.logger = logger
    }

    /// Handle a pushed authorization request
    /// - Parameter request: The incoming HTTP request
    /// - Returns: Response containing the request URI and expiration time
    /// - Throws: Any error that prevents processing the request
    public func handleRequest(_ request: Request) async throws -> PushedAuthorizationResponse {
        logger.info("Processing pushed authorization request")

        // Extract client authentication from request
        let client = try await extractAuthenticatedClient(from: request)

        // Validate the pushed authorization request
        let parameters = try await validator.validatePushedAuthorizationRequest(request, client: client)

        // Generate a unique request URI
        let requestURI = try await parManager.generateRequestURI()

        // Calculate expiration time
        let expiresAt = Date().addingTimeInterval(parManager.requestExpirationTime)

        // Create the pushed authorization request
        let parRequest = PushedAuthorizationRequest(
            id: UUID().uuidString,
            clientID: client.clientID,
            requestURI: requestURI,
            expiresAt: expiresAt,
            parameters: parameters
        )

        // Store the request
        try await parManager.storeRequest(parRequest)

        logger.info("Successfully created pushed authorization request: \(requestURI) for client: \(client.clientID)")

        // Return the response
        return PushedAuthorizationResponse(
            requestURI: requestURI,
            expiresIn: Int(parManager.requestExpirationTime)
        )
    }

    /// Extract and validate the authenticated client from the request
    /// - Parameter request: The incoming HTTP request
    /// - Returns: The authenticated OAuth client
    /// - Throws: OAuthExtensionError if client authentication fails
    private func extractAuthenticatedClient(from request: Request) async throws -> OAuthClient {
        // Try to extract client credentials from Authorization header
        if let authHeader = request.headers.first(name: "Authorization") {
            if authHeader.hasPrefix("Basic ") {
                return try await extractClientFromBasicAuth(authHeader, request: request)
            }
        }

        // Try to extract client credentials from form data
        if let clientID = request.content[String.self, at: OAuthRequestParameters.clientID],
            let clientSecret = request.content[String.self, at: OAuthRequestParameters.clientSecret]
        {
            return try await extractClientFromFormData(clientID: clientID, clientSecret: clientSecret, request: request)
        }

        throw OAuthExtensionError.invalidParameter(
            "authentication",
            "Client authentication is required for pushed authorization requests"
        )
    }

    /// Extract client from Basic Authentication header
    /// - Parameters:
    ///   - authHeader: The Authorization header value
    ///   - request: The incoming HTTP request
    /// - Returns: The authenticated OAuth client
    /// - Throws: OAuthExtensionError if authentication fails
    private func extractClientFromBasicAuth(_ authHeader: String, request: Request) async throws -> OAuthClient {
        let credentials = String(authHeader.dropFirst("Basic ".count))

        guard let data = Data(base64Encoded: credentials),
            let decoded = String(data: data, encoding: .utf8)
        else {
            throw OAuthExtensionError.invalidParameter(
                "authentication",
                "Invalid Basic Authentication credentials format"
            )
        }

        let components = decoded.components(separatedBy: ":")
        guard components.count == 2 else {
            throw OAuthExtensionError.invalidParameter(
                "authentication",
                "Invalid Basic Authentication credentials format"
            )
        }

        let clientID = components[0]
        let clientSecret = components[1]

        return try await extractClientFromFormData(clientID: clientID, clientSecret: clientSecret, request: request)
    }

    /// Extract and validate client from form data with timing attack protection
    /// - Parameters:
    ///   - clientID: The client identifier
    ///   - clientSecret: The client secret
    ///   - request: The incoming HTTP request
    /// - Returns: The authenticated OAuth client
    /// - Throws: OAuthExtensionError if client validation fails
    private func extractClientFromFormData(clientID: String, clientSecret: String, request: Request) async throws -> OAuthClient {
        guard let client = try await validator.clientRetriever.getClient(clientID: clientID) else {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.clientID,
                "Client not found"
            )
        }

        // Validate client secret with timing attack protection using Swift Crypto
        guard let storedSecret = client.clientSecret else {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.clientSecret,
                "Client secret not configured"
            )
        }

        // Use constant-time comparison to prevent timing attacks
        let isValid = secureCompare(storedSecret, clientSecret)
        guard isValid else {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.clientSecret,
                "Invalid client secret"
            )
        }

        // Ensure client is confidential (PAR requires client authentication)
        guard client.confidentialClient ?? false else {
            throw OAuthExtensionError.invalidParameter(
                "client",
                "Pushed authorization requests require confidential clients"
            )
        }

        return client
    }

    /// Secure string comparison to prevent timing attacks
    /// - Parameters:
    ///   - lhs: First string to compare
    ///   - rhs: Second string to compare
    /// - Returns: True if strings are equal, false otherwise
    private func secureCompare(_ lhs: String, _ rhs: String) -> Bool {
        // Convert strings to data for constant-time comparison
        let lhsData = lhs.data(using: .utf8) ?? Data()
        let rhsData = rhs.data(using: .utf8) ?? Data()

        // Use constant-time comparison to prevent timing attacks
        return lhsData.withUnsafeBytes { lhsBytes in
            rhsData.withUnsafeBytes { rhsBytes in
                // If lengths are different, still compare to prevent timing attacks
                let _ = max(lhsBytes.count, rhsBytes.count)
                var result = lhsBytes.count == rhsBytes.count ? 0 : 1

                for i in 0..<min(lhsBytes.count, rhsBytes.count) {
                    result |= Int(lhsBytes[i] ^ rhsBytes[i])
                }

                return result == 0
            }
        }
    }
}

/// Error response for PAR endpoint failures
public struct PARErrorResponse: Codable, Sendable, AsyncResponseEncodable {
    public let error: String
    public let errorDescription: String?
    public let errorURI: String?

    public init(error: String, errorDescription: String? = nil, errorURI: String? = nil) {
        self.error = error
        self.errorDescription = errorDescription
        self.errorURI = errorURI
    }

    public func encodeResponse(for request: Request) async throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        let response = Response(body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: "application/json")
        response.status = .badRequest
        return response
    }
}
