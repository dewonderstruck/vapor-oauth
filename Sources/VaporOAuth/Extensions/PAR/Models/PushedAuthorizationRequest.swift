import Foundation
import Vapor

/// A Pushed Authorization Request (PAR) as defined in RFC 9126.
///
/// This model represents a pushed authorization request that has been stored
/// on the authorization server and can be referenced by a `request_uri`.
///
/// ## RFC 9126 Compliance
///
/// - The request contains all the parameters that would normally be sent to the authorization endpoint
/// - The request is stored securely and can only be accessed by the client that created it
/// - The request has an expiration time (typically 60 seconds)
/// - The request is referenced by a unique `request_uri` that is returned to the client
///
/// ## Security Considerations
///
/// - The `request_uri` must be bound to the client that created the request
/// - The request must expire after a reasonable time period
/// - The request must be stored securely to prevent unauthorized access
/// - The request must be validated against the client's configuration
public struct PushedAuthorizationRequest: Codable, Sendable {
    /// The unique identifier for this pushed authorization request
    public let id: String

    /// The client ID that created this request
    public let clientID: String

    /// The request URI that can be used to reference this request
    public let requestURI: String

    /// The expiration time of this request (Unix timestamp)
    public let expiresAt: Date

    /// The authorization request parameters
    public let parameters: AuthorizationRequestParameters

    /// The time when this request was created
    public let createdAt: Date

    /// Whether this request has been used (to prevent replay attacks)
    public var isUsed: Bool

    /// Initialize a new pushed authorization request
    /// - Parameters:
    ///   - id: Unique identifier for the request
    ///   - clientID: The client ID that created the request
    ///   - requestURI: The request URI for referencing this request
    ///   - expiresAt: When the request expires
    ///   - parameters: The authorization request parameters
    ///   - createdAt: When the request was created
    ///   - isUsed: Whether the request has been used
    public init(
        id: String,
        clientID: String,
        requestURI: String,
        expiresAt: Date,
        parameters: AuthorizationRequestParameters,
        createdAt: Date = Date(),
        isUsed: Bool = false
    ) {
        self.id = id
        self.clientID = clientID
        self.requestURI = requestURI
        self.expiresAt = expiresAt
        self.parameters = parameters
        self.createdAt = createdAt
        self.isUsed = isUsed
    }

    /// Check if this request has expired
    public var isExpired: Bool {
        return Date() > expiresAt
    }

    /// Check if this request is valid (not expired and not used)
    public var isValid: Bool {
        return !isExpired && !isUsed
    }
}

/// Authorization request parameters that can be pushed to the authorization server
public struct AuthorizationRequestParameters: Codable, Sendable {
    /// OAuth 2.0 response type (e.g., "code", "token")
    public let responseType: String

    /// The client identifier
    public let clientID: String

    /// The redirect URI
    public let redirectURI: String?

    /// The scope of the access request
    public let scope: String?

    /// An opaque value used by the client to maintain state between the request and callback
    public let state: String?

    /// PKCE code challenge
    public let codeChallenge: String?

    /// PKCE code challenge method
    public let codeChallengeMethod: String?

    /// Rich Authorization Requests authorization details
    public let authorizationDetails: String?

    /// Additional custom parameters
    public let additionalParameters: [String: String]

    /// Initialize authorization request parameters
    /// - Parameters:
    ///   - responseType: The OAuth 2.0 response type
    ///   - clientID: The client identifier
    ///   - redirectURI: The redirect URI
    ///   - scope: The scope of the access request
    ///   - state: State parameter for CSRF protection
    ///   - codeChallenge: PKCE code challenge
    ///   - codeChallengeMethod: PKCE code challenge method
    ///   - authorizationDetails: RAR authorization details
    ///   - additionalParameters: Additional custom parameters
    public init(
        responseType: String,
        clientID: String,
        redirectURI: String? = nil,
        scope: String? = nil,
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil,
        authorizationDetails: String? = nil,
        additionalParameters: [String: String] = [:]
    ) {
        self.responseType = responseType
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scope = scope
        self.state = state
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.authorizationDetails = authorizationDetails
        self.additionalParameters = additionalParameters
    }

    /// Convert parameters to a dictionary for URL construction
    public func toDictionary() -> [String: String] {
        var params: [String: String] = [
            OAuthRequestParameters.responseType: responseType,
            OAuthRequestParameters.clientID: clientID,
        ]

        if let redirectURI = redirectURI {
            params[OAuthRequestParameters.redirectURI] = redirectURI
        }

        if let scope = scope {
            params[OAuthRequestParameters.scope] = scope
        }

        if let state = state {
            params[OAuthRequestParameters.state] = state
        }

        if let codeChallenge = codeChallenge {
            params[OAuthRequestParameters.codeChallenge] = codeChallenge
        }

        if let codeChallengeMethod = codeChallengeMethod {
            params[OAuthRequestParameters.codeChallengeMethod] = codeChallengeMethod
        }

        if let authorizationDetails = authorizationDetails {
            params[OAuthRequestParameters.authorizationDetails] = authorizationDetails
        }

        // Add additional parameters
        for (key, value) in additionalParameters {
            params[key] = value
        }

        return params
    }

    /// Create authorization request parameters from a Vapor request
    /// - Parameter request: The Vapor request containing the parameters
    /// - Returns: Authorization request parameters
    /// - Throws: OAuthExtensionError if required parameters are missing
    public static func fromRequest(_ request: Request) throws -> AuthorizationRequestParameters {
        guard let responseType = request.query[String.self, at: OAuthRequestParameters.responseType] else {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.responseType,
                "response_type is required for pushed authorization requests"
            )
        }

        guard let clientID = request.query[String.self, at: OAuthRequestParameters.clientID] else {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.clientID,
                "client_id is required for pushed authorization requests"
            )
        }

        let redirectURI = request.query[String.self, at: OAuthRequestParameters.redirectURI]
        let scope = request.query[String.self, at: OAuthRequestParameters.scope]
        let state = request.query[String.self, at: OAuthRequestParameters.state]
        let codeChallenge = request.query[String.self, at: OAuthRequestParameters.codeChallenge]
        let codeChallengeMethod = request.query[String.self, at: OAuthRequestParameters.codeChallengeMethod]
        let authorizationDetails = request.query[String.self, at: OAuthRequestParameters.authorizationDetails]

        // Extract additional parameters (excluding known OAuth parameters)
        var additionalParameters: [String: String] = [:]
        let knownParameters = [
            OAuthRequestParameters.responseType,
            OAuthRequestParameters.clientID,
            OAuthRequestParameters.redirectURI,
            OAuthRequestParameters.scope,
            OAuthRequestParameters.state,
            OAuthRequestParameters.codeChallenge,
            OAuthRequestParameters.codeChallengeMethod,
            OAuthRequestParameters.authorizationDetails,
        ]

        // Note: We can't easily iterate over query parameters in Vapor
        // Additional parameters would need to be handled differently
        // For now, we'll focus on the standard OAuth parameters

        return AuthorizationRequestParameters(
            responseType: responseType,
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope,
            state: state,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            authorizationDetails: authorizationDetails,
            additionalParameters: additionalParameters
        )
    }
}

/// Response for a successful pushed authorization request
public struct PushedAuthorizationResponse: Codable, Sendable, AsyncResponseEncodable {
    /// The request URI that can be used to reference the pushed request
    public let requestURI: String

    /// The expiration time of the request (Unix timestamp)
    public let expiresIn: Int

    /// Initialize a pushed authorization response
    /// - Parameters:
    ///   - requestURI: The request URI for the pushed request
    ///   - expiresIn: The expiration time in seconds
    public init(requestURI: String, expiresIn: Int) {
        self.requestURI = requestURI
        self.expiresIn = expiresIn
    }

    public func encodeResponse(for request: Request) async throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        let response = Response(body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: "application/json")
        return response
    }
}
