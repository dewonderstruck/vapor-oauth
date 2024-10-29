import Vapor
import VaporOAuth

public struct PARHandler : Sendable {
    private let clientValidator: ClientValidator
    private let storage: PARRequestStorage
    private let configuration: PARConfiguration
    private let validator: PARRequestValidator
    
    public init(
        clientValidator: ClientValidator,
        storage: PARRequestStorage,
        configuration: PARConfiguration,
        validator: PARRequestValidator = PARRequestValidator()
    ) {
        self.clientValidator = clientValidator
        self.storage = storage
        self.configuration = configuration
        self.validator = validator
    }
    
    @Sendable
    public func handlePARRequest(_ req: Request) async throws -> Response {
        // Validate request size first
        guard let contentLength = req.headers.first(name: .contentLength),
              Int(contentLength) ?? 0 <= configuration.maxRequestSize else {
            let response = Response(status: .badRequest)
            try response.content.encode(ErrorResponse(
                error: "invalid_request",
                errorDescription: "Request exceeds maximum allowed size"
            ))
            return response
        }
        
        // Check required parameters
        guard let clientID = req.content[String.self, at: OAuthRequestParameters.clientID] else {
            let response = Response(status: .badRequest)
            try response.content.encode(ErrorResponse(
                error: "invalid_request",
                errorDescription: "Missing client_id parameter"
            ))
            return response
        }
        
        // Authenticate client
        do {
            try await clientValidator.authenticateClient(
                clientID: clientID,
                clientSecret: req.content[String.self, at: OAuthRequestParameters.clientSecret],
                grantType: .authorization
            )
        } catch {
            let response = Response(status: .unauthorized)
            try response.content.encode(ErrorResponse(
                error: "invalid_client",
                errorDescription: "Invalid client credentials"
            ))
            return response
        }
        
        // Validate request parameters
        let parRequest: PARRequest
        do {
            parRequest = try await validator.validateRequest(req)
        } catch {
            let response = Response(status: .badRequest)
            try response.content.encode(ErrorResponse(
                error: "invalid_request",
                errorDescription: "Invalid request parameters"
            ))
            return response
        }
        
        // Generate request URI and store the request
        let requestURI = "\(configuration.requestURIPrefix)\(UUID().uuidString)"
        try await storage.store(parRequest, withURI: requestURI)
        
        // Return success response
        let response = Response(status: .created)
        try response.content.encode(
            PushedAuthorizationRequest(
                requestURI: requestURI,
                expiresIn: configuration.expiresIn
            )
        )
        return response
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
