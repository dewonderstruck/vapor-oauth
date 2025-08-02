import Vapor
import Logging

/// Utility for logging security-related events in OAuth flows
struct SecurityLogger: Sendable {
    private let logger: Logger
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    /// Logs origin validation failures for security monitoring
    /// - Parameters:
    ///   - clientID: The client ID that attempted the request
    ///   - attemptedOrigin: The origin that was attempted (nil if missing)
    ///   - authorizedOrigins: The list of authorized origins for the client
    ///   - request: The request object for additional metadata
    func logOriginValidationFailure(
        clientID: String,
        attemptedOrigin: String?,
        authorizedOrigins: [String]?,
        request: Request
    ) {
        let metadata: Logger.Metadata = [
            "event": "origin_validation_failure",
            "client_id": "\(clientID)",
            "attempted_origin": "\(attemptedOrigin ?? "missing")",
            "authorized_origins": "\(authorizedOrigins?.joined(separator: ",") ?? "none")",
            "remote_address": "\(request.remoteAddress?.description ?? "unknown")",
            "user_agent": "\(request.headers.first(name: .userAgent) ?? "unknown")"
        ]
        
        logger.warning("OAuth origin validation failed", metadata: metadata)
    }
    
    /// Logs successful origin validation for audit purposes
    /// - Parameters:
    ///   - clientID: The client ID that made the request
    ///   - validatedOrigin: The origin that was successfully validated
    ///   - request: The request object for additional metadata
    func logOriginValidationSuccess(
        clientID: String,
        validatedOrigin: String,
        request: Request
    ) {
        let metadata: Logger.Metadata = [
            "event": "origin_validation_success",
            "client_id": "\(clientID)",
            "validated_origin": "\(validatedOrigin)",
            "remote_address": "\(request.remoteAddress?.description ?? "unknown")"
        ]
        
        logger.info("OAuth origin validation succeeded", metadata: metadata)
    }
}