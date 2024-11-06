import VaporOAuth
import Vapor
/// Error types specific to issuer identification
public enum IssuerIdentificationError: Error {
    case metadataUnavailable(underlying: Error)
    case missingIssuer
}

extension OAuth2 {
    /// Adds RFC 9207 issuer identification support to the OAuth2 instance.
    ///
    /// This method wraps the existing authorize handler with issuer-aware functionality that includes
    /// the `iss` parameter in all authorization responses as specified in RFC 9207. The issuer value
    /// is obtained from the authorization server metadata.
    ///
    /// Example usage:
    /// ```swift
    /// let oauth = OAuth2(...)
    /// let oauthWithIssuer = try await oauth.withIssuerIdentification(logger: app.logger)
    /// ```
    ///
    /// - Parameter logger: Optional logger for diagnostic information
    /// - Returns: A new OAuth2 instance with issuer identification support
    /// - Throws: `IssuerIdentificationError` if metadata cannot be retrieved or issuer is missing
    public func withIssuerIdentification(
        logger: Logger? = nil
    ) async throws -> OAuth2 {
        var copy = self
        
        do {
            let metadata = try await metadataProvider.getMetadata()
            
            // Validate that issuer is not empty
            guard !metadata.issuer.isEmpty else {
                logger?.warning("OAuth issuer identification failed: metadata contains empty issuer")
                throw IssuerIdentificationError.missingIssuer
            }
            
            copy.authorizeHandler = IssuerAwareAuthorizeHandler(
                wrapped: authorizeHandler,
                issuer: metadata.issuer
            )
            
            logger?.info("OAuth issuer identification enabled with issuer: \(metadata.issuer)")
            return copy
            
        } catch let error as IssuerIdentificationError {
            // Re-throw our known error types
            logger?.error("OAuth issuer identification failed: \(error)")
            throw error
            
        } catch {
            // Wrap unknown errors
            logger?.error("OAuth issuer identification failed: unable to retrieve metadata: \(error)")
            throw IssuerIdentificationError.metadataUnavailable(underlying: error)
        }
    }
}

// MARK: - CustomStringConvertible
extension IssuerIdentificationError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .metadataUnavailable(let error):
            return "Failed to retrieve authorization server metadata: \(error)"
        case .missingIssuer:
            return "Authorization server metadata does not contain a valid issuer identifier"
        }
    }
}

// MARK: - LocalizedError
extension IssuerIdentificationError: LocalizedError {
    public var errorDescription: String? {
        description
    }
}

#if DEBUG
// MARK: - Testing Support
extension OAuth2 {
    /// Creates a new OAuth2 instance with issuer identification using a specific issuer value.
    /// This method is intended for testing purposes only.
    ///
    /// - Parameter issuer: The issuer value to use
    /// - Returns: A new OAuth2 instance with issuer identification support
    internal func withIssuerIdentification(testIssuer issuer: String) -> OAuth2 {
        var copy = self
        copy.authorizeHandler = IssuerAwareAuthorizeHandler(
            wrapped: authorizeHandler,
            issuer: issuer
        )
        return copy
    }
}
#endif
