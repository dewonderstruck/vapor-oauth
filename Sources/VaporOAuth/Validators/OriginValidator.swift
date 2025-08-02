import Vapor

/// Validator for OAuth client authorized origins
///
/// Provides comprehensive origin validation including exact matching and wildcard pattern support.
/// Helps prevent CSRF attacks by ensuring only trusted origins can initiate OAuth flows.
struct OriginValidator: Sendable {
    
    /// Validates an origin against a list of authorized origins
    /// 
    /// Supports both exact matching and wildcard patterns (e.g., "*.example.com").
    /// Performs case-insensitive domain matching while preserving protocol and port sensitivity.
    /// 
    /// - Parameters:
    ///   - origin: The origin to validate (e.g., "https://app.example.com")
    ///   - authorizedOrigins: List of authorized origins/patterns
    /// - Returns: Whether the origin is authorized
    func validateOrigin(_ origin: String, against authorizedOrigins: [String]) -> Bool {
        // Empty authorized origins list means no validation (backward compatibility)
        guard !authorizedOrigins.isEmpty else {
            return true
        }
        
        // Validate that wildcard patterns are not overly broad
        for pattern in authorizedOrigins {
            if isOverlyBroadPattern(pattern) {
                // Log warning but continue validation - don't fail the entire validation
                // In production, this should be caught during client configuration
                continue
            }
        }
        
        // Check for exact match first (most common case)
        for authorizedOrigin in authorizedOrigins {
            if exactMatch(origin: origin, authorized: authorizedOrigin) {
                return true
            }
        }
        
        // Check for wildcard pattern matches
        for authorizedOrigin in authorizedOrigins {
            if matchesPattern(origin, pattern: authorizedOrigin) {
                return true
            }
        }
        
        return false
    }
    
    /// Checks if an origin matches a pattern (supports wildcards)
    /// 
    /// Supports subdomain wildcard patterns in the format "*.domain.com".
    /// Validates that wildcards are not overly broad (e.g., rejects "*.com").
    /// 
    /// - Parameters:
    ///   - origin: The origin to check
    ///   - pattern: The pattern to match against
    /// - Returns: Whether the origin matches the pattern
    func matchesPattern(_ origin: String, pattern: String) -> Bool {
        // First check if it's an exact match (non-wildcard)
        if !pattern.contains("*") {
            return exactMatch(origin: origin, authorized: pattern)
        }
        
        // Only support subdomain wildcards (*.domain.com)
        guard pattern.hasPrefix("*.") else {
            return false
        }
        
        // Validate that the pattern is not overly broad
        guard !isOverlyBroadPattern(pattern) else {
            return false
        }
        
        let patternDomain = String(pattern.dropFirst(2)).lowercased() // Remove "*." and normalize case
        let originDomain = extractDomain(from: origin)
        
        // Wildcard matches both subdomains and the root domain
        // e.g., "*.example.com" matches both "app.example.com" and "example.com"
        return originDomain.hasSuffix("." + patternDomain) || originDomain == patternDomain
    }
    
    /// Validates origin for device code flow requests
    /// 
    /// Device code flow can originate from browsers when users initiate the flow,
    /// so origin validation is applicable. However, it's more lenient than authorization
    /// flows since the actual authorization happens on a different device.
    /// 
    /// - Parameters:
    ///   - client: The OAuth client to validate against
    ///   - request: The HTTP request containing the origin header
    ///   - securityLogger: Optional security logger for logging validation events
    /// - Throws: AuthorizationError.unauthorizedOrigin or AuthorizationError.missingOrigin
    func validateOriginForDeviceFlow(client: OAuthClient, request: Request, securityLogger: SecurityLogger? = nil) throws {
        // Skip origin validation if no authorized origins are configured (backward compatibility)
        guard let authorizedOrigins = client.authorizedOrigins, !authorizedOrigins.isEmpty else {
            return
        }
        
        // For device code flow, origin validation is optional if the request doesn't come from a browser
        // Check if this is a browser-based request by looking for common browser headers
        let isBrowserRequest = request.headers.contains(name: .origin) || 
                              request.headers.contains(name: .referer) ||
                              request.headers.first(name: .userAgent)?.contains("Mozilla") == true
        
        // If it's not a browser request, skip origin validation
        guard isBrowserRequest else {
            return
        }
        
        // Extract origin from request
        guard let origin = extractOrigin(from: request) else {
            // For device code flow, missing origin is only an error if we detected it's a browser request
            securityLogger?.logOriginValidationFailure(
                clientID: client.clientID,
                attemptedOrigin: nil,
                authorizedOrigins: authorizedOrigins,
                request: request
            )
            throw AuthorizationError.missingOrigin
        }
        
        // Validate origin against authorized origins
        guard validateOrigin(origin, against: authorizedOrigins) else {
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
    
    /// Extracts and validates the origin from request headers
    /// 
    /// Safely extracts the Origin header from HTTP requests.
    /// Handles cases where multiple Origin headers might be present (uses first valid one).
    /// Validates that the origin is well-formed.
    /// 
    /// - Parameter request: The HTTP request
    /// - Returns: The origin string if present and valid, nil otherwise
    func extractOrigin(from request: Request) -> String? {
        // Get the Origin header
        guard let origin = request.headers.first(name: .origin) else {
            return nil
        }
        
        // Basic validation - origin should not be empty
        guard !origin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        
        let trimmedOrigin = origin.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Basic format validation - should contain protocol or be a valid domain
        if isValidOriginFormat(trimmedOrigin) {
            return trimmedOrigin
        }
        
        return nil
    }
    
    /// Validates origin configuration for security during client setup
    /// 
    /// Performs comprehensive validation of authorized origins configuration to ensure
    /// security best practices are followed. This should be called during client registration
    /// or configuration updates to prevent insecure origin patterns.
    /// 
    /// - Parameters:
    ///   - authorizedOrigins: The list of authorized origins to validate
    ///   - requireHTTPS: Whether to require HTTPS origins (typically true in production)
    /// - Throws: OriginValidationError for various security violations
    func validateOriginConfiguration(_ authorizedOrigins: [String]?, requireHTTPS: Bool = false) throws {
        guard let origins = authorizedOrigins, !origins.isEmpty else {
            // Empty or nil origins is valid (backward compatibility)
            return
        }
        
        for origin in origins {
            try validateSingleOriginConfiguration(origin, requireHTTPS: requireHTTPS)
        }
    }
    
    /// Validates a single origin configuration for security
    /// 
    /// - Parameters:
    ///   - origin: The origin pattern to validate
    ///   - requireHTTPS: Whether to require HTTPS origins
    /// - Throws: OriginValidationError for security violations
    private func validateSingleOriginConfiguration(_ origin: String, requireHTTPS: Bool) throws {
        // Check for empty or whitespace-only origins
        let trimmedOrigin = origin.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedOrigin.isEmpty else {
            throw OriginValidationError.invalidOriginFormat
        }
        
        // Check for overly broad wildcard patterns
        if trimmedOrigin.hasPrefix("*.") {
            guard !isOverlyBroadPattern(trimmedOrigin) else {
                throw OriginValidationError.overlyBroadPattern
            }
            
            // Additional wildcard security checks
            try validateWildcardSecurity(trimmedOrigin)
        }
        
        // Validate origin format
        guard isValidOriginFormat(trimmedOrigin) else {
            throw OriginValidationError.invalidOriginFormat
        }
        
        // Check HTTPS requirement if specified
        if requireHTTPS {
            try validateHTTPSRequirement(trimmedOrigin)
        }
        
        // Additional security validations
        try validateOriginSecurity(trimmedOrigin)
    }
    
    /// Validates wildcard pattern security
    /// 
    /// - Parameter pattern: The wildcard pattern to validate
    /// - Throws: OriginValidationError for insecure patterns
    private func validateWildcardSecurity(_ pattern: String) throws {
        let domainPart = String(pattern.dropFirst(2)) // Remove "*."
        
        // Reject patterns with multiple wildcards
        guard !domainPart.contains("*") else {
            throw OriginValidationError.overlyBroadPattern
        }
        
        // Reject patterns that would match localhost variations
        let lowercaseDomain = domainPart.lowercased()
        let dangerousPatterns = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        for dangerous in dangerousPatterns {
            if lowercaseDomain.contains(dangerous) {
                throw OriginValidationError.overlyBroadPattern
            }
        }
        
        // Ensure the domain part has proper structure
        let components = domainPart.components(separatedBy: ".")
        guard components.count >= 2 else {
            throw OriginValidationError.overlyBroadPattern
        }
        
        // Check for empty components
        for component in components {
            guard !component.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw OriginValidationError.invalidOriginFormat
            }
        }
    }
    
    /// Validates HTTPS requirement for origins
    /// 
    /// - Parameter origin: The origin to validate
    /// - Throws: OriginValidationError.insecureOrigin if HTTP is used when HTTPS is required
    private func validateHTTPSRequirement(_ origin: String) throws {
        // Allow localhost and 127.0.0.1 to use HTTP even when HTTPS is required (development)
        let isLocalhost = origin.contains("localhost") || origin.contains("127.0.0.1") || origin.contains("::1")
        
        if !isLocalhost {
            // If origin has protocol, it must be HTTPS
            if origin.contains("://") {
                guard origin.lowercased().hasPrefix("https://") else {
                    throw OriginValidationError.insecureOrigin
                }
            }
            // If no protocol specified, we assume it can be used with HTTPS
        }
    }
    
    /// Validates general origin security
    /// 
    /// - Parameter origin: The origin to validate
    /// - Throws: OriginValidationError for security violations
    private func validateOriginSecurity(_ origin: String) throws {
        // Check for suspicious characters that could indicate injection attempts
        let suspiciousChars = CharacterSet(charactersIn: "<>\"'`\\")
        guard origin.rangeOfCharacter(from: suspiciousChars) == nil else {
            throw OriginValidationError.invalidOriginFormat
        }
        
        // Check for control characters
        guard origin.rangeOfCharacter(from: .controlCharacters) == nil else {
            throw OriginValidationError.invalidOriginFormat
        }
        
        // Validate length (prevent extremely long origins)
        guard origin.count <= 2048 else {
            throw OriginValidationError.invalidOriginFormat
        }
        
        // Check for multiple protocols (potential injection)
        let protocolCount = origin.components(separatedBy: "://").count - 1
        guard protocolCount <= 1 else {
            throw OriginValidationError.invalidOriginFormat
        }
        
        // If it contains a protocol, validate the protocol part
        if let protocolRange = origin.range(of: "://") {
            let protocolPart = String(origin[..<protocolRange.lowerBound]).lowercased()
            let allowedProtocols = ["http", "https"]
            guard allowedProtocols.contains(protocolPart) else {
                throw OriginValidationError.invalidOriginFormat
            }
        }
    }
    
    // MARK: - Private Helper Methods
    
    /// Checks for exact match between origin and authorized origin
    /// 
    /// Performs case-insensitive domain matching while preserving protocol and port sensitivity.
    /// Also handles cases where authorized origin is domain-only (no protocol).
    /// 
    /// - Parameters:
    ///   - origin: The origin to check
    ///   - authorized: The authorized origin to match against
    /// - Returns: Whether they match exactly
    private func exactMatch(origin: String, authorized: String) -> Bool {
        let normalizedOrigin = normalizeOrigin(origin)
        let normalizedAuthorized = normalizeOrigin(authorized)
        
        // Direct match
        if normalizedOrigin == normalizedAuthorized {
            return true
        }
        
        // If authorized doesn't have protocol, check if origin domain matches
        if !authorized.contains("://") {
            let originDomain = extractDomain(from: origin)
            let authorizedDomain = authorized.lowercased()
            return originDomain == authorizedDomain
        }
        
        return false
    }
    
    /// Normalizes an origin for comparison
    /// 
    /// Makes domain part case-insensitive while preserving protocol and port.
    /// 
    /// - Parameter origin: The origin to normalize
    /// - Returns: The normalized origin
    private func normalizeOrigin(_ origin: String) -> String {
        // Split protocol and domain parts
        if let protocolRange = origin.range(of: "://") {
            let protocolPart = String(origin[..<protocolRange.upperBound])
            let domainPart = String(origin[protocolRange.upperBound...])
            return protocolPart + domainPart.lowercased()
        } else {
            // No protocol, just lowercase the whole thing
            return origin.lowercased()
        }
    }
    
    /// Extracts the domain from an origin URL
    /// 
    /// Removes protocol and port to get just the domain part.
    /// 
    /// - Parameter origin: The origin URL (e.g., "https://app.example.com:8080")
    /// - Returns: The domain part (e.g., "app.example.com")
    private func extractDomain(from origin: String) -> String {
        var domain = origin
        
        // Remove protocol
        if let protocolRange = domain.range(of: "://") {
            domain = String(domain[protocolRange.upperBound...])
        }
        
        // Remove port
        if let portRange = domain.range(of: ":") {
            domain = String(domain[..<portRange.lowerBound])
        }
        
        return domain.lowercased()
    }
    
    /// Validates that wildcard patterns are not overly broad
    /// 
    /// Prevents patterns like "*.com", "*.org" that would match too many domains.
    /// Requires at least one dot in the domain part after the wildcard.
    /// 
    /// - Parameter pattern: The pattern to validate
    /// - Returns: Whether the pattern is overly broad
    private func isOverlyBroadPattern(_ pattern: String) -> Bool {
        guard pattern.hasPrefix("*.") else {
            return false
        }
        
        let domainPart = String(pattern.dropFirst(2))
        
        // Pattern is overly broad if:
        // 1. It's just a TLD (e.g., "*.com", "*.org")
        // 2. It doesn't contain at least one dot (e.g., "*.localhost")
        let components = domainPart.components(separatedBy: ".")
        
        // Must have at least 2 components (e.g., "example.com" not just "com")
        if components.count < 2 {
            return true
        }
        
        // Check for common TLDs that would be too broad
        let broadTLDs = ["com", "org", "net", "edu", "gov", "mil", "int", "co", "io"]
        if components.count == 1 && broadTLDs.contains(components[0].lowercased()) {
            return true
        }
        
        return false
    }
    
    /// Validates that an origin has a valid format
    /// 
    /// Checks basic format requirements for origins.
    /// 
    /// - Parameter origin: The origin to validate
    /// - Returns: Whether the origin format is valid
    private func isValidOriginFormat(_ origin: String) -> Bool {
        // Must not be empty
        guard !origin.isEmpty else {
            return false
        }
        
        // If it contains "://", it should be a full URL
        if origin.contains("://") {
            // Basic URL validation - should have protocol and domain
            let components = origin.components(separatedBy: "://")
            guard components.count == 2 else {
                return false
            }
            
            let protocolPart = components[0]
            let domainPart = components[1]
            
            // Protocol should be http or https
            guard ["http", "https"].contains(protocolPart.lowercased()) else {
                return false
            }
            
            // Domain part should not be empty and should not end with just "/"
            guard !domainPart.isEmpty && domainPart != "/" else {
                return false
            }
            
            // Check for double dots in domain (invalid)
            guard !domainPart.contains("..") else {
                return false
            }
            
            // Extract just the domain part (remove path, query, etc.)
            let domainOnly = domainPart.components(separatedBy: "/")[0]
            
            // Domain should not be empty after removing path
            guard !domainOnly.isEmpty else {
                return false
            }
            
            return true
        } else {
            // If no protocol, should be a valid domain name
            // Basic domain validation - should contain at least one dot or be localhost
            // Also check for double dots
            guard !origin.contains("..") else {
                return false
            }
            
            return origin.contains(".") || origin.lowercased() == "localhost"
        }
    }
}

/// Errors related to origin validation
public enum OriginValidationError: Error, Sendable {
    case unauthorizedOrigin
    case missingOrigin
    case invalidOriginFormat
    case overlyBroadPattern
    case insecureOrigin
}