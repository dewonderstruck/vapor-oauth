import Foundation

public struct PARConfiguration: Sendable {
    /// The prefix for request URIs
    public let requestURIPrefix: String
    
    /// How long PAR requests are valid for (in seconds)
    public let expiresIn: Int
    
    /// Maximum allowed size of the request (in bytes)
    public let maxRequestSize: Int
    
    public init(
        requestURIPrefix: String = "urn:ietf:params:oauth:request_uri:",
        expiresIn: Int = 60,
        maxRequestSize: Int = 50_000
    ) {
        self.requestURIPrefix = requestURIPrefix
        self.expiresIn = expiresIn
        self.maxRequestSize = maxRequestSize
    }
}
