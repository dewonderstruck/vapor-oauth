import Vapor

public struct PushedAuthorizationRequest: Content {
    public let requestURI: String
    public let expiresIn: Int
    
    public init(requestURI: String, expiresIn: Int) {
        self.requestURI = requestURI
        self.expiresIn = expiresIn
    }
    
    enum CodingKeys: String, CodingKey {
        case requestURI = "request_uri"
        case expiresIn = "expires_in"
    }
}
