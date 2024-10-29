import Vapor

public enum PARError: AbortError, Equatable {
    case invalidRequest(reason: String)
    case requestTooLarge
    case unsupportedGrantType
    case invalidClient
    
    public var status: HTTPStatus {
        switch self {
        case .invalidRequest: return .badRequest
        case .requestTooLarge: return .payloadTooLarge  // 413
        case .unsupportedGrantType: return .badRequest
        case .invalidClient: return .unauthorized
        }
    }
    
    public var reason: String {
        switch self {
        case .invalidRequest(let reason): return reason
        case .requestTooLarge: return "Request exceeds maximum allowed size"
        case .unsupportedGrantType: return "Unsupported grant type"
        case .invalidClient: return "Invalid client credentials"
        }
    }
}
