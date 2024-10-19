import Vapor

public protocol RefreshToken: Sendable {
    var tokenString: String { get set }
    var clientID: String { get set }
    var userID: String? { get set }
    var scopes: [String]? { get set }
}
