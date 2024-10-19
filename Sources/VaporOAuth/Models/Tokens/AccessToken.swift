import Vapor

public protocol AccessToken: Sendable {
    var tokenString: String { get }
    var clientID: String { get }
    var userID: String? { get }
    var scopes: [String]? { get }
    var expiryTime: Date { get }
}
