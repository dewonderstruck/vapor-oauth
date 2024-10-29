import Foundation

public enum PARConstants {
    public static let defaultExpirationInterval: TimeInterval = 60
    public static let maxRequestSize: Int = 50_000
    public static let endpointPath = "oauth/par"
    
    public enum Parameters {
        public static let requestURI = "request_uri"
        public static let expiresIn = "expires_in"
    }
    
    public enum Headers {
        public static let contentType = "application/x-www-form-urlencoded"
    }
}
