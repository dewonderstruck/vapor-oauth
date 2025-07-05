import Vapor

extension Request {
    var authService: AuthService {
        application.authService
    }
    
    var sessionService: SessionService {
        application.sessionService
    }
} 