import Vapor

extension Application {
    var authService: AuthService {
        guard let service = storage[AuthServiceKey.self] else {
            fatalError("AuthService not configured. Use app.authService = ...")
        }
        return service
    }
    
    var sessionService: SessionService {
        guard let service = storage[SessionServiceKey.self] else {
            fatalError("SessionService not configured. Use app.sessionService = ...")
        }
        return service
    }
}

extension Application {
    func authService(_ service: AuthService) {
        storage[AuthServiceKey.self] = service
    }
    
    func sessionService(_ service: SessionService) {
        storage[SessionServiceKey.self] = service
    }
}

private struct AuthServiceKey: StorageKey {
    typealias Value = AuthService
}

private struct SessionServiceKey: StorageKey {
    typealias Value = SessionService
} 