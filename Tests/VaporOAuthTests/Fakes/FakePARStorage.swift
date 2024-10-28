import Foundation
import VaporOAuthPAR 

class FakePARStorage: PARRequestStorage { 
    var storedRequests: [String: PARRequest] = [:] 
    var storeCallCount = 0 
    var retrieveCallCount = 0 
    var removeCallCount = 0 
    
    func store(_ request: PARRequest, withURI requestURI: String) async throws { 
        storeCallCount += 1 
        storedRequests[requestURI] = request 
    } 
        
    func retrieve(requestURI: String) async throws -> PARRequest? { 
        retrieveCallCount += 1 
        return storedRequests[requestURI] 
    } 
            
    func remove(requestURI: String) async throws { 
        removeCallCount += 1
        storedRequests.removeValue(forKey: requestURI)
    }

    func removeExpired() async throws { 
        // No-op
    }
}