public struct PKCEParameters: Sendable {
    public let codeChallenge: String
    public let codeChallengeMethod: CodeChallengeMethod
    
    public enum CodeChallengeMethod: String, Sendable {
        case plain = "plain"
        case s256 = "S256"
    }
    
    public init(codeChallenge: String, codeChallengeMethod: CodeChallengeMethod = .s256) {
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
    }
}
