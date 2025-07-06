import Foundation

/// Represents a single authorization detail as defined in RFC 9396
public struct AuthorizationDetail: Codable, Sendable {
    /// The type of authorization being requested (REQUIRED)
    public let type: String

    /// The actions being requested for this resource type (OPTIONAL)
    public let actions: [String]?

    /// The locations (URIs) where the authorization applies (OPTIONAL)
    public let locations: [String]?

    /// Additional data specific to the authorization type (OPTIONAL)
    public let data: [String: AnyCodable]?

    /// Custom fields specific to the authorization type (OPTIONAL)
    public let custom: [String: AnyCodable]?

    public init(
        type: String,
        actions: [String]? = nil,
        locations: [String]? = nil,
        data: [String: AnyCodable]? = nil,
        custom: [String: AnyCodable]? = nil
    ) {
        self.type = type
        self.actions = actions
        self.locations = locations
        self.data = data
        self.custom = custom
    }
}

/// Helper type for encoding/decoding arbitrary JSON values
public struct AnyCodable: Codable, @unchecked Sendable {
    public let value: Any

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self.value = ()
        } else if let bool = try? container.decode(Bool.self) {
            self.value = bool
        } else if let int = try? container.decode(Int.self) {
            self.value = int
        } else if let double = try? container.decode(Double.self) {
            self.value = double
        } else if let string = try? container.decode(String.self) {
            self.value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            self.value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            self.value = dict.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "AnyCodable: cannot decode")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dict as [String: Any]:
            try container.encode(dict.mapValues { AnyCodable($0) })
        default:
            try container.encode(String(describing: value))
        }
    }
}
