import Vapor
import XCTest

@testable import VaporOAuth

final class RARBuilderTests: XCTestCase {

    // MARK: - Generic Builder Tests

    func testGenericBuilderWithDefaultRegistry() {
        let registry = DefaultRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: RARType.paymentInitiation, registry: registry)

        builder.action(RARAction.initiate)
        builder.action(RARAction.status)
        builder.location("https://api.example.com/payments")
        builder.data("amount", "100.00")
        builder.data("currency", "EUR")

        let detail = builder.build()

        XCTAssertEqual(detail.type, "payment_initiation")
        XCTAssertEqual(detail.actions, ["initiate", "status"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/payments"])
        XCTAssertEqual(detail.data?["amount"]?.value as? String, "100.00")
        XCTAssertEqual(detail.data?["currency"]?.value as? String, "EUR")
    }

    func testGenericBuilderWithCustomRegistry() {
        let registry = CustomRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: CustomRARType.documentAccess, registry: registry)

        builder.action(CustomRARAction.read)
        builder.action(CustomRARAction.download)
        builder.location("https://api.example.com/documents")
        builder.data("documentId", "12345")
        builder.custom("maxSize", "10MB")

        let detail = builder.build()

        XCTAssertEqual(detail.type, "document_access")
        XCTAssertEqual(detail.actions, ["read", "download"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/documents"])
        XCTAssertEqual(detail.data?["documentId"]?.value as? String, "12345")
        XCTAssertEqual(detail.custom?["maxSize"]?.value as? String, "10MB")
    }

    func testGenericBuilderWithStringType() {
        let registry = DefaultRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: "custom_analytics", registry: registry)

        builder.action("aggregate")
        builder.action("export")
        builder.locations(["https://api.example.com/analytics", "https://api.example.com/reports"])
        builder.data("timeRange", "30d")
        builder.data("format", "csv")

        let detail = builder.build()

        XCTAssertEqual(detail.type, "custom_analytics")
        XCTAssertEqual(detail.actions, ["aggregate", "export"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/analytics", "https://api.example.com/reports"])
        XCTAssertEqual(detail.data?["timeRange"]?.value as? String, "30d")
        XCTAssertEqual(detail.data?["format"]?.value as? String, "csv")
    }

    func testGenericBuilderUseDefaultActions() {
        let registry = DefaultRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: RARType.paymentInitiation, registry: registry)

        // Don't specify actions, use defaults
        builder.useDefaultActions()

        let detail = builder.build()

        XCTAssertEqual(detail.type, "payment_initiation")
        XCTAssertEqual(detail.actions, ["initiate", "status", "cancel"])  // Default actions for payment_initiation
    }

    func testGenericBuilderUseDefaultActionsWithCustomType() {
        let registry = CustomRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: CustomRARType.documentAccess, registry: registry)

        // Don't specify actions, use defaults
        builder.useDefaultActions()

        let detail = builder.build()

        XCTAssertEqual(detail.type, "document_access")
        XCTAssertEqual(detail.actions, ["read", "download"])  // Default actions for document_access
    }

    func testGenericBuilderWithMixedActions() {
        let registry = DefaultRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: RARType.accountAccess, registry: registry)

        builder.action(RARAction.read)
        builder.action("custom_action")  // String action
        builder.action(RARAction.write)

        let detail = builder.build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertEqual(detail.actions, ["read", "custom_action", "write"])
    }

    // MARK: - AuthorizationDetailBuilder Tests (Type Alias)

    func testAuthorizationDetailBuilder() {
        var builder = AuthorizationDetailBuilder(type: RARType.accountAccess, registry: DefaultRARTypeRegistry())

        builder.action(RARAction.read)
        builder.location("https://api.example.com/accounts")
        builder.data("accountId", "12345")

        let detail = builder.build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertEqual(detail.actions, ["read"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/accounts"])
        XCTAssertEqual(detail.data?["accountId"]?.value as? String, "12345")
    }

    func testAuthorizationDetailBuilderWithStringType() {
        var builder = AuthorizationDetailBuilder(type: "custom_type", registry: DefaultRARTypeRegistry())

        builder.action("custom_action")
        builder.locations(["https://api.example.com/custom"])
        builder.data("customField", "customValue")

        let detail = builder.build()

        XCTAssertEqual(detail.type, "custom_type")
        XCTAssertEqual(detail.actions, ["custom_action"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/custom"])
        XCTAssertEqual(detail.data?["customField"]?.value as? String, "customValue")
    }

    // MARK: - Convenience Methods Tests

    func testPaymentInitiationConvenienceMethod() {
        let detail = AuthorizationDetailBuilder.paymentInitiation(
            actions: [.initiate, .status],
            locations: ["https://api.example.com/payments"],
            data: ["amount": "100.00", "currency": "EUR"]
        ).build()

        XCTAssertEqual(detail.type, "payment_initiation")
        XCTAssertEqual(detail.actions, ["initiate", "status"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/payments"])
        XCTAssertEqual(detail.data?["amount"]?.value as? String, "100.00")
        XCTAssertEqual(detail.data?["currency"]?.value as? String, "EUR")
    }

    func testAccountAccessConvenienceMethod() {
        let detail = AuthorizationDetailBuilder.accountAccess(
            actions: [.read],
            locations: ["https://api.example.com/accounts"],
            data: ["accountId": "12345"]
        ).build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertEqual(detail.actions, ["read"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/accounts"])
        XCTAssertEqual(detail.data?["accountId"]?.value as? String, "12345")
    }

    func testDataAccessConvenienceMethod() {
        let detail = AuthorizationDetailBuilder.dataAccess(
            actions: [.read, .write],
            locations: ["https://api.example.com/data"],
            data: ["scope": "user_data"]
        ).build()

        XCTAssertEqual(detail.type, "data_access")
        XCTAssertEqual(detail.actions, ["read", "write"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/data"])
        XCTAssertEqual(detail.data?["scope"]?.value as? String, "user_data")
    }

    func testCustomConvenienceMethod() {
        let detail = AuthorizationDetailBuilder.custom(
            type: "custom_analytics",
            locations: ["https://api.example.com/analytics"],
            data: ["timeRange": "30d", "format": "json"]
        ).build()

        XCTAssertEqual(detail.type, "custom_analytics")
        XCTAssertNil(detail.actions)  // No default actions for custom types
        XCTAssertEqual(detail.locations, ["https://api.example.com/analytics"])
        XCTAssertEqual(detail.data?["timeRange"]?.value as? String, "30d")
        XCTAssertEqual(detail.data?["format"]?.value as? String, "json")
    }

    func testDefaultActionsInConvenienceMethods() {
        // Test that convenience methods use default actions when not specified
        let paymentDetail = AuthorizationDetailBuilder.paymentInitiation().build()
        XCTAssertEqual(paymentDetail.actions, ["initiate", "status", "cancel"])

        let accountDetail = AuthorizationDetailBuilder.accountAccess().build()
        XCTAssertEqual(accountDetail.actions, ["read"])

        let dataDetail = AuthorizationDetailBuilder.dataAccess().build()
        XCTAssertEqual(dataDetail.actions, ["read"])
    }

    // MARK: - Builder Chaining Tests

    func testBuilderChaining() {
        var builder = AuthorizationDetailBuilder(type: RARType.accountAccess, registry: DefaultRARTypeRegistry())
        builder.action(RARAction.read)
        builder.action(RARAction.write)
        builder.location("https://api.example.com/accounts")
        builder.location("https://api.example.com/accounts/v2")
        builder.data("accountId", "12345")
        builder.data("permissions", ["read", "write"])
        builder.custom("metadata", "additional_info")

        let detail = builder.build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertEqual(detail.actions, ["read", "write"])
        XCTAssertEqual(detail.locations, ["https://api.example.com/accounts", "https://api.example.com/accounts/v2"])
        XCTAssertEqual(detail.data?["accountId"]?.value as? String, "12345")
        XCTAssertEqual(detail.data?["permissions"]?.value as? [String], ["read", "write"])
        XCTAssertEqual(detail.custom?["metadata"]?.value as? String, "additional_info")
    }

    // MARK: - Edge Cases Tests

    func testEmptyBuilder() {
        let detail = AuthorizationDetailBuilder(type: RARType.accountAccess, registry: DefaultRARTypeRegistry()).build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertNil(detail.actions)
        XCTAssertNil(detail.locations)
        XCTAssertNil(detail.data)
        XCTAssertNil(detail.custom)
    }

    func testBuilderWithEmptyArrays() {
        var builder = AuthorizationDetailBuilder(type: RARType.accountAccess, registry: DefaultRARTypeRegistry())
        builder.actions([])
        builder.locations([])

        let detail = builder.build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertNil(detail.actions)  // Empty arrays become nil
        XCTAssertNil(detail.locations)  // Empty arrays become nil
    }

    func testBuilderWithComplexData() {
        let complexData: [String: Any] = [
            "nested": [
                "field1": "value1",
                "field2": 42,
                "field3": [1, 2, 3],
            ],
            "array": ["item1", "item2"],
            "boolean": true,
            "number": 3.14,
        ]

        var builder = AuthorizationDetailBuilder(type: RARType.accountAccess, registry: DefaultRARTypeRegistry())
        for (key, value) in complexData {
            builder.data(key, value)
        }

        let detail = builder.build()

        XCTAssertEqual(detail.type, "account_access")
        XCTAssertNotNil(detail.data)
        XCTAssertEqual(detail.data?.count, 4)
    }

    // MARK: - Type Safety Tests

    func testTypeSafetyWithProtocols() {
        // Test that we can use protocol-based types
        let types: [any RARTypeProtocol] = [RARType.paymentInitiation, CustomRARType.documentAccess]
        let actions: [any RARActionProtocol] = [RARAction.read, CustomRARAction.download]

        let registry = DefaultRARTypeRegistry()
        var builder = GenericAuthorizationDetailBuilder(type: types[0], registry: registry)
        builder.action(actions[0])

        let detail = builder.build()
        XCTAssertEqual(detail.type, "payment_initiation")
        XCTAssertEqual(detail.actions, ["read"])
    }

    func testGenericBuilderWithDifferentRegistries() {
        // Test that different registries work correctly
        let defaultRegistry = DefaultRARTypeRegistry()
        let customRegistry = CustomRARTypeRegistry()

        var defaultBuilder = GenericAuthorizationDetailBuilder(type: RARType.accountAccess, registry: defaultRegistry)
        defaultBuilder.action(RARAction.read)

        var customBuilder = GenericAuthorizationDetailBuilder(type: CustomRARType.documentAccess, registry: customRegistry)
        customBuilder.action(CustomRARAction.download)

        let defaultDetail = defaultBuilder.build()
        let customDetail = customBuilder.build()

        XCTAssertEqual(defaultDetail.type, "account_access")
        XCTAssertEqual(defaultDetail.actions, ["read"])

        XCTAssertEqual(customDetail.type, "document_access")
        XCTAssertEqual(customDetail.actions, ["download"])
    }
}
