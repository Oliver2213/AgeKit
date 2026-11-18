import CryptoKit
import XCTest
@testable import AgeKit

/// The chunk counter is an 11-byte big-endian integer followed by the last-chunk
/// flag byte. These cover the carry between bytes, which the generated round
/// trips (at most two chunks) never reach.
final class NonceTests: XCTestCase {
    func testIncrementCarriesIntoNextByte() {
        var nonce = Nonce()
        for _ in 0..<256 { nonce.increment() }
        XCTAssertEqual(nonce.nonce, Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]))
    }

    func testIncrementCarriesAcrossSeveralBytes() {
        var nonce = Nonce()
        for _ in 0..<(256 * 256 + 1) { nonce.increment() }
        XCTAssertEqual(nonce.nonce, Data([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]))
    }
}

extension StreamTests {
    /// More than 256 chunks — past the point where the counter's low byte wraps.
    func testRoundTripPastLowByteWrap() throws {
        try roundTrip(stepSize: chunkSize, length: chunkSize * 300 + 100)
    }
}
