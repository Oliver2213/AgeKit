import CryptoKit
import XCTest
import AgeKit

/// Passphrase (scrypt) files checked against output from another implementation.
/// A self round trip can't reliably catch a wrong KDF. The previous scrypt dependency
/// (libscrypt) was correct in debug but derived wrong keys under optimization, so
/// run these with `swift test -c release` too.
final class ScryptVectorTests: XCTestCase {
    static let passphrase = "testest"
    static let plaintext = "age scrypt test vector\n"

    /// `rage -p -a` (rage 0.12.1), passphrase "testest", scrypt work factor 19.
    static let rageArmorBody = """
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCAxT2x0eUw5eHVQb2ZjREdX
        dGRxMTl3IDE5Cmh3ZnBEanRaMGhOSjVzcEc2N05PQjRzWGZCODBSUU9hMFhRM0dk
        ZjlnaEkKLS0tIG9wd3pVd0o5Zi9oeElOM056MUc2YlJSdnJtL2U0THpMYlBpK0VM
        aXBSYjAK4axCr49VpfCEI6vvqT/m0f+KeCna0Qh7gHTsNTsNpNenaik5Zdv9w1MW
        Q9BnGnnE1fMui14b0w==
        """

    func testDecryptsRageOutput() throws {
        let file = try XCTUnwrap(Data(base64Encoded: Self.rageArmorBody, options: .ignoreUnknownCharacters))
        XCTAssertEqual(try decrypt(file, passphrase: Self.passphrase), Data(Self.plaintext.utf8))
    }

    func testRejectsWrongPassphraseOnRageOutput() throws {
        let file = try XCTUnwrap(Data(base64Encoded: Self.rageArmorBody, options: .ignoreUnknownCharacters))
        XCTAssertThrowsError(try decrypt(file, passphrase: "wrong"))
    }

    /// Our own output must decrypt too. A sanity check only: a self round trip can
    /// pass with a broken KDF (libscrypt's release build passed this), so the rage
    /// vector above is the real regression guard.
    func testRoundTrip() throws {
        var recipient = try XCTUnwrap(Age.ScryptRecipient(password: Self.passphrase))
        recipient.setWorkFactor(10)
        var out: OutputStream = .toMemory()
        out.open()
        var writer = try Age.encrypt(dst: &out, recipients: recipient)
        _ = try writer.write(Self.plaintext)
        try writer.close()
        out.close()
        let file = try XCTUnwrap(out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data)

        XCTAssertEqual(try decrypt(file, passphrase: Self.passphrase), Data(Self.plaintext.utf8))
    }

    private func decrypt(_ file: Data, passphrase: String) throws -> Data {
        let src = InputStream(data: file)
        src.open()
        var reader = try Age.decrypt(src: src, identities: XCTUnwrap(Age.ScryptIdentity(passphrase)))
        var plaintext = Data()
        var buf = Data(count: 64 * 1024)
        while true {
            let n: Int
            do { n = try reader.read(&buf) } catch where "\(error)" == "unexpectedEOF" { break }
            if n == 0 { break }
            plaintext.append(buf.prefix(n))
        }
        return plaintext
    }
}
