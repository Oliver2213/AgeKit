import XCTest
import CryptoKit
@testable import AgeKit

/// Tests for the `ssh-ed25519` recipient/identity, ported from age's `agessh`.
///
/// Fixtures are a fixed Ed25519 SSH keypair (`cypherdex-test-plain`) and a
/// binary age file produced by `rage 0.10.0` encrypting a known plaintext to
/// that key — the cross-implementation proof that our wrap/unwrap matches age.
final class SSHEd25519Tests: XCTestCase {

    // MARK: Fixtures

    static let plainAuthorizedKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEmujjJWkoywNI8VHfDrnAkhNZqBhv7JUNe9fdXpby74 cypherdex-test-plain"
    static let plainEd25519PubB64 = "Sa6OMlaSjLA0jxUd8OucCSE1moGG/slQ17191elvLvg"
    static let plainMontgomeryB64 = "UcZcShWjt+cB7n5uNraekXuz7t4tWV11rL5BFRoymWs"
    static let plainFingerprint = "E9we8w"

    static let plaintext = "Cypherdex ssh-ed25519 interop vector v1"

    static let plainPrivatePEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACBJro4yVpKMsDSPFR3w65wJITWagYb+yVDXvX3V6W8u+AAAAJgJ5dF1CeXR
    dQAAAAtzc2gtZWQyNTUxOQAAACBJro4yVpKMsDSPFR3w65wJITWagYb+yVDXvX3V6W8u+A
    AAAEBCyKIU00Tw1b7QP602jmc6+XtTMTTGQM9tuA4J+FSa+EmujjJWkoywNI8VHfDrnAkh
    NZqBhv7JUNe9fdXpby74AAAAFGN5cGhlcmRleC10ZXN0LXBsYWluAQ==
    -----END OPENSSH PRIVATE KEY-----
    """

    /// A binary age file (base64) produced by `rage -r <plainAuthorizedKey>`.
    static let rageVectorB64 = """
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IEU5d2U4dyBRZm1KaERmbWdKSmpUMUJIb0hXWDR0aGRhZnFSVDBKUFlSNm9zSENSK1g0ClNBMEFsNTdoYkdGbXBGL2pEL1R1MDdvUzVyRXR1d2pGVm5DM2xWNysvSXMKLT4gOlh8LWdyZWFzZSArWiB9IFs8TyN9IDxdeQpSeC9pY2I2QlVIVFlDS1JWNUlrTW5hbVI5NUxmakl4eks4K1dHeEM0L0VLUVY3elhkaFVxbjlZZ1lRcTUKLS0tIEh5UWp6cVZPMW1tOVpndFlZMWxoaDNNUmRRQTF5Q2ltTkltclJKNUdJZUkKbifBtrDXYDpzdHnebeBmSQsRjF/23BQtjnkzLM7spY87US0XxNd1Ty+DG4JQsqybZUZYaQz4SDd2qr7c2+4IiYe1spjgpwA=
    """

    // Passphrase-protected fixtures (passphrase: "testpass", aes256-ctr + bcrypt).
    static let encFingerprint = "TMjdjA"
    static let encPassphrase = "testpass"
    static let encPrivatePEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAaGqOGhU
    BmRJZ9236kKNXpAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINKsk9Qu8YaRTq58
    /IYSt/6bT8k/keQY0ihoVV5FWo5ZAAAAoJ8QKZ/MbNNNwgpukQveQyOmaw4Mm13ZskO3EG
    TALD/7+0pPF1MbVT7wIXBjXENohNLK4UGMuHb85Ll1k0m5djbXq1SdTxO9wSl1GcjohbxK
    f5dDovF+jKVGxR9VL3YK1rf0rgiB6IhU8zQkC+37brHtjXFCrtZJkyiqI74UkfCto6nCrx
    9qg60yQGXoEHYxYhZU4kWbTdBdTiiQ44D7PN4=
    -----END OPENSSH PRIVATE KEY-----
    """
    /// A binary age file (base64) produced by `rage -r <encAuthorizedKey>`.
    static let rageEncVectorB64 = """
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IFRNamRqQSB3VGxkTlFYdHkxOUdZTnRpSXdQT2JKYkZxVXRoSk96bFRlVER1VVpFcWxBCkFLYTl5dG1haTM4emxIam9wYkxIWW1GUDkwVHE0MGF0YWY0Vnh5YkViSGMKLT4gQTduaFc7TlktZ3JlYXNlID56IiUsJmYgT087VThBIGBaKCcKbDJxVlo5TU5BdFlWWUNRNnJSVzVNc0xpUUZGTW5PTExWSzdFdndNL2F3ckFoZmRzUjNrQ3RBT1RTWmZSYWIrdQpFSmlpTytNb3RHZGZuc3R0Ci0tLSAzZ2hpZldwWFBMMmd2cUp0Z2RlbUJVcUp5bStvRnREYmtvUkNROERpNHRvCsNueLaEpKnTBCd8+HCLhslVS7HNmupNc3zA3zz/9B281IL8ksUljO6Tf2I5KxR/FwYXiLY8kz9yCNlcuQH9wUq5Gjxr2dwa
    """

    // MARK: Helpers

    private func b64(_ s: String) -> [UInt8] {
        var t = s
        while t.count % 4 != 0 { t += "=" }
        return Array(Data(base64Encoded: t)!)
    }

    private func encrypt(_ recipient: any Recipient, _ text: String) throws -> Data {
        var out = OutputStream.toMemory()
        out.open()
        var w = try Age.encrypt(dst: &out, recipients: recipient)
        _ = try w.write(text)
        try w.close()
        out.close()
        return out.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
    }

    private func decryptString(_ identity: any Identity, _ ageFile: Data) throws -> String {
        let input = InputStream(data: ageFile)
        input.open()
        defer { input.close() }
        var r = try Age.decrypt(src: input, identities: identity)
        var out = Data()
        var chunk = Data(repeating: 0, count: 4096)
        while true {
            let n: Int
            do { n = try r.read(&chunk) } catch {
                if "\(error)" == "unexpectedEOF" { break }
                throw error
            }
            if n <= 0 { break }
            out.append(chunk.prefix(n))
        }
        return String(decoding: out, as: UTF8.self)
    }

    // MARK: Field conversion (the one novel primitive)

    func testEd25519ToCurve25519MatchesReference() {
        let pub = b64(Self.plainEd25519PubB64)
        let got = ed25519PublicKeyToCurve25519(pub)
        XCTAssertEqual(got, b64(Self.plainMontgomeryB64),
                       "Montgomery conversion must match filippo.io/edwards25519 BytesMontgomery")
    }

    // MARK: Parsing / fingerprint

    func testRecipientFingerprint() throws {
        let r = try Age.SSHEd25519Recipient(authorizedKey: Self.plainAuthorizedKey)
        XCTAssertEqual(r.fingerprint, Self.plainFingerprint)
        XCTAssertEqual(r.comment, "cypherdex-test-plain")
    }

    func testUnsupportedKeyTypeRejected() {
        XCTAssertThrowsError(try Age.SSHEd25519Recipient(
            authorizedKey: "ssh-rsa AAAAB3NzaC1yc2E comment")) { error in
            XCTAssertEqual(error as? SSHKeyError, .unsupportedKeyType("ssh-rsa"))
        }
    }

    func testIdentityDerivesMatchingRecipient() throws {
        let id = try Age.SSHEd25519Identity(opensshPEM: Self.plainPrivatePEM)
        XCTAssertEqual(id.fingerprint, Self.plainFingerprint)
        XCTAssertEqual(id.recipient.fingerprint, Self.plainFingerprint)
        XCTAssertEqual(id.comment, "cypherdex-test-plain")
    }

    // MARK: Round trip (self-consistency)

    func testEncryptDecryptRoundTrip() throws {
        let id = try Age.SSHEd25519Identity(opensshPEM: Self.plainPrivatePEM)
        let ageFile = try encrypt(id.recipient, Self.plaintext)
        XCTAssertEqual(try decryptString(id, ageFile), Self.plaintext)
    }

    // MARK: Cross-implementation decrypt (the real proof)

    func testDecryptsRageProducedVector() throws {
        let id = try Age.SSHEd25519Identity(opensshPEM: Self.plainPrivatePEM)
        let ageFile = Data(b64(Self.rageVectorB64))
        XCTAssertEqual(try decryptString(id, ageFile), Self.plaintext)
    }

    func testWrongIdentityCannotDecrypt() throws {
        // A different ssh key must not decrypt the vector.
        let otherPEM = try makeThrowawayIdentityPEM()
        let other = try Age.SSHEd25519Identity(opensshPEM: otherPEM)
        let ageFile = Data(b64(Self.rageVectorB64))
        XCTAssertThrowsError(try decryptString(other, ageFile))
    }

    // MARK: Seed round-trip + OpenSSH serialization

    func testSeedRoundTrip() throws {
        let id = try Age.SSHEd25519Identity(opensshPEM: Self.plainPrivatePEM)
        let rebuilt = try Age.SSHEd25519Identity(seed: id.seed, comment: id.comment)
        XCTAssertEqual(rebuilt.fingerprint, id.fingerprint)
        XCTAssertEqual(rebuilt.authorizedKey, Self.plainAuthorizedKey)
        // The rebuilt identity decrypts the same rage vector.
        XCTAssertEqual(try decryptString(rebuilt, Data(b64(Self.rageVectorB64))), Self.plaintext)
    }

    func testSerializedKeyIsAcceptedBySSHKeygen() throws {
        let keygen = "/usr/bin/ssh-keygen"
        guard FileManager.default.isExecutableFile(atPath: keygen) else {
            throw XCTSkip("ssh-keygen not available")
        }
        let id = try Age.SSHEd25519Identity(opensshPEM: Self.plainPrivatePEM)
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agekit-ser-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        let keyPath = tmp.appendingPathComponent("id_ed25519")
        try (id.opensshPEM() + "\n").write(to: keyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath.path)

        // ssh-keygen -y derives the public key from our serialized private key.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: keygen)
        proc.arguments = ["-y", "-f", keyPath.path]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = Pipe()
        try proc.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0, "ssh-keygen rejected our serialized key")
        // ssh-keygen prints "ssh-ed25519 <base64>" (no comment) — compare the key fields.
        let printed = String(decoding: data, as: UTF8.self).split(separator: " ").prefix(2).joined(separator: " ")
        let expected = Self.plainAuthorizedKey.split(separator: " ").prefix(2).joined(separator: " ")
        XCTAssertEqual(printed, expected)
    }

    // MARK: Passphrase-protected keys (bcrypt-pbkdf + AES-256-CTR)

    func testDecryptsWithPassphraseProtectedKey() throws {
        let id = try Age.SSHEd25519Identity(opensshPEM: Self.encPrivatePEM, passphrase: Self.encPassphrase)
        XCTAssertEqual(id.fingerprint, Self.encFingerprint)
        let ageFile = Data(b64(Self.rageEncVectorB64))
        XCTAssertEqual(try decryptString(id, ageFile), Self.plaintext)
    }

    func testWrongPassphraseIsRejected() {
        XCTAssertThrowsError(
            try Age.SSHEd25519Identity(opensshPEM: Self.encPrivatePEM, passphrase: "wrong-passphrase")
        ) { error in
            XCTAssertEqual(error as? SSHKeyError, .incorrectPassphrase)
        }
    }

    func testMissingPassphraseIsReported() {
        XCTAssertThrowsError(try Age.SSHEd25519Identity(opensshPEM: Self.encPrivatePEM)) { error in
            XCTAssertEqual(error as? SSHKeyError, .passphraseRequired)
        }
    }

    // MARK: Cross-implementation encrypt (our ciphertext -> real rage)

    func testOurCiphertextDecryptsWithRage() throws {
        let rage = ("~/.cargo/bin/rage" as NSString).expandingTildeInPath
        guard FileManager.default.isExecutableFile(atPath: rage) else {
            throw XCTSkip("rage not installed at \(rage)")
        }
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agekit-ssh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let keyPath = tmp.appendingPathComponent("id_ed25519")
        try (Self.plainPrivatePEM + "\n").write(to: keyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath.path)

        let recipient = try Age.SSHEd25519Recipient(authorizedKey: Self.plainAuthorizedKey)
        let ageFile = try encrypt(recipient, Self.plaintext)
        let agePath = tmp.appendingPathComponent("msg.age")
        try ageFile.write(to: agePath)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: rage)
        proc.arguments = ["-d", "-i", keyPath.path, agePath.path]
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = Pipe()
        try proc.run()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        XCTAssertEqual(proc.terminationStatus, 0, "rage failed to decrypt our ssh-ed25519 output")
        XCTAssertEqual(String(decoding: data, as: UTF8.self), Self.plaintext)
    }

    /// Build an unrelated ssh-ed25519 identity PEM for the negative test, by
    /// hand-assembling an unencrypted openssh-key-v1 container from a random seed.
    private func makeThrowawayIdentityPEM() throws -> String {
        let signing = Curve25519.Signing.PrivateKey()
        let seed = Array(signing.rawRepresentation)          // 32-byte seed
        let pub = Array(signing.publicKey.rawRepresentation) // 32-byte public
        let pubBlob = sshString("ssh-ed25519") + sshString(pub)
        var priv: [UInt8] = []
        priv += [0, 0, 0, 0]                                 // check1
        priv += [0, 0, 0, 0]                                 // check2
        priv += sshString("ssh-ed25519")
        priv += sshString(pub)
        priv += sshString(seed + pub)                        // 64-byte private
        priv += sshString("throwaway")
        while priv.count % 8 != 0 { priv.append(UInt8(priv.count % 8 + 1)) }
        var blob = Array("openssh-key-v1\0".utf8)
        blob += sshString("none")
        blob += sshString("none")
        blob += sshString([])
        blob += [0, 0, 0, 1]
        blob += sshString(pubBlob)
        blob += sshString(priv)
        let body = Data(blob).base64EncodedString()
        let wrapped = stride(from: 0, to: body.count, by: 70).map { i -> String in
            let start = body.index(body.startIndex, offsetBy: i)
            let end = body.index(start, offsetBy: 70, limitedBy: body.endIndex) ?? body.endIndex
            return String(body[start..<end])
        }.joined(separator: "\n")
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(wrapped)\n-----END OPENSSH PRIVATE KEY-----"
    }
}
