import XCTest
import CryptoKit
@testable import AgeKit

/// Tests for the `mlkem768x25519` (X-Wing) post-quantum recipient/identity.
///
/// Correctness is pinned two ways: the recipient encoding example from the age
/// spec, and round-trip interop against the reference `age` v1.3+ binary (both
/// directions), which is skipped when no such binary is installed.
@available(macOS 26, iOS 26, tvOS 26, watchOS 26, *)
final class MLKEM768X25519Tests: XCTestCase {

    // The example recipient from the age spec ("The MLKEM768-X25519 hybrid
    // post-quantum recipient type").
    static let specRecipient = "age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf5zrqtzdxz95paef6caq5aapdmwjjqpjfdyxnzr2zampc3uxy0dg4z2n2gm9su72p0pc3u0jvev55l694v78snxg3yzvcl7yda0eyytqj6a0ec477lnhcy5hzpz4zq3pxanve4cn62gqj3pjy5lqj9c6kyj4v2z8alktn8zh99970x79gjkv7522hv9kfz35zsnxhsx8wwtmu9cy3ftzjgwcp4sshn3llnylnpdsyz5jm72vefv4x5vfwytrefxg4wq3mv42wcrvkj742479zrxzpvp2p3e9fed9f0739vcu80r7ma28qfhnvlv4gfzel9q654dj3zmuvvz893azhxdvs9fxd0r7jzchzcfcs5mkyyjxhw0n2z6dvp9yn9qfdp29h0azxqyjw6v7fhyuzj7zel0uq6j9rd7wgrpz7mf5dnj43jwsgvrc8qcnhy7tu6dkdujuxzkp9xj43xe8h92ktre2a3u3s8mm5mrp9nr9pwkgtz4mdlq9hgn4fps4k57ff6wddn2fy23t47sm20r8km8sd2pcyyafnet8f0dajsrlyjeah4n3mssr6aseevuuskdvq5lzguyvpgwpta742c6698vgutzqgny8usfg0w2he7kq5vyxjd0f9hqg8xk26y9e4th0gezq92q4cpp5p2y9hf5f2cje5l0c3sa3a2qxmm38pxxvhxh99yzmfz0zk7r2s64nnwjhkfgfr3gf8xnmppcgmaykvh5sh6g7vk9790rf8ws0axmr2t7z8aae5fq2029uvcn2ghgt4fu4wgwdc0k0cz52qkvwmuzj8p8k5jgf3xzk5zmrkavjekjrpeq408xz3zxazwkc6tyfmhayrkfpjhwtz5mp8j8guqe43k2q6m2kte03vrw27y3wmqyu5etmt9dnkwcnnpmu9gz9dekfhdevf42ucshphnrk38ra6hx8w5f8q5ru0xdhrjxmwqf6cused7zc5xvq43r0zscjglpwlptpwydhqw64xz7ptjdyeyzpq2zkxtmzg29gzjpvzva4d3l0cenn9xs297wf4y4ukwrunf57xj6pm7nvrkwvtrt8hwcmgv8x7ajw7258ugf9wvkmk4052ekg87tw5vnx8nq2swyzv77v8yqlwsenvamr0zssknwts8rrhfuwj7ykysnq9jxy0uv3kuyt22djszjdtvpz6d0s0kwh8ryynddzud92emeyvvyqktd0jtj7rvvg5gch25v8smlvny3kvn5gagyz475ze2y6q466xqmz2n3hs77lddeqyta2nch5k2u5yacuk9ywnwfdzvyejnucz724hj77hrrmakm7pr3kxsrxq22ejexlud9fy2kdqmkg5yncz7jm5wv2qjk5w5kvcpqsry2yqffh2la52dxfjkjq5rzhjzeyn6dupn0qwtyv7s4lwg3xdarsdlwe2y3tujy480y7z39q259fzx6jhd2j0f5hagqpcpees7hzc2yrk5cy788uk3s7qvp5cpepx24gvws3m2g433exgwppnkjscec8qu4y9z9r7vccexjcjaen42245lmgmxmuavg9alej92322gvvyy2t6267v09ch64y0m53jff0vjj96s0ypk60hr3jw4myd6m5hpn3xjstx7tl2szhpr5qe8jj08ydjc4wy2rch2fhuy3pdfjax5awe9j99ly5hkntzz9fe5zatgjvzdd0kgtxs25njnajyf6ssekp7gelxquusn4pt25czh3scj68kq79wdn5tgm6yvm9nzavrg043x3msnygf8dweknw5jmqd0uvny6ttsn09508k0c55zfnegrm9efhxpfqdkmhh6gjtqmwze9pyyzk3tlhl53k2ykx3qheyty7saeq0d3fzv49zc0k"

    static let plaintext = "pqtest"

    // MARK: Encoding

    func testSpecRecipientParsesAndReEncodes() throws {
        let recipient = try Age.MLKEM768X25519Recipient(Self.specRecipient)
        XCTAssertEqual(recipient.string, Self.specRecipient)
    }

    func testGeneratedEncodingPrefixesAndRoundTrip() throws {
        let identity = try Age.MLKEM768X25519Identity.generate()
        XCTAssertTrue(identity.string.hasPrefix("AGE-SECRET-KEY-PQ-1"))
        XCTAssertTrue(identity.recipient.string.hasPrefix("age1pq1"))

        // Parsing the encodings back reproduces the same key material.
        let reIdentity = try Age.MLKEM768X25519Identity(identity.string)
        XCTAssertEqual(reIdentity.recipient.string, identity.recipient.string)
        let reRecipient = try Age.MLKEM768X25519Recipient(identity.recipient.string)
        XCTAssertEqual(reRecipient.string, identity.recipient.string)
    }

    func testWrongPrefixesAreRejected() {
        // An X25519 recipient/identity must not parse as post-quantum.
        XCTAssertThrowsError(try Age.MLKEM768X25519Recipient("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9x0 typo"))
        XCTAssertThrowsError(try Age.MLKEM768X25519Identity("AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"))
    }

    // MARK: Round trip

    func testRoundTrip() throws {
        let identity = try Age.MLKEM768X25519Identity.generate()
        let ageFile = try encrypt(identity.recipient, Self.plaintext)
        XCTAssertEqual(try decryptString(identity, ageFile), Self.plaintext)
    }

    func testWrongIdentityDoesNotDecrypt() throws {
        let identity = try Age.MLKEM768X25519Identity.generate()
        let stranger = try Age.MLKEM768X25519Identity.generate()
        let ageFile = try encrypt(identity.recipient, Self.plaintext)
        XCTAssertThrowsError(try decryptString(stranger, ageFile))
    }

    // MARK: Interop with the reference age binary

    func testAgeDecryptsOurCiphertext() throws {
        let age = try ageBinary()
        let dir = try scratchDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let identity = try Age.MLKEM768X25519Identity.generate()
        let idPath = dir.appendingPathComponent("key.txt")
        try (identity.string + "\n").write(to: idPath, atomically: true, encoding: .utf8)

        let cipherPath = dir.appendingPathComponent("msg.age")
        try encrypt(identity.recipient, Self.plaintext).write(to: cipherPath)

        let (status, out, err) = run(age, ["--decrypt", "-i", idPath.path, cipherPath.path])
        XCTAssertEqual(status, 0, "age failed to decrypt our ciphertext: \(String(decoding: err, as: UTF8.self))")
        XCTAssertEqual(String(decoding: out, as: UTF8.self), Self.plaintext)
    }

    func testWeDecryptAgeCiphertext() throws {
        let age = try ageBinary()
        let dir = try scratchDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let identity = try Age.MLKEM768X25519Identity.generate()
        let plainPath = dir.appendingPathComponent("msg.txt")
        try Self.plaintext.write(to: plainPath, atomically: true, encoding: .utf8)
        let cipherPath = dir.appendingPathComponent("msg.age")

        let (status, _, err) = run(age, ["--encrypt", "-r", identity.recipient.string, "-o", cipherPath.path, plainPath.path])
        XCTAssertEqual(status, 0, "age failed to encrypt to our recipient: \(String(decoding: err, as: UTF8.self))")

        let ageFile = try Data(contentsOf: cipherPath)
        XCTAssertEqual(try decryptString(identity, ageFile), Self.plaintext)
    }

    // MARK: Helpers

    private func ageBinary() throws -> String {
        for path in ["~/go/bin/age", "/opt/homebrew/bin/age", "/usr/local/bin/age"] {
            let expanded = (path as NSString).expandingTildeInPath
            if FileManager.default.isExecutableFile(atPath: expanded) { return expanded }
        }
        throw XCTSkip("age v1.3+ (post-quantum) binary not installed")
    }

    private func scratchDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agekit-pq-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func run(_ executable: String, _ arguments: [String]) -> (status: Int32, stdout: Data, stderr: Data) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = arguments
        let out = Pipe(), err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        try? proc.run()
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (proc.terminationStatus, outData, errData)
    }

    @discardableResult
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
}
