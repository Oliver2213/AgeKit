import CryptoKit
import Foundation

/// bcrypt-pbkdf key derivation, ported from OpenBSD's `bcrypt_pbkdf(3)` via
/// `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf`. Used to turn an OpenSSH
/// private key passphrase into the cipher key + IV.
enum BcryptPBKDF {
    private static let magic = Array("OxychromaticBlowfishSwatDynamite".utf8)
    private static let blockSize = 32

    static func deriveKey(password: [UInt8], salt: [UInt8], rounds: Int, keyLength: Int) throws -> [UInt8] {
        guard rounds >= 1 else { throw SSHKeyError.malformedPrivateKey }
        guard !password.isEmpty else { throw SSHKeyError.malformedPrivateKey }
        guard !salt.isEmpty, salt.count <= 1 << 20 else { throw SSHKeyError.malformedPrivateKey }
        guard keyLength > 0, keyLength <= 1024 else { throw SSHKeyError.malformedPrivateKey }

        let numBlocks = (keyLength + blockSize - 1) / blockSize
        var key = [UInt8](repeating: 0, count: numBlocks * blockSize)

        let shapass = sha512(password)
        var tmp = [UInt8](repeating: 0, count: blockSize)

        for block in 1...numBlocks {
            var counted = salt
            counted.append(contentsOf: [
                UInt8(truncatingIfNeeded: block >> 24), UInt8(truncatingIfNeeded: block >> 16),
                UInt8(truncatingIfNeeded: block >> 8), UInt8(truncatingIfNeeded: block)])
            bcryptHash(&tmp, shapass: shapass, shasalt: sha512(counted))

            var out = tmp
            if rounds >= 2 {
                for _ in 2...rounds {
                    bcryptHash(&tmp, shapass: shapass, shasalt: sha512(tmp))
                    for j in 0..<out.count { out[j] ^= tmp[j] }
                }
            }
            // Deliberate PBKDF2 deviation: bytes are spread across the output.
            for i in 0..<out.count { key[i * numBlocks + (block - 1)] = out[i] }
        }
        return Array(key.prefix(keyLength))
    }

    /// One bcrypt hash: EksBlowfish setup from (shapass, shasalt), then encrypt
    /// the fixed magic 64× per 8-byte word, with the OpenBSD endian swap.
    private static func bcryptHash(_ out: inout [UInt8], shapass: [UInt8], shasalt: [UInt8]) {
        var cipher = Blowfish()
        cipher.expandKeyWithSalt(shapass, shasalt)
        for _ in 0..<64 {
            cipher.expandKey(shasalt)
            cipher.expandKey(shapass)
        }
        for i in 0..<blockSize { out[i] = magic[i] }
        for i in stride(from: 0, to: blockSize, by: 8) {
            for _ in 0..<64 { cipher.encrypt(&out, at: i) }
        }
        // Swap bytes within each 4-byte word (big-endian → OpenBSD word order).
        for i in stride(from: 0, to: blockSize, by: 4) {
            out.swapAt(i, i + 3)
            out.swapAt(i + 1, i + 2)
        }
    }

    private static func sha512(_ data: [UInt8]) -> [UInt8] {
        Array(SHA512.hash(data: Data(data)))
    }
}
