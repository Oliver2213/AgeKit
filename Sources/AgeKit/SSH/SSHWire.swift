import Foundation

/// Errors from parsing SSH keys or decrypting protected private keys.
public enum SSHKeyError: Error, Equatable {
    case malformedPublicKey
    case malformedPrivateKey
    /// A key type other than `ssh-ed25519` (e.g. `ssh-rsa`), which is not supported.
    case unsupportedKeyType(String)
    /// An unsupported private-key cipher (only `none` and `aes256-ctr` are handled).
    case unsupportedCipher(String)
    /// An unsupported KDF (only `bcrypt` is handled for encrypted keys).
    case unsupportedKDF(String)
    /// The private key is encrypted but no passphrase was supplied.
    case passphraseRequired
    /// The supplied passphrase did not decrypt the private key.
    case incorrectPassphrase
}

/// A minimal reader for the SSH wire format: big-endian `uint32` lengths and
/// length-prefixed strings (RFC 4251 §5).
struct SSHBufferReader {
    private let data: [UInt8]
    private var offset = 0

    init(_ data: [UInt8]) { self.data = data }

    var remaining: Int { data.count - offset }

    mutating func readBytes(_ n: Int) -> [UInt8]? {
        guard n >= 0, offset + n <= data.count else { return nil }
        defer { offset += n }
        return Array(data[offset..<offset + n])
    }

    mutating func readUInt32() -> UInt32? {
        guard let b = readBytes(4) else { return nil }
        return (UInt32(b[0]) << 24) | (UInt32(b[1]) << 16) | (UInt32(b[2]) << 8) | UInt32(b[3])
    }

    mutating func readString() -> [UInt8]? {
        guard let len = readUInt32() else { return nil }
        return readBytes(Int(len))
    }
}

/// Encode a byte string as an SSH wire string (big-endian length prefix + bytes).
func sshString(_ bytes: [UInt8]) -> [UInt8] {
    let n = UInt32(bytes.count)
    return [UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16),
            UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)] + bytes
}

func sshString(_ s: String) -> [UInt8] { sshString(Array(s.utf8)) }

// MARK: - Public key

/// A parsed `ssh-ed25519` public key.
struct SSHEd25519PublicKey {
    /// The raw 32-byte Ed25519 public key.
    let raw: [UInt8]
    /// The SSH wire marshaling (identical to Go's `ssh.PublicKey.Marshal()`),
    /// used both for the recipient hash and as the HKDF salt in the tweak step.
    let blob: [UInt8]
    let comment: String
}

/// Parse a single `authorized_keys`-format line: `ssh-ed25519 <base64> [comment]`.
func parseSSHAuthorizedKey(_ line: String) throws -> SSHEd25519PublicKey {
    let fields = line
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .split(whereSeparator: { $0 == " " || $0 == "\t" })
        .map(String.init)
    guard fields.count >= 2 else { throw SSHKeyError.malformedPublicKey }
    guard fields[0] == "ssh-ed25519" else { throw SSHKeyError.unsupportedKeyType(fields[0]) }
    guard let blob = Data(base64Encoded: fields[1]).map(Array.init) else {
        throw SSHKeyError.malformedPublicKey
    }
    var r = SSHBufferReader(blob)
    guard let innerType = r.readString(),
          String(decoding: innerType, as: UTF8.self) == "ssh-ed25519",
          let pub = r.readString(), pub.count == 32 else {
        throw SSHKeyError.malformedPublicKey
    }
    let comment = fields.count >= 3 ? fields[2...].joined(separator: " ") : ""
    return SSHEd25519PublicKey(raw: pub, blob: blob, comment: comment)
}

// MARK: - Private key (openssh-key-v1)

/// A parsed `ssh-ed25519` private key.
struct SSHEd25519PrivateKey {
    /// The 32-byte Ed25519 seed.
    let seed: [UInt8]
    let publicKey: SSHEd25519PublicKey
    let comment: String
}

private let opensshAuthMagic = Array("openssh-key-v1\0".utf8)

/// Parse an OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`,
/// openssh-key-v1 container). Encrypted keys require `passphrase`.
func parseOpenSSHPrivateKey(_ pem: String, passphrase: String?) throws -> SSHEd25519PrivateKey {
    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
    let end = "-----END OPENSSH PRIVATE KEY-----"
    guard let br = pem.range(of: begin), let er = pem.range(of: end), br.upperBound <= er.lowerBound else {
        throw SSHKeyError.malformedPrivateKey
    }
    let base64Body = pem[br.upperBound..<er.lowerBound]
        .split(whereSeparator: \.isNewline).joined()
    guard let blob = Data(base64Encoded: base64Body).map(Array.init) else {
        throw SSHKeyError.malformedPrivateKey
    }

    var r = SSHBufferReader(blob)
    guard let magic = r.readBytes(opensshAuthMagic.count), magic == opensshAuthMagic,
          let cipherBytes = r.readString(),
          let kdfBytes = r.readString(),
          let kdfOptions = r.readString(),
          let keyCount = r.readUInt32(), keyCount == 1,
          r.readString() != nil,                    // public key blob (unused; taken from private section)
          let privEnc = r.readString() else {
        throw SSHKeyError.malformedPrivateKey
    }
    let cipher = String(decoding: cipherBytes, as: UTF8.self)
    let kdf = String(decoding: kdfBytes, as: UTF8.self)

    let privBlob: [UInt8]
    if cipher == "none" {
        privBlob = privEnc
    } else {
        guard let passphrase, !passphrase.isEmpty else { throw SSHKeyError.passphraseRequired }
        privBlob = try decryptOpenSSHPrivateBlob(
            privEnc, cipher: cipher, kdf: kdf, kdfOptions: kdfOptions, passphrase: passphrase)
    }

    var pr = SSHBufferReader(privBlob)
    guard let check1 = pr.readUInt32(), let check2 = pr.readUInt32() else {
        throw SSHKeyError.malformedPrivateKey
    }
    guard check1 == check2 else {
        // The two check ints only match when the blob decrypted correctly.
        throw cipher == "none" ? SSHKeyError.malformedPrivateKey : SSHKeyError.incorrectPassphrase
    }
    guard let keyTypeBytes = pr.readString() else { throw SSHKeyError.malformedPrivateKey }
    let keyType = String(decoding: keyTypeBytes, as: UTF8.self)
    guard keyType == "ssh-ed25519" else { throw SSHKeyError.unsupportedKeyType(keyType) }
    guard let pub = pr.readString(), pub.count == 32,
          let priv = pr.readString(), priv.count == 64,
          let commentBytes = pr.readString() else {
        throw SSHKeyError.malformedPrivateKey
    }
    // The 64-byte private field is seed(32) || public(32).
    let seed = Array(priv[0..<32])
    let comment = String(decoding: commentBytes, as: UTF8.self)
    let pubBlob = sshString("ssh-ed25519") + sshString(pub)
    let publicKey = SSHEd25519PublicKey(raw: pub, blob: pubBlob, comment: comment)
    return SSHEd25519PrivateKey(seed: seed, publicKey: publicKey, comment: comment)
}
