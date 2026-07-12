import CryptoKit
import ExtrasBase64
import Foundation

let sshEd25519Label = "age-encryption.org/v1/ssh-ed25519"

/// HKDF-SHA256 (RFC 5869), matching Go's `golang.org/x/crypto/hkdf`.
///
/// Kept local because CryptoKit's `HKDF` takes the input keying material as a
/// `SymmetricKey`, and `SymmetricKey(data:)` traps on empty data — so it can't
/// express age's tweak step, which is an HKDF with an *empty* IKM
/// (`hkdf.New(sha256, nil, …)`). HMAC has no such restriction, so we drive
/// extract/expand ourselves over it.
///
/// This is the age-specific subset, not a general-purpose HKDF, but it honors the
/// two limits RFC 5869 defines so misuse fails predictably rather than silently:
///   - §2.2 (extract): an empty/absent salt becomes `HashLen` zero bytes — the
///     behavior the RFC and Go's `hkdf` specify, and it also avoids the
///     `SymmetricKey(data:)` trap. (The empty *IKM* we rely on is fine — it's the
///     HMAC message, not the key.)
///   - §2.3 (expand): output length must be `<= 255 * HashLen`; a larger request
///     is a programmer error and trips a `precondition`. Within that bound the
///     block counter never exceeds 255, so it always fits the one output byte.
enum SSHHKDF {
    static func derive(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        let hashLen = SHA256.byteCount
        precondition(length >= 0 && length <= 255 * hashLen,
                     "HKDF-Expand: requested \(length) bytes; RFC 5869 allows 0...\(255 * hashLen) for SHA-256")

        // §2.2 Extract: PRK = HMAC(salt, IKM). No salt -> HashLen zeros (RFC/Go).
        let saltData = salt.isEmpty ? Data(repeating: 0, count: hashLen) : Data(salt)
        let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: saltData))

        // §2.3 Expand: T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i), OKM = first L bytes.
        let prkKey = SymmetricKey(data: Data(prk))
        var okm = [UInt8]()
        var previous = [UInt8]()
        var counter = 1  // Int; the precondition bounds it to <= 255, so UInt8(counter) is always in range.
        while okm.count < length {
            var input = previous
            input.append(contentsOf: info)
            input.append(UInt8(counter))
            let block = HMAC<SHA256>.authenticationCode(for: input, using: prkKey)
            previous = Array(block)
            okm.append(contentsOf: previous)
            counter += 1
        }
        return Array(okm.prefix(length))
    }
}

/// The 4-byte age recipient hash of an SSH key, base64 (no padding).
private func sshFingerprint(_ blob: [UInt8]) -> String {
    let hash = SHA256.hash(data: Data(blob))
    return Base64.encodeString(bytes: Array(hash.prefix(4)), options: [.omitPaddingCharacter])
}

private let sshLabelBytes = Array(sshEd25519Label.utf8)

/// Render an `authorized_keys` line: `ssh-ed25519 <base64 of wire blob> [comment]`.
/// The base64 uses the standard alphabet with padding, as ssh tools emit.
private func authorizedKeyLine(blob: [UInt8], comment: String) -> String {
    let b64 = Data(blob).base64EncodedString()
    return comment.isEmpty ? "ssh-ed25519 \(b64)" : "ssh-ed25519 \(b64) \(comment)"
}

// MARK: - Recipient

extension Age {
    /// An `ssh-ed25519` recipient: reuse an existing SSH Ed25519 public key to
    /// encrypt an age file. Wire-compatible with age's `agessh` package.
    ///
    /// Unlike `X25519Recipient` this recipient is *not* anonymous — the header
    /// carries a short 32-bit hash of the public key.
    public struct SSHEd25519Recipient: Recipient {
        /// The recipient's Curve25519 (Montgomery) public key.
        private let theirPublicKey: [UInt8]
        /// The SSH wire marshaling of the public key (hash + tweak salt).
        private let sshKeyBlob: [UInt8]

        /// A human-facing comment carried on the `authorized_keys` line, if any.
        public let comment: String

        /// The age recipient hash, base64 (no padding).
        public var fingerprint: String { sshFingerprint(sshKeyBlob) }

        /// The `authorized_keys` line for this key (`ssh-ed25519 <base64> [comment]`).
        public var authorizedKey: String { authorizedKeyLine(blob: sshKeyBlob, comment: comment) }

        /// Parse from a single `authorized_keys` line
        /// (`ssh-ed25519 AAAA… [comment]`).
        ///
        /// - Throws: `SSHKeyError.unsupportedKeyType` for non-Ed25519 keys,
        ///   `SSHKeyError.malformedPublicKey` for anything unparseable.
        public init(authorizedKey line: String) throws {
            self.init(publicKey: try parseSSHAuthorizedKey(line))
        }

        init(publicKey: SSHEd25519PublicKey) {
            self.init(montgomery: ed25519PublicKeyToCurve25519(publicKey.raw),
                      blob: publicKey.blob, comment: publicKey.comment)
        }

        /// Construct directly from an already-computed Curve25519 public key,
        /// used when deriving the recipient from an identity (which holds the
        /// Montgomery key already, so there's no Ed25519 key to convert).
        init(montgomery: [UInt8], blob: [UInt8], comment: String) {
            self.theirPublicKey = montgomery
            self.sshKeyBlob = blob
            self.comment = comment
        }

        public func wrap(fileKey: SymmetricKey) throws -> [Stanza] {
            let ephemeral = Curve25519.KeyAgreement.PrivateKey()
            let ourPublicKey = Array(ephemeral.publicKey.rawRepresentation)
            let theirPK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(theirPublicKey))
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: theirPK)
            let sharedBytes = shared.withUnsafeBytes { Array($0) }

            // Tweak the shared secret so it can't be reproduced by anyone who only
            // knows the (public) SSH key marshaling.
            let tweak = SSHHKDF.derive(ikm: [], salt: sshKeyBlob, info: sshLabelBytes, length: 32)
            let shared2 = try scalarMult(scalar: tweak, point: sharedBytes)

            let salt = ourPublicKey + theirPublicKey
            let wrappingKey = SSHHKDF.derive(ikm: shared2, salt: salt, info: sshLabelBytes, length: 32)
            let wrappedKey = try Age.aeadEncrypt(key: SymmetricKey(data: wrappingKey), plaintext: fileKey)

            let stanza = Stanza(
                type: "ssh-ed25519",
                args: [sshFingerprint(sshKeyBlob),
                       Base64.encodeString(bytes: ourPublicKey, options: [.omitPaddingCharacter])],
                body: wrappedKey)
            return [stanza]
        }
    }
}

// MARK: - Identity

extension Age {
    /// An `ssh-ed25519` identity: decrypt age files wrapped to an existing SSH
    /// Ed25519 private key. Wire-compatible with age's `agessh` package.
    public struct SSHEd25519Identity: Identity {
        /// The 32-byte Ed25519 seed — the portable secret; enough to rebuild the
        /// whole key (see `init(seed:comment:)`).
        public let seed: [UInt8]
        /// The Curve25519 secret scalar derived from the Ed25519 seed.
        private let curveSecret: [UInt8]
        /// Our Curve25519 (Montgomery) public key.
        private let curvePublic: [UInt8]
        private let sshKeyBlob: [UInt8]

        public let comment: String

        /// The `authorized_keys` line for this key's public half.
        public var authorizedKey: String { authorizedKeyLine(blob: sshKeyBlob, comment: comment) }

        /// Parse from an OpenSSH private key. Pass `passphrase` for encrypted keys.
        ///
        /// - Throws: `SSHKeyError.passphraseRequired` / `.incorrectPassphrase`
        ///   for protected keys, `SSHKeyError.unsupportedKeyType` for non-Ed25519.
        public init(opensshPEM pem: String, passphrase: String? = nil) throws {
            try self.init(privateKey: parseOpenSSHPrivateKey(pem, passphrase: passphrase))
        }

        /// Rebuild an identity from a stored 32-byte Ed25519 seed (the public key
        /// and all derived material follow deterministically). `comment` is
        /// cosmetic — it isn't part of the recipient hash.
        public init(seed: [UInt8], comment: String = "") throws {
            guard seed.count == 32 else { throw SSHKeyError.malformedPrivateKey }
            let signing = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
            let pub = Array(signing.publicKey.rawRepresentation)
            let blob = sshString("ssh-ed25519") + sshString(pub)
            try self.init(privateKey: SSHEd25519PrivateKey(
                seed: seed,
                publicKey: SSHEd25519PublicKey(raw: pub, blob: blob, comment: comment),
                comment: comment))
        }

        init(privateKey: SSHEd25519PrivateKey) throws {
            self.seed = privateKey.seed
            // Curve25519 secret = SHA-512(seed)[:32]; public = X25519(secret, base).
            let hashed = SHA512.hash(data: Data(privateKey.seed))
            self.curveSecret = Array(hashed.prefix(32))
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(curveSecret))
            self.curvePublic = Array(priv.publicKey.rawRepresentation)
            self.sshKeyBlob = privateKey.publicKey.blob
            self.comment = privateKey.comment
        }

        /// The public recipient corresponding to this identity.
        public var recipient: Age.SSHEd25519Recipient {
            Age.SSHEd25519Recipient(montgomery: curvePublic, blob: sshKeyBlob, comment: comment)
        }

        public var fingerprint: String { sshFingerprint(sshKeyBlob) }

        public func unwrap(stanzas: [Stanza]) throws -> SymmetricKey {
            try Age.multiUnwrap(stanzas: stanzas) { block in
                guard block.type == "ssh-ed25519" else { throw DecryptError.incorrectIdentity }
                guard block.args.count == 2 else { throw SSHKeyError.malformedPublicKey }
                guard block.args[0] == sshFingerprint(sshKeyBlob) else {
                    throw DecryptError.incorrectIdentity
                }
                let ephemeralShare = try Base64.decode(string: block.args[1], options: [.omitPaddingCharacter])
                guard ephemeralShare.count == 32 else { throw SSHKeyError.malformedPublicKey }

                let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(curveSecret))
                let sharePK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(ephemeralShare))
                let shared = try priv.sharedSecretFromKeyAgreement(with: sharePK)
                let sharedBytes = shared.withUnsafeBytes { Array($0) }

                let tweak = SSHHKDF.derive(ikm: [], salt: sshKeyBlob, info: sshLabelBytes, length: 32)
                let shared2 = try scalarMult(scalar: tweak, point: sharedBytes)

                let salt = ephemeralShare + curvePublic
                let wrappingKey = SSHHKDF.derive(ikm: shared2, salt: salt, info: sshLabelBytes, length: 32)
                do {
                    let fileKey = try Age.aeadDecrypt(
                        key: SymmetricKey(data: wrappingKey), size: Age.fileKeySize, ciphertext: block.body)
                    return SymmetricKey(data: fileKey)
                } catch {
                    throw DecryptError.incorrectIdentity
                }
            }
        }
    }
}

// MARK: - Raw X25519

/// Raw X25519 scalar multiplication of an arbitrary 32-byte `scalar` by an
/// arbitrary 32-byte `point` (u-coordinate). CryptoKit clamps the scalar per
/// RFC 7748, matching Go's `curve25519.X25519`.
private func scalarMult(scalar: [UInt8], point: [UInt8]) throws -> [UInt8] {
    let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(scalar))
    let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(point))
    let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
    return shared.withUnsafeBytes { Array($0) }
}
