import Bech32
import CryptoKit
import ExtrasBase64
import Foundation

// The MLKEM768-X25519 (a.k.a. X-Wing) hybrid post-quantum recipient type. It wraps
// the file key with HPKE base mode (RFC 9180) over the X-Wing KEM, using
// HKDF-SHA256 and ChaCha20Poly1305. See the age spec, "The MLKEM768-X25519 (i.e.
// X-Wing) hybrid post-quantum recipient type".
//
// The KEM itself (key generation from a 32-byte seed, encapsulation, and
// decapsulation) is provided by CryptoKit's `XWingMLKEM768X25519`, which requires
// macOS 26 / iOS 26; only the HPKE key schedule and encoding live here.

private let pqStanzaType = "mlkem768x25519"
private let pqLabel = Data("age-encryption.org/mlkem768x25519".utf8)
private let pqKEMID: UInt16 = 0x647a
private let pqRecipientHRP = "age1pq"
private let pqIdentityHRP = "AGE-SECRET-KEY-PQ-"
// The encapsulated key is an ML-KEM-768 ciphertext (1088 bytes) concatenated with
// an X25519 ephemeral public key (32 bytes).
private let pqEncapsulatedKeySize = 1120

// MARK: - Recipient

extension Age {
    /// The public side of an X-Wing hybrid post-quantum key pair. A file wrapped to
    /// this recipient is secure against a future quantum computer, so it must only
    /// be combined with other post-quantum recipients.
    ///
    /// This recipient is anonymous: the header alone doesn't reveal which recipient
    /// a file is encrypted to.
    @available(macOS 26, iOS 26, tvOS 26, watchOS 26, *)
    public struct MLKEM768X25519Recipient: Recipient {
        enum Error: Swift.Error {
            case invalidType
            case invalidPublicKey
        }

        private let publicKey: XWingMLKEM768X25519.PublicKey

        /// The Bech32 public key encoding of the recipient, with the "age1pq" prefix.
        public var string: String {
            try! Bech32.encode(to: pqRecipientHRP, data: publicKey.rawRepresentation)
        }

        /// Create a recipient from a Bech32-encoded public key with the "age1pq1" prefix.
        public init(_ string: String) throws {
            let (hrp, data) = try Bech32.decode(from: string)
            guard hrp == pqRecipientHRP else {
                throw Error.invalidType
            }
            try self.init(data)
        }

        fileprivate init(_ publicKey: Data) throws {
            do {
                self.publicKey = try XWingMLKEM768X25519.PublicKey(rawRepresentation: publicKey)
            } catch {
                throw Error.invalidPublicKey
            }
        }

        public func wrap(fileKey: SymmetricKey) throws -> [Stanza] {
            let encapsulation = try publicKey.encapsulate()
            let sharedSecret = encapsulation.sharedSecret.withUnsafeBytes { Data($0) }
            let context = HPKE.context(kemID: pqKEMID, sharedSecret: sharedSecret, info: pqLabel)
            let wrappedKey = try HPKE.seal(context, plaintext: fileKey.withUnsafeBytes { Data($0) })

            let enc = Base64.encodeString(bytes: encapsulation.encapsulated, options: .omitPaddingCharacter)
            return [Stanza(type: pqStanzaType, args: [enc], body: wrappedKey)]
        }
    }
}

// MARK: - Identity

extension Age {
    /// The private side of an X-Wing hybrid post-quantum key pair, which decrypts
    /// files wrapped to the corresponding `MLKEM768X25519Recipient`. The identity is
    /// a 32-byte seed, encoded with the "AGE-SECRET-KEY-PQ-" prefix.
    @available(macOS 26, iOS 26, tvOS 26, watchOS 26, *)
    public struct MLKEM768X25519Identity: Identity {
        enum Error: Swift.Error {
            case malformedSecretKey
            case invalidRecipientBlock
        }

        private let secretKey: XWingMLKEM768X25519.PrivateKey

        /// The Bech32 private key encoding of the identity, with the
        /// "AGE-SECRET-KEY-PQ-1" prefix.
        public var string: String {
            try! Bech32.encode(to: pqIdentityHRP, data: secretKey.seedRepresentation).uppercased()
        }

        /// The public `MLKEM768X25519Recipient` corresponding to this identity.
        public var recipient: MLKEM768X25519Recipient {
            try! MLKEM768X25519Recipient(secretKey.publicKey.rawRepresentation)
        }

        private init(secretKey: XWingMLKEM768X25519.PrivateKey) {
            self.secretKey = secretKey
        }

        /// Create an identity from a Bech32-encoded 32-byte seed with the
        /// "AGE-SECRET-KEY-PQ-1" prefix.
        public init(_ string: String) throws {
            let (hrp, data) = try Bech32.decode(from: string)
            guard hrp == pqIdentityHRP else {
                throw Error.malformedSecretKey
            }
            do {
                self.secretKey = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: data, publicKey: nil)
            } catch {
                throw Error.malformedSecretKey
            }
        }

        /// Randomly generate a new identity.
        public static func generate() throws -> MLKEM768X25519Identity {
            MLKEM768X25519Identity(secretKey: try XWingMLKEM768X25519.PrivateKey.generate())
        }

        public func unwrap(stanzas: [Stanza]) throws -> SymmetricKey {
            try multiUnwrap(stanzas: stanzas) { block in
                guard block.type == pqStanzaType else {
                    throw DecryptError.incorrectIdentity
                }
                guard block.args.count == 1 else {
                    throw Error.invalidRecipientBlock
                }
                let enc = Data(try Base64.decode(string: block.args[0], options: .omitPaddingCharacter))
                guard enc.count == pqEncapsulatedKeySize else {
                    throw Error.invalidRecipientBlock
                }
                // Reject before decrypting, per the spec, to avoid partitioning
                // oracle attacks: the body must be exactly one wrapped file key.
                guard block.body.count == fileKeySize + 16 else {
                    throw AEADError.incorrectCiphertextSize
                }

                let sharedSecret = try secretKey.decapsulate(enc).withUnsafeBytes { Data($0) }
                let context = HPKE.context(kemID: pqKEMID, sharedSecret: sharedSecret, info: pqLabel)
                do {
                    let fileKey = try HPKE.open(context, ciphertext: block.body)
                    return SymmetricKey(data: fileKey)
                } catch {
                    throw DecryptError.incorrectIdentity
                }
            }
        }
    }
}
