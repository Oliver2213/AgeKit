import Bech32
import CryptoKit
import ExtrasBase64
import Foundation

// The `mlkem768p256tag` tagged hybrid post-quantum recipient type (see the age
// spec, "tagged recipient types"). A recipient is an ML-KEM-768 encapsulation key
// concatenated with an uncompressed P-256 point, encoded as Bech32 `age1tagpq…`.
//
// age defines only the recipient encoding and the encrypt stanza for the tagged
// types; identity generation and decryption are hardware-plugin specific (e.g.
// age-plugin-se, which keeps the ML-KEM key in the Secure Enclave). So this is a
// wrap-only recipient — it lets us encrypt to such a key, and the plugin decrypts.
//
// The KEM is MLKEM768-P256 from draft-ietf-hpke-pq: ML-KEM-768 encapsulation and a
// P-256 ECDH, combined with SHA3-256, then HPKE base mode (HKDF-SHA256,
// ChaCha20Poly1305). Requires macOS 26 for CryptoKit's ML-KEM and SHA3.

private let mlkem768p256Stanza = "mlkem768p256tag"
private let mlkem768p256Label = Data("age-encryption.org/mlkem768p256tag".utf8)
private let mlkem768p256KEMID: UInt16 = 0x0050
private let mlkem768p256KEMLabel = Data("MLKEM768-P256".utf8)
private let mlkem768p256RecipientHRP = "age1tagpq"
private let mlkemEncapsulationKeySize = 1184
private let p256UncompressedPointSize = 65

extension Age {
    /// A tagged hybrid post-quantum recipient (`age1tagpq…`): ML-KEM-768 for
    /// quantum resistance hybridized with P-256 for hardware compatibility. This
    /// type can only wrap (encrypt); the matching identity and decryption live in a
    /// hardware plugin such as age-plugin-se.
    @available(macOS 26, iOS 26, tvOS 26, watchOS 26, *)
    public struct MLKEM768P256Recipient: Recipient {
        enum Error: Swift.Error {
            case invalidType
            case invalidPublicKey
        }

        private let mlkemKey: MLKEM768.PublicKey
        private let p256Key: P256.KeyAgreement.PublicKey
        /// The recipient's P-256 point in uncompressed (65-byte) form, kept verbatim
        /// for the shared-secret combiner and the recipient tag.
        private let p256Point: Data

        /// The Bech32 public key encoding of the recipient, with the "age1tagpq" prefix.
        public var string: String {
            try! Bech32.encode(to: mlkem768p256RecipientHRP, data: mlkemKey.rawRepresentation + p256Point)
        }

        /// Create a recipient from a Bech32-encoded public key with the "age1tagpq" prefix.
        public init(_ string: String) throws {
            let (hrp, data) = try Bech32.decode(from: string)
            guard hrp == mlkem768p256RecipientHRP else {
                throw Error.invalidType
            }
            try self.init(data)
        }

        fileprivate init(_ data: Data) throws {
            guard data.count == mlkemEncapsulationKeySize + p256UncompressedPointSize else {
                throw Error.invalidPublicKey
            }
            let point = Data(data.suffix(p256UncompressedPointSize))
            do {
                self.mlkemKey = try MLKEM768.PublicKey(rawRepresentation: data.prefix(mlkemEncapsulationKeySize))
                self.p256Key = try P256.KeyAgreement.PublicKey(x963Representation: point)
            } catch {
                throw Error.invalidPublicKey
            }
            self.p256Point = point
        }

        public func wrap(fileKey: SymmetricKey) throws -> [Stanza] {
            // MLKEM768-P256 hybrid KEM encapsulation.
            let mlkem = try mlkemKey.encapsulate()
            let ssPQ = mlkem.sharedSecret.withUnsafeBytes { Data($0) }
            let ctPQ = mlkem.encapsulated

            let ephemeral = P256.KeyAgreement.PrivateKey()
            let ssT = try ephemeral.sharedSecretFromKeyAgreement(with: p256Key).withUnsafeBytes { Data($0) }
            let ctT = ephemeral.publicKey.x963Representation

            var hasher = SHA3_256()
            hasher.update(data: ssPQ)
            hasher.update(data: ssT)
            hasher.update(data: ctT)
            hasher.update(data: p256Point)
            hasher.update(data: mlkem768p256KEMLabel)
            let sharedSecret = Data(hasher.finalize())

            let enc = ctPQ + ctT
            let context = HPKE.context(kemID: mlkem768p256KEMID, sharedSecret: sharedSecret, info: mlkem768p256Label)
            let wrappedKey = try HPKE.seal(context, plaintext: fileKey.withUnsafeBytes { Data($0) })

            // Recipient tag: HKDF-Extract-SHA256(salt = label,
            //   ikm = enc || SHA-256(uncompressed P-256 point)[:4])[:4].
            let pointHash = Data(SHA256.hash(data: p256Point).prefix(4))
            let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: enc + pointHash), salt: mlkem768p256Label)
            let tag = Data(prk).prefix(4)

            return [Stanza(
                type: mlkem768p256Stanza,
                args: [
                    Base64.encodeString(bytes: tag, options: .omitPaddingCharacter),
                    Base64.encodeString(bytes: enc, options: .omitPaddingCharacter),
                ],
                body: wrappedKey
            )]
        }
    }
}
