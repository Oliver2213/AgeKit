import CryptoKit
import Foundation

// Minimal HPKE (Hybrid Public Key Encryption, RFC 9180) base-mode key schedule,
// enough for a single-shot Seal/Open of one file key. The KEM is supplied by the
// caller as a shared secret plus its numeric HPKE id, so the same schedule serves
// any KEM (e.g. the MLKEM768-X25519 hybrid). The KDF and AEAD are fixed to the
// pair age's post-quantum stanza uses: HKDF-SHA256 and ChaCha20Poly1305.
//
// Only base mode (no PSK, no sender auth) and sequence number zero are
// implemented, matching age's one-file-key-per-recipient use where each context
// seals exactly once.
extension Age {
    enum HPKE {
        // Ciphersuite component ids from the HPKE IANA registry (RFC 9180 §7).
        private static let kdfID: UInt16 = 0x0001 // HKDF-SHA256
        private static let aeadID: UInt16 = 0x0003 // ChaCha20Poly1305
        private static let aeadKeySize = 32
        private static let aeadNonceSize = 12 // ChaChaPoly nonce

        enum Error: Swift.Error {
            case openFailed
        }

        /// A derived base-mode context: the AEAD key and the base nonce used
        /// (unmodified, since the sequence number is zero) for the single Seal/Open.
        struct Context {
            let key: SymmetricKey
            let baseNonce: Data
        }

        /// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
        private static func suiteID(kemID: UInt16) -> Data {
            var id = Data("HPKE".utf8)
            id.append(bigEndian: kemID)
            id.append(bigEndian: kdfID)
            id.append(bigEndian: aeadID)
            return id
        }

        /// `LabeledExtract(salt, label, ikm)` from RFC 9180 §4: HKDF-Extract over
        /// `"HPKE-v1" || suite_id || label || ikm`, keyed by `salt`. Returns the PRK.
        private static func labeledExtract(suiteID: Data, salt: Data, label: String, ikm: Data) -> Data {
            var labeledIKM = Data("HPKE-v1".utf8)
            labeledIKM.append(suiteID)
            labeledIKM.append(Data(label.utf8))
            labeledIKM.append(ikm)
            let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeledIKM), salt: salt)
            return Data(prk)
        }

        /// `LabeledExpand(prk, label, info, L)` from RFC 9180 §4: HKDF-Expand with
        /// info `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`.
        private static func labeledExpand(suiteID: Data, prk: Data, label: String, info: Data, length: Int) -> Data {
            var labeledInfo = Data()
            labeledInfo.append(bigEndian: UInt16(length))
            labeledInfo.append(Data("HPKE-v1".utf8))
            labeledInfo.append(suiteID)
            labeledInfo.append(Data(label.utf8))
            labeledInfo.append(info)
            let key = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeledInfo, outputByteCount: length)
            return key.withUnsafeBytes { Data($0) }
        }

        /// Derive the base-mode context from a KEM shared secret (`KeySchedule` with
        /// `mode_base` and empty psk/psk_id, RFC 9180 §5.1).
        static func context(kemID: UInt16, sharedSecret: Data, info: Data) -> Context {
            let sid = suiteID(kemID: kemID)
            let pskIDHash = labeledExtract(suiteID: sid, salt: Data(), label: "psk_id_hash", ikm: Data())
            let infoHash = labeledExtract(suiteID: sid, salt: Data(), label: "info_hash", ikm: info)

            var ksContext = Data([0x00]) // mode_base
            ksContext.append(pskIDHash)
            ksContext.append(infoHash)

            let secret = labeledExtract(suiteID: sid, salt: sharedSecret, label: "secret", ikm: Data())
            let key = labeledExpand(suiteID: sid, prk: secret, label: "key", info: ksContext, length: aeadKeySize)
            let baseNonce = labeledExpand(suiteID: sid, prk: secret, label: "base_nonce", info: ksContext, length: aeadNonceSize)
            return Context(key: SymmetricKey(data: key), baseNonce: baseNonce)
        }

        /// Seal `plaintext` with empty associated data at sequence number zero,
        /// returning the HPKE ciphertext (AEAD ciphertext `||` tag, without the nonce).
        static func seal(_ context: Context, plaintext: Data) throws -> Data {
            let nonce = try ChaChaPoly.Nonce(data: context.baseNonce)
            let box = try ChaChaPoly.seal(plaintext, using: context.key, nonce: nonce)
            return box.ciphertext + box.tag
        }

        /// Open an HPKE ciphertext (AEAD ciphertext `||` 16-byte tag) at sequence
        /// number zero. Throws `Error.openFailed` if authentication fails.
        static func open(_ context: Context, ciphertext: Data) throws -> Data {
            let tagSize = 16
            guard ciphertext.count >= tagSize else { throw Error.openFailed }
            let split = ciphertext.index(ciphertext.endIndex, offsetBy: -tagSize)
            let nonce = try ChaChaPoly.Nonce(data: context.baseNonce)
            let box = try ChaChaPoly.SealedBox(
                nonce: nonce,
                ciphertext: ciphertext[..<split],
                tag: ciphertext[split...])
            do {
                return try ChaChaPoly.open(box, using: context.key)
            } catch {
                throw Error.openFailed
            }
        }
    }
}

private extension Data {
    /// Append a big-endian (network byte order) 16-bit integer, i.e. `I2OSP(v, 2)`.
    mutating func append(bigEndian value: UInt16) {
        append(UInt8(value >> 8))
        append(UInt8(value & 0xff))
    }
}
