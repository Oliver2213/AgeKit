import CommonCrypto
import Foundation

/// Decrypt the private-key section of an encrypted openssh-key-v1 container.
///
/// The KDF is bcrypt-pbkdf (the only KDF OpenSSH uses); the cipher is one of the
/// AES CTR/CBC variants. The passphrase + KDF salt derive a key and IV, which
/// decrypt the private blob.
func decryptOpenSSHPrivateBlob(
    _ ciphertext: [UInt8],
    cipher: String,
    kdf: String,
    kdfOptions: [UInt8],
    passphrase: String
) throws -> [UInt8] {
    guard kdf == "bcrypt" else { throw SSHKeyError.unsupportedKDF(kdf) }

    // kdfoptions for bcrypt: string(salt) + uint32(rounds).
    var opts = SSHBufferReader(kdfOptions)
    guard let salt = opts.readString(), let rounds = opts.readUInt32() else {
        throw SSHKeyError.malformedPrivateKey
    }

    let params: (keyLen: Int, ivLen: Int, mode: Int)
    switch cipher {
    case "aes256-ctr": params = (32, 16, kCCModeCTR)
    case "aes192-ctr": params = (24, 16, kCCModeCTR)
    case "aes128-ctr": params = (16, 16, kCCModeCTR)
    case "aes256-cbc": params = (32, 16, kCCModeCBC)
    case "aes192-cbc": params = (24, 16, kCCModeCBC)
    case "aes128-cbc": params = (16, 16, kCCModeCBC)
    default: throw SSHKeyError.unsupportedCipher(cipher)
    }

    let derived = try BcryptPBKDF.deriveKey(
        password: Array(passphrase.utf8), salt: salt,
        rounds: Int(rounds), keyLength: params.keyLen + params.ivLen)
    let key = Array(derived[0..<params.keyLen])
    let iv = Array(derived[params.keyLen..<params.keyLen + params.ivLen])

    return try aesDecrypt(mode: params.mode, key: key, iv: iv, ciphertext: ciphertext)
}

/// AES decryption via CommonCrypto in CTR or CBC mode, no padding (the
/// openssh-key-v1 blob carries its own length + padding). For CTR, decrypt and
/// encrypt are the same operation.
private func aesDecrypt(mode: Int, key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
    var cryptorRef: CCCryptorRef?
    let status = CCCryptorCreateWithMode(
        CCOperation(kCCDecrypt), CCMode(mode), CCAlgorithm(kCCAlgorithmAES),
        CCPadding(ccNoPadding), iv, key, key.count,
        nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptorRef)
    guard status == kCCSuccess, let cryptor = cryptorRef else {
        throw SSHKeyError.malformedPrivateKey
    }
    defer { CCCryptorRelease(cryptor) }

    var out = [UInt8](repeating: 0, count: ciphertext.count)
    var moved = 0
    let updateStatus = CCCryptorUpdate(cryptor, ciphertext, ciphertext.count, &out, out.count, &moved)
    guard updateStatus == kCCSuccess else { throw SSHKeyError.malformedPrivateKey }

    var finalMoved = 0
    let finalStatus = out.withUnsafeMutableBufferPointer { buf -> CCCryptorStatus in
        CCCryptorFinal(cryptor, buf.baseAddress!.advanced(by: moved), buf.count - moved, &finalMoved)
    }
    guard finalStatus == kCCSuccess else { throw SSHKeyError.malformedPrivateKey }
    return Array(out.prefix(moved + finalMoved))
}
