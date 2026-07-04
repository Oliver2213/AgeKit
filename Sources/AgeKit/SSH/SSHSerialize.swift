import CryptoKit
import Foundation

extension Age.SSHEd25519Identity {
    /// Serialize this identity as an unencrypted OpenSSH private key
    /// (`-----BEGIN OPENSSH PRIVATE KEY-----`, openssh-key-v1). The result is a
    /// valid `id_ed25519` file that `ssh`, `age`, and `rage` all accept.
    ///
    /// Reconstructed from the stored seed, so the derived public key and comment
    /// are byte-for-byte what the key implies (the original file's exact bytes —
    /// checkint, cipher, comment — are not necessarily reproduced).
    public func opensshPEM() -> String {
        let signing = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
        let pub = Array(signing.publicKey.rawRepresentation)
        let pubBlob = sshString("ssh-ed25519") + sshString(pub)

        // The private section: matching check ints, the key, then 1,2,3… padding
        // to the "none" cipher's 8-byte block size.
        var priv: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]   // check1 == check2 == 0
        priv += sshString("ssh-ed25519")
        priv += sshString(pub)
        priv += sshString(seed + pub)                   // 64-byte private: seed || public
        priv += sshString(comment)
        var pad: UInt8 = 1
        while priv.count % 8 != 0 { priv.append(pad); pad += 1 }

        var blob = Array("openssh-key-v1\0".utf8)
        blob += sshString("none")   // cipher
        blob += sshString("none")   // kdf
        blob += sshString([])       // kdfoptions
        blob += [0, 0, 0, 1]        // one key
        blob += sshString(pubBlob)
        blob += sshString(priv)

        let body = Data(blob).base64EncodedString()
        var wrapped: [String] = []
        var i = body.startIndex
        while i < body.endIndex {
            let end = body.index(i, offsetBy: 70, limitedBy: body.endIndex) ?? body.endIndex
            wrapped.append(String(body[i..<end]))
            i = end
        }
        return (["-----BEGIN OPENSSH PRIVATE KEY-----"]
            + wrapped
            + ["-----END OPENSSH PRIVATE KEY-----"]).joined(separator: "\n")
    }
}
