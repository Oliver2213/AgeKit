import Foundation

/// Blowfish, used solely as the primitive inside bcrypt-pbkdf when decrypting
/// passphrase-protected OpenSSH private keys. Ported from
/// `golang.org/x/crypto/blowfish`; the S-boxes and P-array live in
/// `BlowfishConst.swift`. All word arithmetic wraps (mod 2^32) via `&+`.
///
/// The four 256-word S-boxes are stored as one flat 1024-word array so the key
/// schedule can fill them with a single continuing cipher chain.
struct Blowfish {
    private var p: [UInt32]
    private var s: [UInt32]   // s0 | s1 | s2 | s3, 256 words each

    init() {
        p = blowfishPInit
        s = blowfishS0 + blowfishS1 + blowfishS2 + blowfishS3
    }

    @inline(__always)
    private func f(_ x: UInt32) -> UInt32 {
        ((s[Int(x >> 24)] &+ s[0x100 + Int((x >> 16) & 0xff)])
            ^ s[0x200 + Int((x >> 8) & 0xff)]) &+ s[0x300 + Int(x & 0xff)]
    }

    private func encryptBlock(_ l: UInt32, _ r: UInt32) -> (UInt32, UInt32) {
        var xl = l, xr = r
        xl ^= p[0]
        xr ^= f(xl) ^ p[1];  xl ^= f(xr) ^ p[2]
        xr ^= f(xl) ^ p[3];  xl ^= f(xr) ^ p[4]
        xr ^= f(xl) ^ p[5];  xl ^= f(xr) ^ p[6]
        xr ^= f(xl) ^ p[7];  xl ^= f(xr) ^ p[8]
        xr ^= f(xl) ^ p[9];  xl ^= f(xr) ^ p[10]
        xr ^= f(xl) ^ p[11]; xl ^= f(xr) ^ p[12]
        xr ^= f(xl) ^ p[13]; xl ^= f(xr) ^ p[14]
        xr ^= f(xl) ^ p[15]; xl ^= f(xr) ^ p[16]
        xr ^= p[17]
        return (xr, xl)
    }

    /// The next big-endian word from `b`, read circularly, advancing `pos`.
    private func nextWord(_ b: [UInt8], _ pos: inout Int) -> UInt32 {
        var w: UInt32 = 0
        for _ in 0..<4 {
            w = (w << 8) | UInt32(b[pos])
            pos += 1
            if pos >= b.count { pos = 0 }
        }
        return w
    }

    /// The plain Blowfish key schedule.
    mutating func expandKey(_ key: [UInt8]) {
        var j = 0
        for i in 0..<18 { p[i] ^= nextWord(key, &j) }
        var l: UInt32 = 0, r: UInt32 = 0
        for i in stride(from: 0, to: 18, by: 2) { (l, r) = encryptBlock(l, r); p[i] = l; p[i + 1] = r }
        for i in stride(from: 0, to: 1024, by: 2) { (l, r) = encryptBlock(l, r); s[i] = l; s[i + 1] = r }
    }

    /// The salted (EksBlowfish) key schedule folded into the pi/S-box tables.
    mutating func expandKeyWithSalt(_ key: [UInt8], _ salt: [UInt8]) {
        var j = 0
        for i in 0..<18 { p[i] ^= nextWord(key, &j) }
        j = 0
        var l: UInt32 = 0, r: UInt32 = 0
        for i in stride(from: 0, to: 18, by: 2) {
            l ^= nextWord(salt, &j); r ^= nextWord(salt, &j)
            (l, r) = encryptBlock(l, r); p[i] = l; p[i + 1] = r
        }
        for i in stride(from: 0, to: 1024, by: 2) {
            l ^= nextWord(salt, &j); r ^= nextWord(salt, &j)
            (l, r) = encryptBlock(l, r); s[i] = l; s[i + 1] = r
        }
    }

    /// Encrypt the 8-byte block at `off` within `block`, in place.
    func encrypt(_ block: inout [UInt8], at off: Int) {
        var l = UInt32(block[off]) << 24 | UInt32(block[off + 1]) << 16
            | UInt32(block[off + 2]) << 8 | UInt32(block[off + 3])
        var r = UInt32(block[off + 4]) << 24 | UInt32(block[off + 5]) << 16
            | UInt32(block[off + 6]) << 8 | UInt32(block[off + 7])
        (l, r) = encryptBlock(l, r)
        block[off] = UInt8(truncatingIfNeeded: l >> 24); block[off + 1] = UInt8(truncatingIfNeeded: l >> 16)
        block[off + 2] = UInt8(truncatingIfNeeded: l >> 8); block[off + 3] = UInt8(truncatingIfNeeded: l)
        block[off + 4] = UInt8(truncatingIfNeeded: r >> 24); block[off + 5] = UInt8(truncatingIfNeeded: r >> 16)
        block[off + 6] = UInt8(truncatingIfNeeded: r >> 8); block[off + 7] = UInt8(truncatingIfNeeded: r)
    }
}
