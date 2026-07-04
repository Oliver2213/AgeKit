import Foundation

/// An element of the field GF(2^255-19), used only to convert an Ed25519 public
/// key to its Curve25519 (Montgomery u-coordinate) encoding for the `ssh-ed25519`
/// recipient.
///
/// This is a faithful port of `filippo.io/edwards25519/field.Element`: radix
/// 2^51, five limbs, with the reduction identity `a·2^255 + b = a·19 + b`. The
/// 128-bit intermediates use `multipliedFullWidth`/carry (mirroring Go's
/// `bits.Mul64`) rather than the stdlib `UInt128`, which is unavailable below
/// macOS 15. All limb arithmetic uses wrapping operators to match the reference
/// (which never actually overflows) and to avoid Swift's overflow traps.
struct Field25519 {
    // t = l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204.
    // Between operations, all limbs are below 2^52.
    var l0: UInt64
    var l1: UInt64
    var l2: UInt64
    var l3: UInt64
    var l4: UInt64

    static let maskLow51: UInt64 = (1 << 51) - 1

    static let zero = Field25519(l0: 0, l1: 0, l2: 0, l3: 0, l4: 0)
    static let one = Field25519(l0: 1, l1: 0, l2: 0, l3: 0, l4: 0)

    init(l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64) {
        self.l0 = l0; self.l1 = l1; self.l2 = l2; self.l3 = l3; self.l4 = l4
    }

    /// Decode from a 32-byte little-endian encoding. Consistent with RFC 7748,
    /// the most significant bit is ignored and non-canonical values are accepted.
    /// `bytes` must be exactly 32 bytes.
    init(bytes x: [UInt8]) {
        precondition(x.count == 32, "Field25519 requires a 32-byte encoding")
        func le64(_ i: Int) -> UInt64 {
            var v: UInt64 = 0
            for k in 0..<8 { v |= UInt64(x[i + k]) << (8 * k) }
            return v
        }
        // Bit ranges match the reference SetBytes exactly.
        l0 = le64(0) & Field25519.maskLow51
        l1 = (le64(6) >> 3) & Field25519.maskLow51
        l2 = (le64(12) >> 6) & Field25519.maskLow51
        l3 = (le64(19) >> 1) & Field25519.maskLow51
        l4 = (le64(24) >> 12) & Field25519.maskLow51
    }

    /// The canonical 32-byte little-endian encoding.
    func encoded() -> [UInt8] {
        var t = self
        t.reduce()
        var out = [UInt8](repeating: 0, count: 32)
        let limbs = [t.l0, t.l1, t.l2, t.l3, t.l4]
        for i in 0..<5 {
            let bitsOffset = i * 51
            let shifted = limbs[i] << UInt64(bitsOffset % 8)
            for j in 0..<8 {
                let off = bitsOffset / 8 + j
                if off >= 32 { break }
                out[off] |= UInt8(truncatingIfNeeded: shifted >> (8 * j))
            }
        }
        return out
    }

    // MARK: - Carry / reduce

    /// Bring the limbs below 52 bits by applying the reduction identity to l4.
    mutating func carryPropagate() {
        let c0 = l0 >> 51
        let c1 = l1 >> 51
        let c2 = l2 >> 51
        let c3 = l3 >> 51
        let c4 = l4 >> 51
        l0 = (l0 & Field25519.maskLow51) &+ c4 &* 19
        l1 = (l1 & Field25519.maskLow51) &+ c0
        l2 = (l2 & Field25519.maskLow51) &+ c1
        l3 = (l3 & Field25519.maskLow51) &+ c2
        l4 = (l4 & Field25519.maskLow51) &+ c3
    }

    /// Reduce fully modulo 2^255-19.
    mutating func reduce() {
        carryPropagate()
        // Compute the carry out of adding 19: c is 1 iff v >= 2^255-19.
        var c = (l0 &+ 19) >> 51
        c = (l1 &+ c) >> 51
        c = (l2 &+ c) >> 51
        c = (l3 &+ c) >> 51
        c = (l4 &+ c) >> 51
        l0 = l0 &+ 19 &* c
        l1 = l1 &+ (l0 >> 51); l0 &= Field25519.maskLow51
        l2 = l2 &+ (l1 >> 51); l1 &= Field25519.maskLow51
        l3 = l3 &+ (l2 >> 51); l2 &= Field25519.maskLow51
        l4 = l4 &+ (l3 >> 51); l3 &= Field25519.maskLow51
        l4 &= Field25519.maskLow51
    }

    // MARK: - Arithmetic

    static func add(_ a: Field25519, _ b: Field25519) -> Field25519 {
        var v = Field25519(l0: a.l0 &+ b.l0, l1: a.l1 &+ b.l1, l2: a.l2 &+ b.l2,
                           l3: a.l3 &+ b.l3, l4: a.l4 &+ b.l4)
        v.carryPropagate()
        return v
    }

    static func subtract(_ a: Field25519, _ b: Field25519) -> Field25519 {
        // Add 2·p first so the subtraction can't underflow.
        var v = Field25519(
            l0: (a.l0 &+ 0xFFFFFFFFFFFDA) &- b.l0,
            l1: (a.l1 &+ 0xFFFFFFFFFFFFE) &- b.l1,
            l2: (a.l2 &+ 0xFFFFFFFFFFFFE) &- b.l2,
            l3: (a.l3 &+ 0xFFFFFFFFFFFFE) &- b.l3,
            l4: (a.l4 &+ 0xFFFFFFFFFFFFE) &- b.l4)
        v.carryPropagate()
        return v
    }

    static func multiply(_ a: Field25519, _ b: Field25519) -> Field25519 {
        let a0 = a.l0, a1 = a.l1, a2 = a.l2, a3 = a.l3, a4 = a.l4
        let b0 = b.l0, b1 = b.l1, b2 = b.l2, b3 = b.l3, b4 = b.l4
        let a1_19 = a1 &* 19, a2_19 = a2 &* 19, a3_19 = a3 &* 19, a4_19 = a4 &* 19

        var r0 = mul64(a0, b0)
        r0 = addMul64(r0, a1_19, b4); r0 = addMul64(r0, a2_19, b3)
        r0 = addMul64(r0, a3_19, b2); r0 = addMul64(r0, a4_19, b1)

        var r1 = mul64(a0, b1)
        r1 = addMul64(r1, a1, b0); r1 = addMul64(r1, a2_19, b4)
        r1 = addMul64(r1, a3_19, b3); r1 = addMul64(r1, a4_19, b2)

        var r2 = mul64(a0, b2)
        r2 = addMul64(r2, a1, b1); r2 = addMul64(r2, a2, b0)
        r2 = addMul64(r2, a3_19, b4); r2 = addMul64(r2, a4_19, b3)

        var r3 = mul64(a0, b3)
        r3 = addMul64(r3, a1, b2); r3 = addMul64(r3, a2, b1)
        r3 = addMul64(r3, a3, b0); r3 = addMul64(r3, a4_19, b4)

        var r4 = mul64(a0, b4)
        r4 = addMul64(r4, a1, b3); r4 = addMul64(r4, a2, b2)
        r4 = addMul64(r4, a3, b1); r4 = addMul64(r4, a4, b0)

        return reduceProducts(r0, r1, r2, r3, r4)
    }

    func squared() -> Field25519 {
        let l0 = self.l0, l1 = self.l1, l2 = self.l2, l3 = self.l3, l4 = self.l4
        let l0_2 = l0 &* 2, l1_2 = l1 &* 2
        let l1_38 = l1 &* 38, l2_38 = l2 &* 38, l3_38 = l3 &* 38
        let l3_19 = l3 &* 19, l4_19 = l4 &* 19

        var r0 = Field25519.mul64(l0, l0)
        r0 = Field25519.addMul64(r0, l1_38, l4); r0 = Field25519.addMul64(r0, l2_38, l3)

        var r1 = Field25519.mul64(l0_2, l1)
        r1 = Field25519.addMul64(r1, l2_38, l4); r1 = Field25519.addMul64(r1, l3_19, l3)

        var r2 = Field25519.mul64(l0_2, l2)
        r2 = Field25519.addMul64(r2, l1, l1); r2 = Field25519.addMul64(r2, l3_38, l4)

        var r3 = Field25519.mul64(l0_2, l3)
        r3 = Field25519.addMul64(r3, l1_2, l2); r3 = Field25519.addMul64(r3, l4_19, l4)

        var r4 = Field25519.mul64(l0_2, l4)
        r4 = Field25519.addMul64(r4, l1_2, l3); r4 = Field25519.addMul64(r4, l2, l2)

        return Field25519.reduceProducts(r0, r1, r2, r3, r4)
    }

    /// v = 1/z mod p, via exponentiation with exponent p−2 (same addition chain
    /// as Curve25519). Returns 0 if z == 0.
    func inverted() -> Field25519 {
        let z = self
        let z2 = z.squared()                                    // 2
        var t = z2.squared()                                    // 4
        t = t.squared()                                         // 8
        let z9 = Field25519.multiply(t, z)                      // 9
        let z11 = Field25519.multiply(z9, z2)                   // 11
        t = z11.squared()                                       // 22
        let z2_5_0 = Field25519.multiply(t, z9)                 // 2^5 - 2^0

        t = z2_5_0.squared()
        for _ in 0..<4 { t = t.squared() }
        let z2_10_0 = Field25519.multiply(t, z2_5_0)            // 2^10 - 2^0

        t = z2_10_0.squared()
        for _ in 0..<9 { t = t.squared() }
        let z2_20_0 = Field25519.multiply(t, z2_10_0)           // 2^20 - 2^0

        t = z2_20_0.squared()
        for _ in 0..<19 { t = t.squared() }
        t = Field25519.multiply(t, z2_20_0)                     // 2^40 - 2^0

        t = t.squared()
        for _ in 0..<9 { t = t.squared() }
        let z2_50_0 = Field25519.multiply(t, z2_10_0)           // 2^50 - 2^0

        t = z2_50_0.squared()
        for _ in 0..<49 { t = t.squared() }
        let z2_100_0 = Field25519.multiply(t, z2_50_0)          // 2^100 - 2^0

        t = z2_100_0.squared()
        for _ in 0..<99 { t = t.squared() }
        t = Field25519.multiply(t, z2_100_0)                    // 2^200 - 2^0

        t = t.squared()
        for _ in 0..<49 { t = t.squared() }
        t = Field25519.multiply(t, z2_50_0)                     // 2^250 - 2^0

        t = t.squared()                                         // 2^251 - 2^1
        t = t.squared()                                         // 2^252 - 2^2
        t = t.squared()                                         // 2^253 - 2^3
        t = t.squared()                                         // 2^254 - 2^4
        t = t.squared()                                         // 2^255 - 2^5
        return Field25519.multiply(t, z11)                      // 2^255 - 21
    }

    // MARK: - 128-bit helpers (two 64-bit limbs, like Go's uint128)

    private struct U128 { var lo: UInt64; var hi: UInt64 }

    private static func mul64(_ a: UInt64, _ b: UInt64) -> U128 {
        let (hi, lo) = a.multipliedFullWidth(by: b)
        return U128(lo: lo, hi: hi)
    }

    private static func addMul64(_ v: U128, _ a: UInt64, _ b: UInt64) -> U128 {
        let (hi0, lo0) = a.multipliedFullWidth(by: b)
        let (lo, carry) = lo0.addingReportingOverflow(v.lo)
        let hi = hi0 &+ v.hi &+ (carry ? 1 : 0)
        return U128(lo: lo, hi: hi)
    }

    private static func shiftRightBy51(_ a: U128) -> UInt64 {
        (a.hi << (64 - 51)) | (a.lo >> 51)
    }

    private static func reduceProducts(_ r0: U128, _ r1: U128, _ r2: U128,
                                       _ r3: U128, _ r4: U128) -> Field25519 {
        let c0 = shiftRightBy51(r0)
        let c1 = shiftRightBy51(r1)
        let c2 = shiftRightBy51(r2)
        let c3 = shiftRightBy51(r3)
        let c4 = shiftRightBy51(r4)
        var v = Field25519(
            l0: (r0.lo & maskLow51) &+ c4 &* 19,
            l1: (r1.lo & maskLow51) &+ c0,
            l2: (r2.lo & maskLow51) &+ c1,
            l3: (r3.lo & maskLow51) &+ c2,
            l4: (r4.lo & maskLow51) &+ c3)
        v.carryPropagate()
        return v
    }
}

// MARK: - Ed25519 → Curve25519

/// Convert a 32-byte Ed25519 public key to its 32-byte Curve25519 (Montgomery
/// u-coordinate) encoding, using the birational map `u = (1 + y) / (1 - y)`
/// from RFC 7748 §4.1. For a compressed public key the projective Z is 1, so the
/// decoded field element *is* y and no point decompression is required.
func ed25519PublicKeyToCurve25519(_ pub: [UInt8]) -> [UInt8] {
    let y = Field25519(bytes: pub)
    let numerator = Field25519.add(.one, y)             // 1 + y
    let denominator = Field25519.subtract(.one, y)      // 1 - y
    let u = Field25519.multiply(numerator, denominator.inverted())
    return u.encoded()
}
