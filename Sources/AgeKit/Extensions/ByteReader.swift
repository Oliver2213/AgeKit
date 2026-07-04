import Foundation

/// A minimal forward byte cursor over a fully-buffered input.
///
/// age headers are small and parsed by fully consuming the input first, so we
/// don't need a networking buffer for this — a byte array plus a read index is
/// enough. This replaces the previous NIO `ByteBuffer`, keeping the same method
/// names and semantics the parser relies on (notably: `readBytes(until:)` reads
/// through the delimiter, or all remaining bytes if it isn't found, and returns
/// an empty array — not nil — at end of input).
struct ByteReader {
    private let storage: [UInt8]
    private var index = 0

    /// Consume the entire `InputStream` into memory.
    init(_ input: InputStream) {
        var all = [UInt8]()
        let bufSize = 4096
        var buf = [UInt8](repeating: 0, count: bufSize)
        while input.hasBytesAvailable {
            let n = input.read(&buf, maxLength: bufSize)
            if n <= 0 { break }
            all.append(contentsOf: buf[..<n])
        }
        self.storage = all
    }

    /// Number of unread bytes remaining.
    var readableBytes: Int { storage.count - index }

    /// The current read position.
    var readerIndex: Int { index }

    /// Peek `length` bytes at absolute offset `at` without advancing. Returns nil
    /// if the requested range runs past the end of the buffer.
    func getBytes(at: Int, length: Int) -> [UInt8]? {
        guard at >= 0, length >= 0, at + length <= storage.count else { return nil }
        return Array(storage[at ..< at + length])
    }

    /// Read `length` bytes and advance. Returns nil if fewer than `length` remain.
    mutating func readBytes(length: Int) -> [UInt8]? {
        guard length >= 0, index + length <= storage.count else { return nil }
        defer { index += length }
        return Array(storage[index ..< index + length])
    }

    /// Read through the next `delim` (inclusive) and advance. If `delim` isn't
    /// found, reads all remaining bytes (an empty array once the buffer is drained).
    mutating func readBytes(until delim: Character) -> [UInt8]? {
        let byte = delim.asciiValue!
        if let offset = storage[index...].firstIndex(of: byte) {
            return readBytes(length: offset - index + 1)
        }
        return readBytes(length: readableBytes)
    }

    /// Read `length` bytes as a UTF-8 string and advance. Returns nil if fewer
    /// than `length` bytes remain.
    mutating func readString(length: Int) -> String? {
        guard let bytes = readBytes(length: length) else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Read through the next `delim` as a UTF-8 string and advance.
    mutating func readString(until delim: Character) -> String? {
        guard let bytes = readBytes(until: delim) else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }
}
