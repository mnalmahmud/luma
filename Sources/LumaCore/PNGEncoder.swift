import Foundation

enum PNGEncoder {
    static func encodeRGBA(width: Int, height: Int, pixels: [UInt8]) -> Data? {
        let rowstride = width * 4
        guard width > 0, height > 0, pixels.count >= rowstride * height else { return nil }

        var raw = [UInt8]()
        raw.reserveCapacity((rowstride + 1) * height)
        for row in 0..<height {
            raw.append(0)
            let start = row * rowstride
            raw.append(contentsOf: pixels[start..<(start + rowstride)])
        }

        var header = Data()
        header.appendBigEndian(UInt32(width))
        header.appendBigEndian(UInt32(height))
        header.append(contentsOf: [8, 6, 0, 0, 0])

        var png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        png.append(chunk(type: "IHDR", payload: header))
        png.append(chunk(type: "IDAT", payload: deflateStored(raw)))
        png.append(chunk(type: "IEND", payload: Data()))
        return png
    }

    /// A zlib stream of stored (type-0) DEFLATE blocks. Emitting real
    /// compression would mean linking one — icons are small enough that
    /// the extra bytes are cheaper than a new dependency in LumaCore.
    private static func deflateStored(_ input: [UInt8]) -> Data {
        var out = Data([0x78, 0x01])
        var offset = 0
        repeat {
            let count = min(input.count - offset, 0xFFFF)
            let isFinal = offset + count >= input.count
            out.append(isFinal ? 1 : 0)
            out.append(UInt8(count & 0xFF))
            out.append(UInt8((count >> 8) & 0xFF))
            out.append(UInt8(~count & 0xFF))
            out.append(UInt8((~count >> 8) & 0xFF))
            out.append(contentsOf: input[offset..<(offset + count)])
            offset += count
        } while offset < input.count
        out.appendBigEndian(adler32(input))
        return out
    }

    private static func chunk(type: String, payload: Data) -> Data {
        var out = Data()
        out.appendBigEndian(UInt32(payload.count))
        let body = Data(type.utf8) + payload
        out.append(body)
        out.appendBigEndian(crc32(body))
        return out
    }

    private static func adler32(_ bytes: [UInt8]) -> UInt32 {
        var a: UInt32 = 1
        var b: UInt32 = 0
        for byte in bytes {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        return (b << 16) | a
    }

    private static let crcTable: [UInt32] = (0..<256).map { index in
        var c = UInt32(index)
        for _ in 0..<8 {
            c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1
        }
        return c
    }

    private static func crc32(_ bytes: Data) -> UInt32 {
        var c: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            c = crcTable[Int((c ^ UInt32(byte)) & 0xFF)] ^ (c >> 8)
        }
        return c ^ 0xFFFF_FFFF
    }
}

extension Data {
    fileprivate mutating func appendBigEndian(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }
}
