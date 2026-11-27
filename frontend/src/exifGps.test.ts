import { describe, expect, it } from 'vitest'
import { parseExifGps } from './exifGps'

type Dms = [number, number, number]

function tiff(
  littleEndian: boolean,
  lat: Dms = [19, 25, 57.36],
  lon: Dms = [99, 7, 59.52],
  latitudeRef = 'N',
  longitudeRef = 'W',
): Uint8Array {
  const out = new Uint8Array(128)
  const view = new DataView(out.buffer)
  const u16 = (offset: number, value: number) => view.setUint16(offset, value, littleEndian)
  const u32 = (offset: number, value: number) => view.setUint32(offset, value, littleEndian)
  const entry = (offset: number, tag: number, type: number, count: number, value: number | string) => {
    u16(offset, tag)
    u16(offset + 2, type)
    u32(offset + 4, count)
    if (typeof value === 'number') u32(offset + 8, value)
    else out[offset + 8] = value.charCodeAt(0)
  }
  out.fill(littleEndian ? 0x49 : 0x4d, 0, 2)
  u16(2, 42)
  u32(4, 8)
  u16(8, 1)
  entry(10, 0x8825, 4, 1, 26)
  u16(26, 4)
  entry(28, 1, 2, 2, latitudeRef)
  entry(40, 2, 5, 3, 80)
  entry(52, 3, 2, 2, longitudeRef)
  entry(64, 4, 5, 3, 104)
  for (const [index, value] of [...lat, ...lon].entries()) {
    u32(80 + index * 8, Math.round(value * 100))
    u32(84 + index * 8, 100)
  }
  return out
}

function jpeg(profile: Uint8Array): Uint8Array {
  const length = profile.length + 8
  return Uint8Array.of(0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0,
    0xff, 0xe1, length >> 8, length & 0xff, 69, 120, 105, 102, 0, 0,
    ...profile, 0xff, 0xd9)
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const chunk = new Uint8Array(data.length + 12)
  const view = new DataView(chunk.buffer)
  view.setUint32(0, data.length)
  chunk.set([...type].map(letter => letter.charCodeAt(0)), 4)
  chunk.set(data, 8)
  let crc = 0xffffffff
  for (const byte of chunk.subarray(4, chunk.length - 4)) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0)
  }
  view.setUint32(chunk.length - 4, ~crc)
  return chunk
}

function png(profile: Uint8Array): Uint8Array {
  const ihdr = pngChunk('IHDR', Uint8Array.of(0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0))
  return Uint8Array.of(137, 80, 78, 71, 13, 10, 26, 10,
    ...ihdr, ...pngChunk('eXIf', profile), ...pngChunk('IEND', new Uint8Array()))
}

describe('Exif GPS preview', () => {
  it('reads little-endian JPEG Exif with a western longitude', () => {
    const point = parseExifGps(jpeg(tiff(true)))
    expect(point?.latitude).toBeCloseTo(19.4326, 6)
    expect(point?.longitude).toBeCloseTo(-99.1332, 6)
  })

  it('reads big-endian PNG eXIf with southern and eastern directions', () => {
    const point = parseExifGps(png(tiff(false, [33, 52, 0], [151, 12, 0], 'S', 'E')))
    expect(point?.latitude).toBeCloseTo(-33.8666667, 6)
    expect(point?.longitude).toBeCloseTo(151.2, 6)
  })

  it('accepts a coordinate of zero in either hemisphere', () => {
    expect(parseExifGps(jpeg(tiff(true, [0, 0, 0], [0, 0, 0], 'S', 'W'))))
      .toEqual({ latitude: 0, longitude: 0 })
  })

  it('rejects out-of-range DMS coordinates and non-coordinate data', () => {
    const cases = [
      tiff(true, [90, 0, 1]),
      tiff(true, [89, 60, 0]),
      tiff(true, [89, 59, 60]),
      tiff(true, [1, 0, 0], [181, 0, 0]),
      tiff(true, [1, 0, 0], [179, 0, 0], 'E'),
    ]
    for (const profile of cases) expect(parseExifGps(jpeg(profile))).toBeNull()
    expect(parseExifGps(tiff(true))).toBeNull()
    expect(parseExifGps(Uint8Array.of(0xff, 0xd8, 0xff, 0xd9))).toBeNull()
  })

  it('does not follow an out-of-bounds pointer or accept ambiguous GPS entries', () => {
    const changes: [number, number, number][] = [
      [18, 4, 0xfffffff0], // IFD beyond the profile
      [18, 4, 8], // IFD0 self-reference
      [64, 2, 2], // duplicate latitude entry
      [72, 4, 125], // RATIONAL data beyond the profile
      [84, 4, 0], // invalid denominator
    ]
    for (const [offset, size, value] of changes) {
      const profile = tiff(true)
      const view = new DataView(profile.buffer)
      if (size === 2) view.setUint16(offset, value, true)
      else view.setUint32(offset, value, true)
      expect(parseExifGps(jpeg(profile))).toBeNull()
    }
  })

  it('rejects truncated or invalid GPS blocks and a bad PNG eXIf CRC', () => {
    const jpegBytes = jpeg(tiff(true))
    expect(parseExifGps(jpegBytes.subarray(0, jpegBytes.length - 3))).toBeNull()
    const pngBytes = png(tiff(true))
    pngBytes[pngBytes.length - 13] ^= 1 // Change just the eXIf CRC before IEND.
    expect(parseExifGps(pngBytes)).toBeNull()
  })
})
