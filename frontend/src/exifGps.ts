export type ExifGpsPoint = Readonly<{ latitude: number; longitude: number }>

export const MAX_GPS_FILE_BYTES = 25 * 1024 * 1024
const MAX_EXIF_BYTES = 1024 * 1024
const MAX_HEADERS = 4096
const MAX_IFD_ENTRIES = 512
const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10]
const EXIF_IDENTIFIER = [69, 120, 105, 102, 0, 0]
const IHDR = 0x49484452
const EXIF_CHUNK = 0x65584966
const IEND = 0x49454e44

const matches = (bytes: Uint8Array, start: number, prefix: number[]) =>
  prefix.every((value, i) => bytes[start + i] === value)

function exifFromJpeg(bytes: Uint8Array): Uint8Array | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let offset = 2
  let profile: Uint8Array | null = null
  for (let header = 0; header < MAX_HEADERS && offset < bytes.length; header++) {
    if (bytes[offset++] !== 0xff) return null
    while (bytes[offset] === 0xff) offset++
    const marker = bytes[offset++]
    if (marker === 0xd9) return profile
    if (marker === 0x00 || marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7)) return null
    if (marker === 0x01) continue // Standalone TEM marker.
    if (offset + 2 > bytes.length) return null
    const length = view.getUint16(offset)
    if (length < 2 || offset + length > bytes.length) return null
    if (marker === 0xda) return profile // Do not interpret any entropy-coded data.
    if (marker === 0xe1 && length >= 2 + EXIF_IDENTIFIER.length &&
        matches(bytes, offset + 2, EXIF_IDENTIFIER)) {
      if (profile) return null
      profile = bytes.subarray(offset + 2 + EXIF_IDENTIFIER.length, offset + length)
    }
    offset += length
  }
  return null
}

function pngCrc(bytes: Uint8Array, start: number, end: number): number {
  let crc = 0xffffffff
  for (let offset = start; offset < end; offset++) {
    crc ^= bytes[offset]
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0)
  }
  return (~crc) >>> 0
}

function exifFromPng(bytes: Uint8Array): Uint8Array | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let offset = PNG_SIGNATURE.length
  let profile: Uint8Array | null = null
  for (let header = 0; header < MAX_HEADERS && offset + 12 <= bytes.length; header++) {
    const length = view.getUint32(offset)
    const type = view.getUint32(offset + 4)
    const end = offset + 8 + length
    if (end + 4 > bytes.length) return null
    if (header === 0 && (type !== IHDR || length !== 13)) return null
    if (type === IEND) return length === 0 && end + 4 === bytes.length ? profile : null
    if (type === EXIF_CHUNK) {
      if (profile || length > MAX_EXIF_BYTES || pngCrc(bytes, offset + 4, end) !== view.getUint32(end)) return null
      profile = bytes.subarray(offset + 8, end)
    }
    offset = end + 4
  }
  return null
}

function pointFromTiff(bytes: Uint8Array): ExifGpsPoint | null {
  if (bytes.length < 8) return null
  const little = bytes[0] === 0x49 && bytes[1] === 0x49
  if (!little && (bytes[0] !== 0x4d || bytes[1] !== 0x4d)) return null
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const read16 = (offset: number) => view.getUint16(offset, little)
  const read32 = (offset: number) => view.getUint32(offset, little)
  if (read16(2) !== 42) return null

  function readEntries(offset: number, selected: number[]): Map<number, number> | null {
    if (offset < 8 || offset + 2 > bytes.length) return null
    const count = read16(offset)
    if (count > MAX_IFD_ENTRIES || offset + 2 + count * 12 + 4 > bytes.length) return null
    const entries = new Map<number, number>()
    for (let i = 0; i < count; i++) {
      const entry = offset + 2 + i * 12
      const tag = read16(entry)
      if (!selected.includes(tag)) continue
      if (entries.has(tag)) return null
      entries.set(tag, entry)
    }
    return entries
  }

  const ifd0 = read32(4)
  const pointer = readEntries(ifd0, [0x8825])?.get(0x8825)
  if (pointer === undefined || read16(pointer + 2) !== 4 || read32(pointer + 4) !== 1) return null
  const gps = read32(pointer + 8)
  if (gps === ifd0) return null
  const entries = readEntries(gps, [1, 2, 3, 4])
  if (entries?.size !== 4) return null

  function coordinate(refTag: number, valueTag: number, positive: number, negative: number, max: number) {
    const refEntry = entries?.get(refTag)
    const valueEntry = entries?.get(valueTag)
    if (refEntry === undefined || valueEntry === undefined) return null
    if (read16(refEntry + 2) !== 2 || read32(refEntry + 4) !== 2 || bytes[refEntry + 9] !== 0) return null
    const ref = bytes[refEntry + 8]
    if (ref !== positive && ref !== negative) return null
    if (read16(valueEntry + 2) !== 5 || read32(valueEntry + 4) !== 3) return null
    const offset = read32(valueEntry + 8)
    if (offset < 8 || offset + 24 > bytes.length) return null
    const parts = [0, 8, 16].map(i => read32(offset + i) / read32(offset + i + 4))
    if (parts.some(part => !Number.isFinite(part)) || parts[1] >= 60 || parts[2] >= 60) return null
    const degrees = parts[0] + parts[1] / 60 + parts[2] / 3600
    if (degrees > max) return null
    return degrees === 0 || ref === positive ? degrees : -degrees
  }

  const latitude = coordinate(1, 2, 78, 83, 90) // N / S
  const longitude = coordinate(3, 4, 69, 87, 180) // E / W
  return latitude === null || longitude === null ? null : { latitude, longitude }
}

/** Reads only the primary Exif GPS fields; it does not decode or validate the image. */
export function parseExifGps(bytes: Uint8Array): ExifGpsPoint | null {
  if (bytes.length > MAX_GPS_FILE_BYTES) return null
  const profile = matches(bytes, 0, [0xff, 0xd8]) ? exifFromJpeg(bytes)
    : matches(bytes, 0, PNG_SIGNATURE) ? exifFromPng(bytes)
      : null
  return profile === null ? null : pointFromTiff(profile)
}
