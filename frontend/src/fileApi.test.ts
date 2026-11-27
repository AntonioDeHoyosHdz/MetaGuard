import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  analyzeUpload,
  deleteReport,
  downloadFile,
  getReport,
  getReports,
  issueDownloadToken,
  uploadFile,
} from './fileApi'

const report = {
  report_id: 'report-123',
  report: {
    media_type: 'image/png',
    metadata_categories: ['software'],
    output_verified: true,
    width: 12,
    height: 8,
    page_count: null,
    active_content_removed: false,
    uri_links_removed: 0,
  },
  created_at: '2026-11-18T10:00:00Z',
  expires_at: '2026-11-19T10:00:00Z',
}

const response = (body: unknown, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  blob: async () => new Blob(['cleaned bytes'], { type: 'image/png' }),
})

const originalSha256 = 'a'.repeat(64)
const cleanedSha256 = 'b'.repeat(64)
const verdictUnavailable = {
  status: 'unavailable', last_analysis_stats: null, last_analysis_date: null, report_url: null,
}
const pdfReport = {
  ...report,
  report: { ...report.report, media_type: 'application/pdf', width: null, height: null, page_count: 1, uri_links_removed: 2 },
}
const pdfDestination = 'https://example.invalid/a'

afterEach(() => vi.unstubAllGlobals())

describe('fileApi', () => {
  it('uploads raw file bytes with the allow-listed content type, cookie credentials, and CSRF', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ upload_id: 'upload-123', media_type: 'image/png' }, 201))
    vi.stubGlobal('fetch', fetchMock)
    const file = new File([new Uint8Array([0, 1, 255])], 'image.png', { type: 'image/png' })

    await expect(uploadFile(file, 'csrf-current')).resolves.toEqual({ uploadId: 'upload-123', mediaType: 'image/png' })

    expect(fetchMock).toHaveBeenCalledExactlyOnceWith('/v1/uploads', expect.objectContaining({
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
      headers: { 'Content-Type': 'image/png', 'X-CSRF-Token': 'csrf-current' },
      body: file,
    }))
    expect((fetchMock.mock.calls[0][1] as RequestInit).body).not.toBeInstanceOf(FormData)
  })

  it('requests analysis with VirusTotal consent explicitly disabled', async () => {
    const responseBody = { ...report, virus_total: {
      original: { status: 'not_requested', last_analysis_stats: null, last_analysis_date: null, report_url: null },
      cleaned: { status: 'not_requested', last_analysis_stats: null, last_analysis_date: null, report_url: null },
    } }
    const fetchMock = vi.fn().mockResolvedValue(response(responseBody))
    vi.stubGlobal('fetch', fetchMock)

    await expect(analyzeUpload('upload-123', 'csrf-current')).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledExactlyOnceWith('/v1/analyses/upload-123', expect.objectContaining({
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-current' },
      body: JSON.stringify({ virus_total_consent: false }),
    }))
  })

  it('sends affirmative consent only on request and validates minimized verdicts', async () => {
    const responseBody = {
      ...report,
      virus_total: {
        original: {
          status: 'found',
          sha256: originalSha256,
          last_analysis_stats: { malicious: 1, undetected: 5 },
          last_analysis_date: 1_800_000_000,
          report_url: `https://www.virustotal.com/gui/file/${originalSha256}`,
        },
        cleaned: {
          status: 'not_found',
          sha256: cleanedSha256,
          last_analysis_stats: null,
          last_analysis_date: null,
          report_url: null,
        },
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(response(responseBody))
    vi.stubGlobal('fetch', fetchMock)

    await expect(analyzeUpload('upload-123', 'csrf-current', true)).resolves.toEqual(responseBody)
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith('/v1/analyses/upload-123', expect.objectContaining({
      body: JSON.stringify({ virus_total_consent: true }),
    }))
  })

  it('rejects provider report links outside the fixed host and path', async () => {
    const responseBody = {
      ...report,
      virus_total: {
        original: {
          status: 'found', last_analysis_stats: { malicious: 0 }, last_analysis_date: 1,
          report_url: `https://attacker.invalid/${'a'.repeat(64)}`,
        },
        cleaned: { status: 'not_requested', last_analysis_stats: null, last_analysis_date: null, report_url: null },
      },
    }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(responseBody)))

    await expect(analyzeUpload('upload-123', 'csrf-current', true)).rejects.toMatchObject({ status: 0 })
  })

  it.each([
    ['empty digest', { sha256: '' }, true],
    ['uppercase digest', { sha256: originalSha256.toUpperCase() }, true],
    ['digest with a trailing newline', { sha256: `${originalSha256}\n` }, true],
    ['non-string digest', { sha256: null }, true],
    ['mismatched digest and report link', {
      sha256: originalSha256,
      status: 'found',
      last_analysis_stats: { undetected: 1 },
      report_url: `https://www.virustotal.com/gui/file/${cleanedSha256}`,
    }, true],
    ['digest in a non-requested result', { status: 'not_requested', sha256: originalSha256 }, true],
    ['digest without request consent', { sha256: originalSha256 }, false],
  ])('rejects %s from the analysis response', async (_name, override, consent) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({
      ...report,
      virus_total: { original: { ...verdictUnavailable, ...override }, cleaned: verdictUnavailable },
    })))

    await expect(analyzeUpload('upload-123', 'csrf-current', consent)).rejects.toMatchObject({ status: 0 })
  })

  it.each([
    ['omitted', undefined],
    ['empty', []],
    ['nonempty', [pdfDestination, 'http://example.invalid:8080/b']],
  ] as const)(
    'accepts a valid transient PDF destination inventory (%s)',
    async (_name, previews) => {
      const body = {
        ...pdfReport,
        virus_total: { original: verdictUnavailable, cleaned: verdictUnavailable },
        ...(previews === undefined ? {} : { removed_pdf_links: previews }),
      }
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(body)))

      await expect(analyzeUpload('upload-123', 'csrf-current')).resolves.toEqual(body)
    },
  )

  it.each([
    ['not a list', null, 2, 'application/pdf'],
    ['an image response', [pdfDestination], 2, 'image/png'],
    ['a duplicate destination', [pdfDestination, pdfDestination], 2, 'application/pdf'],
    ['more previews than removed actions', [pdfDestination], 0, 'application/pdf'],
    ['more than sixteen previews', Array.from({ length: 17 }, (_, i) => `https://example.invalid/${i}`), 17, 'application/pdf'],
    ['a long destination', [`https://example.invalid/${'a'.repeat(384)}`], 2, 'application/pdf'],
    ['a relative reference', ['example.invalid/a'], 2, 'application/pdf'],
    ['a blank authority', ['https:///example.invalid/a'], 2, 'application/pdf'],
    ['userinfo', ['https://visitor@example.invalid/a'], 2, 'application/pdf'],
    ['empty userinfo', ['https://@example.invalid/a'], 2, 'application/pdf'],
    ['a query string', [`${pdfDestination}?test=1`], 2, 'application/pdf'],
    ['a fragment', [`${pdfDestination}#page`], 2, 'application/pdf'],
    ['a control character', [`${pdfDestination}\n`], 2, 'application/pdf'],
    ['an invalid escape', [`${pdfDestination}%q5`], 2, 'application/pdf'],
    ['a bad port', ['https://example.invalid:abc/a'], 2, 'application/pdf'],
    ['an empty port', ['https://example.invalid:/a'], 2, 'application/pdf'],
    ['port zero', ['https://example.invalid:0/a'], 2, 'application/pdf'],
  ])('rejects %s in the PDF destination inventory', async (_name, previews, count, mediaType) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({
      ...pdfReport,
      report: { ...pdfReport.report, media_type: mediaType, uri_links_removed: count },
      virus_total: { original: verdictUnavailable, cleaned: verdictUnavailable },
      removed_pdf_links: previews,
    })))

    await expect(analyzeUpload('upload-123', 'csrf-current')).rejects.toMatchObject({ status: 0, message: 'file_api_error' })
  })

  it('lists and reads report resources with credentials and the current CSRF header', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ reports: [report] }))
      .mockResolvedValueOnce(response(report))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getReports('csrf-current')).resolves.toEqual([report])
    await expect(getReport('report-123', 'csrf-current')).resolves.toEqual(report)

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/v1/reports', expect.objectContaining({
      method: 'GET', credentials: 'include', cache: 'no-store',
      headers: { 'X-CSRF-Token': 'csrf-current' },
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/v1/reports/report-123', expect.objectContaining({
      method: 'GET', credentials: 'include', cache: 'no-store',
      headers: { 'X-CSRF-Token': 'csrf-current' },
    }))
  })

  it('keeps destination previews out of historical report resources', async () => {
    const extras = { removed_pdf_links: [pdfDestination] }
    const unprojected = { ...pdfReport, ...extras, report: { ...pdfReport.report, ...extras } }
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response({ reports: [unprojected] }))
      .mockResolvedValueOnce(response(unprojected)))

    await expect(getReports('csrf-current')).resolves.toEqual([pdfReport])
    await expect(getReport('report-123', 'csrf-current')).resolves.toEqual(pdfReport)
  })

  it('issues one-use download tokens, downloads binary content, and deletes owner reports', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ token: 'opaque-one-use', expires_at: '2026-11-18T10:10:00Z' }))
      .mockResolvedValueOnce(response(null))
      .mockResolvedValueOnce(response(null, 204))
    vi.stubGlobal('fetch', fetchMock)

    const token = await issueDownloadToken('report-123', 'csrf-current')
    const file = await downloadFile(token.token, 'csrf-current')
    await deleteReport('report-123', 'csrf-current')

    expect(token).toEqual({ token: 'opaque-one-use', expiresAt: '2026-11-18T10:10:00Z' })
    expect(file.type).toBe('image/png')
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/v1/reports/report-123/download-token', expect.objectContaining({
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'X-CSRF-Token': 'csrf-current' },
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/v1/downloads', expect.objectContaining({
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'X-CSRF-Token': 'csrf-current', 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'opaque-one-use' }),
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/v1/reports/report-123', expect.objectContaining({
      method: 'DELETE', credentials: 'include', cache: 'no-store',
      headers: { 'X-CSRF-Token': 'csrf-current' },
    }))
  })

  it('rejects unsupported media types before making a request', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const file = new File(['text'], 'notes.txt', { type: 'text/plain' })

    await expect(uploadFile(file, 'csrf-current')).rejects.toMatchObject({ status: 415 })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('does not expose server error details to callers', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ detail: 'private stack trace' }, 503))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getReports('csrf-current')).rejects.toMatchObject({ status: 503, message: 'file_api_error' })
  })
})
