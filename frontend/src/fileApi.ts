const allowedMediaTypes = new Set(['image/jpeg', 'image/png', 'application/pdf'])

export class FileApiError extends Error {
  readonly status: number

  constructor(status: number) {
    super('file_api_error')
    this.name = 'FileApiError'
    this.status = status
  }
}

export interface ProcessingReport {
  media_type: string
  metadata_categories: string[]
  output_verified: boolean
  width: number | null
  height: number | null
  page_count: number | null
  active_content_removed: boolean
  uri_links_removed: number
}

export interface ReportResource {
  report_id: string
  report: ProcessingReport
  created_at: string
  expires_at: string
}

export type VirusTotalStatus =
  | 'found'
  | 'not_found'
  | 'not_requested'
  | 'rate_limited'
  | 'key_unavailable'
  | 'unavailable'

export interface VirusTotalFileResult {
  status: VirusTotalStatus
  last_analysis_stats: Record<string, number> | null
  last_analysis_date: number | null
  report_url: string | null
}

export interface VirusTotalResults {
  original: VirusTotalFileResult
  cleaned: VirusTotalFileResult
}

export interface AnalysisResource extends ReportResource {
  virus_total: VirusTotalResults
}

export interface UploadResource {
  uploadId: string
  mediaType: string
}

export interface OneUseDownloadToken {
  token: string
  expiresAt: string
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null

function isNullablePositiveNumber(value: unknown): value is number | null {
  return value === null || (typeof value === 'number' && Number.isFinite(value) && value > 0)
}

function isReportResource(value: unknown): value is ReportResource {
  if (!isRecord(value) || !isRecord(value.report)) return false
  const report = value.report
  return (
    typeof value.report_id === 'string' && value.report_id.length > 0 &&
    typeof value.created_at === 'string' && typeof value.expires_at === 'string' &&
    typeof report.media_type === 'string' && allowedMediaTypes.has(report.media_type) &&
    Array.isArray(report.metadata_categories) && report.metadata_categories.every((item) => typeof item === 'string') &&
    typeof report.output_verified === 'boolean' &&
    isNullablePositiveNumber(report.width) && isNullablePositiveNumber(report.height) &&
    (report.page_count === null || (typeof report.page_count === 'number' && Number.isFinite(report.page_count) && report.page_count > 0)) &&
    typeof report.active_content_removed === 'boolean' &&
    typeof report.uri_links_removed === 'number' && Number.isInteger(report.uri_links_removed) && report.uri_links_removed >= 0
  )
}

const virusTotalStatuses = new Set<VirusTotalStatus>([
  'found', 'not_found', 'not_requested', 'rate_limited', 'key_unavailable', 'unavailable',
])
const virusTotalStats = new Set([
  'confirmed-timeout', 'failure', 'harmless', 'malicious', 'suspicious', 'timeout',
  'type-unsupported', 'undetected',
])
const virusTotalReportUrl = /^https:\/\/www\.virustotal\.com\/gui\/file\/[0-9a-f]{64}$/

function isVirusTotalFileResult(value: unknown): value is VirusTotalFileResult {
  if (!isRecord(value) || !virusTotalStatuses.has(value.status as VirusTotalStatus)) return false
  const stats = value.last_analysis_stats
  const validStats = stats === null || (
    isRecord(stats) && Object.keys(stats).length > 0 &&
    Object.entries(stats).every(([key, count]) => virusTotalStats.has(key) &&
      typeof count === 'number' && Number.isSafeInteger(count) && count >= 0)
  )
  const validDate = value.last_analysis_date === null ||
    (typeof value.last_analysis_date === 'number' && Number.isSafeInteger(value.last_analysis_date) && value.last_analysis_date >= 0)
  const validUrl = value.report_url === null ||
    (typeof value.report_url === 'string' && virusTotalReportUrl.test(value.report_url))
  return validStats && validDate && validUrl &&
    (value.status !== 'found' || (stats !== null && value.report_url !== null))
}

function isAnalysisResource(value: unknown): value is AnalysisResource {
  if (!isRecord(value)) return false
  const verdict = value.virus_total
  return isReportResource(value) && isRecord(verdict) &&
    isVirusTotalFileResult(verdict.original) &&
    isVirusTotalFileResult(verdict.cleaned)
}

async function request(
  path: string,
  csrfToken: string,
  options: { method?: 'GET' | 'POST' | 'DELETE'; body?: BodyInit; contentType?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = { 'X-CSRF-Token': csrfToken }
  if (options.contentType) headers['Content-Type'] = options.contentType

  let response: Response
  try {
    response = await fetch(path, {
      method: options.method ?? 'GET',
      credentials: 'include',
      cache: 'no-store',
      headers,
      ...(options.body !== undefined ? { body: options.body } : {}),
    })
  } catch {
    throw new FileApiError(0)
  }

  if (!response.ok) throw new FileApiError(response.status)
  return response
}

async function readJson<T>(response: Response, validate: (value: unknown) => value is T): Promise<T> {
  try {
    const value: unknown = await response.json()
    if (!validate(value)) throw new FileApiError(0)
    return value
  } catch (error) {
    if (error instanceof FileApiError) throw error
    throw new FileApiError(0)
  }
}

export async function uploadFile(file: File, csrfToken: string): Promise<UploadResource> {
  if (!allowedMediaTypes.has(file.type)) throw new FileApiError(415)

  const response = await request('/v1/uploads', csrfToken, {
    method: 'POST',
    contentType: file.type,
    body: file,
  })
  const value = await readJson(response, (candidate): candidate is { upload_id: string; media_type: string } =>
    isRecord(candidate) && typeof candidate.upload_id === 'string' && candidate.upload_id.length > 0 &&
    typeof candidate.media_type === 'string' && allowedMediaTypes.has(candidate.media_type),
  )
  return { uploadId: value.upload_id, mediaType: value.media_type }
}

export async function analyzeUpload(
  uploadId: string,
  csrfToken: string,
  virusTotalConsent = false,
): Promise<AnalysisResource> {
  const response = await request(`/v1/analyses/${encodeURIComponent(uploadId)}`, csrfToken, {
    method: 'POST',
    contentType: 'application/json',
    body: JSON.stringify({ virus_total_consent: virusTotalConsent }),
  })
  return readJson(response, isAnalysisResource)
}

export async function getReports(csrfToken: string): Promise<ReportResource[]> {
  const response = await request('/v1/reports', csrfToken)
  const value = await readJson(response, (candidate): candidate is { reports: ReportResource[] } =>
    isRecord(candidate) && Array.isArray(candidate.reports) && candidate.reports.every(isReportResource),
  )
  return value.reports
}

export async function getReport(reportId: string, csrfToken: string): Promise<ReportResource> {
  const response = await request(`/v1/reports/${encodeURIComponent(reportId)}`, csrfToken)
  return readJson(response, isReportResource)
}

export async function issueDownloadToken(reportId: string, csrfToken: string): Promise<OneUseDownloadToken> {
  const response = await request(`/v1/reports/${encodeURIComponent(reportId)}/download-token`, csrfToken, {
    method: 'POST',
  })
  const value = await readJson(response, (candidate): candidate is { token: string; expires_at: string } =>
    isRecord(candidate) && typeof candidate.token === 'string' && candidate.token.length > 0 &&
    typeof candidate.expires_at === 'string',
  )
  return { token: value.token, expiresAt: value.expires_at }
}

export async function downloadFile(token: string, csrfToken: string): Promise<Blob> {
  const response = await request('/v1/downloads', csrfToken, {
    method: 'POST',
    contentType: 'application/json',
    body: JSON.stringify({ token }),
  })
  try {
    return await response.blob()
  } catch {
    throw new FileApiError(0)
  }
}

export async function deleteReport(reportId: string, csrfToken: string): Promise<void> {
  await request(`/v1/reports/${encodeURIComponent(reportId)}`, csrfToken, { method: 'DELETE' })
}

export function fileErrorMessage(error: unknown): string {
  const status = error instanceof FileApiError
    ? error.status
    : typeof error === 'object' && error !== null && 'status' in error
      ? Number(error.status)
      : 0

  if (status === 401) return 'La sesión ha caducado. Inicia sesión de nuevo.'
  if (status === 403) return 'No pudimos verificar tu sesión. Recarga la página y vuelve a intentarlo.'
  if (status === 404) return 'El reporte o su copia ya no están disponibles.'
  if (status === 413) return 'El archivo es demasiado grande. Elige uno más pequeño.'
  if (status === 415) return 'Ese formato no es compatible. Elige un archivo JPG, PNG o PDF.'
  if (status === 429) return 'Has hecho varias solicitudes. Espera un momento antes de volver a intentarlo.'
  if (status === 503) return 'El servicio de archivos no está disponible en este momento. Vuelve a intentarlo más tarde.'
  return 'No pudimos completar la solicitud. Vuelve a intentarlo más tarde.'
}
