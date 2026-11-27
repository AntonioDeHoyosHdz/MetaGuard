import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import ReputationFileResult from './ReputationFileResult'
import type { VirusTotalFileResult } from './fileApi'

const sha256 = 'a'.repeat(64)
const noDetails = {
  last_analysis_stats: null,
  last_analysis_date: null,
  report_url: null,
}
const found: VirusTotalFileResult = {
  status: 'found',
  ...noDetails,
  sha256,
  report_url: `https://www.virustotal.com/gui/file/${sha256}`,
}

afterEach(cleanup)

describe('ReputationFileResult', () => {
  it.each([
    { kind: 'original', target: 'este archivo original' },
    { kind: 'cleaned', target: 'esta copia sin metadatos' },
  ] as const)('identifies malicious detections in the $kind without claiming a byte scan', ({ kind, target }) => {
    render(<ReputationFileResult kind={kind} result={{
      ...found, last_analysis_stats: { malicious: 2, suspicious: 1 },
    }} />)

    expect(screen.getByRole('alert').textContent).toContain('VirusTotal reportó detecciones maliciosas.')
    expect(screen.getByRole('alert').textContent).toContain(`No abras ni compartas ${target}.`)
    expect(screen.getByText(sha256).tagName).toBe('CODE')
    expect(screen.getByText(/Detecciones maliciosas: 2/)).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Abrir reporte de VirusTotal' }).getAttribute('href'))
      .toBe(found.report_url)
  })

  it('distinguishes a suspicious result from a malicious detection', () => {
    render(<ReputationFileResult kind="cleaned" result={{
      ...found, last_analysis_stats: { suspicious: 1, malicious: 0 },
    }} />)

    expect(screen.getByText('VirusTotal reportó resultados sospechosos.')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it.each([
    ['not_found', /sin antecedentes no significa que el archivo sea seguro/i],
    ['unavailable', /análisis del archivo continuó/i],
  ] as const)('displays a consented digest for %s without inventing a verdict or link', (status, message) => {
    render(<ReputationFileResult kind="cleaned" result={{ status, ...noDetails, sha256 }} />)

    expect(screen.getByText(message)).toBeTruthy()
    expect(screen.getByText(sha256)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('preserves the legacy non-requested result without a digest', () => {
    render(<ReputationFileResult kind="original" result={{ status: 'not_requested', ...noDetails }} />)

    expect(screen.getByText('VirusTotal no fue consultado.')).toBeTruthy()
    expect(screen.queryByText('SHA-256')).toBeNull()
  })
})
