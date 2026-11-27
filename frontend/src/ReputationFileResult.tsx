import type { VirusTotalFileResult } from './fileApi'
import './ReputationFileResult.css'

const verdictNames: Record<string, string> = {
  malicious: 'Detecciones maliciosas', suspicious: 'Sospechosos', undetected: 'Sin detecciones',
  harmless: 'Sin riesgo identificado', timeout: 'Sin respuesta', 'confirmed-timeout': 'Tiempo agotado',
  failure: 'Errores', 'type-unsupported': 'Formato no compatible',
}

export default function ReputationFileResult({ kind, result }: { kind: 'original' | 'cleaned'; result: VirusTotalFileResult }) {
  const label = kind === 'original' ? 'del original' : 'de la copia sin metadatos'
  const target = kind === 'original' ? 'este archivo original' : 'esta copia sin metadatos'
  const hasReport = result.status === 'found'
  const stats = hasReport ? result.last_analysis_stats : null
  const malicious = (stats?.malicious ?? 0) > 0
  const suspicious = (stats?.suspicious ?? 0) > 0
  const status = {
    found: 'Reporte encontrado',
    not_found: 'No se encontró un reporte. Estar sin antecedentes no significa que el archivo sea seguro.',
    not_requested: 'VirusTotal no fue consultado.',
    rate_limited: 'Se alcanzó el límite de consultas de VirusTotal.',
    key_unavailable: 'No pudimos consultar VirusTotal. Aún puedes revisar los metadatos del archivo.',
    unavailable: 'VirusTotal no estuvo disponible; el análisis del archivo continuó.',
  }[result.status]
  return <div className="reputation-result">
    <h5>Reporte VirusTotal {label}</h5>
    {malicious && <p className="reputation-result__warning reputation-result__warning--danger" role="alert">
      <strong>VirusTotal reportó detecciones maliciosas.</strong> No abras ni compartas {target}.
    </p>}
    {!malicious && suspicious && <p className="reputation-result__warning">
      <strong>VirusTotal reportó resultados sospechosos.</strong> Evita abrir o compartir {target} hasta aclararlos.
    </p>}
    <p>{status}</p>
    {result.sha256 && <p className="reputation-result__fingerprint"><strong>SHA-256</strong> <code>{result.sha256}</code></p>}
    {stats && <p>{Object.entries(stats)
      .map(([name, count]) => `${verdictNames[name] ?? name}: ${count}`).join(' · ')}</p>}
    {hasReport && result.last_analysis_date !== null && <p>Último análisis en VirusTotal: {new Date(result.last_analysis_date * 1000).toLocaleString('es')}</p>}
    {hasReport && !malicious && !suspicious && <p>Un resultado sin detecciones no garantiza que el archivo sea seguro.</p>}
    {hasReport && result.report_url && <a href={result.report_url} target="_blank" rel="noopener noreferrer">Abrir reporte de VirusTotal</a>}
  </div>
}
