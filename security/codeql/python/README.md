# PDF private metadata policy query

`pdf-pieceinfo-policy.ql` is a repository-specific structural check for MetaGuard's PDF scanner. It flags `_scan_pdf` when the file lacks the `/PieceInfo` policy reference or `_process_pdf` does not call the named private-object collection and retained-alias rejection helpers.

This is a **heuristic**, not a proof of privacy: it does not inspect helper behavior, independently copied data, other proprietary keys, or differently named implementations. Run the regression tests as well and review findings manually.

From a prepared Python CodeQL database and this directory, with CodeQL packs available locally:

```sh
codeql database analyze /path/to/python-database ./pdf-pieceinfo-policy.ql \
  --format=sarifv2.1.0 --output=/private/path/pieceinfo.sarif \
  --no-download --no-sarif-add-file-contents --no-sarif-add-snippets --rerun
```

Create the database from the intended first-party source using `codeql database create --language=python --build-mode=none --source-root=/path/to/source /path/to/python-database`. Keep the database and raw SARIF private; they may contain source or filesystem paths. CodeQL is subject to its [license terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).

The initial assessment and validated limitations are recorded in [`docs/reporte-seguridad-codeql.md`](../../../docs/reporte-seguridad-codeql.md).
