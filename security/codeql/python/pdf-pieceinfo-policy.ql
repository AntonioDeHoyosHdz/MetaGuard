/**
 * @name PDF private metadata policy missing
 * @description Flags MetaGuard-style PDF scanners that lack an explicit PieceInfo policy reference.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id metaguard/pdf-pieceinfo-policy
 * @tags security external/cwe/cwe-200
 */

import python

predicate invokes(Function f, string name) {
  exists(Call call, Name target |
    f.contains(call) and call.getFunc() = target and target.getId() = name
  )
}

from Function scanner
where
  scanner.getName() = "_scan_pdf" and
  (
    not exists(StringLiteral key, Name policy |
      key.getText() = "/PieceInfo" and
      key.getLocation().getFile() = scanner.getLocation().getFile() and
      policy.getId() = "_PRIVATE_PDF_METADATA_KEYS" and
      scanner.contains(policy)
    ) or
    not exists(Function processor |
      processor.getName() = "_process_pdf" and
      processor.getLocation().getFile() = scanner.getLocation().getFile() and
      invokes(processor, "_collect_private_metadata_objects") and
      invokes(processor, "_reject_retained_private_objects")
    )
  )
select scanner, "Review this PDF scanner: its /PieceInfo removal or retained-alias checks are missing."
