import {
  CATEGORIES,
  CHECKS,
  type Evaluation,
  type Workspace,
} from "@palisade/core";
const escape = (value: unknown) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
export function renderReport(
  workspace: Workspace,
  evaluation: Evaluation,
): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'"><title>${escape(workspace.name)} · Palisade</title><style>
  :root{color-scheme:light;font-family:ui-sans-serif,system-ui,sans-serif;color:#193c32;background:#f6f6ef}*{box-sizing:border-box}body{margin:0}main{max-width:1060px;margin:auto;padding:48px 24px}header{display:flex;justify-content:space-between;gap:20px;align-items:center;border-bottom:1px solid #cfd8ce;padding-bottom:24px}h1{font-size:clamp(28px,4vw,44px);letter-spacing:-.04em;margin:32px 0 12px}h2{margin-top:40px;font-size:24px}p{line-height:1.6;color:#52675e}.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:11px}.score{display:flex;gap:50px;padding:24px 0}.score strong{display:block;font-size:48px;letter-spacing:-.06em}.score span{font-size:14px}.categories{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.category{border:1px solid #d6ddd3;border-radius:12px;padding:20px;background:#fcfcf7}.category b{display:block;margin-bottom:12px}.category span{font-size:13px;color:#52675e}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:14px 10px;border-bottom:1px solid #d6ddd3;vertical-align:top}th{color:#52675e;font-size:12px}td:first-child{min-width:160px}.subject{margin-top:10px;padding-top:8px;border-top:1px dotted #d6ddd3}.subject b{color:#193c32}.reason{color:#52675e;line-height:1.5}.status{display:inline-block;border:1px solid #cbd4c7;border-radius:99px;padding:4px 8px;font-size:12px}.pass{color:#1b6847;background:#e7f2e8}.fail,.conflict{color:#954632;background:#f7e9e0}footer{border-top:1px solid #cfd8ce;margin-top:40px;padding-top:16px;font-size:12px;color:#52675e}@media(max-width:600px){main{padding:24px 16px}table{font-size:12px}th,td{padding:10px 5px}.score{gap:28px}td:first-child{min-width:100px}}@media print{main{padding:0}body{background:white}.category{break-inside:avoid}tr{break-inside:avoid}}
  </style><main><header><b>◈ PALISADE</b><span class="eyebrow">Private security audit</span></header><h1>${escape(workspace.name)}</h1><p>Evidence-based security posture. This is a record of verified controls, not a prediction of compromise.</p><div class="score"><div><strong>${evaluation.score === null ? "—" : evaluation.score}<span> / 100</span></strong><span>Security posture</span></div><div><strong>${evaluation.coverage}<span>%</span></strong><span>Assessed coverage</span></div></div><div class="categories">${evaluation.categories.map((category) => `<div class="category"><b>${escape(CATEGORIES.find((c) => c.id === category.categoryId)?.name)}</b><span>${category.score === null ? "Unassessed" : `${category.score}/100`} · ${category.coverage}% assessed</span></div>`).join("")}</div><h2>Checklist</h2><table><thead><tr><th>Check</th><th>State</th><th>Evidence and next step</th></tr></thead><tbody>${evaluation.checks
    .map((check) => {
      const definition = CHECKS.find((c) => c.id === check.checkId);
      return `<tr><td>${escape(definition?.title ?? check.checkId)}</td><td><span class="status ${escape(check.status)}">${escape(check.status.replaceAll("_", " "))}</span></td><td class="reason">${escape(check.reason)}${check.subjects
        .filter((subject) => subject.assetId)
        .map(
          (subject) =>
            `<div class="subject"><b>${escape(workspace.assets.find((asset) => asset.id === subject.assetId)?.label ?? "Asset no longer in scope")}</b> · ${escape(subject.status.replaceAll("_", " "))}<br>${escape(subject.reason)}</div>`,
        )
        .join(
          "",
        )}${check.status !== "pass" && definition ? `<br>${escape(definition.verification)}` : ""}</td></tr>`;
    })
    .join(
      "",
    )}</tbody></table><footer>Evaluated ${escape(evaluation.evaluatedAt)} · Catalog ${escape(evaluation.catalogVersion)} · Scoring ${escape(evaluation.scoreVersion)}<p>Unknown, stale, imported, and conflicting evidence requires verification. Completing an action does not pass a check. This private report includes asset labels and evaluated evidence reasons. It contains no scripts or external requests.</p></footer></main></html>`;
}
