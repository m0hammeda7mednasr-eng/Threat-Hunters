import { ObjectId } from "mongodb";
import { getDb } from "./mongo.js";

const RECENT_SCAN_PROJECTION = {
  _id: 1,
  report_id: 1,
  scan_id: 1,
  target: 1,
  url: 1,
  risk_score: 1,
  risk_label: 1,
  scan_status: 1,
  created_at: 1,
  summary: 1,
  findings: { $slice: 3 },
};

const CACHE_TTL_MS = 30_000;
const cache = {
  analytics: { expiresAt: 0, payload: null },
  adminReports: { expiresAt: 0, payload: null, limit: 25 },
};

function cacheFresh(entry, limit) {
  if (!entry.payload || entry.expiresAt <= Date.now()) {
    return false;
  }
  if (typeof limit === "number" && entry.limit !== limit) {
    return false;
  }
  return true;
}

function emptyPayload() {
  return {
    total_scans: 0,
    completed_scans: 0,
    unique_targets: 0,
    vulnerable_targets: 0,
    average_risk_score: 0,
    risk_grade: "Low",
    severity_counts: { Critical: 0, High: 0, Medium: 0, Low: 0 },
    total_findings: 0,
    recent_scans: [],
    monthly_trend: [],
    scans_last_7_days: 0,
  };
}

function riskGrade(score) {
  if (score >= 80) return "Critical";
  if (score >= 50) return "High";
  if (score >= 20) return "Moderate";
  return "Low";
}

function summarySeverityCounts(summary) {
  const source = summary && typeof summary === "object" ? summary : {};
  const severity = source.severity_counts && typeof source.severity_counts === "object"
    ? source.severity_counts
    : {};
  return {
    Critical: Number(severity.Critical || 0),
    High: Number(severity.High || 0),
    Medium: Number(severity.Medium || 0),
    Low: Number(severity.Low || 0) + Number(severity.Info || 0),
  };
}

function summaryTotalFindings(summary) {
  return Number(summary?.total_findings || 0);
}

function formatRelativeTime(dateValue) {
  const timestamp = dateValue instanceof Date ? dateValue : new Date(dateValue);
  if (Number.isNaN(timestamp.getTime())) {
    return "Recently";
  }
  const diffMs = Math.max(Date.now() - timestamp.getTime(), 0);
  const diffMinutes = Math.floor(diffMs / 60_000);
  if (diffMinutes < 1) return "Just now";
  if (diffMinutes < 60) return `${diffMinutes} minute(s) ago`;
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours} hour(s) ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays} day(s) ago`;
}

async function aggregateTotals(db) {
  const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
  const pipeline = [
    {
      $project: {
        target: { $ifNull: ["$target", "$url"] },
        risk_score: { $ifNull: ["$risk_score", 0] },
        scan_status: { $toLower: { $ifNull: ["$scan_status", "completed"] } },
        created_at: "$created_at",
        total_findings: { $ifNull: ["$summary.total_findings", 0] },
        critical: { $ifNull: ["$summary.severity_counts.Critical", 0] },
        high: { $ifNull: ["$summary.severity_counts.High", 0] },
        medium: { $ifNull: ["$summary.severity_counts.Medium", 0] },
        low: {
          $add: [
            { $ifNull: ["$summary.severity_counts.Low", 0] },
            { $ifNull: ["$summary.severity_counts.Info", 0] },
          ],
        },
      },
    },
    {
      $group: {
        _id: null,
        total_scans: { $sum: 1 },
        completed_scans: {
          $sum: {
            $cond: [{ $in: ["$scan_status", ["completed", "done", "success"]] }, 1, 0],
          },
        },
        total_findings: { $sum: "$total_findings" },
        critical: { $sum: "$critical" },
        high: { $sum: "$high" },
        medium: { $sum: "$medium" },
        low: { $sum: "$low" },
        risk_score_sum: { $sum: "$risk_score" },
        targets: { $addToSet: "$target" },
        vulnerable_targets_raw: {
          $addToSet: {
            $cond: [{ $gt: [{ $add: ["$critical", "$high"] }, 0] }, "$target", null],
          },
        },
        scans_last_7_days: {
          $sum: {
            $cond: [{ $gte: ["$created_at", sevenDaysAgo] }, 1, 0],
          },
        },
      },
    },
  ];

  const [result] = await db.collection("scan_reports").aggregate(pipeline, { allowDiskUse: true }).toArray();
  return result || null;
}

async function recentScanDocuments(db, limit = 25) {
  return db.collection("scan_reports")
    .find({}, { projection: RECENT_SCAN_PROJECTION })
    .sort({ created_at: -1 })
    .limit(limit)
    .toArray();
}

export async function aggregateScanAnalytics(limit = 25) {
  if (cacheFresh(cache.analytics)) {
    return cache.analytics.payload;
  }

  const db = await getDb();
  const totals = await aggregateTotals(db);
  if (!totals) {
    const payload = emptyPayload();
    cache.analytics = { expiresAt: Date.now() + CACHE_TTL_MS, payload };
    return payload;
  }

  const recentDocuments = await recentScanDocuments(db, limit);
  const recentScans = [];
  const monthlyBuckets = new Map();

  for (const document of recentDocuments) {
    const summary = document.summary;
    const counts = summarySeverityCounts(summary);
    const findingsCount = summaryTotalFindings(summary);
    const target = String(document.target || document.url || "").trim() || "Unknown target";
    const createdAt = document.created_at instanceof Date ? document.created_at : new Date(document.created_at);

    if (!Number.isNaN(createdAt.getTime())) {
      const month = createdAt.toLocaleString("en-US", { month: "short", timeZone: "UTC" });
      monthlyBuckets.set(month, (monthlyBuckets.get(month) || 0) + findingsCount);
    }

    recentScans.push({
      report_id: document.report_id || document.scan_id,
      target,
      risk_label: document.risk_label || "No Risk",
      risk_score: Number(document.risk_score || 0),
      findings_count: findingsCount,
      critical_count: counts.Critical,
      high_count: counts.High,
      scan_status: document.scan_status || "completed",
      created_at: createdAt.toISOString(),
    });
  }

  const totalScans = Number(totals.total_scans || 0);
  const averageRiskScore = totalScans
    ? Math.round(Number(totals.risk_score_sum || 0) / totalScans)
    : 0;

  const payload = {
    total_scans: totalScans,
    completed_scans: Number(totals.completed_scans || 0),
    unique_targets: new Set((totals.targets || []).filter(Boolean)).size,
    vulnerable_targets: new Set((totals.vulnerable_targets_raw || []).filter(Boolean)).size,
    average_risk_score: averageRiskScore,
    risk_grade: riskGrade(averageRiskScore),
    severity_counts: {
      Critical: Number(totals.critical || 0),
      High: Number(totals.high || 0),
      Medium: Number(totals.medium || 0),
      Low: Number(totals.low || 0),
    },
    total_findings: Number(totals.total_findings || 0),
    recent_scans: recentScans,
    monthly_trend: Array.from(monthlyBuckets.entries()).map(([label, value]) => ({ label, value })),
    scans_last_7_days: Number(totals.scans_last_7_days || 0),
  };

  cache.analytics = { expiresAt: Date.now() + CACHE_TTL_MS, payload };
  return payload;
}

export async function buildDashboardStats() {
  const analytics = await aggregateScanAnalytics();
  if (analytics.total_scans === 0) {
    return [
      { label: "Overall Risk Score", value: "0/100", subtitle: "No scans recorded yet" },
      { label: "Active Vulnerabilities", value: "0", subtitle: "Run scans to populate findings" },
      { label: "Vulnerable Assets", value: "0 of 0", subtitle: "No scanned targets yet" },
      { label: "Total Scans", value: "0", subtitle: "Waiting for the first scan" },
    ];
  }

  const severity = analytics.severity_counts;
  return [
    {
      label: "Overall Risk Score",
      value: `${analytics.average_risk_score}/100`,
      subtitle: `${analytics.risk_grade} risk across completed scans`,
    },
    {
      label: "Active Vulnerabilities",
      value: String(analytics.total_findings),
      subtitle: `Critical: ${severity.Critical} | High: ${severity.High}`,
    },
    {
      label: "Vulnerable Assets",
      value: `${analytics.vulnerable_targets} of ${analytics.unique_targets}`,
      subtitle: "Targets with critical or high findings",
    },
    {
      label: "Total Scans",
      value: String(analytics.total_scans),
      subtitle: `${analytics.scans_last_7_days} in the last 7 days`,
    },
  ];
}

export async function buildSecurityMetrics() {
  const analytics = await aggregateScanAnalytics();
  const severity = analytics.severity_counts;
  const totalScans = analytics.total_scans;
  const completed = analytics.completed_scans;
  const successRate = totalScans ? Math.round((completed / totalScans) * 100) : 0;
  const avgPerScan = totalScans ? Math.round((analytics.total_findings / totalScans) * 10) / 10 : 0;

  return [
    { label: "Critical", value: severity.Critical, subtitle: "Confirmed critical findings" },
    { label: "High", value: severity.High, subtitle: "High severity findings" },
    { label: "Medium", value: severity.Medium, subtitle: "Medium severity findings" },
    { label: "Low", value: severity.Low, subtitle: "Low and informational findings" },
    { label: "Total Scans", value: totalScans, subtitle: `${analytics.scans_last_7_days} in the last 7 days` },
    { label: "Success Rate", value: `${successRate}%`, subtitle: "Completed scan rate" },
    { label: "Total Vulnerabilities", value: analytics.total_findings, subtitle: "Across all stored scans" },
    { label: "Avg. per Scan", value: String(avgPerScan), subtitle: "Findings per completed scan" },
  ];
}

export async function buildRecentActivities() {
  const analytics = await aggregateScanAnalytics();
  return analytics.recent_scans.slice(0, 6).map((scan) => ({
    title: `Scan completed for ${scan.target}`,
    detail: `${scan.risk_label} | ${scan.findings_count} finding(s) | ${scan.critical_count} critical | ${scan.high_count} high`,
    time: formatRelativeTime(scan.created_at),
  }));
}

function serializeAdminReport(document) {
  const summary = document.summary;
  const severity = summarySeverityCounts(summary);
  const findingsCount = summaryTotalFindings(summary);
  const createdAt = document.created_at instanceof Date ? document.created_at : new Date(document.created_at || Date.now());
  const reportId = document.report_id || document.scan_id || String(document._id || new ObjectId());
  const findings = Array.isArray(document.findings) ? document.findings : [];

  const findingTitles = findings
    .slice(0, 3)
    .filter((finding) => finding && typeof finding === "object")
    .map((finding) => String(finding.title || finding.name || finding.vuln_type || "Finding"));

  return {
    id: reportId,
    title: document.target || document.url || "Scan Report",
    subtitle: `${document.risk_label || "No Risk"} | ${findingsCount} finding(s)`,
    date: createdAt.toISOString(),
    size: "Live scan report",
    type: "Scan",
    status: document.scan_status || "completed",
    scanCount: 1,
    vulnerabilities: findingsCount,
    critical: severity.Critical,
    high: severity.High,
    medium: severity.Medium,
    low: severity.Low,
    score: Number(document.risk_score || 0),
    downloads: 0,
    findings: findingTitles.length ? findingTitles : [
      `${severity.Critical} critical finding(s)`,
      `${severity.High} high severity finding(s)`,
      `${findingsCount} total finding(s)`,
    ],
    target: document.target || document.url || "",
    report_id: reportId,
  };
}

export async function listAdminScanReports(limit = 25) {
  const safeLimit = Math.max(1, Math.min(Number(limit || 25), 100));
  if (cacheFresh(cache.adminReports, safeLimit)) {
    return cache.adminReports.payload;
  }

  const db = await getDb();
  const scans = await recentScanDocuments(db, safeLimit);
  const payload = scans.map(serializeAdminReport);
  cache.adminReports = {
    expiresAt: Date.now() + CACHE_TTL_MS,
    payload,
    limit: safeLimit,
  };
  return payload;
}
