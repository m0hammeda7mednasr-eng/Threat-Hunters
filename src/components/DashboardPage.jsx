import { memo, useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bell,
  BookOpen,
  CalendarDays,
  ChevronDown,
  ChevronRight,
  Clock3,
  Download,
  Globe,
  Hash,
  LineChart,
  FileText,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Mail,
  Pencil,
  PieChart,
  Play,
  Search,
  SlidersHorizontal,
  Settings,
  Shield,
  Sparkles,
  Target,
  Trash2,
  User,
  Wifi,
  X,
  Zap,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import AuthNavbar from './AuthNavbar';
import { scannerAPI } from '../services/api';
import { buildBrandedPdfBlob, downloadPdfBlob } from '../utils/pdfBuilder';
import './DashboardPage.css';

const SIDEBAR_ITEMS = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'reports', label: 'Reports', icon: FileText },
  { key: 'settings', label: 'Settings', icon: Settings },
  { key: 'profile', label: 'Profile', icon: User },
];

const SETTINGS_SCAN_MODE_OPTIONS = [
  {
    key: 'quick',
    title: 'Quick Scan',
    description: 'Fast Scan with Essential security checks',
  },
  {
    key: 'deep',
    title: 'Deep Scan',
    description: 'Comprehensive Analysis With detailed vulnerability detection',
  },
];

const SETTINGS_NOTIFICATION_ITEMS = [
  { key: 'completion', title: 'Scan Complete Notifications', sub: 'Notify me when a scan completes' },
  { key: 'critical', title: 'Critical Vulnerability Alerts', sub: 'Alert me for critical vulnerabilities discovered' },
  { key: 'weekly', title: 'Weekly Security Summary', sub: 'Receive a weekly summary of security findings' },
  { key: 'cve', title: 'New CVE Notifications', sub: 'Notify me about new Common Vulnerabilities and Exposures' },
];

const SETTINGS_REPORT_ITEMS = [
  { key: 'technical', title: 'Include Detailed Technical Analysis', sub: 'Add in-depth technical details to reports' },
  { key: 'aiSummary', title: 'Include AI-Generated Summary', sub: 'Add executive summary created by AI' },
  { key: 'autoPdf', title: 'Auto-Generate PDF Report', sub: 'Automatically create PDF version after scan completes' },
];

const DASHBOARD_SCAN_TYPES = [
  { key: 'quick', label: 'Quick Scan' },
  { key: 'deep', label: 'Deep Scan' },
];

const ADVANCED_SCAN_MODULES = [
  { key: 'subdomain', label: 'subdomain' },
  { key: 'ports', label: 'ports' },
  { key: 'fuzz', label: 'fuzz' },
  { key: 'extraction', label: 'extraction' },
  { key: 'js_secrets', label: 'js_secrets' },
  { key: 'targeted', label: 'targeted' },
  { key: 'vulns', label: 'vulns' },
  { key: 'osint', label: 'osint' },
  { key: 'screenshot', label: 'screenshot' },
  { key: 's3scanner', label: 's3scanner' },
  { key: 'crlfuzz', label: 'crlfuzz' },
  { key: 'apk_recon', label: 'apk_recon' },
];

const ADVANCED_SCAN_DEFAULTS = ADVANCED_SCAN_MODULES.reduce(
  (defaults, moduleItem) => ({ ...defaults, [moduleItem.key]: true }),
  {},
);

const SECURITY_AWARENESS_ITEMS = [
  {
    title: 'Security Best Practices',
    description: 'Learn fundamental security practices to protect your web applications from common threats.',
    icon: BookOpen,
  },
  {
    title: 'Vulnerability Reports',
    description: 'Access detailed reports and analysis of recent security vulnerabilities and exploits.',
    icon: FileText,
  },
  {
    title: 'Training Resources',
    description: 'Watch tutorial videos and guides on implementing robust security measures.',
    icon: Target,
  },
];

const toDashOffset = (percent) => {
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  return circumference - (circumference * percent) / 100;
};

const normalizeWebsiteUrl = (value) => {
  const trimmedValue = value.trim();
  if (!trimmedValue) {
    throw new Error('Enter a website URL before starting the scan.');
  }
  const candidate = /^https?:\/\//i.test(trimmedValue) ? trimmedValue : `https://${trimmedValue}`;
  const parsed = new URL(candidate);
  if (!['http:', 'https:'].includes(parsed.protocol) || !isValidWebsiteHostname(parsed.hostname)) {
    throw new Error('Enter a valid website URL like https://example.com.');
  }
  return parsed.toString();
};

const isValidWebsiteHostname = (hostname) => {
  const host = String(hostname || '').toLowerCase();
  if (host === 'localhost') return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host) && !host.includes('..');
};

const severityTone = (value) => String(value || 'low').toLowerCase();

const severityKey = (value) => String(value || '').trim().toLowerCase();

const countFindingsBySeverity = (report, severity) => {
  const summaryCounts = report?.summary?.severity_counts || {};
  const wanted = severityKey(severity);
  const summaryMatch = Object.entries(summaryCounts).find(([key]) => severityKey(key) === wanted);
  if (summaryMatch) {
    return Number(summaryMatch[1] || 0);
  }

  return report?.findings?.filter((finding) => severityKey(finding.severity || finding.status) === wanted).length ?? 0;
};

const normalizeScanMode = (mode) => {
  const value = String(mode || '').trim().toLowerCase();
  if (value === 'deep') return 'deep';
  if (value === 'quick' || value === 'light' || value === 'fast') return 'light';
  return 'light';
};

const deriveRiskScore = (report) => {
  if (!report || typeof report !== 'object') {
    return 0;
  }

  const explicitScore = Number(report.risk_score);
  if (Number.isFinite(explicitScore)) {
    return Math.max(0, Math.min(100, Math.round(explicitScore)));
  }

  const legacyScore = Number(report.score);
  if (Number.isFinite(legacyScore)) {
    return Math.max(0, Math.min(100, Math.round(legacyScore)));
  }

  const severityWeights = {
    critical: 30,
    high: 18,
    medium: 10,
    low: 4,
    info: 1,
    informational: 1,
    recon: 1,
    candidate: 6,
    blocked: 0,
    inconclusive: 2,
  };

  const findings = Array.isArray(report.findings) ? report.findings : [];
  const summary = report.summary && typeof report.summary === 'object' ? report.summary : {};
  let score = findings.reduce((total, finding) => {
    if (!finding || typeof finding !== 'object') {
      return total;
    }
    const severity = String(finding.severity || finding.status || '').trim().toLowerCase();
    return total + (severityWeights[severity] || 2);
  }, 0);

  score += Number(summary.confirmed_findings || summary.confirmed_vulns || 0) * 25;
  score += Number(summary.candidate_findings || summary.candidate_issues || 0) * 6;
  score += Number(summary.blocked_tests || 0) * 1;
  score += Number(summary.inconclusive_tests || 0) * 1;

  return Math.max(0, Math.min(100, Math.round(score)));
};

const deriveRiskLabel = (report) => {
  if (report?.risk_label) {
    return report.risk_label;
  }

  const score = deriveRiskScore(report);
  if (score >= 80) return 'Critical Risk';
  if (score >= 50) return 'High Risk';
  if (score >= 20) return 'Moderate Risk';
  if (score > 0) return 'Low Risk';
  return 'No Risk';
};

const deriveScanCoverage = (report) => {
  const summary = report?.summary && typeof report.summary === 'object' ? report.summary : {};
  const explicitCoverage = Number(report?.scan_coverage ?? summary.scan_coverage);
  if (Number.isFinite(explicitCoverage)) {
    return Math.max(0, Math.min(100, Math.round(explicitCoverage)));
  }

  const executed = Number(summary.modules_executed);
  const planned = Number(summary.modules_planned);
  if (Number.isFinite(executed) && Number.isFinite(planned) && planned > 0) {
    return Math.max(0, Math.min(100, Math.round((executed / planned) * 100)));
  }

  return 0;
};

const deriveScanConfidence = (report) => {
  const summary = report?.summary && typeof report.summary === 'object' ? report.summary : {};
  const explicitConfidence = Number(report?.scan_confidence ?? summary.scan_confidence);
  if (Number.isFinite(explicitConfidence)) {
    return Math.max(0, Math.min(100, Math.round(explicitConfidence)));
  }

  const coverage = deriveScanCoverage(report);
  return Math.max(0, Math.min(100, Math.round(coverage * 0.85)));
};

const riskToneFromReport = (report) => {
  const score = deriveRiskScore(report);
  if (score >= 80) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
};

const normalizeScanReport = (report) => {
  if (!report || typeof report !== 'object') {
    return report;
  }

  const nestedReport = report.report && typeof report.report === 'object' ? report.report : {};
  const firstHost = Array.isArray(nestedReport.alive_hosts) && nestedReport.alive_hosts.length
    ? nestedReport.alive_hosts[0]
    : {};
  const firstHostResponse = firstHost?.response_summary && typeof firstHost.response_summary === 'object'
    ? firstHost.response_summary
    : {};
  const mergedReport = {
    ...nestedReport,
    ...report,
    summary: {
      ...(nestedReport.summary || {}),
      ...(report.summary || {}),
    },
  };
  const findings = Array.isArray(mergedReport.findings) && mergedReport.findings.length
    ? mergedReport.findings
    : Array.isArray(nestedReport.actionable_findings) && nestedReport.actionable_findings.length
      ? nestedReport.actionable_findings
      : Array.isArray(nestedReport.confirmed_findings)
        ? nestedReport.confirmed_findings
        : [];
  const checks = Array.isArray(mergedReport.checks) ? mergedReport.checks : [];
  const parameterInventory = Array.isArray(mergedReport.parameter_inventory) ? mergedReport.parameter_inventory : [];
  const formInventory = Array.isArray(mergedReport.form_inventory) ? mergedReport.form_inventory : [];
  const activeValidationResults = Array.isArray(mergedReport.active_validation_results) ? mergedReport.active_validation_results : [];
  const headers = mergedReport.headers && typeof mergedReport.headers === 'object'
    ? mergedReport.headers
    : firstHostResponse.headers && typeof firstHostResponse.headers === 'object'
      ? firstHostResponse.headers
      : {};
  const scanTime = mergedReport.scan_time || report.created_at || '';
  const riskScore = deriveRiskScore(mergedReport);
  const riskLabel = deriveRiskLabel(mergedReport);
  const normalizedMode = normalizeScanMode(mergedReport.scan_mode || mergedReport.profile || mergedReport.mode);
  const scoreText = mergedReport.score || `${riskScore}/100`;

  return {
    ...mergedReport,
    id: mergedReport.id || mergedReport.report_id || mergedReport.scan_id || 'RPT-LIVE',
    reference: mergedReport.reference || mergedReport.scan_id || mergedReport.report_id || 'LIVE',
    date: mergedReport.date || String(scanTime).slice(0, 10) || new Date().toISOString().slice(0, 10),
    time: mergedReport.time || (String(scanTime).includes('T') ? String(scanTime).split('T')[1].slice(0, 5) : new Date().toTimeString().slice(0, 5)),
    target: mergedReport.target || mergedReport.domain || report.target,
    url: mergedReport.url || firstHost.url || report.target,
    final_url: mergedReport.final_url || firstHost.final_url || mergedReport.url || report.target,
    http_status: mergedReport.http_status || firstHost.status_code || firstHost.status || firstHostResponse.status_code,
    server: mergedReport.server || firstHost.server || headers.Server || headers.server,
    content_type: mergedReport.content_type || firstHost.content_type || headers['Content-Type'] || headers['content-type'],
    content_length: mergedReport.content_length || firstHost.content_length,
    scan_mode: normalizedMode,
    profile: normalizedMode,
    scan_status: mergedReport.scan_status || mergedReport.summary?.scan_status || 'completed',
    risk_score: riskScore,
    risk_label: riskLabel,
    score: scoreText,
    scan_coverage: deriveScanCoverage(mergedReport),
    scan_confidence: deriveScanConfidence(mergedReport),
    findings,
    checks,
    parameter_inventory: parameterInventory,
    form_inventory: formInventory,
    active_validation_results: activeValidationResults,
    active_validation_summary: mergedReport.active_validation_summary || {},
    discovered_urls: Array.isArray(mergedReport.discovered_urls) ? mergedReport.discovered_urls : [],
    headers,
    recommendations: Array.isArray(mergedReport.recommendations) ? mergedReport.recommendations : [],
    report: nestedReport,
  };
};

const reportToCard = (report) => {
  const normalizedReport = normalizeScanReport(report);

  return {
    id: normalizedReport.id || 'RPT-LIVE',
    riskLabel: normalizedReport.risk_label || deriveRiskLabel(normalizedReport),
    riskTone: riskToneFromReport(normalizedReport),
    url: normalizedReport.url || normalizedReport.target,
    reference: normalizedReport.reference || normalizedReport.id || 'LIVE',
    date: normalizedReport.date || new Date().toISOString().slice(0, 10),
    time: normalizedReport.time || new Date().toTimeString().slice(0, 5),
    duration: normalizedReport.duration || '0.0s',
    score: normalizedReport.score || `${normalizedReport.risk_score || 0}/100`,
    scoreTone: riskToneFromReport(normalizedReport),
    breakdown: [
      { label: 'Critical', value: countFindingsBySeverity(normalizedReport, 'Critical'), tone: 'critical' },
      { label: 'High', value: countFindingsBySeverity(normalizedReport, 'High'), tone: 'high' },
      { label: 'Medium', value: countFindingsBySeverity(normalizedReport, 'Medium'), tone: 'medium' },
      { label: 'Low', value: countFindingsBySeverity(normalizedReport, 'Low'), tone: 'low' },
    ],
    raw: normalizedReport,
  };
};

const formatHeaderValue = (value) => {
  const normalizedValue = String(value || 'Missing');
  return normalizedValue.length > 140 ? `${normalizedValue.slice(0, 137)}...` : normalizedValue;
};

const buildScanReportPdf = (report) => {
  const normalizedReport = normalizeScanReport(report);
  const findings = Array.isArray(normalizedReport.findings) ? normalizedReport.findings : [];
  const checks = Array.isArray(normalizedReport.checks) ? normalizedReport.checks : [];
  const parameterInventory = Array.isArray(normalizedReport.parameter_inventory) ? normalizedReport.parameter_inventory : [];
  const formInventory = Array.isArray(normalizedReport.form_inventory) ? normalizedReport.form_inventory : [];
  const activeValidationResults = Array.isArray(normalizedReport.active_validation_results) ? normalizedReport.active_validation_results : [];
  const headers = normalizedReport.headers && typeof normalizedReport.headers === 'object' ? normalizedReport.headers : {};
  const severityCounts = normalizedReport.summary?.severity_counts || findings.reduce((acc, finding) => {
    if (!finding || typeof finding !== 'object') {
      return acc;
    }
    const severity = String(finding.severity || finding.status || '').trim().toLowerCase();
    if (!severity) {
      return acc;
    }
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});
  const recommendations = Array.isArray(normalizedReport.recommendations) && normalizedReport.recommendations.length
    ? normalizedReport.recommendations
    : [
      'Re-run the scan after remediation to confirm risk reduction.',
      'Prioritize exploitable issues before routine hardening tasks.',
      'Keep a dated copy of this report with the remediation owner and next review date.',
    ];
  const score = normalizedReport.score || `${normalizedReport.risk_score || 0}/100`;
  const risk = normalizedReport.risk_label || normalizedReport.risk || 'Unknown Risk';
  const coverage = deriveScanCoverage(normalizedReport);
  const confidence = deriveScanConfidence(normalizedReport);
  const generatedDate = `${normalizedReport.date || ''} ${normalizedReport.time || ''}`.trim() || new Date().toLocaleString('en-US');

  return buildBrandedPdfBlob({
    title: 'Vulnerability Scan Report',
    subtitle: `Target intelligence pack for ${normalizedReport.target || normalizedReport.url || 'selected website'} with evidence, risk lanes, and remediation guidance.`,
    eyebrow: 'Live Web Exposure Report',
    generatedAt: generatedDate,
    classification: 'CLIENT-READY SECURITY REPORT',
    metrics: [
      { label: 'Risk', value: risk, fill: '#fff5f6', valueColor: '#d8324a', hint: 'Priority lane' },
      { label: 'Score', value: score, fill: '#f3f0ff', valueColor: '#6c5ce7', hint: 'Security posture' },
      { label: 'Findings', value: String(findings.length), fill: '#eef6ff', valueColor: '#0b66c3', hint: 'Detected issues' },
      { label: 'Params', value: String(parameterInventory.length), fill: '#f8f5ff', valueColor: '#6c5ce7', hint: 'Discovered inputs' },
      { label: 'Forms', value: String(formInventory.length), fill: '#fff7ed', valueColor: '#b45309', hint: 'Form inventory' },
      { label: 'Coverage', value: `${coverage}%`, fill: '#eefbf7', valueColor: '#11855d', hint: 'Executed checks' },
      { label: 'Confidence', value: `${confidence}%`, fill: '#fff1f8', valueColor: '#c0266f', hint: 'Scan quality' },
      { label: 'Checks', value: String(normalizedReport.summary?.checks_run || checks.length || 0), fill: '#eefbf7', valueColor: '#11855d', hint: 'Signals tested' },
      { label: 'HTTP', value: String(normalizedReport.http_status || 'N/A'), fill: '#fff8e8', valueColor: '#b35d00', hint: normalizedReport.server || 'Server check' },
      { label: 'Duration', value: normalizedReport.duration || '0.0s', fill: '#f7f9ff', valueColor: '#151a32', hint: normalizedReport.scan_mode || 'scan mode' },
    ],
    sections: [
      {
        title: 'Executive Summary',
        kicker: 'Overview',
        body: `Threat Hunters reviewed ${normalizedReport.target || normalizedReport.url || 'the target'} and produced a ${risk} assessment with score ${score}. This report is structured for fast decision-making: severity, evidence, technical checks, and recommended next moves.`,
        accent: '#7c6cff',
        rows: [
          { label: 'Report ID', value: normalizedReport.id || 'Live scan', detail: `Reference: ${normalizedReport.reference || 'Not available'}` },
          { label: 'Target', value: normalizedReport.target || normalizedReport.url || 'Not available', detail: `Final URL: ${normalizedReport.url || normalizedReport.target || 'Not available'}` },
          { label: 'Response', value: normalizedReport.http_status || 'Unknown', detail: `Server: ${normalizedReport.server || 'Not disclosed'} | Content: ${normalizedReport.content_type || 'Unknown'} | Length: ${normalizedReport.content_length || 'Unknown'}` },
        ],
      },
      {
        title: 'Severity Lanes',
        kicker: 'Risk Radar',
        body: 'The lanes below show how the detected signals are distributed. Critical and high items should be assigned immediately before lower-risk hygiene tasks.',
        accent: '#ff5f6d',
        severityCounts,
      },
      {
        title: 'TLS & Transport Posture',
        kicker: 'Encrypted Channel',
        body: 'Transport security is reviewed separately because expired certificates, weak TLS posture, or missing issuer data can turn a clean app into an operational risk.',
        accent: '#25c799',
        rows: [
          {
            label: 'TLS Validation',
            value: normalizedReport.tls?.valid === false ? 'Needs review' : normalizedReport.tls ? 'Valid' : 'Not scanned',
            tone: normalizedReport.tls?.valid === false ? 'High' : normalizedReport.tls ? 'Success' : 'Info',
            detail: normalizedReport.tls?.valid === false
              ? 'Certificate validation returned a failing signal.'
              : 'Certificate validation did not surface a blocking issue in the available data.',
          },
          {
            label: 'Issuer',
            value: normalizedReport.tls?.issuer || 'Not available',
            detail: 'Use this to confirm the certificate chain matches the expected provider.',
          },
          {
            label: 'Expiry',
            value: normalizedReport.tls?.expires || 'Not available',
            detail: 'Schedule renewal before expiry and keep monitoring alerts active.',
          },
        ],
      },
      {
        title: 'Finding Evidence',
        kicker: 'What Changed',
        body: findings.length
          ? 'Each finding includes the business impact and a clear remediation path so the report can move directly into action.'
          : 'No findings were returned by the selected checks. Keep monitoring and run a deeper scan for stronger assurance.',
        accent: '#00c2ff',
        items: findings.length
          ? findings.map((finding, index) => ({
            tone: finding.severity || 'Info',
            title: `${index + 1}. [${finding.severity || 'Info'}] ${finding.title || finding.name || finding.code || finding.id || 'Finding'}`,
            detail: `${finding.description || finding.proof || 'No impact description supplied.'} Fix: ${finding.recommendation || finding.remediation || 'Review manually and document remediation.'}`,
          }))
          : ['No findings detected by the selected checks.'],
      },
      {
        title: 'Executed Checks',
        kicker: 'Validation Path',
        body: 'These checks show the evidence trail behind the final score. Failed or warning checks deserve follow-up even when the headline risk is low.',
        accent: '#25c799',
        rows: checks.length
          ? checks.slice(0, 18).map((check) => {
            const findingCount = Number.isFinite(Number(check.finding_count)) ? Number(check.finding_count) : null;
            return {
              label: check.name || 'Security check',
              value: check.status || 'Info',
              tone: check.status === 'Failed' ? 'High' : check.status === 'Passed' ? 'Success' : 'Info',
              detail: `${check.details || 'No details supplied.'}${findingCount !== null ? ` Findings: ${findingCount}.` : ''}${check.evidence ? ` Evidence: ${check.evidence}` : ''}`,
            };
          })
          : [{ label: 'Checks', value: 'Not attached', detail: 'No detailed checks were attached to this report.' }],
      },
      {
        title: 'Parameter Inventory',
        kicker: 'Attack Surface',
        body: 'Discovered URL parameters are listed with candidate vulnerability classes and whether active validation touched them.',
        accent: '#0b66c3',
        rows: parameterInventory.length
          ? parameterInventory.slice(0, 18).map((item) => ({
            label: `${item.method || 'GET'} ${item.endpoint || item.url || 'Endpoint'} :: ${item.parameter || 'parameter'}`,
            value: item.status || 'not_tested',
            tone: item.status === 'confirmed' ? 'Critical' : item.status === 'tested_candidate' ? 'Medium' : item.status === 'tested_not_confirmed' ? 'Success' : 'Info',
            detail: `Candidates: ${(item.candidates || []).join(', ') || 'None'} | Tests: ${(item.tests || []).join(', ') || 'not run'}`,
          }))
          : [{ label: 'Parameters', value: 'None', detail: 'No URL parameters were discovered in the captured crawl.' }],
      },
      {
        title: 'Active Validation Results',
        kicker: 'Test Evidence',
        body: 'These records show tested and skipped validation groups, including the reason when no proof was produced.',
        accent: '#25c799',
        rows: activeValidationResults.length
          ? activeValidationResults.slice(0, 24).map((item) => ({
            label: `${item.test_type || 'validation'}${item.parameter ? ` :: ${item.parameter}` : ''}`,
            value: item.status || 'unknown',
            tone: item.status === 'confirmed' ? 'Critical' : item.status === 'candidate' ? 'Medium' : item.status === 'not_confirmed' ? 'Success' : item.status === 'skipped' ? 'Info' : 'Info',
            detail: `${item.method || 'GET'} ${item.url || 'n/a'} | ${item.reason || 'no reason'} | payloads=${item.payloads_sent ?? 0}`,
          }))
          : [{ label: 'Validation', value: 'No records', detail: 'No active validation telemetry was attached to this report.' }],
      },
      {
        title: 'Form Inventory',
        kicker: 'Submitted Surfaces',
        body: 'Forms discovered during crawling are listed with inputs and CSRF-token visibility so validation gaps are explicit.',
        accent: '#ffb347',
        rows: formInventory.length
          ? formInventory.slice(0, 12).map((form) => ({
            label: `${form.method || 'GET'} ${form.action || 'Form action'}`,
            value: `${Array.isArray(form.inputs) ? form.inputs.length : 0} inputs`,
            tone: form.has_csrf_token ? 'Success' : 'Info',
            detail: `Page: ${form.page || 'unknown'} | Inputs: ${Array.isArray(form.inputs) ? form.inputs.map((input) => input.name || input).filter(Boolean).slice(0, 8).join(', ') : 'n/a'}`,
          }))
          : [{ label: 'Forms', value: 'None', detail: 'No HTML forms were captured by the selected scan profile.' }],
      },
      {
        title: 'Security Header Snapshot',
        kicker: 'Response Evidence',
        body: 'Headers help validate browser-side protection and server disclosure. Missing hardening headers should be handled as configuration tasks.',
        accent: '#ffb347',
        rows: Object.keys(headers).length
          ? Object.entries(headers).slice(0, 14).map(([header, value]) => ({
            label: header,
            value: 'Captured',
            detail: formatHeaderValue(value),
          }))
          : [{ label: 'Headers', value: 'No snapshot', detail: 'No header snapshot was attached to this report.' }],
      },
      {
        title: 'Prioritized Recommendations',
        kicker: 'Next Moves',
        body: 'Use this section as the remediation checklist for the next sprint or handoff conversation.',
        accent: '#7c6cff',
        items: recommendations.map((recommendation, index) => `${index + 1}. ${recommendation}`),
      },
    ],
  });
};

const downloadScanReport = (report) => {
  const blob = buildScanReportPdf(report);
  downloadPdfBlob(blob, `${report.id || 'threat-hunters-report'}.pdf`);
};

const getLinePoints = (values, width, height, padding = 16) => {
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = Math.max(max - min, 1);

  return values.map((value, index) => {
    const x = padding + (index * (width - padding * 2)) / (values.length - 1);
    const y = height - padding - ((value - min) / span) * (height - padding * 2);
    return { x, y, value };
  });
};

const SCAN_REPORTS_STORAGE_KEY = 'threatHuntersScanReports';

const loadStoredScanReports = () => {
  try {
    const storedReports = window.localStorage.getItem(SCAN_REPORTS_STORAGE_KEY);
    const parsedReports = JSON.parse(storedReports || '[]');
    return Array.isArray(parsedReports) ? parsedReports.map(normalizeScanReport) : [];
  } catch {
    return [];
  }
};

const storeScanReports = (reports) => {
  try {
    window.localStorage.setItem(SCAN_REPORTS_STORAGE_KEY, JSON.stringify(reports.slice(0, 12)));
  } catch {
    // Scan results still stay in memory if localStorage is unavailable.
  }
};

function DashboardPage({ onNavigate, onLogout, currentPage, initialSection }) {
  const {
    user,
    getProfile,
    updateProfile,
    changePassword,
    getSettings,
    updateSettings,
    deleteAccount,
  } = useAuth();
  const [activeSection, setActiveSection] = useState(initialSection || 'dashboard');
  const [scanUrl, setScanUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [scanReports, setScanReports] = useState(loadStoredScanReports);
  const [isAdvancedScanOpen, setIsAdvancedScanOpen] = useState(false);
  const [advancedScanMode, setAdvancedScanMode] = useState('deep');
  const [advancedCookieHeader, setAdvancedCookieHeader] = useState('');
  const [advancedPermissionConfirmed, setAdvancedPermissionConfirmed] = useState(true);
  const [advancedScanChecks, setAdvancedScanChecks] = useState(() => ({ ...ADVANCED_SCAN_DEFAULTS }));
  const [dashboardScanTypes, setDashboardScanTypes] = useState({
    quick: false,
    deep: true,
  });
  const [reportSearchQuery, setReportSearchQuery] = useState('');
  const [profileTwoFactorEnabled, setProfileTwoFactorEnabled] = useState(false);
  const [profileForm, setProfileForm] = useState({
    username: '',
    email: '',
    phone: '',
    lastLogin: 'Current session',
    bio: '',
  });
  const [passwordForm, setPasswordForm] = useState({
    current: '',
    next: '',
    confirm: '',
  });
  const [profileNotice, setProfileNotice] = useState('');
  const [settingsNotice, setSettingsNotice] = useState('');
  const [settingsForm, setSettingsForm] = useState({
    language: 'English (US)',
    timezone: 'UTC+02:00 (Cairo)',
  });
  const [scanMode, setScanMode] = useState('quick');
  const [notificationPrefs, setNotificationPrefs] = useState({
    completion: true,
    critical: true,
    weekly: true,
    cve: true,
  });
  const [reportPrefs, setReportPrefs] = useState({
    technical: true,
    aiSummary: true,
    autoPdf: false,
  });
  const profileLoadedRef = useRef(false);
  const settingsLoadedRef = useRef(false);

  useEffect(() => {
    if (profileLoadedRef.current) {
      return;
    }

    profileLoadedRef.current = true;

    const loadProfile = async () => {
      const result = await getProfile();
      const profile = result.success ? result.data : user;

      if (!profile) return;

      setProfileForm((current) => ({
        ...current,
        username: `${profile.firstName || ''} ${profile.lastName || ''}`.trim()
          || profile.email?.split('@')[0]
          || current.username,
        email: profile.email || current.email,
        phone: profile.phone || '',
        lastLogin: profile.lastLogin || profile.loginTime || 'Current session',
        bio: profile.bio || '',
      }));
    };

    loadProfile();
  }, [getProfile, user]);

  useEffect(() => {
    if (settingsLoadedRef.current) {
      return;
    }

    settingsLoadedRef.current = true;

    const loadSettings = async () => {
      const result = await getSettings?.();
      if (!result?.success || !result.data) return;

      setSettingsForm({
        language: result.data.language || 'English (US)',
        timezone: result.data.timezone || 'UTC+02:00 (Cairo)',
      });
      setScanMode(result.data.scanMode === 'deep' ? 'deep' : 'quick');
      setProfileTwoFactorEnabled(Boolean(result.data.twoFactorEnabled));
      setNotificationPrefs((current) => ({
        ...current,
        ...(result.data.notifications || {}),
      }));
      setReportPrefs((current) => ({
        ...current,
        ...(result.data.reports || {}),
      }));
    };

    loadSettings();
  }, [getSettings]);

  useEffect(() => {
    if (!isAdvancedScanOpen || activeSection !== 'dashboard') return undefined;
    const previousOverflow = document.body.style.overflow;
    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        setIsAdvancedScanOpen(false);
      }
    };

    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', handleEscape);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', handleEscape);
    };
  }, [activeSection, isAdvancedScanOpen]);

  useEffect(() => {
    let ignore = false;

    const loadServerReports = async () => {
      try {
        const payload = await scannerAPI.getReports(12);
        const items = Array.isArray(payload?.items) ? payload.items.map(normalizeScanReport) : [];
        if (!ignore && items.length) {
          setScanReports(items);
          storeScanReports(items);
        }
      } catch {
        // Local reports remain available when the authenticated report endpoint is unavailable.
      }
    };

    loadServerReports();

    return () => {
      ignore = true;
    };
  }, []);

  const navigateToSection = (section) => {
    setActiveSection(section);
    if (!onNavigate) return;
    if (section === 'dashboard') {
      onNavigate('dashboard');
      return;
    }
    onNavigate(section);
  };

  const startScan = async () => {
    if (isScanning) return;

    try {
      const target = normalizeWebsiteUrl(scanUrl);
      const enabledScanTypes = Object.entries(dashboardScanTypes)
        .filter(([, enabled]) => enabled)
        .map(([key]) => key);
      const scanModeForBackend = enabledScanTypes.includes('deep') ? 'deep' : 'light';

      setScanError('');
      setIsScanning(true);

      const result = await scannerAPI.scanWebsite({
        target,
        scan_mode: scanModeForBackend,
        cookie_header: advancedCookieHeader.trim() || undefined,
        confirm_permission: advancedPermissionConfirmed,
        modules: {
          dashboard: enabledScanTypes,
          advanced: advancedScanChecks,
        },
      });

      const normalizedResult = normalizeScanReport(result);
      const nextReports = [normalizedResult, ...scanReports].slice(0, 12);
      storeScanReports(nextReports);
      setScanReports(nextReports);
      navigateToSection('reports');
    } catch (error) {
      setScanError(error.message || 'Scan failed. Check the URL and try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const toggleDashboardScanType = (key) => {
    setDashboardScanTypes({
      quick: key === 'quick',
      deep: key === 'deep',
    });
    setAdvancedScanMode(key === 'deep' ? 'deep' : 'quick');
  };

  const changeAdvancedScanMode = (mode) => {
    const normalizedMode = mode === 'deep' ? 'deep' : 'quick';
    setAdvancedScanMode(normalizedMode);
    setDashboardScanTypes({
      quick: normalizedMode === 'quick',
      deep: normalizedMode === 'deep',
    });
  };

  const toggleAdvancedScanCheck = (key) => {
    setAdvancedScanChecks((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const applyAdvancedDemoPreset = () => {
    setScanUrl('https://www.crmpixels.app/');
    setAdvancedCookieHeader('security=low; PHPSESSID=demo');
    setAdvancedPermissionConfirmed(true);
    setAdvancedScanMode('deep');
    setDashboardScanTypes({ quick: false, deep: true });
    setAdvancedScanChecks({ ...ADVANCED_SCAN_DEFAULTS });
    setScanError('');
  };

  const toggleNotification = (key) => {
    setNotificationPrefs((prev) => ({ ...prev, [key]: !prev[key] }));
    setSettingsNotice('');
  };

  const toggleReportPref = (key) => {
    setReportPrefs((prev) => ({ ...prev, [key]: !prev[key] }));
    setSettingsNotice('');
  };

  const updateProfileForm = (key, value) => {
    setProfileForm((prev) => ({ ...prev, [key]: value }));
    setProfileNotice('');
  };

  const updatePasswordForm = (key, value) => {
    setPasswordForm((prev) => ({ ...prev, [key]: value }));
    setProfileNotice('');
  };

  const updateSettingsForm = (key, value) => {
    setSettingsForm((prev) => ({ ...prev, [key]: value }));
    setSettingsNotice('');
  };

  const handleProfileUpdate = async () => {
    const [firstName = '', ...restName] = profileForm.username.trim().split(/\s+/);
    const lastName = restName.join(' ');

    const result = await updateProfile({
      firstName,
      lastName,
      email: profileForm.email,
      phone: profileForm.phone,
      bio: profileForm.bio,
    });

    setProfileNotice(result.success ? 'Profile saved to backend.' : result.error);
  };

  const handlePasswordUpdate = async () => {
    if (!passwordForm.current || !passwordForm.next || !passwordForm.confirm) {
      setProfileNotice('Fill all password fields first.');
      return;
    }

    if (passwordForm.next !== passwordForm.confirm) {
      setProfileNotice('New passwords do not match.');
      return;
    }

    const result = await changePassword({
      currentPassword: passwordForm.current,
      newPassword: passwordForm.next,
    });

    if (!result.success) {
      setProfileNotice(result.error);
      return;
    }

    setPasswordForm({ current: '', next: '', confirm: '' });
    setProfileNotice('Password updated successfully.');
  };

  const saveSettings = async (overrides = {}) => {
    const payload = {
      language: settingsForm.language,
      timezone: settingsForm.timezone,
      scanMode,
      twoFactorEnabled: profileTwoFactorEnabled,
      notifications: notificationPrefs,
      reports: reportPrefs,
      ...overrides,
    };

    const result = await updateSettings?.(payload);
    if (!result?.success) {
      setSettingsNotice(result?.error || 'Settings could not be saved.');
      setProfileNotice(result?.error || 'Security setting could not be saved.');
      return false;
    }

    setSettingsNotice('Settings saved successfully.');
    setProfileNotice('Security settings saved successfully.');
    return true;
  };

  const toggleTwoFactor = async () => {
    const nextValue = !profileTwoFactorEnabled;
    setProfileTwoFactorEnabled(nextValue);
    await saveSettings({ twoFactorEnabled: nextValue });
  };

  const handleDeleteAccount = async () => {
    const confirmed = window.confirm('Delete this account permanently? This will remove the local session and account data.');
    if (!confirmed) return;

    const result = await deleteAccount?.();
    if (!result?.success) {
      setProfileNotice(result?.error || 'Account could not be deleted.');
      return;
    }

    onLogout?.();
    onNavigate?.('home');
  };

  const reportCards = scanReports.map(reportToCard);
  const latestReport = scanReports[0] || null;
  const latestRiskScore = latestReport ? deriveRiskScore(latestReport) : 0;
  const latestRiskLabel = latestReport ? deriveRiskLabel(latestReport) : 'No scan completed yet';
  const latestScanCoverage = latestReport ? deriveScanCoverage(latestReport) : 0;
  const latestScanConfidence = latestReport ? deriveScanConfidence(latestReport) : 0;
  const profileDisplayName = profileForm.username || (user?.email ? user.email.split('@')[0] : '') || 'Threat Hunters User';
  const profileEmail = profileForm.email || user?.email || 'No email available';
  const profileInitial = profileDisplayName.trim().charAt(0).toUpperCase() || 'U';
  const memberSince = user?.createdAt
    ? new Date(user.createdAt).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })
    : 'Current member';
  const profileScanStats = [
    { label: 'Total Scans', value: String(scanReports.length) },
    { label: 'Last Scan', value: latestReport ? `${latestReport.date || ''} ${latestReport.time || ''}`.trim() : 'No scans yet' },
    { label: 'Critical issues', value: String(scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'Critical'), 0)) },
  ];
  const profileScanRows = scanReports.slice(0, 5).map((report) => ({
    website: report.url || report.target,
    risk: report.risk || 'Low',
    date: report.date || new Date(report.created_at || Date.now()).toLocaleDateString('en-US'),
  }));
  const recentScanRows = scanReports.length
    ? scanReports.map((report) => {
        const firstFinding = report.findings?.[0];
        return {
          target: report.url || report.target,
          status: report.status || 'Completed',
          issue: firstFinding ? firstFinding.title : 'No issues found',
          risk: report.risk || 'Low',
          date: report.date || new Date(report.created_at || Date.now()).toLocaleDateString('en-US'),
          raw: report,
        };
      })
    : [];
  const dashboardOverviewCards = [
    { label: 'Total Scans', value: String(scanReports.length), subtitle: 'Saved in your console', icon: Activity },
    {
      label: 'Critical Issues',
      value: String(scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'Critical'), 0)),
      subtitle: 'Need immediate remediation',
      icon: Bell,
    },
    {
      label: 'Vulnerabilities Found',
      value: String(scanReports.reduce((sum, report) => sum + (report.findings?.length || 0), 0)),
      subtitle: 'Across latest assessments',
      icon: AlertTriangle,
    },
    {
      label: 'Last Scan',
      value: latestReport ? latestReport.time || 'Now' : 'None',
      subtitle: latestReport?.target || 'Run a scan to populate data',
      icon: Clock3,
    },
  ];

  const renderAdvancedScanModal = () => (
    <div
      className="db-advanced-overlay"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          setIsAdvancedScanOpen(false);
        }
      }}
    >
      <section className="db-advanced-modal db-dragon-modal" role="dialog" aria-modal="true" aria-labelledby="advanced-scan-title">
        <div className="db-dragon-head">
          <h2 id="advanced-scan-title">ReconTool Dragon</h2>
          <button
            type="button"
            className="db-advanced-close"
            aria-label="Close advanced scan settings"
            onClick={() => setIsAdvancedScanOpen(false)}
          >
            <X size={14} />
          </button>
        </div>

        <div className="db-dragon-body">
          <label className="db-dragon-field db-dragon-field-full">
            <span>Target</span>
            <input
              type="url"
              value={scanUrl}
              placeholder="https://www.crmpixels.app/"
              onChange={(event) => {
                setScanUrl(event.target.value);
                setScanError('');
              }}
            />
          </label>

          <div className="db-dragon-field-grid">
            <label className="db-dragon-field">
              <span>Profile</span>
              <select value={advancedScanMode} onChange={(event) => changeAdvancedScanMode(event.target.value)}>
                <option value="quick">Quick</option>
                <option value="deep">Deep</option>
              </select>
            </label>

            <label className="db-dragon-field">
              <span>Cookie Header</span>
              <input
                type="text"
                value={advancedCookieHeader}
                placeholder="security=low; PHPSESSID=..."
                onChange={(event) => setAdvancedCookieHeader(event.target.value)}
              />
            </label>
          </div>

          <label className="db-dragon-permission">
            <input
              type="checkbox"
              checked={advancedPermissionConfirmed}
              onChange={() => setAdvancedPermissionConfirmed((current) => !current)}
            />
            <span>I have permission to scan this public target</span>
          </label>

          <div className="db-dragon-modules-head">MODULES</div>
          <div className="db-dragon-module-grid">
            {ADVANCED_SCAN_MODULES.map((moduleItem) => (
              <label key={moduleItem.key} className="db-dragon-module">
                <input
                  type="checkbox"
                  checked={Boolean(advancedScanChecks[moduleItem.key])}
                  onChange={() => toggleAdvancedScanCheck(moduleItem.key)}
                />
                <span>{moduleItem.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="db-dragon-actions">
          <button type="button" className="db-primary-btn db-dragon-start" onClick={startScan} disabled={isScanning}>
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
          <button type="button" className="db-mini-btn db-dragon-demo" onClick={applyAdvancedDemoPreset}>
            Demo Preset
          </button>
        </div>

        {scanError && (
          <div className="db-scan-error db-dragon-error" role="alert">
            <AlertTriangle size={14} />
            <span>{scanError}</span>
          </div>
        )}
      </section>
    </div>
  );

  const renderDashboardSection = () => {
    const severityDistribution = [
      { label: 'Low', value: scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'Low'), 0), color: 'var(--accent-green)' },
      { label: 'Medium', value: scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'Medium'), 0), color: 'var(--accent-yellow)' },
      { label: 'High', value: scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'High'), 0), color: 'var(--accent-coral)' },
      { label: 'Critical', value: scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'Critical'), 0), color: 'var(--accent-red)' },
    ];
    const activityDays = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setDate(date.getDate() - (6 - index));
      return {
        key: date.toISOString().slice(0, 10),
        label: date.toLocaleDateString('en-US', { weekday: 'short' }),
      };
    });
    const scanActivityValues = activityDays.map((day) => (
      scanReports.filter((report) => (report.date || '').slice(0, 10) === day.key).length
    ));
    const chartValues = scanActivityValues.some(Boolean) ? scanActivityValues : [0, 0, 0, 0, 0, 0, 0];
    const linePoints = getLinePoints(chartValues, 360, 160, 16);
    const linePath = linePoints
      .map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`)
      .join(' ');
    const distributionTotal = severityDistribution.reduce((sum, item) => sum + item.value, 0) || 1;
    let segmentStart = 0;
    const donutStops = severityDistribution.map((item) => {
      const segmentSize = (item.value / distributionTotal) * 100;
      const segmentEnd = segmentStart + segmentSize;
      const stop = `${item.color} ${segmentStart.toFixed(2)}% ${segmentEnd.toFixed(2)}%`;
      segmentStart = segmentEnd;
      return stop;
    }).join(', ');
    const recommendationItems = latestReport?.findings?.length
      ? latestReport.findings.slice(0, 4).map((finding) => ({
          title: finding.title,
          severity: finding.severity,
          description: finding.description,
          aiRecommendation: finding.recommendation,
          steps: [
            finding.recommendation,
            'Validate the fix in staging before production release.',
            'Run a follow-up scan and archive the updated PDF report.',
          ],
        }))
      : [];
    const intelligenceItems = latestReport?.checks?.length
      ? latestReport.checks.slice(0, 4).map((check, index) => ({
          cve: check.name || `CHECK-${index + 1}`,
          severity: check.status === 'Review' ? 'Medium' : check.status === 'Skipped' ? 'Low' : 'Low',
          description: check.details || 'Scanner check completed.',
        }))
      : [];
    const activitySummaryStats = [
      {
        label: 'Average',
        value: `${Math.round(scanActivityValues.reduce((sum, value) => sum + value, 0) / scanActivityValues.length)} Scans`,
      },
      {
        label: 'Total',
        value: `${scanReports.length} Scans`,
      },
      {
        label: 'Peak',
        value: `${Math.max(...scanActivityValues, 0)} Scans`,
      },
    ];

    return (
      <div className="db-dashboard-layout">
        <h1 className="db-sr-only">User Console Dashboard</h1>
        <section className="db-overview-grid">
          {dashboardOverviewCards.map((card) => (
            <article key={card.label} className="db-overview-card">
              <span className="db-overview-icon">
                <card.icon size={16} />
              </span>
              <p className="db-overview-label">{card.label}</p>
              <h3 className={`db-overview-value ${card.valueSuffix ? 'stacked' : ''}`}>
                {card.value}
                {card.valueSuffix ? <span>{card.valueSuffix}</span> : null}
              </h3>
              <p className="db-overview-subtitle">{card.subtitle}</p>
            </article>
          ))}
          <article className="db-risk-card overview">
            <p className="db-risk-label">AI Risk Score</p>
            <div className="db-risk-ring">
              <svg viewBox="0 0 90 90" aria-hidden="true">
                <circle cx="45" cy="45" r="34" className="db-risk-track" />
                <circle
                  cx="45"
                  cy="45"
                  r="34"
                  className="db-risk-progress"
                  strokeDasharray={2 * Math.PI * 34}
                  strokeDashoffset={toDashOffset(latestRiskScore)}
                />
              </svg>
              <strong>{latestReport ? `${latestRiskScore}%` : '0%'}</strong>
            </div>
            <p className="db-risk-copy">
              {latestReport ? latestRiskLabel : 'No scan completed yet'}
              <br />
              {latestReport ? latestReport.target : 'Start a scan to calculate risk'}
              <br />
              {latestReport ? `Coverage ${latestScanCoverage}% · Confidence ${latestScanConfidence}%` : ''}
            </p>
          </article>
        </section>

        <section className="db-panel db-quick-scan-panel">
          <div className="db-quick-head">
            <div className="db-head-with-icon">
              <span className="db-head-icon">
                <Globe size={16} />
              </span>
              <div>
                <h2>Quick Scan</h2>
                <p>Enter a website URL to start scanning for vulnerabilities</p>
              </div>
            </div>

            <div className="db-scan-type-list">
              {DASHBOARD_SCAN_TYPES.map((scanType) => (
                <label key={scanType.key} className="db-inline-check">
                  <input
                    type="checkbox"
                    checked={dashboardScanTypes[scanType.key]}
                    onChange={() => toggleDashboardScanType(scanType.key)}
                  />
                  <span>{scanType.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="db-scan-row">
            <input
              type="url"
              placeholder="https://yourwebsite.com"
              value={scanUrl}
              onChange={(event) => {
                setScanUrl(event.target.value);
                setScanError('');
              }}
              className="db-input"
            />
            <button className="db-primary-btn db-start-scan-btn" onClick={startScan} disabled={isScanning}>
              <Play size={14} />
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </button>
          </div>

          <button type="button" className="db-advanced-btn" onClick={() => setIsAdvancedScanOpen(true)}>
            <Settings size={14} />
            Advanced Scan Settings
          </button>
          {scanError && (
            <div className="db-scan-error" role="alert">
              <AlertTriangle size={14} />
              <span>{scanError}</span>
            </div>
          )}
          <p className="db-quick-copy">Comprehensive security analysis powered by AI technology</p>
        </section>

        <section className="db-panel db-recent-scans-panel">
          <div className="db-panel-head">
            <div>
              <h2>Recent Scans</h2>
              <p>Latest security scan results and status</p>
            </div>
          </div>
          <div className="db-table">
            <div className="db-table-head">
              <span>Website</span>
              <span>Status</span>
              <span>Vulnerability</span>
              <span>Risk level</span>
              <span>Date</span>
              <span>Action</span>
            </div>
            {recentScanRows.map((row, index) => (
              <div key={`${row.target}-${row.date}-${index}`} className="db-table-row">
                <span className="db-scan-target">{row.target}</span>
                <span className={`db-chip ${row.status.toLowerCase().replace(/\s+/g, '-')}`}>
                  <span>{row.status}</span>
                </span>
                <span>{row.issue}</span>
                <span className={`db-risk ${row.risk.toLowerCase()}`}>{row.risk}</span>
                <span>{row.date}</span>
                <button
                  type="button"
                  className="db-action-btn"
                  aria-label={`Download report for ${row.target}`}
                  onClick={() => downloadScanReport(row.raw)}
                >
                  <Download size={14} />
                </button>
              </div>
            ))}
            {!recentScanRows.length && (
              <div className="db-table-row db-table-empty">
                <span>Run your first website scan to populate real results.</span>
              </div>
            )}
          </div>
        </section>

        <section className="db-panel db-ai-insights-panel">
          <div className="db-panel-head">
            <div className="db-head-with-icon">
              <span className="db-head-icon">
                <Sparkles size={16} />
              </span>
              <div>
                <h2>AI Security Insights</h2>
                <p>Comprehensive vulnerability detection powered by advanced AI analysis</p>
              </div>
            </div>
          </div>

          <div className="db-insight-grid">
            {(latestReport ? [
              { label: 'Critical Issues Detected', value: String(countFindingsBySeverity(latestReport, 'Critical')) },
              { label: 'High-Risk Issues Detected', value: String(countFindingsBySeverity(latestReport, 'High')) },
              { label: 'Medium-Risk Issues Detected', value: String(countFindingsBySeverity(latestReport, 'Medium')) },
              { label: 'Low-Risk Issues Detected', value: String(countFindingsBySeverity(latestReport, 'Low')) },
            ] : [
              { label: 'Critical Issues Detected', value: '0' },
              { label: 'High-Risk Issues Detected', value: '0' },
              { label: 'Medium-Risk Issues Detected', value: '0' },
              { label: 'Low-Risk Issues Detected', value: '0' },
            ]).map((item) => (
              <article className="db-insight-item" key={item.label}>
                <p>{item.label}</p>
                <strong>{item.value}</strong>
              </article>
            ))}
          </div>

          <p className="db-insight-copy">
            {latestReport
              ? `The scanner checked ${latestReport.target} and found ${latestReport.findings?.length || 0} issue(s). The current score is ${latestReport.score}, with ${latestReport.risk_label}. Download the report for remediation details.`
              : 'Run a website scan to generate live security insights, risk scoring, recommendations, and a downloadable report.'}
          </p>

          <button type="button" className="db-secondary-btn db-report-btn" onClick={() => setActiveSection('reports')}>
            View Report
            <ChevronRight size={14} />
          </button>
        </section>

        <section className="db-panel db-ai-summary-panel">
          <div className="db-panel-head">
            <div className="db-head-with-icon">
              <span className="db-head-icon">
                <FileText size={16} />
              </span>
              <div>
                <h2>AI Summary</h2>
              </div>
            </div>
          </div>

          <div className="db-summary-body">
            {(latestReport
              ? [
                  `${latestReport.target} returned HTTP ${latestReport.http_status || 'unknown'} and completed in ${latestReport.duration}.`,
                  `Risk score is ${latestReport.score}; total findings detected: ${latestReport.findings?.length || 0}.`,
                  ...(latestReport.recommendations?.length ? latestReport.recommendations : ['No urgent recommendations were generated by the selected checks.']),
                ]
              : ['Run a scan to replace this placeholder with a live report summary.']).map((line, index) => (
              <p key={`${index}-${line}`}>{line}</p>
            ))}
          </div>
        </section>

        <section className="db-panel db-recommendations-panel">
          <div className="db-panel-head">
            <div className="db-head-with-icon">
              <span className="db-head-icon">
                <Zap size={16} />
              </span>
              <div>
                <h2>Recommendations</h2>
                <p>Automatically generated suggestions based on detected vulnerabilities</p>
              </div>
            </div>
          </div>

          <div className="db-recommend-list">
            {recommendationItems.map((item) => (
              <article className="db-recommend-item" key={item.title}>
                <div className="db-recommend-top">
                  <h3>
                    <AlertTriangle size={14} />
                    {item.title}
                  </h3>
                  <span className={`db-risk ${item.severity.toLowerCase()}`}>{item.severity}</span>
                </div>

                <p className="db-recommend-text">{item.description}</p>
                <p className="db-recommend-subtitle">AI Recommendation:</p>
                <p className="db-recommend-text">{item.aiRecommendation}</p>
                <p className="db-recommend-subtitle">Manual Remediation Steps:</p>

                <ul className="db-recommend-steps">
                  {item.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>

                <div className="db-recommend-actions">
                  <button type="button" className="db-mini-btn db-mini-btn-flat" onClick={() => navigateToSection('reports')}>View Full Details</button>
                  <button type="button" className="db-mini-btn db-mini-btn-flat" onClick={() => downloadScanReport(latestReport)}>Export Report</button>
                  <button type="button" className="db-mini-btn db-mini-btn-flat">Reviewed</button>
                </div>
              </article>
            ))}
            {!recommendationItems.length && (
              <div className="db-reports-empty compact">
                <p>Run a scan to generate real recommendations.</p>
              </div>
            )}
          </div>
        </section>

        <section className="db-panel db-threat-panel">
          <div className="db-panel-head">
            <div>
              <h2>Threat Intelligence</h2>
              <p>Latest security vulnerabilities and CVE updates</p>
            </div>
          </div>

          <div className="db-threat-grid">
            {intelligenceItems.map((item) => (
              <article key={item.cve} className="db-threat-item">
                <div className="db-threat-top">
                  <h3>
                    <Shield size={14} />
                    {item.cve}
                  </h3>
                  <span className={`db-risk ${item.severity.toLowerCase()}`}>{item.severity}</span>
                </div>
                <p>{item.description}</p>
                <button type="button" className="db-mini-btn db-threat-btn" onClick={() => navigateToSection('reports')}>
                  View Report
                  <ChevronRight size={14} />
                </button>
              </article>
            ))}
            {!intelligenceItems.length && (
              <div className="db-reports-empty compact">
                <p>Run a deep scan to populate live scanner intelligence.</p>
              </div>
            )}
          </div>
        </section>

        <section className="db-panel db-awareness-panel">
          <div className="db-panel-head">
            <div>
              <h2>Security Awareness</h2>
              <p>Educational resources and best practices</p>
            </div>
          </div>

          <div className="db-awareness-grid">
            {SECURITY_AWARENESS_ITEMS.map((item) => (
              <article key={item.title} className="db-awareness-item">
                <span className="db-awareness-icon">
                  <item.icon size={15} />
                </span>
                <h3>{item.title}</h3>
                <p>{item.description}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="db-chart-grid">
          <article className="db-panel db-chart-card">
            <div className="db-panel-head">
              <div className="db-head-with-icon">
                <span className="db-head-icon">
                  <PieChart size={16} />
                </span>
                <div>
                  <h2>Vulnerability Distribution</h2>
                  <p>By severity level</p>
                </div>
              </div>
            </div>

            <div className="db-donut-wrap">
              <div className="db-donut-chart" style={{ background: `conic-gradient(${donutStops})` }}>
                <div className="db-donut-hole" />
              </div>

              <div className="db-donut-legend">
                {severityDistribution.map((item) => (
                  <div key={item.label} className="db-donut-row">
                    <span className="db-donut-label">
                      <i style={{ background: item.color }} />
                      {item.label}
                    </span>
                    <strong>{item.value}</strong>
                  </div>
                ))}
              </div>
            </div>
          </article>

          <article className="db-panel db-chart-card">
            <div className="db-panel-head">
              <div className="db-head-with-icon">
                <span className="db-head-icon">
                  <LineChart size={16} />
                </span>
                <div>
                  <h2>Security Scan Over Time</h2>
                  <p>Last 7 days</p>
                </div>
              </div>
            </div>

            <div className="db-line-chart-wrap">
              <svg viewBox="0 0 360 160" aria-hidden="true">
                <path d={linePath} className="db-line-path" />
                {linePoints.map((point) => (
                  <circle
                    key={`${point.x}-${point.y}`}
                    cx={point.x}
                    cy={point.y}
                    r="3.5"
                    className="db-line-point"
                  />
                ))}
              </svg>

              <div className="db-line-days">
                {activityDays.map((day) => (
                  <span key={day.key}>{day.label}</span>
                ))}
              </div>
            </div>

            <div className="db-line-stats">
              {activitySummaryStats.map((item) => (
                <article key={item.label}>
                  <p>{item.label}</p>
                  <strong>{item.value}</strong>
                </article>
              ))}
            </div>
          </article>
        </section>
      </div>
    );
  };

  const renderReportsSection = () => {
    const normalizedQuery = reportSearchQuery.trim().toLowerCase();
    const filteredReportCards = reportCards.filter((card) => (
      !normalizedQuery
      || [card.id, card.url, card.reference, card.riskLabel].some((value) => value.toLowerCase().includes(normalizedQuery))
    ));
    const reportHistoryItems = scanReports.map((report, index) => ({
      index: index + 1,
      url: report.url || report.target,
      timestamp: `${report.date || ''} at ${report.time || ''}`.trim(),
      vulnerabilities: report.findings?.length || 0,
      score: report.score || `${report.risk_score || 0}/100`,
      scoreTone: severityTone(report.risk),
      raw: report,
    }));
    const filteredHistoryItems = reportHistoryItems.filter((item) => (
      !normalizedQuery
      || [`${item.index}`, item.url, item.timestamp, `${item.vulnerabilities}`, item.score]
        .some((value) => value.toLowerCase().includes(normalizedQuery))
    ));
    const reportStats = [
      {
        label: 'Total Reports',
        value: String(scanReports.length),
        subtitle: 'Generated reports',
        icon: FileText,
        tone: 'primary',
      },
      {
        label: 'Total Vulnerabilities',
        value: String(scanReports.reduce((sum, report) => sum + (report.findings?.length || 0), 0)),
        subtitle: 'Issues detected',
        icon: AlertTriangle,
        tone: 'medium',
      },
      {
        label: 'Critical Issues',
        value: String(scanReports.reduce((sum, report) => sum + countFindingsBySeverity(report, 'Critical'), 0)),
        subtitle: 'Require immediate action',
        icon: Bell,
        tone: 'high',
      },
      {
        label: 'Average Risk Score',
        value: scanReports.length
          ? String(Math.round(scanReports.reduce((sum, report) => sum + Number(report.risk_score || 0), 0) / scanReports.length))
          : '0',
        subtitle: 'Across all scans',
        icon: Activity,
        tone: 'low',
      },
    ];

    return (
      <div className="db-reports-layout">
        <section className="db-reports-hero">
          <h1>Security Reports</h1>
          <p>View and download all your vulnerability scan reports</p>
        </section>

        <section className="db-reports-stats-grid">
          {reportStats.map((card) => (
            <article key={card.label} className={`db-report-stat-card ${card.tone}`}>
              <span className="db-report-stat-icon">
                <card.icon size={18} />
              </span>
              <div className="db-report-stat-copy">
                <p>{card.label}</p>
                <strong>{card.value}</strong>
                <span>{card.subtitle}</span>
              </div>
            </article>
          ))}
        </section>

        <section className="db-reports-search-panel">
          <div className="db-reports-search-row">
            <label className="db-reports-search-field" htmlFor="reports-search">
              <Search size={18} />
              <input
                id="reports-search"
                type="search"
                placeholder="Search by URL or Report ID..."
                value={reportSearchQuery}
                onChange={(event) => setReportSearchQuery(event.target.value)}
              />
            </label>
            <button type="button" className="db-reports-filter-btn" aria-label="Filter reports">
              <SlidersHorizontal size={18} />
            </button>
          </div>
        </section>

        <section className="db-reports-card-grid">
          {filteredReportCards.map((card, index) => (
            <article key={`${card.id}-${card.reference}-${index}`} className="db-report-card">
              <div className="db-report-card-top">
                <div className="db-report-card-copy">
                  <div className="db-report-card-title-row">
                    <span className="db-report-card-title-icon">
                      <FileText size={16} />
                    </span>
                    <h3>{card.id}</h3>
                    <span className={`db-report-pill ${card.riskTone}`}>{card.riskLabel}</span>
                  </div>

                  <div className="db-report-card-link-row">
                    <Globe size={13} />
                    <span>{card.url}</span>
                  </div>

                  <div className="db-report-card-id-row">
                    <Hash size={13} />
                    <span>{`ID:${card.reference}`}</span>
                  </div>
                </div>

                <button
                  type="button"
                  className="db-report-card-download"
                  aria-label={`Download ${card.id}`}
                  onClick={() => downloadScanReport(card.raw)}
                >
                  <Download size={14} />
                </button>
              </div>

              <div className="db-report-card-meta">
                <div className="db-report-card-meta-group">
                  <span>
                    <CalendarDays size={13} />
                    {card.date}
                  </span>
                  <span className="db-report-card-time">{card.time}</span>
                </div>

                <span className="db-report-card-duration">
                  <Clock3 size={13} />
                  {`Duration: ${card.duration}`}
                </span>
              </div>

              <div className="db-report-card-breakdown">
                <div className="db-report-score-row">
                  <p>Risk Score</p>
                  <strong className={card.scoreTone}>{card.score}</strong>
                </div>

                <div className="db-report-breakdown-grid">
                  {card.breakdown.map((item) => (
                    <article key={`${card.id}-${card.reference}-${item.label}-${index}`} className="db-report-breakdown-item">
                      <strong className={item.tone}>{item.value}</strong>
                      <span>{item.label}</span>
                    </article>
                  ))}
                </div>
              </div>
            </article>
          ))}

          {!filteredReportCards.length && (
            <div className="db-reports-empty">
              <p>No reports match this search.</p>
            </div>
          )}
        </section>

        <section className="db-reports-history-panel">
          <div className="db-reports-history-head">
            <span className="db-reports-history-icon">
              <Clock3 size={15} />
            </span>
            <h2>Scan History Summary</h2>
          </div>

          <div className="db-reports-history-list">
            {filteredHistoryItems.map((item) => (
              <article key={`${item.index}-${item.score}`} className="db-reports-history-row">
                <div className="db-reports-history-main">
                  <span className="db-reports-history-index">{item.index}</span>
                  <div className="db-reports-history-copy">
                    <p>{item.url}</p>
                    <span>{item.timestamp}</span>
                  </div>
                </div>

                <div className="db-reports-history-stats">
                  <div className="db-reports-history-stat">
                    <span>Vulnerabilities</span>
                    <strong>{item.vulnerabilities}</strong>
                  </div>
                  <div className="db-reports-history-stat">
                    <span>Risk Score</span>
                    <strong className={item.scoreTone}>{item.score}</strong>
                  </div>
                  <button
                    type="button"
                    className="db-reports-history-download"
                    aria-label={`Download history row ${item.index}`}
                    onClick={() => downloadScanReport(item.raw)}
                  >
                    <Download size={13} />
                  </button>
                </div>
              </article>
            ))}

            {!filteredHistoryItems.length && (
              <div className="db-reports-empty compact">
                <p>No history rows match this search.</p>
              </div>
            )}
          </div>

          <div className="db-reports-history-footer">
            <p>{`Showing ${filteredHistoryItems.length} of ${reportHistoryItems.length} scans`}</p>
            <button type="button" className="db-reports-history-link">
              View All History
              <ArrowUpRight size={15} />
            </button>
          </div>
        </section>
      </div>
    );
  };

  const renderSettingsSection = () => (
    <div className="db-settings-layout">
      <header className="db-settings-hero">
        <h1>Settings</h1>
        <p>Configure your application preferences</p>
      </header>

      <section className="db-settings-panel db-settings-panel-general">
        <div className="db-settings-panel-head">
          <span className="db-settings-panel-icon">
            <Settings size={30} />
          </span>
          <div className="db-settings-panel-copy">
            <h2>General Settings</h2>
            <p>Basic application configuration</p>
          </div>
        </div>

        <div className="db-settings-field">
          <label htmlFor="settings-language">Language</label>
          <div className="db-settings-select-wrap">
            <select
              id="settings-language"
              value={settingsForm.language}
              className="db-settings-select"
              onChange={(event) => updateSettingsForm('language', event.target.value)}
            >
              <option>English (US)</option>
              <option>Arabic</option>
              <option>French</option>
            </select>
            <ChevronDown size={18} />
          </div>
        </div>

        <div className="db-settings-field">
          <label htmlFor="settings-timezone">Timezone</label>
          <div className="db-settings-select-wrap">
            <select
              id="settings-timezone"
              value={settingsForm.timezone}
              className="db-settings-select"
              onChange={(event) => updateSettingsForm('timezone', event.target.value)}
            >
              <option>UTC (GMT+0:00)</option>
              <option>UTC-08:00 (Pacific)</option>
              <option>UTC-05:00 (Eastern)</option>
              <option>UTC+02:00 (Cairo)</option>
            </select>
            <ChevronDown size={18} />
          </div>
        </div>

        <div className="db-settings-field mode">
          <label>Default Scan Mode</label>
          <div className="db-settings-mode-list">
            {SETTINGS_SCAN_MODE_OPTIONS.map((option) => (
              <label className={`db-settings-mode-card ${scanMode === option.key ? 'active' : ''}`} key={option.key}>
                <input
                  type="radio"
                  name="scan-mode"
                  checked={scanMode === option.key}
                  onChange={() => {
                    setScanMode(option.key);
                    setSettingsNotice('');
                  }}
                />
                <span className="db-settings-mode-radio" />
                <span className="db-settings-mode-copy">
                  <strong>{option.title}</strong>
                  <small>{option.description}</small>
                </span>
              </label>
            ))}
          </div>
        </div>

        <button type="button" className="db-user-profile-action-btn primary" onClick={() => saveSettings()}>
          Save General Settings
        </button>
      </section>

      <section className="db-settings-panel">
        <div className="db-settings-panel-head">
          <span className="db-settings-panel-icon">
            <Bell size={30} />
          </span>
          <div className="db-settings-panel-copy">
            <h2>Notification Settings</h2>
            <p>Manage your notification preferences</p>
          </div>
        </div>

        <div className="db-settings-toggle-list">
          {SETTINGS_NOTIFICATION_ITEMS.map((row) => (
            <label className="db-settings-toggle-card" key={row.key}>
              <span className="db-settings-toggle-copy">
                <strong>{row.title}</strong>
                <small>{row.sub}</small>
              </span>
              <span className="db-settings-switch">
                <input
                  type="checkbox"
                  checked={notificationPrefs[row.key]}
                  onChange={() => toggleNotification(row.key)}
                />
                <span className="db-settings-switch-track" />
              </span>
            </label>
          ))}
        </div>

        <button type="button" className="db-user-profile-action-btn primary" onClick={() => saveSettings()}>
          Save Notification Settings
        </button>
      </section>

      <section className="db-settings-panel db-settings-panel-report">
        <div className="db-settings-panel-head">
          <span className="db-settings-panel-icon">
            <FileText size={30} />
          </span>
          <div className="db-settings-panel-copy">
            <h2>Report Settings</h2>
            <p>Configure report generation options</p>
          </div>
        </div>

        <div className="db-settings-check-list">
          {SETTINGS_REPORT_ITEMS.map((row) => (
            <label className="db-settings-check-card" key={row.key}>
              <input
                type="checkbox"
                checked={reportPrefs[row.key]}
                onChange={() => toggleReportPref(row.key)}
              />
              <span className="db-settings-check-copy">
                <strong>{row.title}</strong>
                <small>{row.sub}</small>
              </span>
              <span className="db-settings-checkbox-box" />
            </label>
          ))}
        </div>

        <button type="button" className="db-user-profile-action-btn primary" onClick={() => saveSettings()}>
          Save Report Settings
        </button>
        {settingsNotice && <p className="db-user-profile-form-note">{settingsNotice}</p>}
      </section>
    </div>
  );

  const renderProfileSection = () => (
    <div className="db-user-profile-layout">
      <header className="db-user-profile-hero">
        <h1>User Profile</h1>
        <p>Manage your account and security settings</p>
      </header>

      <section className="db-user-profile-card db-user-profile-summary-card">
        <div className="db-user-profile-summary">
          <div className="db-user-profile-avatar">
            <span>{profileInitial}</span>
          </div>

          <div className="db-user-profile-summary-copy">
            <h2>{profileDisplayName}</h2>
            <p>{user?.role ? `${user.role.charAt(0).toUpperCase()}${user.role.slice(1)} Account` : 'Threat Hunters Account'}</p>

            <div className="db-user-profile-summary-meta">
              <span>
                <Mail size={14} />
                {profileEmail}
              </span>
              <span>
                <CalendarDays size={14} />
                {`Member Since ${memberSince}`}
              </span>
            </div>
          </div>

          <button
            type="button"
            className="db-user-profile-action-btn"
            onClick={() => document.getElementById('profile-username')?.focus()}
          >
            <Pencil size={13} />
            Edit Profile
          </button>
          <button type="button" className="db-user-profile-action-btn is-logout" onClick={onLogout || (() => onNavigate('home'))}>
            <LogOut size={14} />
            Log Out
          </button>
        </div>
      </section>

      <section className="db-user-profile-card db-user-profile-info-card">
        <div className="db-user-profile-card-head">
          <div className="db-user-profile-card-title">
            <span className="db-user-profile-card-icon">
              <User size={34} />
            </span>
            <div>
              <h2>Personal Information</h2>
              <p>Basic Account Details</p>
            </div>
          </div>

          <button type="button" className="db-user-profile-action-btn" onClick={handleProfileUpdate}>
            <Pencil size={13} />
            Save Info
          </button>
        </div>

        <div className="db-user-profile-info-grid">
          <label className="db-user-profile-field">
            <span>Username</span>
            <input
              id="profile-username"
              className="db-user-profile-input"
              value={profileForm.username}
              onChange={(event) => updateProfileForm('username', event.target.value)}
            />
          </label>

          <label className="db-user-profile-field">
            <span>Email Address</span>
            <input
              className="db-user-profile-input"
              type="email"
              value={profileForm.email}
              onChange={(event) => updateProfileForm('email', event.target.value)}
            />
          </label>

          <label className="db-user-profile-field">
            <span>Phone Number</span>
            <input
              className="db-user-profile-input"
              value={profileForm.phone}
              onChange={(event) => updateProfileForm('phone', event.target.value)}
            />
          </label>

          <label className="db-user-profile-field">
            <span>Last Login</span>
            <input
              className="db-user-profile-input"
              value={profileForm.lastLogin}
              onChange={(event) => updateProfileForm('lastLogin', event.target.value)}
            />
          </label>

          <label className="db-user-profile-field full">
            <span>Bio</span>
            <textarea
              className="db-user-profile-input db-user-profile-textarea"
              value={profileForm.bio}
              onChange={(event) => updateProfileForm('bio', event.target.value)}
            />
          </label>
        </div>
      </section>

      <section className="db-user-profile-card db-user-profile-security-card">
        <div className="db-user-profile-card-head">
          <div className="db-user-profile-card-title">
            <span className="db-user-profile-card-icon">
              <Shield size={38} />
            </span>
            <div>
              <h2>Security Settings</h2>
              <p>Manage Your Account Security</p>
            </div>
          </div>
        </div>

        <article className="db-user-profile-security-subcard">
          <div className="db-user-profile-subcard-title">
            <KeyRound size={16} />
            <h3>Change Password</h3>
          </div>

          <div className="db-user-profile-password-grid">
            <label className="db-user-profile-field">
              <span>Current Password</span>
              <input
                className="db-user-profile-input"
                type="password"
                placeholder="Enter Current Password"
                value={passwordForm.current}
                onChange={(event) => updatePasswordForm('current', event.target.value)}
              />
            </label>

            <label className="db-user-profile-field">
              <span>New Password</span>
              <input
                className="db-user-profile-input"
                type="password"
                placeholder="Enter New Password"
                value={passwordForm.next}
                onChange={(event) => updatePasswordForm('next', event.target.value)}
              />
            </label>

            <label className="db-user-profile-field full">
              <span>Confirm New Password</span>
              <input
                className="db-user-profile-input"
                type="password"
                placeholder="Confirm new Password"
                value={passwordForm.confirm}
                onChange={(event) => updatePasswordForm('confirm', event.target.value)}
              />
            </label>
          </div>

          <button type="button" className="db-user-profile-action-btn primary" onClick={handlePasswordUpdate}>
            Update Password
          </button>
          {profileNotice && <p className="db-user-profile-form-note">{profileNotice}</p>}
        </article>

        <article className="db-user-profile-twofactor-card">
          <div className="db-user-profile-twofactor-copy">
            <div className="db-user-profile-twofactor-title">
              <Shield size={18} />
              <strong>Two-Factor Authentication</strong>
            </div>
            <p>Enable 2FA for extra protection. Adds an additional layer of security to your account.</p>
          </div>

          <label className="db-user-profile-switch">
            <input
              type="checkbox"
              checked={profileTwoFactorEnabled}
              onChange={toggleTwoFactor}
            />
            <span className="db-user-profile-switch-track" />
          </label>
        </article>
      </section>

      <section className="db-user-profile-card db-user-profile-activity-card">
        <div className="db-user-profile-card-head no-action">
          <div className="db-user-profile-card-title">
            <span className="db-user-profile-card-icon">
              <Clock3 size={36} />
            </span>
            <div>
              <h2>Scan Activity Overview</h2>
              <p>Your recent security scan activity</p>
            </div>
          </div>
        </div>

        <div className="db-user-profile-stat-grid">
          {profileScanStats.map((item) => (
            <article key={item.label} className="db-user-profile-stat-card">
              <p>{item.label}</p>
              <strong>{item.value}</strong>
            </article>
          ))}
        </div>

        <div className="db-user-profile-table">
          <div className="db-user-profile-table-head">
            <span>Website</span>
            <span>Risk Level</span>
            <span>Date</span>
          </div>
          {profileScanRows.map((item, index) => (
            <div key={`${item.website}-${item.risk}-${index}`} className="db-user-profile-table-row">
              <span>{item.website}</span>
              <span className={`db-risk ${item.risk.toLowerCase()}`}>{item.risk}</span>
              <span>{item.date}</span>
            </div>
          ))}
          {!profileScanRows.length && (
            <div className="db-user-profile-table-row">
              <span>No scans yet</span>
              <span className="db-risk low">Ready</span>
              <span>Run your first scan</span>
            </div>
          )}
        </div>
      </section>

      <section className="db-user-profile-card db-user-profile-logout-card">
        <div className="db-user-profile-card-title">
          <span className="db-user-profile-card-icon">
            <LogOut size={34} />
          </span>
          <div>
            <h2>Account Session</h2>
            <p>End this session and return to the public website</p>
          </div>
        </div>

        <button type="button" className="db-user-profile-action-btn is-logout primary-logout" onClick={onLogout || (() => onNavigate('home'))}>
          <LogOut size={14} />
          Log Out
        </button>
      </section>

      <section className="db-user-profile-delete-card">
        <div className="db-user-profile-delete-head">
          <AlertTriangle size={18} />
          <h2>Delete Account</h2>
        </div>
        <p>
          Once you delete your account, there is no going back. This action will permanently delete all your data
          including scan history, reports, and settings. Please be certain before proceeding.
        </p>
        <button type="button" className="db-user-profile-delete-btn" onClick={handleDeleteAccount}>
          <Trash2 size={14} />
          Delete Account
        </button>
      </section>
    </div>
  );

  return (
    <div className="user-dashboard-page">
      <AuthNavbar onNavigate={onNavigate} currentPage={currentPage} activeSection={activeSection} />

      <div className="user-dashboard-shell">
        <aside className="user-dashboard-sidebar">
          <div className="user-sidebar-title">
            <LayoutDashboard size={15} />
            <span>User Console</span>
          </div>

          {SIDEBAR_ITEMS.map((item) => (
            <button
              key={item.key}
              className={`user-sidebar-btn ${activeSection === item.key ? 'active' : ''}`}
              onClick={() => navigateToSection(item.key)}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
            </button>
          ))}
        </aside>

        <main className="user-dashboard-main">
          {activeSection === 'dashboard' && renderDashboardSection()}
          {activeSection === 'reports' && renderReportsSection()}
          {activeSection === 'settings' && renderSettingsSection()}
          {activeSection === 'profile' && renderProfileSection()}
        </main>
      </div>

      {activeSection === 'dashboard' && isAdvancedScanOpen && renderAdvancedScanModal()}
    </div>
  );
}

export default memo(DashboardPage);



