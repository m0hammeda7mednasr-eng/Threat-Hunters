import { memo, useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Gauge,
  Globe,
  Download,
  KeyRound,
  Mail,
  Play,
  RotateCcw,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import './MoreToolsPage.css';
import Navbar from './Navbar';
import Footer from './Footer';
import { securityAPI } from '../services/api';
import { buildBrandedPdfBlob, downloadPdfBlob } from '../utils/pdfBuilder';

const tabContent = {
  password: {
    label: 'Password Checker',
    shortLabel: 'Password',
    icon: KeyRound,
    eyebrow: 'Credential hygiene',
    inputLabel: 'Enter your password',
    inputType: 'password',
    placeholder: 'Enter a password',
    heroCopy: 'Audit password quality, weak construction patterns, and policy fit before reuse becomes a real risk.',
    detailCopy: 'A fast way to preview strength, reuse, exposure, and a downloadable backend-backed report.',
    idleTitle: 'Password review is standing by',
    idleCopy: 'Run the checker to see live breach counts, risk level, and reuse-style guidance.',
    helperCopy: 'The password analysis runs through the backend, checks live Pwned Passwords exposure, and can export a PDF report.',
    signalTags: ['Entropy score', 'Length policy', 'Weak patterns'],
    examples: ['CorrectHorseBattery!42', 'Vault-Access-2026!'],
    heroStats: [
      { label: 'Typical run', value: '< 2 sec' },
      { label: 'Checks surfaced', value: '4 layers' },
      { label: 'Storage', value: '0 data' },
    ],
    summary: [
      { label: 'Entropy', value: 'Strong', note: '116-bit est.', tone: 'safe' },
      { label: 'Reuse risk', value: 'Low', note: 'No obvious hints', tone: 'safe' },
      { label: 'Pattern flags', value: '0', note: 'No trivial sequences', tone: 'info' },
    ],
    insights: [
      {
        title: 'Length baseline is healthy',
        copy: 'The sample exceeds a safer length threshold, which reduces low-effort brute-force exposure.',
        tone: 'safe',
      },
      {
        title: 'Composition looks balanced',
        copy: 'Uppercase, lowercase, digits, and symbols are all present without obvious repetition.',
        tone: 'info',
      },
      {
        title: 'No common pattern detected',
        copy: 'The live review did not flag dates, keyboard walks, or simple suffix habits.',
        tone: 'safe',
      },
    ],
    checklist: [
      'Structure and length review',
      'Weak pattern detection',
      'Policy fit and reuse hints',
    ],
    successTitle: 'Password posture has been analyzed',
    successCopy: 'The live review now shows breach counts and a risk label from HIBP.',
  },
  email: {
    label: 'Email Checker',
    shortLabel: 'Email',
    icon: Mail,
    eyebrow: 'Exposure review',
    inputLabel: 'Enter your email',
    inputType: 'email',
    placeholder: 'you@example.com',
    heroCopy: 'Run a fast exposure-style review for email addresses and see live breach intelligence in one pass.',
    detailCopy: 'Powered by the backend so the browser never talks to the HIBP API key directly.',
    idleTitle: 'Exposure review is ready',
    idleCopy: 'Start a check to preview breach results, data classes, and account hygiene hints.',
    helperCopy: 'Live HIBP lookup through the backend. Use a test address from the HIBP docs if needed.',
    signalTags: ['Breach hints', 'Domain posture', 'Alias hygiene'],
    examples: ['security.team@company.com', 'alias+alerts@example.org'],
    heroStats: [
      { label: 'Typical run', value: '< 2 sec' },
      { label: 'Signal lanes', value: '3 sources' },
      { label: 'API calls', value: 'Live backend' },
    ],
    summary: [
      { label: 'Exposure', value: '0 hits', note: 'Live result', tone: 'safe' },
      { label: 'Domain health', value: 'Healthy', note: 'Valid pattern', tone: 'safe' },
      { label: 'Alias hygiene', value: 'Stable', note: 'No obvious issue', tone: 'info' },
    ],
    insights: [
      {
        title: 'No breach-style signal surfaced',
        copy: 'The live lookup returned a clean result set for the sample address.',
        tone: 'safe',
      },
      {
        title: 'Domain shape looks valid',
        copy: 'The address structure supports domain-level checks and exposure grouping in a real pipeline.',
        tone: 'info',
      },
      {
        title: 'Good fit for quick triage',
        copy: 'This flow gives users a fast answer before escalating to deeper identity or account monitoring.',
        tone: 'safe',
      },
    ],
    checklist: [
      'Address and domain validation',
      'Exposure-style signal matching',
      'Alias and posture review',
    ],
    successTitle: 'Email posture has been analyzed',
    successCopy: 'The live review now shows breach count, verified hits, and exposed data classes.',
  },
};

const workflowCards = [
  {
    icon: Search,
    title: 'Quick triage first',
    copy: 'Check obvious signals before you spend time on a deeper assessment or manual review.',
  },
  {
    icon: ShieldCheck,
    title: 'Safe product checks',
    copy: 'Everything here is backend-backed and kept focused, which makes it suitable for real checks without noisy UI behavior.',
  },
  {
    icon: Gauge,
    title: 'Better escalation',
    copy: 'The output gives enough direction to decide whether a user should move to a stronger scan flow.',
  },
];

const roadmapCards = [
  {
    icon: Globe,
    title: 'Domain posture snapshots',
    copy: 'DNS and security-header style checks presented with the same product language.',
  },
  {
    icon: Sparkles,
    title: 'Identity hygiene checks',
    copy: 'Username reuse, alias quality, and recovery-surface hints for higher-risk accounts.',
  },
  {
    icon: Activity,
    title: 'Trend-based scoring',
    copy: 'Repeat checks, historical comparison, and smarter escalation signals over time.',
  },
];

const statItems = [
  { value: '10+', label: 'New tools planned' },
  { value: '24/7', label: 'Fast utility access' },
  { value: '100%', label: 'Live backend checks' },
];

const scanStatusMeta = {
  idle: { label: 'Awaiting input', tone: 'idle' },
  checking: { label: 'Running preview', tone: 'checking' },
  success: { label: 'Signals clear', tone: 'success' },
  error: { label: 'Check failed', tone: 'watch' },
};

const getScanStatusMeta = (activeTab, scanState, scanResult) => {
  if (scanState !== 'success') {
    return scanStatusMeta[scanState] || scanStatusMeta.idle;
  }

  if (activeTab === 'password') {
    const score = Number(scanResult?.score || 0);
    const breached = Boolean(scanResult?.breached);

    if (breached || score < 60) {
      return { label: 'Needs attention', tone: 'watch' };
    }

    if (score >= 80) {
      return { label: 'Strong posture', tone: 'success' };
    }

    return { label: 'Review needed', tone: 'checking' };
  }

  if (activeTab === 'email') {
    if (scanResult?.breached) {
      return { label: scanResult?.risk_level || 'Exposure found', tone: 'watch' };
    }

    return { label: 'No breach hit', tone: 'success' };
  }

  return scanStatusMeta.success;
};

const getEmailLiveNote = (value) => {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Enter a full address to unlock domain and exposure-style checks.';
  }

  if (!trimmedValue.includes('@')) {
    return 'Add a domain so the preview can reason about posture and exposure grouping.';
  }

  const [, domain = 'this domain'] = trimmedValue.split('@');
  return `Ready to inspect ${domain.toLowerCase()} for exposure-style signals and domain hygiene hints.`;
};

const getPasswordLiveNote = (value) => {
  const length = value.length;

  if (!length) {
    return 'Try a longer passphrase-style sample to preview stronger scoring and clearer guidance.';
  }

  if (length < 10) {
    return `${length} characters entered. Add more length before you trust the result.`;
  }

  if (!/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/\d/.test(value)) {
    return 'The structure is usable, but more variation would improve resilience and scoring.';
  }

  return 'Good structure detected. Run the checker to preview policy fit and reuse-style hints.';
};

const formatCount = (value) => Number(value || 0).toLocaleString();

const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value.trim());

const validateToolInput = (activeTab, value) => {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Enter a value before starting the check.';
  }

  if (activeTab === 'email' && !isValidEmail(trimmedValue)) {
    return 'Enter a valid email address like name@example.com.';
  }

  if (activeTab === 'password' && value.length < 8) {
    return 'Enter at least 8 characters so the password check can be useful.';
  }

  return '';
};

const buildPasswordResultView = (result) => {
  const count = Number(result?.count || result?.breach_count || 0);
  const breached = Boolean(result?.breached);
  const score = Number(result?.score || 0);
  const strength = result?.strength || 'Unknown';
  const entropyBits = Number(result?.entropy_bits || 0);
  const entropyLevel = result?.entropy_level || 'Unknown';
  const recommendations = Array.isArray(result?.recommendations) ? result.recommendations : [];
  const priorityActions = Array.isArray(result?.priority_actions) ? result.priority_actions : [];
  const issues = Array.isArray(result?.issues) ? result.issues : [];
  const checks = Array.isArray(result?.checks) ? result.checks : [];
  const safeTone = breached ? 'watch' : 'safe';
  const failedChecks = checks.filter((item) => !item.passed);
  const passedChecks = checks.filter((item) => item.passed).length;

  return {
    title: breached ? 'Password needs immediate replacement' : 'Password posture review is ready',
    copy: breached
      ? `This password appeared ${formatCount(count)} times in known breaches and needs to be rotated immediately.`
      : 'The live review did not find a breach match. Use the detailed checks below to harden it further.',
    summary: [
      {
        label: 'Score',
        value: `${score}/100`,
        note: strength,
        tone: safeTone,
      },
      {
        label: 'Exposure',
        value: breached ? 'Pwned' : 'Clear',
        note: breached ? `${formatCount(count)} hits` : 'No breach hit',
        tone: safeTone,
      },
      {
        label: 'Entropy',
        value: `${entropyBits} bits`,
        note: entropyLevel,
        tone: 'info',
      },
      {
        label: 'Checks',
        value: `${passedChecks}/${checks.length || 1}`,
        note: failedChecks.length ? `${failedChecks.length} flagged` : 'All passed',
        tone: failedChecks.length ? 'watch' : 'safe',
      },
    ],
    insights: breached
      ? [
          {
            title: 'Known breach exposure',
            copy: `The password appeared ${formatCount(count)} times in the live Pwned Passwords corpus.`,
            tone: 'watch',
          },
          {
            title: 'Replace it everywhere',
            copy: 'Use a unique passphrase for every account and rotate any reused copies first.',
            tone: 'info',
          },
          {
            title: 'Save the fix in a manager',
            copy: 'A password manager will help keep the replacement strong, unique, and realistic to maintain.',
            tone: 'safe',
          },
        ]
      : [
          {
            title: 'No breach hit surfaced',
            copy: 'The live HIBP check did not match this password against the current breach corpus.',
            tone: 'safe',
          },
          {
            title: 'Review the weaker checks',
            copy: failedChecks.length
              ? `${failedChecks.length} check(s) still need attention before you should trust this password.`
              : 'The password passed the structural checks in this review.',
            tone: failedChecks.length ? 'watch' : 'info',
          },
          {
            title: 'Keep the passphrase unique',
            copy: 'Even a clean breach result should still stay unique, long, and hard to guess.',
            tone: 'safe',
          },
        ],
    tags: breached
      ? ['Rotate now', 'No reuse', 'Password manager']
      : ['No direct hit', 'Unique password', 'Passphrase'],
    issues,
    checks,
    recommendations,
    priorityActions,
  };
};

const buildPasswordAnalysisPdf = (password, resultView, rawResult) => {
  const score = Number(rawResult?.score || 0);
  const strength = rawResult?.strength || 'Unknown';
  const riskLevel = rawResult?.risk_level || 'Medium';
  const entropyBits = Number(rawResult?.entropy_bits || 0);
  const passwordLength = Number(rawResult?.password_length || password.length);
  const breachedCount = Number(rawResult?.breach_count || 0);
  const checks = Array.isArray(resultView?.checks) ? resultView.checks : [];
  const issues = Array.isArray(resultView?.issues) ? resultView.issues : [];
  const recommendations = Array.isArray(resultView?.recommendations) ? resultView.recommendations : [];
  const priorityActions = Array.isArray(resultView?.priorityActions) && resultView.priorityActions.length
    ? resultView.priorityActions
    : ['Replace weak credentials with a unique passphrase.', 'Use a password manager.', 'Retest after the change.'];
  const weakChecks = checks.filter((item) => !item.passed);
  const passwordTraits = [
    `Length: ${passwordLength} characters`,
    `Uppercase: ${rawResult?.has_uppercase ? 'yes' : 'no'}`,
    `Lowercase: ${rawResult?.has_lowercase ? 'yes' : 'no'}`,
    `Numbers: ${rawResult?.has_numbers ? 'yes' : 'no'}`,
    `Symbols: ${rawResult?.has_special_characters ? 'yes' : 'no'}`,
  ];
  const whereIssueIs = rawResult?.breached
    ? `The password matches known breach data, so the weak point is credential exposure itself rather than just composition.`
    : weakChecks.length
      ? `The weak points are in the password structure: ${weakChecks.slice(0, 3).map((item) => item.title || item.key || 'check').join(', ')}.`
      : 'No single structural hotspot was flagged, but the password still benefits from stronger uniqueness and rotation discipline.';
  const whatItMeans = rawResult?.breached
    ? `This password is present in breach data ${formatCount(breachedCount)} time(s), which means it should be treated as compromised and replaced immediately.`
    : `The password is not currently matched in breach data, but the structure still matters because weak composition can make guessing, reuse, or policy failure easier.`;
  const howToAvoidIt = rawResult?.breached
    ? [
        'Replace the password everywhere it is reused.',
        'Store the new secret in a password manager so it stays unique.',
        'Review connected accounts and enable MFA where possible.',
      ]
    : [
        'Use a longer, unique passphrase instead of a predictable pattern.',
        'Add variation with upper/lowercase, numbers, and symbols only when it stays memorable.',
        'Keep it out of shared notes and recheck after any policy change.',
      ];
  const analysisSummary = rawResult?.breached
    ? 'The password is exposed in known breach data and should be replaced immediately.'
    : `The password is not currently matched in breach data, but structural review still found ${issues.length} weak point(s).`;

  return buildBrandedPdfBlob({
    eyebrow: 'Password Analysis Report',
    title: 'Password Review Summary',
    subtitle: analysisSummary,
    generatedAt: new Date().toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }),
    classification: 'CONFIDENTIAL PASSWORD REVIEW',
    metrics: [
      { label: 'Score', value: `${score}/100`, fill: '#eef6ff', valueColor: score >= 80 ? '#11855d' : '#b35d00' },
      { label: 'Strength', value: strength, fill: '#fff7ed', valueColor: rawResult?.breached ? '#c62828' : '#8a5b00' },
      { label: 'Entropy', value: `${entropyBits} bits`, fill: '#eefbf7', valueColor: '#11855d' },
      { label: 'Length', value: `${passwordLength} chars`, fill: '#f4f0ff', valueColor: '#6d4cff' },
      { label: 'Exposure', value: `${breachedCount.toLocaleString()} hits`, fill: '#fff0f0', valueColor: rawResult?.breached ? '#c62828' : '#0b66c3' },
      { label: 'Risk', value: riskLevel, fill: '#f4f7ff', valueColor: rawResult?.breached ? '#c62828' : '#0b66c3' },
    ],
    sections: [
      {
        title: 'Executive Summary',
        body: analysisSummary,
        accent: '#8b7cff',
      },
      {
        title: 'What This Means',
        body: whatItMeans,
        accent: '#6c5ce7',
      },
      {
        title: 'Where The Issue Is',
        body: whereIssueIs,
        rows: passwordTraits.map((trait) => ({
          label: trait.split(': ')[0],
          value: trait.split(': ')[1] || 'Unknown',
          detail: 'This property helps explain the current risk shape.',
        })),
        accent: '#ff8b3d',
      },
      {
        title: 'Top Issues',
        items: issues.length
          ? issues.map((issue) => `${issue.title}: ${issue.detail}${issue.fix ? ` Fix: ${issue.fix}` : ''}`)
          : ['No structural issues were flagged by the review.'],
        accent: '#ffb347',
      },
      {
        title: 'Checks Passed',
        items: checks.filter((item) => item.passed).map((item) => `${item.title}: ${item.detail}`).slice(0, 6),
        accent: '#18a058',
      },
      {
        title: 'How To Avoid It',
        items: [
          ...howToAvoidIt,
          ...priorityActions,
          ...recommendations.filter(Boolean),
        ].filter(Boolean).slice(0, 10),
        accent: '#00b8d9',
      },
    ],
  });
};

const buildEmailResultView = (result) => {
  const breachCount = Number(result?.breach_count || 0);
  const verifiedCount = Number(result?.verified_breach_count || 0);
  const stealerCount = Number(result?.stealer_log_count || 0);
  const breached = Boolean(result?.breached);
  const latestBreach = result?.latest_breach || null;
  const riskLevel = result?.risk_level || (breached ? 'Medium' : 'Safe');
  const exposedData = Array.isArray(result?.exposed_data) ? result.exposed_data : [];
  const latestLabel = latestBreach?.title || latestBreach?.name || 'No breach';
  const latestDate = latestBreach?.breach_date || 'Not found';
  const safeTone = breached ? 'watch' : 'safe';
  const checks = [
    {
      key: 'breach-count',
      title: 'Breach exposure',
      passed: !breached,
      detail: breached
        ? `${formatCount(breachCount)} breach record(s) were returned.`
        : 'No breach record was returned by the backend lookup.',
      severity: breached ? 'critical' : 'safe',
      fix: breached ? 'Reset the password and monitor the account.' : null,
    },
    {
      key: 'verified-count',
      title: 'Verified breach coverage',
      passed: verifiedCount === 0,
      detail: `${formatCount(verifiedCount)} verified breach(s) were matched.`,
      severity: verifiedCount > 0 ? 'watch' : 'safe',
      fix: verifiedCount > 0 ? 'Review the breached services and rotate any reused credentials.' : null,
    },
    {
      key: 'stealer-count',
      title: 'Stealer log exposure',
      passed: stealerCount === 0,
      detail: `${formatCount(stealerCount)} stealer log hit(s) were matched.`,
      severity: stealerCount > 0 ? 'critical' : 'safe',
      fix: stealerCount > 0 ? 'Change the password immediately and review account recovery paths.' : null,
    },
  ];
  const exposedIssues = Array.isArray(result?.breaches) ? result.breaches.slice(0, 3).map((breach) => ({
    key: breach.name || breach.title || 'breach',
    title: breach.title || breach.name || 'Breach exposure',
    severity: breach.stealer_log ? 'critical' : breach.verified ? 'watch' : 'info',
    detail: [
      breach.domain ? `Domain: ${breach.domain}` : null,
      breach.breach_date ? `Breach date: ${breach.breach_date}` : null,
      Array.isArray(breach.data_classes) && breach.data_classes.length ? `Data: ${breach.data_classes.slice(0, 5).join(', ')}` : null,
    ].filter(Boolean).join(' | ') || 'No breach metadata was returned.',
    fix: 'Treat the exposed account as compromised and rotate related credentials.',
  })) : [];
  const recommendations = breached
    ? [
        'Rotate this password immediately.',
        'Update reused credentials on other accounts.',
        'Enable two-factor authentication where available.',
      ]
    : [
        'Keep the password unique per account.',
        'Store the replacement in a password manager.',
        'Recheck exposure periodically.',
      ];
  const priorityActions = breached
    ? [
        'Replace the password with a unique passphrase.',
        'Review any accounts that reused the same secret.',
        'Enable stronger account recovery controls.',
      ]
    : [
        'Keep the password unique and long.',
        'Use a manager for storage and rotation.',
      ];

  return {
    title: breached ? 'Email appears in breach data' : 'No breach match found',
    copy: breached
      ? `This email appears in ${formatCount(breachCount)} breach record(s). Review the latest match and exposed data classes.`
      : 'The live HIBP lookup did not surface breach records for this email address.',
    summary: [
      {
        label: 'Exposure',
        value: breached ? `${formatCount(breachCount)} breaches` : 'Clear',
        note: riskLevel,
        tone: safeTone,
      },
      {
        label: 'Verified',
        value: formatCount(verifiedCount),
        note: 'Verified breaches',
        tone: 'info',
      },
      {
        label: 'Stealer logs',
        value: formatCount(stealerCount),
        note: stealerCount > 0 ? 'Critical' : 'No hits',
        tone: stealerCount > 0 ? 'watch' : 'safe',
      },
    ],
    insights: breached
      ? [
          {
            title: `Latest breach: ${latestLabel}`,
            copy: `Breach date: ${latestDate}. Use the latest incident details to decide the next remediation step.`,
            tone: 'watch',
          },
          {
            title: 'Exposed data classes',
            copy: exposedData.length
              ? exposedData.slice(0, 6).join(', ')
              : 'No data class metadata was returned.',
            tone: 'info',
          },
          {
            title: 'Verified and stealer signals',
            copy: `${formatCount(verifiedCount)} verified breach(s) and ${formatCount(stealerCount)} stealer-log hit(s) were found for this address.`,
            tone: stealerCount > 0 ? 'watch' : 'safe',
          },
        ]
      : [
          {
            title: 'No live breach hit surfaced',
            copy: 'The email address was not found in the breach corpus returned by HIBP.',
            tone: 'safe',
          },
          {
            title: 'Use a real inbox carefully',
            copy: 'If you test a real address, keep in mind the response may reveal sensitive account exposure details.',
            tone: 'info',
          },
          {
            title: 'Keep monitoring',
            copy: 'Regular checks and password hygiene are still the safest next steps for a clean result.',
            tone: 'safe',
          },
        ],
    tags: breached
      ? exposedData.slice(0, 6)
      : ['No direct hit', 'Exposure review', 'Hygiene'],
    checks,
    issues: exposedIssues,
    recommendations,
    priorityActions,
    latestBreach,
  };
};

const buildEmailAnalysisPdf = (emailValue, resultView, rawResult) => {
  const email = String(emailValue || rawResult?.email || 'Email').trim() || 'Email';
  const breachCount = Number(rawResult?.breach_count || 0);
  const verifiedCount = Number(rawResult?.verified_breach_count || 0);
  const stealerCount = Number(rawResult?.stealer_log_count || 0);
  const breached = Boolean(rawResult?.breached);
  const riskLevel = rawResult?.risk_level || (breached ? 'Critical' : 'Safe');
  const checks = Array.isArray(resultView?.checks) ? resultView.checks : [];
  const issues = Array.isArray(resultView?.issues) ? resultView.issues : [];
  const recommendations = Array.isArray(resultView?.recommendations) ? resultView.recommendations : [];
  const priorityActions = Array.isArray(resultView?.priorityActions) && resultView.priorityActions.length
    ? resultView.priorityActions
    : ['Keep the address unique.', 'Use a manager for stored credentials.', 'Review exposure again later.'];
  const exposedData = Array.isArray(rawResult?.exposed_data) ? rawResult.exposed_data : [];
  const latestBreach = rawResult?.latest_breach || null;
  const whereIssueIs = breached
    ? [
        latestBreach?.title ? `Latest match: ${latestBreach.title}` : null,
        latestBreach?.domain ? `Source domain: ${latestBreach.domain}` : null,
        latestBreach?.breach_date ? `Breach date: ${latestBreach.breach_date}` : null,
        exposedData.length ? `Exposed data classes: ${exposedData.slice(0, 6).join(', ')}` : null,
      ].filter(Boolean).join(' | ')
    : 'No breach source was returned, so there is no confirmed exposure location in the current lookup.';
  const whatItMeans = breached
    ? `This address appears in ${formatCount(breachCount)} breach record(s), with ${formatCount(verifiedCount)} verified and ${formatCount(stealerCount)} stealer-log hit(s). Treat the inbox as exposed until the password, recovery paths, and active sessions are reviewed.`
    : 'No live breach hit was returned, which lowers immediate exposure risk, but it does not replace unique passwords, MFA, and regular monitoring.';
  const howToAvoidIt = breached
    ? [
        'Change the inbox password and any account that reused the same secret.',
        'Enable MFA and review recovery email, phone, and active session settings.',
        'Monitor sign-ins and connected app access for suspicious activity.',
      ]
    : [
        'Keep a unique password for every inbox and avoid reuse across services.',
        'Use a password manager so updates stay easy and consistent.',
        'Recheck exposure periodically and rotate credentials if the risk profile changes.',
      ];

  return buildBrandedPdfBlob({
    eyebrow: 'Email Exposure Report',
    title: `Email Review for ${email}`,
    subtitle: breached
      ? 'The address appears in breach data and needs immediate review.'
      : 'The lookup did not return a live breach hit, but the hygiene review remains useful.',
    generatedAt: new Date().toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }),
    classification: 'CONFIDENTIAL EMAIL REVIEW',
    metrics: [
      { label: 'Risk', value: riskLevel, fill: '#fff5f6', valueColor: breached ? '#c62828' : '#11855d' },
      { label: 'Breaches', value: String(breachCount), fill: '#eef6ff', valueColor: '#0b66c3' },
      { label: 'Verified', value: String(verifiedCount), fill: '#f3f0ff', valueColor: '#6d4cff' },
      { label: 'Stealer logs', value: String(stealerCount), fill: '#fff0f0', valueColor: stealerCount > 0 ? '#c62828' : '#0b66c3' },
    ],
    sections: [
      {
        title: 'Executive Summary',
        body: breached
          ? `The address appears in ${formatCount(breachCount)} breach record(s) and should be reviewed immediately.`
          : 'The address was not matched in the live breach corpus, but account hygiene guidance is still included below.',
        accent: '#8b7cff',
      },
      {
        title: 'What This Means',
        body: whatItMeans,
        accent: '#6c5ce7',
      },
      {
        title: 'Where The Issue Is',
        body: whereIssueIs,
        accent: '#ff8b3d',
      },
      {
        title: 'Top Issues',
        items: issues.length
          ? issues.map((issue) => `${issue.title}: ${issue.detail}${issue.fix ? ` Fix: ${issue.fix}` : ''}`)
          : ['No breach-specific issues were returned by the lookup.'],
        accent: '#ffb347',
      },
      {
        title: 'Checks',
        items: checks.map((check) => `${check.title}: ${check.detail}${check.fix ? ` Fix: ${check.fix}` : ''}`).slice(0, 6),
        accent: '#18a058',
      },
      {
        title: 'How To Avoid It',
        items: [
          ...howToAvoidIt,
          ...priorityActions,
          ...recommendations,
        ].filter(Boolean).slice(0, 8),
        accent: '#00b8d9',
      },
      {
        title: 'Exposure Detail',
        items: [
          latestBreach?.title ? `Latest breach: ${latestBreach.title}` : 'Latest breach: not available',
          latestBreach?.breach_date ? `Breach date: ${latestBreach.breach_date}` : 'Breach date: not available',
          exposedData.length ? `Exposed data: ${exposedData.slice(0, 6).join(', ')}` : 'Exposed data: not returned',
        ],
        accent: '#ffb347',
      },
    ],
  });
};

const MoreToolsPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools,
  isLoggedIn,
}) => {
  const [activeTab, setActiveTab] = useState('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [scanState, setScanState] = useState('idle');
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState('');
  const checkTimeoutRef = useRef(null);
  const activeContent = tabContent[activeTab];
  const currentValue = activeTab === 'email' ? email : password;
  const canScan = currentValue.trim().length > 0;
  const statusMeta = getScanStatusMeta(activeTab, scanState, scanResult);
  const liveNote = activeTab === 'email' ? getEmailLiveNote(email) : getPasswordLiveNote(password);
  const ToolIcon = activeContent.icon;
  const resultView = scanState === 'success'
    ? (activeTab === 'email'
        ? buildEmailResultView(scanResult)
        : buildPasswordResultView(scanResult))
    : null;

  useEffect(() => () => {
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
      checkTimeoutRef.current = null;
    }
  }, []);

  const resetScanState = useCallback(() => {
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
      checkTimeoutRef.current = null;
    }

    setScanState('idle');
    setScanResult(null);
    setScanError('');
  }, []);

  const runLiveCheck = useCallback(async () => {
    const validationError = validateToolInput(activeTab, currentValue);

    if (validationError) {
      resetScanState();
      setScanError(validationError);
      setScanState('error');
      return;
    }

    resetScanState();
    setScanState('checking');

    try {
      const result = activeTab === 'email'
        ? await securityAPI.checkEmailBreach({ email: currentValue.trim() })
        : await securityAPI.analyzePassword({ password: currentValue });

      setScanResult(result);
      setScanError('');
      setScanState('success');
    } catch (error) {
      setScanResult(null);
      setScanError(error.message || 'Unable to complete the check.');
      setScanState('error');
    } finally {
      checkTimeoutRef.current = null;
    }
  }, [activeTab, currentValue, resetScanState]);

  const handleTabChange = useCallback(
    (nextTab) => {
      setActiveTab(nextTab);
      resetScanState();
    },
    [resetScanState],
  );

  const handleScan = async () => {
    await runLiveCheck();
  };

  const handleDownloadReport = useCallback(() => {
    if (scanState !== 'success' || !scanResult) {
      return;
    }

    const report = activeTab === 'password'
      ? buildPasswordAnalysisPdf(password, resultView, scanResult)
      : buildEmailAnalysisPdf(email, resultView, scanResult);
    const safeName = activeTab === 'password'
      ? (password.trim() ? `password-analysis-${password.length}-chars` : 'password-analysis')
      : (email.trim().replace(/[^a-z0-9]+/gi, '-').replace(/(^-|-$)/g, '') || 'email-analysis');
    downloadPdfBlob(report, `${safeName}.pdf`);
  }, [activeTab, email, password, resultView, scanResult, scanState]);

  const handleInputChange = (nextValue) => {
    resetScanState();

    if (activeTab === 'email') {
      setEmail(nextValue);
      return;
    }

    setPassword(nextValue);
  };

  const handleReset = useCallback(() => {
    resetScanState();

    if (activeTab === 'email') {
      setEmail('');
      return;
    }

    setPassword('');
  }, [activeTab, resetScanState]);

  return (
    <div className="more-tools-page">
      {!isLoggedIn && (
        <Navbar
          onNavigateToSignUp={onNavigateToSignUp}
          onNavigateToHome={onNavigateToHome}
          onNavigateToBlog={onNavigateToBlog}
          onNavigateToAwareness={onNavigateToAwareness}
          onNavigateToTools={onNavigateToTools}
          currentPage="tools"
        />
      )}

      <section className="more-tools-hero">
        <div className="more-tools-hero-shell">
          <div className="more-tools-hero-copy">
            <div className="more-tools-hero-badge">
              <span className="more-tools-hero-badge-dot" aria-hidden="true" />
              <span>Fast utility checks</span>
            </div>

            <h1>Security tools that feel sharper and faster</h1>
            <p>{activeContent.heroCopy}</p>
            <p className="more-tools-hero-detail">{activeContent.detailCopy}</p>

            <div className="more-tools-hero-tags" aria-label={`${activeContent.label} capabilities`}>
              {activeContent.signalTags.map((tag) => (
                <span className="more-tools-hero-tag" key={tag}>
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <aside className="more-tools-hero-panel">
            <div className="more-tools-hero-panel-head">
              <span className="more-tools-hero-panel-icon" aria-hidden="true">
                <ToolIcon size={20} />
              </span>

              <div>
                <span className="more-tools-hero-panel-eyebrow">Selected utility</span>
                <strong className="more-tools-hero-panel-title">{activeContent.label}</strong>
              </div>
            </div>

            <div className="more-tools-hero-metrics">
              {activeContent.heroStats.map((item) => (
                <article className="more-tools-hero-metric" key={item.label}>
                  <strong>{item.value}</strong>
                  <span>{item.label}</span>
                </article>
              ))}
            </div>
          </aside>
        </div>
      </section>

      <section className="more-tools-workbench-section">
        <div className="more-tools-workbench">
          <div className="more-tools-tabbar" role="tablist" aria-label="Security tools">
            {Object.entries(tabContent).map(([key, item]) => {
              const TabIcon = item.icon;

              return (
                <button
                  key={key}
                  className={`more-tools-tab ${activeTab === key ? 'is-active' : ''}`}
                  onClick={() => handleTabChange(key)}
                  role="tab"
                  type="button"
                >
                  <span className="more-tools-tab-icon" aria-hidden="true">
                    <TabIcon size={16} />
                  </span>
                  <span className="more-tools-tab-copy">
                    <strong>{item.shortLabel}</strong>
                    <span>{item.eyebrow}</span>
                  </span>
                </button>
              );
            })}
          </div>

          <div className="more-tools-workbench-grid">
            <div className="more-tools-form-panel">
              <div className="more-tools-panel-head">
                <span className="more-tools-panel-kicker">{activeContent.eyebrow}</span>
                <h2>{activeContent.label}</h2>
                <p>{activeContent.detailCopy}</p>
              </div>

              <label className="more-tools-label" htmlFor="more-tools-input">
                {activeContent.inputLabel}
              </label>

              <input
                id="more-tools-input"
                className="more-tools-input"
                onChange={(event) => handleInputChange(event.target.value)}
                placeholder={activeContent.placeholder}
                type={activeContent.inputType}
                value={currentValue}
              />

              <div className="more-tools-live-note">
                <Activity aria-hidden="true" size={16} />
                <p>{liveNote}</p>
              </div>

              <div className="more-tools-example-block">
                <span className="more-tools-example-label">Quick examples</span>

                <div className="more-tools-example-list">
                  {activeContent.examples.map((example) => (
                    <button
                      key={example}
                      className="more-tools-example-chip"
                      onClick={() => handleInputChange(example)}
                      type="button"
                    >
                      {example}
                    </button>
                  ))}
                </div>
              </div>

              <div className="more-tools-action-row">
                <button
                  className="more-tools-scan-button"
                  disabled={scanState === 'checking' || !canScan}
                  onClick={handleScan}
                  type="button"
                >
                  <Play aria-hidden="true" fill="currentColor" />
                  <span>{scanState === 'checking' ? 'Scanning...' : 'Start scan'}</span>
                </button>

                <div className="more-tools-action-cluster">
                  {scanState === 'success' && (
                    <button
                      className="more-tools-download-button"
                      onClick={handleDownloadReport}
                      type="button"
                    >
                      <Download aria-hidden="true" size={16} />
                      <span>Download PDF</span>
                    </button>
                  )}

                  <button
                    className="more-tools-reset-button"
                    disabled={!currentValue && scanState === 'idle'}
                    onClick={handleReset}
                    type="button"
                  >
                    <RotateCcw aria-hidden="true" size={16} />
                    <span>Reset</span>
                  </button>
                </div>
              </div>

              <div className="more-tools-helper-row">
                <span className="more-tools-helper-badge">Live backend</span>
                <p>{activeContent.helperCopy}</p>
              </div>
            </div>

            <div className="more-tools-output-panel">
              <div className="more-tools-output-head">
                <span className="more-tools-output-badge">Result preview</span>
                <span className={`more-tools-output-status tone-${statusMeta.tone}`}>
                  {statusMeta.label}
                </span>
              </div>

              <div className="more-tools-output-state" aria-live="polite">
                <div
                  className={`more-tools-output-icon ${scanState === 'checking' ? 'is-scanning' : ''}`}
                  aria-hidden="true"
                >
                  {scanState === 'error' ? <AlertTriangle size={34} /> : scanState === 'success' ? <CheckCircle2 size={34} /> : <Shield size={34} />}
                </div>

                <p>
                  {scanState === 'success'
                    ? resultView?.title
                    : scanState === 'error'
                      ? 'Check could not complete'
                      : activeContent.idleTitle}
                </p>
                <span>
                  {scanState === 'success'
                    ? resultView?.copy
                    : scanState === 'error'
                      ? scanError
                      : activeContent.idleCopy}
                </span>
              </div>

              {scanState === 'checking' && (
                <div className="more-tools-progress-list" aria-label="Scan stages">
                  {activeContent.checklist.map((item) => (
                    <article className="more-tools-progress-item" key={item}>
                      <span className="more-tools-progress-mark" aria-hidden="true" />
                      <div>
                        <strong>{item}</strong>
                        <span>Analyzing backend-backed security signals for this stage.</span>
                      </div>
                    </article>
                  ))}
                </div>
              )}

              {scanState === 'error' && (
                <div className="more-tools-insight-list">
                  <article className="more-tools-insight-card tone-watch" role="alert">
                    <div className="more-tools-insight-head">
                      <AlertTriangle aria-hidden="true" size={16} />
                      <strong>Request failed</strong>
                    </div>
                    <p>{scanError || 'The backend could not complete the check.'}</p>
                  </article>
                </div>
              )}

              {scanState === 'idle' && (
                <>
                  <div className="more-tools-output-tags">
                    {activeContent.signalTags.map((tag) => (
                      <span className="more-tools-output-tag" key={tag}>
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="more-tools-summary-grid is-preview">
                    {activeContent.summary.map((item) => (
                      <article className={`more-tools-summary-card tone-${item.tone}`} key={item.label}>
                        <strong>{item.value}</strong>
                        <span>{item.label}</span>
                        <small>{item.note}</small>
                      </article>
                    ))}
                  </div>
                </>
              )}

              {scanState === 'success' && (
                <>
                  <div className="more-tools-summary-grid">
                    {resultView.summary.map((item) => (
                      <article className={`more-tools-summary-card tone-${item.tone}`} key={item.label}>
                        <strong>{item.value}</strong>
                        <span>{item.label}</span>
                        <small>{item.note}</small>
                      </article>
                    ))}
                  </div>

                  <div className="more-tools-output-tags">
                    {resultView.tags.map((tag) => (
                      <span className="more-tools-output-tag" key={tag}>
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="more-tools-insight-list">
                    {resultView.insights.map((item) => (
                      <article className={`more-tools-insight-card tone-${item.tone}`} key={item.title}>
                        <div className="more-tools-insight-head">
                          {item.tone === 'safe' ? (
                            <ShieldCheck aria-hidden="true" size={16} />
                          ) : (
                            <AlertTriangle aria-hidden="true" size={16} />
                          )}
                          <strong>{item.title}</strong>
                        </div>
                        <p>{item.copy}</p>
                      </article>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="more-tools-lanes-section">
        <div className="more-tools-lanes-shell">
          <div className="more-tools-lanes-copy">
            <span className="more-tools-section-badge">Where it fits</span>
            <h2>Quick checks before deeper security workflows</h2>
            <p>
              This page works best as a first-pass utility layer: fast enough for onboarding and clean enough
              to guide users toward more advanced scans when needed.
            </p>
          </div>

          <div className="more-tools-lanes-grid">
            {workflowCards.map((item) => {
              const Icon = item.icon;

              return (
                <article className="more-tools-lane-card" key={item.title}>
                  <span className="more-tools-lane-icon" aria-hidden="true">
                    <Icon size={18} />
                  </span>
                  <h3>{item.title}</h3>
                  <p>{item.copy}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section className="more-tools-roadmap-section">
        <div className="more-tools-roadmap">
          <div className="more-tools-roadmap-badge">
            <span className="more-tools-roadmap-dot" aria-hidden="true" />
            <span>More tools coming soon</span>
          </div>

          <h2>We can push this toolkit further</h2>
          <p>
            The current page is now stronger as a product surface, but it also sets up a cleaner path for
            deeper checks, more realistic telemetry, and broader utility coverage later.
          </p>

          <div className="more-tools-roadmap-grid">
            {roadmapCards.map((item) => {
              const Icon = item.icon;

              return (
                <article className="more-tools-roadmap-card" key={item.title}>
                  <span className="more-tools-roadmap-icon" aria-hidden="true">
                    <Icon size={18} />
                  </span>
                  <h3>{item.title}</h3>
                  <p>{item.copy}</p>
                </article>
              );
            })}
          </div>

          <div className="more-tools-stats-panel">
            {statItems.map((item) => (
              <article className="more-tools-stat" key={item.label}>
                <strong>{item.value}</strong>
                <span>{item.label}</span>
              </article>
            ))}
          </div>
        </div>
      </section>

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(MoreToolsPage);
