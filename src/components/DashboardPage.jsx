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
  Mail,
  MoreVertical,
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
import AuthNavbar from './AuthNavbar';
import './DashboardPage.css';

const SIDEBAR_ITEMS = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'reports', label: 'Reports', icon: FileText },
  { key: 'settings', label: 'Settings', icon: Settings },
  { key: 'profile', label: 'Profile', icon: User },
];

const DASHBOARD_OVERVIEW_CARDS = [
  { label: 'Total Scans', value: '135', subtitle: 'Completed this month', icon: Activity },
  { label: 'Critical Issues', value: '23', subtitle: 'Need immediate remediation', icon: Bell },
  { label: 'Vulnerabilities Found', value: '342', subtitle: 'Across latest assessments', icon: AlertTriangle },
  { label: 'Last Scan', value: '2h ago', subtitle: 'example.com', icon: Clock3 },
];

const REPORT_OVERVIEW_CARDS = [
  {
    label: 'Total Reports',
    value: '6',
    subtitle: 'Generated reports',
    icon: FileText,
    tone: 'primary',
  },
  {
    label: 'Total Vulnerabilities',
    value: '82',
    subtitle: 'Issues detected',
    icon: AlertTriangle,
    tone: 'medium',
  },
  {
    label: 'Critical Issues',
    value: '22',
    subtitle: 'Require immediate action',
    icon: Bell,
    tone: 'high',
  },
  {
    label: 'Average Risk Score',
    value: '70',
    subtitle: 'Across all scans',
    icon: Activity,
    tone: 'low',
  },
];

const REPORT_RESULT_CARDS = [
  {
    id: 'RPT-2025-002',
    riskLabel: 'Medium Risk',
    riskTone: 'medium',
    url: 'https://myapp.io',
    reference: 'AF2587E',
    date: '2025-01-15',
    time: '14:32',
    duration: '2m 45s',
    score: '72/100',
    scoreTone: 'medium',
    breakdown: [
      { label: 'Critical', value: 3, tone: 'critical' },
      { label: 'High', value: 4, tone: 'high' },
      { label: 'Medium', value: 3, tone: 'medium' },
      { label: 'Low', value: 2, tone: 'low' },
    ],
  },
  {
    id: 'RPT-2025-002',
    riskLabel: 'Low Risk',
    riskTone: 'low',
    url: 'https://myapp.io',
    reference: 'AF2587E',
    date: '2025-01-14',
    time: '08:15',
    duration: '3m 12s',
    score: '58/100',
    scoreTone: 'low',
    breakdown: [
      { label: 'Critical', value: 1, tone: 'critical' },
      { label: 'High', value: 2, tone: 'high' },
      { label: 'Medium', value: 3, tone: 'medium' },
      { label: 'Low', value: 2, tone: 'low' },
    ],
  },
  {
    id: 'RPT-2025-002',
    riskLabel: 'High Risk',
    riskTone: 'high',
    url: 'https://myapp.io',
    reference: 'AF2587E',
    date: '2025-01-10',
    time: '10:30',
    duration: '3m 45s',
    score: '84/100',
    scoreTone: 'high',
    breakdown: [
      { label: 'Critical', value: 6, tone: 'critical' },
      { label: 'High', value: 6, tone: 'high' },
      { label: 'Medium', value: 4, tone: 'medium' },
      { label: 'Low', value: 3, tone: 'low' },
    ],
  },
  {
    id: 'RPT-2025-002',
    riskLabel: 'Low Risk',
    riskTone: 'low',
    url: 'https://myapp.io',
    reference: 'AF2587E',
    date: '2025-01-14',
    time: '08:15',
    duration: '3m 12s',
    score: '58/100',
    scoreTone: 'low',
    breakdown: [
      { label: 'Critical', value: 1, tone: 'critical' },
      { label: 'High', value: 2, tone: 'high' },
      { label: 'Medium', value: 3, tone: 'medium' },
      { label: 'Low', value: 2, tone: 'low' },
    ],
  },
  {
    id: 'RPT-2025-002',
    riskLabel: 'Medium Risk',
    riskTone: 'medium',
    url: 'https://myapp.io',
    reference: 'AF2587E',
    date: '2025-01-15',
    time: '14:32',
    duration: '2m 45s',
    score: '72/100',
    scoreTone: 'medium',
    breakdown: [
      { label: 'Critical', value: 3, tone: 'critical' },
      { label: 'High', value: 4, tone: 'high' },
      { label: 'Medium', value: 3, tone: 'medium' },
      { label: 'Low', value: 2, tone: 'low' },
    ],
  },
  {
    id: 'RPT-2025-002',
    riskLabel: 'High Risk',
    riskTone: 'high',
    url: 'https://myapp.io',
    reference: 'AF2587E',
    date: '2025-01-10',
    time: '10:30',
    duration: '3m 45s',
    score: '84/100',
    scoreTone: 'high',
    breakdown: [
      { label: 'Critical', value: 6, tone: 'critical' },
      { label: 'High', value: 6, tone: 'high' },
      { label: 'Medium', value: 4, tone: 'medium' },
      { label: 'Low', value: 3, tone: 'low' },
    ],
  },
];

const REPORT_HISTORY_ITEMS = [
  { index: 1, url: 'https://example.com', timestamp: '2025-01-15 at 14:32', vulnerabilities: 12, score: '72/100', scoreTone: 'medium' },
  { index: 2, url: 'https://example.com', timestamp: '2025-01-15 at 14:32', vulnerabilities: 8, score: '58/100', scoreTone: 'low' },
  { index: 3, url: 'https://example.com', timestamp: '2025-01-15 at 14:32', vulnerabilities: 23, score: '91/100', scoreTone: 'high' },
  { index: 4, url: 'https://example.com', timestamp: '2025-01-15 at 14:32', vulnerabilities: 5, score: '35/100', scoreTone: 'low' },
  { index: 5, url: 'https://example.com', timestamp: '2025-01-15 at 14:32', vulnerabilities: 15, score: '78/100', scoreTone: 'medium' },
  { index: 6, url: 'https://example.com', timestamp: '2025-01-15 at 14:32', vulnerabilities: 15, score: '78/100', scoreTone: 'medium' },
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

const RECENT_SCANS = [
  { target: 'Example.com', status: 'Completed', issue: 'XSS,CSRF', risk: 'High', date: '19-11-2025' },
  { target: 'testsite.io', status: 'Completed', issue: 'SQL Injection', risk: 'Critical', date: '25-11-2025' },
  { target: 'Webapp.dev', status: 'In Progress', issue: '-', risk: '-', date: '28-11-2025' },
  { target: 'Myapp.com', status: 'Completed', issue: 'Weak SSL', risk: 'Medium', date: '29-11-2025' },
  { target: 'Myapp.com', status: 'Completed', issue: 'None', risk: 'Low', date: '29-11-2025' },
  { target: 'Myapp.com', status: 'Failed', issue: '-', risk: '-', date: '29-11-2025' },
];

const DASHBOARD_SCAN_TYPES = [
  { key: 'quick', label: 'Quick Scan' },
  { key: 'deep', label: 'Deep Scan' },
];

const ADVANCED_SCAN_MODE_CARDS = [
  {
    key: 'quick',
    title: 'Quick Scan Settings',
    description: 'Fast overview scanning. Lightweight and safe. Ideal for quick checks.',
    icon: Zap,
  },
  {
    key: 'deep',
    title: 'Deep Scan Settings',
    description: 'Full vulnerability scanning with advanced tools. Slower but more accurate.',
    icon: Shield,
  },
];

const ADVANCED_QUICK_BASIC_OPTIONS = [
  { key: 'qBasicPort', label: 'Basic Port Scan (Top 100 ports)', icon: Wifi },
  { key: 'qFingerprint', label: 'Technology Fingerprinting (WhatWeb basic)', icon: Sparkles },
  { key: 'qServerInfo', label: 'Detect Web Server Information', icon: Globe },
  { key: 'qHeaders', label: 'Check Security Headers', icon: Shield },
  { key: 'qLightDirectory', label: 'Light Directory Scan (Common paths only)', icon: FileText },
];

const ADVANCED_DEEP_PORT_OPTIONS = [
  { key: 'dFullPort', label: 'Full Port Scan (1-65535)', icon: Wifi },
  { key: 'dAggressiveNmap', label: 'Aggressive Nmap Scan (Version detection + OS detect)', icon: Activity },
  { key: 'dNseScripts', label: 'Run NSE Vulnerability Scripts', icon: Settings },
];

const ADVANCED_DEEP_WEB_OPTIONS = [
  { key: 'dNikto', label: 'Nikto Full Scan', icon: Globe },
  { key: 'dSqlMap', label: 'SQL Injection Testing (SQLmap)', icon: AlertTriangle },
  { key: 'dXsstrike', label: 'XSS Testing (XSStrike)', icon: Zap },
  { key: 'dDirsearch', label: 'Full Directory Enumeration (Dirsearch full wordlist)', icon: FileText },
  { key: 'dOutdated', label: 'Detect Outdated Components (CVE Lookup)', icon: Bell },
];

const ADVANCED_DEEP_RISK_OPTIONS = [
  { key: 'dBruteforce', label: 'Login Brute-force (Hydra)', icon: User },
  { key: 'dSslTls', label: 'Full SSL/TLS Inspection', icon: Shield },
];

const ADVANCED_SCAN_DEFAULTS = {
  qBasicPort: true,
  qFingerprint: true,
  qServerInfo: true,
  qHeaders: true,
  qLightDirectory: false,
  dFullPort: true,
  dAggressiveNmap: true,
  dNseScripts: true,
  dNikto: true,
  dSqlMap: true,
  dXsstrike: true,
  dDirsearch: false,
  dOutdated: true,
  dBruteforce: false,
  dSslTls: true,
};

const AI_INSIGHT_STATS = [
  { label: 'Critical Issues Detected', value: '23' },
  { label: 'High-Risk Issues Detected', value: '28' },
  { label: 'Medium-Risk Issues Detected', value: '215' },
  { label: 'Low-Risk Issues Detected', value: '400' },
];

const AI_SUMMARY_LINES = [
  'Based on comprehensive analysis of your web application, our AI security engine has identified 342 total vulnerabilities across multiple categories. The scan detected 23 critical issues that pose immediate security risks and require urgent attention.',
  'The most severe vulnerabilities include SQL injection points in authentication modules, weak session management implementations, and missing security headers that could expose your application to various attack vectors. These critical issues could potentially allow unauthorized database access and session hijacking if exploited.',
  'Additionally, the analysis revealed 87 high-risk issues primarily related to cross-site scripting vulnerabilities, insecure direct object references, and outdated cryptographic configurations. Medium and low-risk findings include missing input validation, insufficient rate limiting, and various security best practice violations.',
  'The AI recommends prioritizing remediation of critical and high-severity vulnerabilities within the next deployment cycle. Detailed step-by-step remediation guidance is provided for each detected issue to assist your development team in implementing secure fixes.',
  "With proper implementation of the recommended security measures, your application's security posture is estimated to improve significantly, reducing the overall risk score from 72/100 to an anticipated 90/100 or higher.",
];

const RECOMMENDATION_ITEMS = [
  {
    title: 'SQL Injection Vulnerability in Login Form',
    severity: 'Critical',
    description:
      'The login form does not properly sanitize user input, allowing potential SQL injection attacks that could compromise the entire database and expose sensitive user information.',
    aiRecommendation:
      'Implement parameterized queries for all database operations. Replace string concatenation with prepared statements and add comprehensive input validation middleware to sanitize all user inputs before processing.',
    steps: [
      'Review all database query implementations in authentication modules',
      'Replace dynamic SQL queries with parameterized prepared statements',
      'Implement server-side input validation and sanitization',
      'Add rate limiting to authentication endpoints to prevent brute force attacks',
      'Test thoroughly with SQL injection payloads to verify fixes',
    ],
  },
  {
    title: 'Missing Security Headers Configuration',
    severity: 'High',
    description:
      'Critical HTTP security headers are not configured on the web server, leaving the application vulnerable to various client-side attacks including XSS, clickjacking, and MIME-type sniffing attacks.',
    aiRecommendation:
      'Configure all essential security headers in your web server or application middleware. This includes Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security headers to protect against common web vulnerabilities.',
    steps: [
      'Add Content-Security-Policy header with strict directives',
      'Enable X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking',
      'Configure X-Content-Type-Options: nosniff header',
      'Implement Strict-Transport-Security with appropriate max-age value',
      'Add Referrer-Policy and Permissions-Policy headers for additional protection',
    ],
  },
];

const THREAT_INTELLIGENCE_ITEMS = [
  {
    cve: 'CVE-2025-1234',
    severity: 'High',
    description: 'Remote code execution vulnerability in popular web framework affecting multiple versions.',
  },
  {
    cve: 'CVE-2025-5678',
    severity: 'Critical',
    description: 'Authentication bypass vulnerability discovered in content management systems.',
  },
  {
    cve: 'CVE-2025-9012',
    severity: 'Medium',
    description: 'Cross-site scripting vulnerability found in widely used JavaScript libraries.',
  },
];

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

const VULNERABILITY_DISTRIBUTION = [
  { label: 'Low', value: 87, color: 'var(--accent-green)' },
  { label: 'Medium', value: 80, color: 'var(--accent-yellow)' },
  { label: 'High', value: 65, color: 'var(--accent-coral)' },
  { label: 'Critical', value: 25, color: 'var(--accent-red)' },
];

const SCAN_ACTIVITY_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const SCAN_ACTIVITY_VALUES = [45, 70, 52, 83, 61, 76, 68];
const SCAN_ACTIVITY_SUMMARY_STATS = [
  { label: 'Average', value: '66 Scans' },
  { label: 'Total', value: '88 Scans' },
  { label: 'Peak', value: '465 Scans' },
];

const PROFILE_SCAN_STATS = [
  { label: 'Total Scans', value: '247' },
  { label: 'Last Scan', value: 'Today' },
  { label: 'Critical issues', value: '12' },
];

const PROFILE_SCAN_ROWS = [
  { website: 'EXAMPLE.COM', risk: 'High', date: 'Dec 9, 2025' },
  { website: 'EXAMPLE.COM', risk: 'Critical', date: 'Dec 9, 2025' },
  { website: 'EXAMPLE.COM', risk: 'Medium', date: 'Dec 9, 2025' },
  { website: 'EXAMPLE.COM', risk: 'Low', date: 'Dec 9, 2025' },
];

const toDashOffset = (percent) => {
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  return circumference - (circumference * percent) / 100;
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

function DashboardPage({ onNavigate, currentPage, initialSection }) {
  const [activeSection, setActiveSection] = useState(initialSection || 'dashboard');
  const [scanUrl, setScanUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isAdvancedScanOpen, setIsAdvancedScanOpen] = useState(false);
  const [advancedScanMode, setAdvancedScanMode] = useState('quick');
  const [advancedFastMode, setAdvancedFastMode] = useState(true);
  const [advancedScanChecks, setAdvancedScanChecks] = useState(() => ({ ...ADVANCED_SCAN_DEFAULTS }));
  const [dashboardScanTypes, setDashboardScanTypes] = useState({
    quick: true,
    deep: true,
  });
  const [reportSearchQuery, setReportSearchQuery] = useState('');
  const [profileTwoFactorEnabled, setProfileTwoFactorEnabled] = useState(true);
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
  const scanTimerRef = useRef(null);

  useEffect(
    () => () => {
      if (scanTimerRef.current) {
        clearTimeout(scanTimerRef.current);
      }
    },
    [],
  );

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

  const navigateToSection = (section) => {
    setActiveSection(section);
    if (!onNavigate) return;
    if (section === 'dashboard') {
      onNavigate('dashboard');
      return;
    }
    onNavigate(section);
  };

  const startScan = () => {
    const value = scanUrl.trim();
    if (!value || isScanning) return;
    if (scanTimerRef.current) {
      clearTimeout(scanTimerRef.current);
    }
    setIsScanning(true);
    scanTimerRef.current = setTimeout(() => {
      setIsScanning(false);
      scanTimerRef.current = null;
    }, 2200);
  };

  const toggleDashboardScanType = (key) => {
    setDashboardScanTypes((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleAdvancedScanCheck = (key) => {
    setAdvancedScanChecks((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleNotification = (key) => {
    setNotificationPrefs((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleReportPref = (key) => {
    setReportPrefs((prev) => ({ ...prev, [key]: !prev[key] }));
  };

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
      <section className="db-advanced-modal" role="dialog" aria-modal="true" aria-labelledby="advanced-scan-title">
        <div className="db-advanced-head">
          <div>
            <h2 id="advanced-scan-title">Advanced Scan Settings</h2>
            <p>Customize your scanning behavior based on depth and performance.</p>
          </div>
          <button
            type="button"
            className="db-advanced-close"
            aria-label="Close advanced scan settings"
            onClick={() => setIsAdvancedScanOpen(false)}
          >
            <X size={14} />
          </button>
        </div>

        <div className={`db-advanced-body ${advancedScanMode === 'quick' ? 'is-quick' : 'is-deep'}`}>
          <div className="db-advanced-mode-grid">
            {ADVANCED_SCAN_MODE_CARDS.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`db-advanced-mode-card ${advancedScanMode === item.key ? 'active' : ''}`}
                onClick={() => setAdvancedScanMode(item.key)}
              >
                <span className="db-advanced-mode-icon">
                  <item.icon size={13} />
                </span>
                <span className="db-advanced-mode-copy">
                  <strong>{item.title}</strong>
                  <small>{item.description}</small>
                </span>
              </button>
            ))}
          </div>

          {advancedScanMode === 'quick' ? (
            <>
              <article className="db-advanced-card">
                <div className="db-advanced-card-head">
                  <Globe size={13} />
                  <h3>Basic Scan Options</h3>
                </div>
                <div className="db-advanced-check-list">
                  {ADVANCED_QUICK_BASIC_OPTIONS.map((option) => (
                    <label key={option.key} className="db-advanced-check">
                      <input
                        type="checkbox"
                        checked={advancedScanChecks[option.key]}
                        onChange={() => toggleAdvancedScanCheck(option.key)}
                      />
                      <span className="db-advanced-checkmark" />
                      <span className="db-advanced-check-label">
                        <option.icon size={11} />
                        <span>{option.label}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </article>

              <article className="db-advanced-card">
                <div className="db-advanced-card-head">
                  <Zap size={13} />
                  <h3>Performance</h3>
                </div>
                <div className="db-advanced-switch-row">
                  <div>
                    <strong>Enable Fast Mode</strong>
                    <p>Skip delays and heavy scripts</p>
                  </div>
                  <label className="db-advanced-switch">
                    <input
                      type="checkbox"
                      checked={advancedFastMode}
                      onChange={() => setAdvancedFastMode((prev) => !prev)}
                    />
                    <span className="db-advanced-switch-track" />
                  </label>
                </div>
              </article>

              <div className="db-advanced-note db-advanced-note-warning">
                <AlertTriangle size={16} />
                <div>
                  <strong>Note:</strong>
                  <p>Quick Scan provides basic insights only and may miss deeper vulnerabilities.</p>
                </div>
              </div>
            </>
          ) : (
            <>
              <article className="db-advanced-card db-advanced-card-port">
                <div className="db-advanced-card-head">
                  <Wifi size={13} />
                  <h3>Port &amp; Network Scanning</h3>
                </div>
                <div className="db-advanced-check-list">
                  {ADVANCED_DEEP_PORT_OPTIONS.map((option) => (
                    <label key={option.key} className="db-advanced-check">
                      <input
                        type="checkbox"
                        checked={advancedScanChecks[option.key]}
                        onChange={() => toggleAdvancedScanCheck(option.key)}
                      />
                      <span className="db-advanced-checkmark" />
                      <span className="db-advanced-check-label">
                        <option.icon size={11} />
                        <span>{option.label}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </article>

              <article className="db-advanced-card db-advanced-card-web">
                <div className="db-advanced-card-head">
                  <Globe size={13} />
                  <h3>Web Vulnerability Testing</h3>
                </div>
                <div className="db-advanced-check-list">
                  {ADVANCED_DEEP_WEB_OPTIONS.map((option) => (
                    <label key={option.key} className="db-advanced-check">
                      <input
                        type="checkbox"
                        checked={advancedScanChecks[option.key]}
                        onChange={() => toggleAdvancedScanCheck(option.key)}
                      />
                      <span className="db-advanced-checkmark" />
                      <span className="db-advanced-check-label">
                        <option.icon size={11} />
                        <span>{option.label}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </article>

              <article className="db-advanced-card danger">
                <div className="db-advanced-card-head danger">
                  <AlertTriangle size={13} />
                  <h3>Optional Risky Tests</h3>
                </div>
                <div className="db-advanced-check-list">
                  {ADVANCED_DEEP_RISK_OPTIONS.map((option) => (
                    <label key={option.key} className="db-advanced-check danger">
                      <input
                        type="checkbox"
                        checked={advancedScanChecks[option.key]}
                        onChange={() => toggleAdvancedScanCheck(option.key)}
                      />
                      <span className="db-advanced-checkmark" />
                      <span className="db-advanced-check-label">
                        <option.icon size={11} />
                        <span>{option.label}</span>
                      </span>
                    </label>
                  ))}
                </div>

                <div className="db-advanced-note db-advanced-note-danger">
                  <AlertTriangle size={16} />
                  <div>
                    <strong>Warning:</strong>
                    <p>These checks may generate significant traffic. Use with permission.</p>
                  </div>
                </div>
              </article>
            </>
          )}
        </div>

        <div className="db-advanced-actions">
          <button type="button" className="db-mini-btn db-advanced-cancel" onClick={() => setIsAdvancedScanOpen(false)}>
            Cancel
          </button>
          <button type="button" className="db-primary-btn db-advanced-apply" onClick={() => setIsAdvancedScanOpen(false)}>
            Apply Settings
          </button>
        </div>
      </section>
    </div>
  );

  const renderDashboardSection = () => {
    const linePoints = getLinePoints(SCAN_ACTIVITY_VALUES, 360, 160, 16);
    const linePath = linePoints
      .map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`)
      .join(' ');
    const distributionTotal = VULNERABILITY_DISTRIBUTION.reduce((sum, item) => sum + item.value, 0);
    let segmentStart = 0;
    const donutStops = VULNERABILITY_DISTRIBUTION.map((item) => {
      const segmentSize = (item.value / distributionTotal) * 100;
      const segmentEnd = segmentStart + segmentSize;
      const stop = `${item.color} ${segmentStart.toFixed(2)}% ${segmentEnd.toFixed(2)}%`;
      segmentStart = segmentEnd;
      return stop;
    }).join(', ');

    return (
      <div className="db-dashboard-layout">
        <section className="db-overview-grid">
          {DASHBOARD_OVERVIEW_CARDS.map((card) => (
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
                  strokeDashoffset={toDashOffset(72)}
                />
              </svg>
              <strong>72%</strong>
            </div>
            <p className="db-risk-copy">
              Overall security level estimate
              <br />
              Moderate risk detected
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
              onChange={(event) => setScanUrl(event.target.value)}
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
            {RECENT_SCANS.map((row, index) => (
              <div key={`${row.target}-${row.date}-${index}`} className="db-table-row">
                <span className="db-scan-target">{row.target}</span>
                <span className={`db-chip ${row.status.toLowerCase().replace(/\s+/g, '-')}`}>
                  <span>{row.status}</span>
                </span>
                <span>{row.issue}</span>
                <span className={`db-risk ${row.risk.toLowerCase()}`}>{row.risk}</span>
                <span>{row.date}</span>
                <button type="button" className="db-action-btn" aria-label={`More actions for ${row.target}`}>
                  <MoreVertical size={14} />
                </button>
              </div>
            ))}
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
            {AI_INSIGHT_STATS.map((item) => (
              <article className="db-insight-item" key={item.label}>
                <p>{item.label}</p>
                <strong>{item.value}</strong>
              </article>
            ))}
          </div>

          <p className="db-insight-copy">
            The AI security engine has detected 342 total vulnerabilities across your web application. Analysis
            reveals 23 critical security issues including SQL injection vulnerabilities and authentication weaknesses
            that require immediate attention. Detailed recommendations for manual remediation are available in the
            comprehensive AI report below.
          </p>

          <button type="button" className="db-secondary-btn db-report-btn">
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
            {AI_SUMMARY_LINES.map((line) => (
              <p key={line}>{line}</p>
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
            {RECOMMENDATION_ITEMS.map((item) => (
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
                  <button type="button" className="db-mini-btn db-mini-btn-flat">View Full Details</button>
                  <button type="button" className="db-mini-btn db-mini-btn-flat">Export Report</button>
                  <button type="button" className="db-mini-btn db-mini-btn-flat">Mark as Reviewed</button>
                </div>
              </article>
            ))}
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
            {THREAT_INTELLIGENCE_ITEMS.map((item) => (
              <article key={item.cve} className="db-threat-item">
                <div className="db-threat-top">
                  <h3>
                    <Shield size={14} />
                    {item.cve}
                  </h3>
                  <span className={`db-risk ${item.severity.toLowerCase()}`}>{item.severity}</span>
                </div>
                <p>{item.description}</p>
                <button type="button" className="db-mini-btn db-threat-btn">
                  View More
                  <ChevronRight size={14} />
                </button>
              </article>
            ))}
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
                {VULNERABILITY_DISTRIBUTION.map((item) => (
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
                {SCAN_ACTIVITY_DAYS.map((day) => (
                  <span key={day}>{day}</span>
                ))}
              </div>
            </div>

            <div className="db-line-stats">
              {SCAN_ACTIVITY_SUMMARY_STATS.map((item) => (
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
    const filteredReportCards = REPORT_RESULT_CARDS.filter((card) => (
      !normalizedQuery
      || [card.id, card.url, card.reference, card.riskLabel].some((value) => value.toLowerCase().includes(normalizedQuery))
    ));
    const filteredHistoryItems = REPORT_HISTORY_ITEMS.filter((item) => (
      !normalizedQuery
      || [`${item.index}`, item.url, item.timestamp, `${item.vulnerabilities}`, item.score]
        .some((value) => value.toLowerCase().includes(normalizedQuery))
    ));

    return (
      <div className="db-reports-layout">
        <section className="db-reports-hero">
          <h1>Security Reports</h1>
          <p>View and download all your vulnerability scan reports</p>
        </section>

        <section className="db-reports-stats-grid">
          {REPORT_OVERVIEW_CARDS.map((card) => (
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

                <button type="button" className="db-report-card-download" aria-label={`Download ${card.id}`}>
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
                  <button type="button" className="db-reports-history-download" aria-label={`Download history row ${item.index}`}>
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
            <p>Showing 5 of 17 scans</p>
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
            <select id="settings-language" defaultValue="English (US)" className="db-settings-select">
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
            <select id="settings-timezone" defaultValue="UTC (GMT+0:00)" className="db-settings-select">
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
                  onChange={() => setScanMode(option.key)}
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
            <User size={54} />
          </div>

          <div className="db-user-profile-summary-copy">
            <h2>Tyler Durden</h2>
            <p>Security Analyst</p>

            <div className="db-user-profile-summary-meta">
              <span>
                <Mail size={14} />
                Tyler_Dureden@gmail.com
              </span>
              <span>
                <CalendarDays size={14} />
                Member Since December 2025
              </span>
            </div>
          </div>

          <button type="button" className="db-user-profile-action-btn">
            <Pencil size={13} />
            Edit Profile
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

          <button type="button" className="db-user-profile-action-btn">
            <Pencil size={13} />
            Edit Info
          </button>
        </div>

        <div className="db-user-profile-info-grid">
          <label className="db-user-profile-field">
            <span>Username</span>
            <input className="db-user-profile-input" value="Tyler_Durden_Pentest" readOnly />
          </label>

          <label className="db-user-profile-field">
            <span>Email Address</span>
            <input className="db-user-profile-input" value="Tyler_Durden@Gmail.com" readOnly />
          </label>

          <label className="db-user-profile-field">
            <span>Phone Number</span>
            <input className="db-user-profile-input" value="+1 (555) 123-4567" readOnly />
          </label>

          <label className="db-user-profile-field">
            <span>Last Login</span>
            <input className="db-user-profile-input" value="December 9,2025 - 9:10 PM" readOnly />
          </label>

          <label className="db-user-profile-field full">
            <span>Bio</span>
            <textarea
              className="db-user-profile-input db-user-profile-textarea"
              value="Experienced security analyst specializing in web vulnerability assessment and penetration testing. Passionate about identifying and mitigating security risks."
              readOnly
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
              <input className="db-user-profile-input" type="password" placeholder="Enter Current Password" readOnly />
            </label>

            <label className="db-user-profile-field">
              <span>New Password</span>
              <input className="db-user-profile-input" type="password" placeholder="Enter New Password" readOnly />
            </label>

            <label className="db-user-profile-field full">
              <span>Confirm New Password</span>
              <input className="db-user-profile-input" type="password" placeholder="Confirm new Password" readOnly />
            </label>
          </div>

          <button type="button" className="db-user-profile-action-btn primary">Update Password</button>
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
              onChange={() => setProfileTwoFactorEnabled((prev) => !prev)}
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
          {PROFILE_SCAN_STATS.map((item) => (
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
          {PROFILE_SCAN_ROWS.map((item, index) => (
            <div key={`${item.website}-${item.risk}-${index}`} className="db-user-profile-table-row">
              <span>{item.website}</span>
              <span className={`db-risk ${item.risk.toLowerCase()}`}>{item.risk}</span>
              <span>{item.date}</span>
            </div>
          ))}
        </div>
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
        <button type="button" className="db-user-profile-delete-btn">
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



