import {
  BarChart3,
  CalendarDays,
  ChevronDown,
  DollarSign,
  Download,
  FileText,
  LayoutDashboard,
  LogOut,
  Moon,
  PenSquare,
  Plus,
  Settings,
  Shield,
  Sun,
  Users,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { adminAPI } from '../services/api';
import { buildBrandedPdfBlob, downloadPdfBlob } from '../utils/pdfBuilder';
import './AdminDashboardPage.css';
import './AdminReportsPage.css';

const topNavItems = [
  { label: 'More Tools', route: 'tools' },
  { label: 'Security Awareness', route: 'awareness' },
  { label: 'Blog', route: 'blog' },
  { label: 'Admin Dashboard', route: 'admin-dashboard' },
];

const sidebarItems = [
  { id: 'admin-dashboard', label: 'Admin Dashboard', icon: LayoutDashboard, route: 'admin-dashboard' },
  { id: 'admin-team', label: 'Admin Team', icon: Shield, route: 'admin-team' },
  { id: 'users', label: 'Users', icon: Users, route: 'admin-users' },
  { id: 'reports', label: 'Reports', icon: FileText, route: 'admin-reports' },
  { id: 'web-edit', label: 'Web Edit', icon: PenSquare, route: 'admin-web-edit', expandable: true },
  { id: 'pricing', label: 'Pricing', icon: DollarSign, route: 'admin-pricing' },
  { id: 'settings', label: 'Settings', icon: Settings, route: 'admin-settings' },
];

const monthLabels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'];

function formatReportDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Recently generated';
  }

  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function buildMonthlyPoints(items, field) {
  const base = monthLabels.map((label) => ({ label, value: 0 }));

  items.forEach((item) => {
    const date = new Date(item.date);
    const monthIndex = Number.isNaN(date.getTime()) ? base.length - 1 : date.getMonth();
    const visibleIndex = Math.max(0, Math.min(base.length - 1, monthIndex));
    base[visibleIndex].value += Number(item[field] || 0);
  });

  return base.map((item) => ({
    ...item,
    value: item.value || 0,
  }));
}

function buildAdminReportPdf(report) {
  const score = Number(report.score || 0);
  const critical = Number(report.critical || 0);
  const vulnerabilities = Number(report.vulnerabilities || 0);
  const scans = Number(report.scanCount || 0);
  const findings = Array.isArray(report.findings) && report.findings.length
    ? report.findings
    : [
      'Review the latest admin metrics and investigate unusual changes.',
      'Prioritize critical and high risk issues before routine hardening work.',
      'Track ownership and remediation progress in the reports workspace.',
    ];

  return buildBrandedPdfBlob({
    title: report.title || 'Admin Security Snapshot',
    subtitle: report.subtitle || 'Generated from the Threat Hunters admin dashboard.',
    eyebrow: 'Admin Intelligence Report',
    generatedAt: formatReportDate(report.date),
    metrics: [
      { label: 'Score', value: `${score}/100`, fill: '#f3f0ff', valueColor: score >= 80 ? '#11855d' : '#b35d00' },
      { label: 'Critical', value: String(critical), fill: '#fff0f0', valueColor: '#c62828' },
      { label: 'Findings', value: String(vulnerabilities), fill: '#eef6ff', valueColor: '#0b66c3' },
      { label: 'Scans', value: String(scans), fill: '#eefbf7', valueColor: '#11855d' },
    ],
    sections: [
      {
        title: 'Executive Summary',
        body: `This report summarizes the latest admin security posture. The current security score is ${score}/100 with ${critical} critical signal(s) requiring immediate attention.`,
        accent: '#8b7cff',
      },
      {
        title: 'Key Findings',
        items: findings,
        accent: '#00b8d9',
      },
      {
        title: 'Recommended Actions',
        items: [
          'Assign owners for every critical item before the next review cycle.',
          'Disable risky accounts or hidden content from the admin dashboard when needed.',
          'Regenerate this report after remediation to confirm score movement and download history.',
        ],
        accent: '#18a058',
      },
    ],
  });
}

function LineChart({ points }) {
  const max = Math.max(...points.map((item) => item.value));
  const min = Math.min(...points.map((item) => item.value));
  const range = max - min || 1;
  const stepX = 260 / Math.max(points.length - 1, 1);

  const polylinePoints = points
    .map((item, index) => {
      const x = index * stepX;
      const y = 112 - ((item.value - min) / range) * 64;
      return `${x},${y.toFixed(2)}`;
    })
    .join(' ');

  return (
    <div className="admin-reports-linechart">
      <svg viewBox="0 0 260 124" preserveAspectRatio="none" aria-hidden="true">
        <polyline className="admin-reports-line" points={polylinePoints} />
        {points.map((item, index) => {
          const x = index * stepX;
          const y = 112 - ((item.value - min) / range) * 64;
          return <circle key={item.label} className="admin-reports-line-dot" cx={x} cy={y} r="2.6" />;
        })}
      </svg>
      <div className="admin-reports-axis">
        {points.map((item) => (
          <span key={item.label}>{item.label}</span>
        ))}
      </div>
    </div>
  );
}

function BarChart({ bars }) {
  const max = Math.max(...bars.map((item) => item.value), 1);

  return (
    <div className="admin-reports-barchart">
      <div className="admin-reports-bars">
        {bars.map((bar) => (
          <div key={bar.label} className="admin-reports-bar-group">
            <div className="admin-reports-bar-track">
              <div className="admin-reports-bar-fill" style={{ '--bar-height': `${(bar.value / max) * 100}%` }} />
            </div>
            <span>{bar.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AdminReportsPage({ onNavigate, onLogout, currentPage = 'admin-reports' }) {
  const { theme, toggleTheme } = useTheme();
  const [reportItems, setReportItems] = useState([]);
  const [notice, setNotice] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);

  const loadReports = useCallback(async () => {
    try {
      setNotice('Loading reports from backend...');
      const payload = await adminAPI.getReports();
      const items = payload.items || payload.reports || [];
      setReportItems(items.map((report) => ({ ...report, type: report.type || 'Scan' })));
      setNotice(items.length ? '' : 'No stored scan reports yet. User scans will appear here automatically.');
    } catch (error) {
      setReportItems([]);
      setNotice(error.message || 'Unable to load scan reports from the backend.');
    }
  }, []);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const computedStats = useMemo(() => {
    const totalReports = reportItems.length;
    const thisMonth = reportItems.filter((report) => {
      const date = new Date(report.date);
      const now = new Date();
      return !Number.isNaN(date.getTime()) && date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
    }).length;
    const downloads = reportItems.reduce((sum, report) => sum + Number(report.downloads || 0), 0);
    const avgScore = reportItems.length
      ? Math.round(reportItems.reduce((sum, report) => sum + Number(report.score || 0), 0) / reportItems.length)
      : 0;

    return [
      { label: 'Total Reports', value: String(totalReports), icon: FileText, tone: 'admin-tone-indigo' },
      { label: 'Generated This Month', value: String(thisMonth), icon: CalendarDays, tone: 'admin-tone-green' },
      { label: 'Downloads', value: String(downloads), icon: Download, tone: 'admin-tone-orange' },
      { label: 'Avg. Security Score', value: `${avgScore}/100`, icon: BarChart3, tone: 'admin-tone-indigo' },
    ];
  }, [reportItems]);

  const scanActivity = useMemo(() => buildMonthlyPoints(reportItems, 'scanCount'), [reportItems]);
  const vulnerabilityTrends = useMemo(
    () => buildMonthlyPoints(reportItems, 'vulnerabilities'),
    [reportItems],
  );

  const handleGenerateReport = async () => {
    try {
      setIsGenerating(true);
      setNotice('Generating a fresh admin report...');
      const report = await adminAPI.generateReport({
        title: 'Admin Security Snapshot',
        subtitle: 'Generated from the latest users, blog, pricing, and security metrics',
      });
      setReportItems((prev) => [report, ...prev.filter((item) => item.id !== report.id)]);
      setNotice('New admin report generated successfully.');
    } catch (error) {
      setNotice(error.message || 'Unable to generate a new report.');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownloadReport = async (report) => {
    try {
      const updatedReport = await adminAPI.recordReportDownload(report.id);
      setReportItems((prev) => prev.map((item) => (item.id === report.id ? updatedReport : item)));
      const safeTitle = report.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'admin-report';
      downloadPdfBlob(buildAdminReportPdf(updatedReport), `${safeTitle}.pdf`);
      setNotice('Professional PDF report downloaded and tracked.');
    } catch (error) {
      setNotice(error.message || 'Unable to download report.');
    }
  };

  return (
    <div className="admin-reports-page">
      <nav className="admin-nav">
        <div className="admin-nav-inner">
          <button type="button" className="admin-brand" onClick={() => onNavigate('admin-dashboard')}>
            <span className="admin-brand-icon">
              <Shield size={18} strokeWidth={2.2} />
            </span>
            <span className="admin-brand-text">Threat Hunters</span>
          </button>

          <div className="admin-nav-links">
            {topNavItems.map((item) => (
              <button
                key={item.label}
                type="button"
                className={`admin-nav-link ${item.route === currentPage ? 'is-active' : ''}`}
                onClick={() => onNavigate(item.route)}
              >
                {item.label}
              </button>
            ))}
          </div>

          <div className="admin-nav-actions">
            <button
              type="button"
              className="admin-nav-icon"
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <button type="button" className="admin-logout-btn" onClick={onLogout ?? (() => onNavigate('home'))}>
              <LogOut size={15} />
              <span>log out</span>
            </button>
          </div>
        </div>
      </nav>

      <div className="admin-shell">
        <aside className="admin-sidebar admin-card">
          <div className="admin-sidebar-group">
            {sidebarItems.map((item) => {
              const Icon = item.icon;
              const isActive = item.id === 'reports';

              return (
                <button
                  key={item.id}
                  type="button"
                  className={`admin-sidebar-link ${isActive ? 'is-active' : ''}`}
                  onClick={() => item.route && onNavigate(item.route)}
                  disabled={!item.route}
                >
                  <span className="admin-sidebar-link-icon">
                    <Icon size={16} />
                  </span>
                  <span>{item.label}</span>
                  {item.expandable && <ChevronDown size={14} className="admin-sidebar-link-chevron" />}
                </button>
              );
            })}
          </div>
        </aside>

        <main className="admin-main admin-reports-main">
          <section className="admin-reports-header">
            <div className="admin-section-head admin-cardless">
              <h1>Reports &amp; Analytics</h1>
              <p>Generate, view, and download security reports</p>
            </div>

            <button type="button" className="admin-reports-generate-btn" onClick={handleGenerateReport} disabled={isGenerating}>
              <Plus size={18} />
              <span>{isGenerating ? 'Generating...' : 'Generate New Report'}</span>
            </button>
          </section>

          {notice && <div className="admin-users-notice admin-card">{notice}</div>}

          <section className="admin-reports-stats">
            {computedStats.map((item) => {
              const Icon = item.icon;

              return (
                <article key={item.label} className="admin-reports-stat-card admin-card">
                  <span className={`admin-stat-icon ${item.tone}`}>
                    <Icon size={16} />
                  </span>
                  <strong>{item.value}</strong>
                  <p>{item.label}</p>
                </article>
              );
            })}
          </section>

          <section className="admin-reports-charts">
            <article className="admin-reports-chart-card admin-card">
              <div className="admin-section-head">
                <h2>Scan Activity</h2>
                <p>Monthly scan count over time</p>
              </div>
              <LineChart points={scanActivity} />
            </article>

            <article className="admin-reports-chart-card admin-card">
              <div className="admin-section-head">
                <h2>Vulnerability Trends</h2>
                <p>Vulnerabilities found per month</p>
              </div>
              <BarChart bars={vulnerabilityTrends} />
            </article>
          </section>

          <section className="admin-reports-list-panel admin-card">
            <div className="admin-section-head">
              <h2>Recent Reports</h2>
            </div>

            <div className="admin-reports-list">
              {reportItems.map((report) => (
                <article key={report.id || report.title} className="admin-reports-list-item">
                  <div className="admin-reports-item-left">
                    <span className="admin-reports-file-icon">
                      <FileText size={18} />
                    </span>

                    <div className="admin-reports-item-copy">
                      <strong>{report.title}</strong>
                      <p>{report.subtitle}</p>
                      <div className="admin-reports-item-meta">
                        <span>{formatReportDate(report.date)}</span>
                        <span className="admin-reports-dot">•</span>
                        <span>{report.size}</span>
                        <span className="admin-reports-dot">•</span>
                        <span className="admin-reports-filetype">PDF</span>
                      </div>
                    </div>
                  </div>

                  <button type="button" className="admin-reports-download-btn" onClick={() => handleDownloadReport(report)}>
                    <Download size={16} />
                    <span>Download</span>
                  </button>
                </article>
              ))}
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default AdminReportsPage;
