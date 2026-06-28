import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  DollarSign,
  Eye,
  FileText,
  LayoutDashboard,
  LogOut,
  Moon,
  PenSquare,
  SearchX,
  Settings,
  Shield,
  ShieldAlert,
  Sun,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { adminAPI, dashboardAPI } from '../services/api';
import { formatEgyptDate } from '../utils/egyptTime';
import './AdminDashboardPage.css';

const quickActions = [
  { title: 'Manage Users', subtitle: 'Review roles and access', icon: Users, route: 'admin-users', colors: ['#7b7eff', '#9ba8ff'] },
  { title: 'Edit Content', subtitle: 'Update the website copy', icon: PenSquare, route: 'admin-web-edit', colors: ['#00d9ff', '#6d7cff'] },
  { title: 'Open Reports', subtitle: 'Inspect exported reports', icon: FileText, route: 'admin-reports', colors: ['#34c759', '#00d9ff'] },
  { title: 'Open Settings', subtitle: 'Tune the admin workspace', icon: Settings, route: 'admin-settings', colors: ['#ff9500', '#ffd60a'] },
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

const topNavItems = [
  { label: 'More Tools', route: 'tools' },
  { label: 'Security Awareness', route: 'awareness' },
  { label: 'Blog', route: 'blog' },
  { label: 'Admin Dashboard', route: 'admin-dashboard' },
];

function getSparkPoints(values, max = Math.max(...values)) {
  const stepX = 84 / Math.max(values.length - 1, 1);

  return values
    .map((value, index) => {
      const x = index * stepX;
      const y = 24 - (value / max) * 18;
      return `${x},${y.toFixed(2)}`;
    })
    .join(' ');
}

function DualSparkline({ found, fixed }) {
  const max = Math.max(...found, ...fixed);

  return (
    <svg viewBox="0 0 84 32" aria-hidden="true">
      <polyline className="admin-mini-trend-line is-found-line" points={getSparkPoints(found, max)} />
      <polyline className="admin-mini-trend-line is-fixed-line" points={getSparkPoints(fixed, max)} />
    </svg>
  );
}

function getSeverityGradient(items) {
  let cursor = 0;
  const stops = items.map(({ color, value }) => {
    const start = cursor;
    cursor += value;
    return `${color} ${start}% ${cursor}%`;
  });

  return `conic-gradient(${stops.join(', ')})`;
}

function getVulnerabilityTone(count) {
  if (count === 0) return 'is-safe';
  if (count >= 5) return 'is-critical';
  return 'is-warning';
}

function getStatusTone(status) {
  if (status === 'Completed') return 'is-complete';
  if (status === 'Critical') return 'is-critical';
  return 'is-warning';
}

const MOJIBAKE_CODES = new Set([195, 194, 216, 217, 197, 65533]);

function looksCorruptedText(value) {
  const text = String(value || '').trim();
  if (!text) return false;
  const mojibakeHits = [...text].filter((char) => MOJIBAKE_CODES.has(char.charCodeAt(0))).length;
  const readableHits = (text.match(/[a-z0-9\u0600-\u06ff]/gi) || []).length;
  return mojibakeHits >= 2 || (mojibakeHits >= 1 && readableHits < 4);
}

function cleanDashboardText(value, fallback) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return !text || looksCorruptedText(text) ? fallback : text;
}

function summarizeAdminReports(reports) {
  const items = Array.isArray(reports) ? reports : [];
  const totalScans = items.length;
  const totalVulnerabilities = items.reduce((sum, report) => sum + Number(report.vulnerabilities || 0), 0);
  const critical = items.reduce((sum, report) => sum + Number(report.critical || 0), 0);
  const high = items.reduce((sum, report) => sum + Number(report.high || 0), 0);
  const medium = items.reduce((sum, report) => sum + Number(report.medium || 0), 0);
  const low = items.reduce((sum, report) => sum + Number(report.low || 0), 0);
  const uniqueTargets = new Set(
    items.map((report) => report.target || report.title).filter(Boolean),
  ).size;
  const vulnerableTargets = items.filter(
    (report) => Number(report.critical || 0) > 0 || Number(report.high || 0) > 0,
  ).length;
  const averageScore = totalScans
    ? Math.round(items.reduce((sum, report) => sum + Number(report.score || 0), 0) / totalScans)
    : 0;

  return {
    totalScans,
    totalVulnerabilities,
    critical,
    high,
    medium,
    low,
    uniqueTargets,
    vulnerableTargets,
    averageScore,
  };
}

function AdminDashboardPage({ onNavigate, onLogout, currentPage = 'admin-dashboard' }) {
  const [activeTab, setActiveTab] = useState('recent');
  const [dashboardStats, setDashboardStats] = useState([]);
  const [recentActivities, setRecentActivities] = useState([]);
  const [securityMetrics, setSecurityMetrics] = useState([]);
  const [adminReports, setAdminReports] = useState([]);
  const [dashboardError, setDashboardError] = useState('');
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
    let cancelled = false;

    const loadDashboardData = async () => {
      setDashboardLoading(true);
      setDashboardError('');

      const [statsResult, activitiesResult, metricsResult, reportsResult] = await Promise.allSettled([
          dashboardAPI.getStats(),
          dashboardAPI.getRecentActivities(),
          dashboardAPI.getSecurityMetrics(),
          adminAPI.getReports().catch(() => ({ items: [] })),
      ]);

      if (cancelled) {
        return;
      }

      setDashboardStats(
        statsResult.status === 'fulfilled' && Array.isArray(statsResult.value)
          ? statsResult.value
          : [],
      );
      setRecentActivities(
        activitiesResult.status === 'fulfilled' && Array.isArray(activitiesResult.value)
          ? activitiesResult.value
          : [],
      );
      setSecurityMetrics(
        metricsResult.status === 'fulfilled' && Array.isArray(metricsResult.value)
          ? metricsResult.value
          : [],
      );
      setAdminReports(
        reportsResult.status === 'fulfilled' && Array.isArray(reportsResult.value?.items)
          ? reportsResult.value.items
          : [],
      );

      const failedSections = [
        statsResult.status === 'rejected' ? 'stats' : null,
        activitiesResult.status === 'rejected' ? 'activity' : null,
        metricsResult.status === 'rejected' ? 'security metrics' : null,
        reportsResult.status === 'rejected' ? 'reports' : null,
      ].filter(Boolean);

      if (failedSections.length) {
        setDashboardError(`Some admin sections are still syncing: ${failedSections.join(', ')}.`);
      }

      setDashboardLoading(false);
    };

    loadDashboardData();

    return () => {
      cancelled = true;
    };
  }, []);

  const topMetrics = useMemo(() => {
    const reportSummary = summarizeAdminReports(adminReports);
    const icons = [ShieldAlert, AlertTriangle, SearchX, Activity];
    const tones = ['admin-tone-orange', 'admin-tone-red', 'admin-tone-cyan', 'admin-tone-indigo'];
    const sourceMetrics = dashboardStats.length
      ? dashboardStats
      : [
          {
            label: 'Overall Risk Score',
            value: `${reportSummary.averageScore}/100`,
            subtitle: reportSummary.totalScans
              ? 'Average score across stored backend reports'
              : 'No scans recorded yet',
          },
          {
            label: 'Active Vulnerabilities',
            value: String(reportSummary.totalVulnerabilities),
            subtitle: `Critical: ${reportSummary.critical} | High: ${reportSummary.high}`,
          },
          {
            label: 'Vulnerable Assets',
            value: `${reportSummary.vulnerableTargets} of ${reportSummary.uniqueTargets}`,
            subtitle: 'Targets with critical or high findings',
          },
          {
            label: 'Total Scans',
            value: String(reportSummary.totalScans),
            subtitle: reportSummary.totalScans
              ? 'Recovered from stored backend reports'
              : 'Waiting for the first completed scan',
          },
        ];

    return sourceMetrics.map((metric, index) => ({
      ...metric,
      detail: metric.subtitle || metric.detail || 'Live scan metric',
      icon: icons[index % icons.length],
      tone: tones[index % tones.length],
      change: null,
      breakdown: metric.subtitle ? [metric.subtitle] : [],
    }));
  }, [adminReports, dashboardStats]);

  const liveSecurityMetrics = useMemo(() => {
    const reportSummary = summarizeAdminReports(adminReports);
    const preferredLabels = ['Total Scans', 'Success Rate', 'Total Vulnerabilities', 'Avg. per Scan'];
    const selected = preferredLabels
      .map((label) => securityMetrics.find((metric) => metric.label === label))
      .filter(Boolean);
    const sourceMetrics = selected.length
      ? selected
      : [
          {
            label: 'Total Scans',
            value: String(reportSummary.totalScans),
            subtitle: 'Recovered from stored backend reports',
          },
          {
            label: 'Success Rate',
            value: reportSummary.totalScans ? '100%' : '0%',
            subtitle: 'Stored reports loaded successfully',
          },
          {
            label: 'Total Vulnerabilities',
            value: String(reportSummary.totalVulnerabilities),
            subtitle: 'Summed across stored admin-visible reports',
          },
          {
            label: 'Avg. per Scan',
            value: reportSummary.totalScans
              ? String(Math.round((reportSummary.totalVulnerabilities / reportSummary.totalScans) * 10) / 10)
              : '0',
            subtitle: 'Calculated from stored report findings',
          },
        ];

    const icons = [Activity, CheckCircle2, AlertTriangle, BarChart3];
    const tones = ['admin-tone-indigo', 'admin-tone-green', 'admin-tone-orange', 'admin-tone-indigo'];

    return sourceMetrics.map((metric, index) => ({
      label: metric.label,
      value: metric.value,
      detail: metric.subtitle || 'Current security metric',
      icon: icons[index % icons.length],
      tone: tones[index % tones.length],
    }));
  }, [adminReports, securityMetrics]);

  const activityCards = useMemo(() => {
    const icons = [Activity, FileText, CheckCircle2, AlertTriangle];
    const tones = ['warning', 'success', 'danger', 'warning'];
    const sourceActivities = recentActivities.length
      ? recentActivities
      : adminReports.slice(0, 4).map((report) => ({
          title: `Stored report ready for ${report.target || report.title || 'scan target'}`,
          detail: `${report.subtitle || 'Backend report recovered'} | Score ${report.score || 0}/100`,
          time: report.date
            ? formatEgyptDate(new Date(report.date), { month: 'short', day: 'numeric', year: 'numeric' })
            : 'Recently',
        }));

    return sourceActivities.map((activity, index) => ({
      title: cleanDashboardText(activity.title, 'Scan activity updated'),
      detail: cleanDashboardText(activity.detail, 'Activity synced from stored scan results.'),
      time: activity.time || 'Recently',
      icon: icons[index % icons.length],
      tone: tones[index % tones.length],
    }));
  }, [adminReports, recentActivities]);

  const issueRows = useMemo(() => {
    const rows = adminReports.map((report) => {
      const date = new Date(report.date);
      const vulnerabilities = Number(report.vulnerabilities || 0);
      const critical = Number(report.critical || 0);
      const high = Number(report.high || 0);
      return {
        target: report.target || report.title,
        date: Number.isNaN(date.getTime())
          ? 'Recent'
          : formatEgyptDate(date, { month: 'short', day: 'numeric', year: 'numeric' }),
        rawDate: Number.isNaN(date.getTime()) ? 0 : date.getTime(),
        status: critical > 0 || high > 0 || Number(report.score || 0) >= 60 ? 'Critical' : 'Completed',
        vulnerabilities,
      };
    });

    return {
      recent: rows,
      vulnerable: [...rows].sort((a, b) => b.vulnerabilities - a.vulnerabilities),
      oldest: [...rows].sort((a, b) => a.rawDate - b.rawDate),
    };
  }, [adminReports]);

  const liveChartBars = useMemo(() => {
    if (!adminReports.length) {
      return [];
    }

    return adminReports.slice(0, 6).reverse().map((report) => {
      const date = new Date(report.date);
      return {
        label: Number.isNaN(date.getTime()) ? 'Scan' : formatEgyptDate(date, { month: 'short' }),
        value: Math.max(Number(report.vulnerabilities || report.critical || 0), 0),
      };
    });
  }, [adminReports]);

  const liveSeverityLegend = useMemo(() => {
    const severityMetrics = securityMetrics.filter((metric) =>
      ['Critical', 'High', 'Medium', 'Low'].includes(metric.label),
    );
    const reportSummary = summarizeAdminReports(adminReports);
    const sourceMetrics = severityMetrics.length
      ? severityMetrics
      : [
          { label: 'Critical', value: reportSummary.critical },
          { label: 'High', value: reportSummary.high },
          { label: 'Medium', value: reportSummary.medium },
          { label: 'Low', value: reportSummary.low },
        ];

    if (!sourceMetrics.some((metric) => Number(metric.value || 0) > 0)) {
      return [];
    }

    const colors = {
      Critical: '#ff9500',
      High: '#fb2c36',
      Medium: '#ffd60a',
      Low: '#34c759',
    };
    const total = sourceMetrics.reduce((sum, item) => sum + Number(item.value || 0), 0) || 1;

    return sourceMetrics.map((item) => ({
      label: item.label,
      value: Math.max(Math.round((Number(item.value || 0) / total) * 100), 0),
      color: colors[item.label] || '#7b7eff',
      count: Number(item.value || 0),
    }));
  }, [adminReports, securityMetrics]);

  return (
    <div className="admin-dashboard-page">
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
              const isActive = item.id === 'admin-dashboard';

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

        <main className="admin-main">
          <section className="admin-section-head admin-cardless">
            <h1>Admin Dashboard</h1>
            <p>Control users, reports, content, pricing, and security activity from one backend-backed workspace</p>
          </section>

          <section className="admin-top-metrics">
            {topMetrics.map((metric) => {
              const Icon = metric.icon;

              return (
                <article key={metric.label} className="admin-stat-card admin-card">
                  <div className="admin-stat-head">
                    <span className={`admin-stat-icon ${metric.tone || ''}`}>
                      <Icon size={16} />
                    </span>
                    {metric.change && <span className="admin-stat-change">{metric.change}</span>}
                  </div>

                  <h3>{metric.label}</h3>

                  {metric.trend ? (
                    <div className="admin-metric-trend-wrap">
                      <div className="admin-metric-trend">
                        <DualSparkline found={metric.trend.found} fixed={metric.trend.fixed} />
                      </div>
                      <div className="admin-metric-trend-legend">
                        <span><i className="is-found" />Found</span>
                        <span><i className="is-fixed" />Fixed</span>
                      </div>
                    </div>
                  ) : (
                    <>
                      <p className="admin-stat-value">{metric.value}</p>
                      <p className="admin-stat-detail">{metric.detail}</p>
                      <div className="admin-stat-breakdown">
                        {metric.breakdown.map((item) => (
                          <span key={item}>{item}</span>
                        ))}
                      </div>
                    </>
                  )}
                </article>
              );
            })}
          </section>

          <section className="admin-section">
            <div className="admin-section-head admin-cardless">
              <h2>Quick Actions</h2>
              <p>Jump straight into the admin pages that are backed by the API</p>
            </div>

            <div className="admin-actions-grid">
              {quickActions.map((action) => {
                const Icon = action.icon;

                return (
                  <button
                    key={action.title}
                    type="button"
                    className="admin-action-card admin-card"
                    style={{ '--action-from': action.colors[0], '--action-to': action.colors[1] }}
                    onClick={() => action.route && onNavigate(action.route)}
                  >
                    <span className="admin-action-icon">
                      <Icon size={18} />
                    </span>
                    <strong>{action.title}</strong>
                    <span>{action.subtitle}</span>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="admin-section">
            <div className="admin-section-head admin-cardless">
              <h2>Security Metrics</h2>
              <p>Live summary returned by the backend dashboard endpoints</p>
            </div>

            <div className="admin-actions-grid admin-scan-grid">
              {liveSecurityMetrics.map((item) => {
                const Icon = item.icon;

                return (
                  <article key={item.label} className="admin-scan-card admin-card">
                    <span className={`admin-stat-icon ${item.tone}`}>
                      <Icon size={16} />
                    </span>
                    <div className="admin-scan-copy">
                      <p>{item.label}</p>
                      <strong>{item.value}</strong>
                      <span>{item.detail}</span>
                    </div>
                  </article>
                );
              })}
            </div>
          </section>

          <section className="admin-chart-grid">
            <article className="admin-chart-card admin-card">
              <div className="admin-section-head">
                <h2>Vulnerability Trend</h2>
                <p>Monthly vulnerabilities count over time</p>
              </div>

              <div className="admin-bar-chart" aria-label="Vulnerability trend">
                {liveChartBars.length ? liveChartBars.map((bar, index) => (
                  <div key={`${bar.label}-${index}`} className="admin-bar-group">
                    <span className="admin-bar-value">{bar.value}</span>
                    <div className="admin-bar-track">
                      <div className="admin-bar-fill" style={{ '--bar-height': `${(bar.value / Math.max(...liveChartBars.map((item) => item.value), 1)) * 100}%` }} />
                    </div>
                    <span className="admin-bar-label">{bar.label}</span>
                  </div>
                )) : (
                  <div className="admin-empty-state admin-chart-empty-state">No scan trend data yet. Completed scans will populate this chart.</div>
                )}
              </div>
            </article>

            <article className="admin-chart-card admin-card">
              <div className="admin-section-head">
                <h2>Severity Distribution</h2>
                <p>Breakdown by vulnerability severity</p>
              </div>

              <div className={`admin-donut-layout ${liveSeverityLegend.length ? '' : 'is-empty'}`}>
                {liveSeverityLegend.length ? (
                  <>
                    <div
                      className="admin-donut-chart"
                      style={{ '--donut-gradient': getSeverityGradient(liveSeverityLegend) }}
                      aria-label="Severity distribution"
                    />

                    <div className="admin-donut-legend">
                      {liveSeverityLegend.map((item) => (
                        <div key={item.label} className="admin-donut-legend-row">
                          <span className="admin-donut-label">
                            <i style={{ backgroundColor: item.color }} />
                            {item.label}
                          </span>
                          <strong>{item.count ?? item.value}</strong>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="admin-empty-state admin-chart-empty-state">No severity data yet. Run scans to populate real findings.</div>
                )}
              </div>
            </article>
          </section>

          <section className="admin-section">
            <div className="admin-section-head admin-cardless">
              <h2>Recent Activity</h2>
              <p>Latest backend activity events for the admin workspace</p>
            </div>

            <div className="admin-alert-grid">
              {activityCards.length ? activityCards.map((alert, index) => {
                const Icon = alert.icon;

                return (
                  <article key={`${alert.title}-${alert.detail}-${index}`} className={`admin-alert-card admin-card is-${alert.tone}`}>
                    <div className="admin-alert-title">
                      <Icon size={16} />
                      <h3>{alert.title}</h3>
                    </div>
                    <p>{alert.detail}</p>
                    <span>{alert.time}</span>
                  </article>
                  );
              }) : (
                <div className="admin-empty-state admin-card">No scan activity yet. Completed scans will appear here automatically.</div>
              )}
            </div>
          </section>

          {dashboardLoading && (
            <section className="admin-section">
              <div className="admin-empty-state admin-card">Loading live dashboard data...</div>
            </section>
          )}

          {dashboardError && (
            <section className="admin-section">
              <div className="admin-empty-state admin-card">{dashboardError}</div>
            </section>
          )}

          <section className="admin-table-panel admin-card">
            <div className="admin-table-top">
              <div className="admin-section-head">
                <h2>Recent Issues</h2>
                <p>Backend-backed report queue sorted by recency, severity, and age</p>
              </div>

              <div className="admin-table-tabs">
                <button type="button" className={activeTab === 'recent' ? 'is-active' : ''} onClick={() => setActiveTab('recent')}>
                  Recent Scans
                </button>
                <button type="button" className={activeTab === 'vulnerable' ? 'is-active' : ''} onClick={() => setActiveTab('vulnerable')}>
                  Most Vulnerable
                </button>
                <button type="button" className={activeTab === 'oldest' ? 'is-active' : ''} onClick={() => setActiveTab('oldest')}>
                  Oldest Issues
                </button>
              </div>
            </div>

            <div className="admin-table-scroll">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Target URL</th>
                    <th>Date</th>
                    <th>Status</th>
                    <th>Vulnerabilities</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {issueRows[activeTab].length ? issueRows[activeTab].map((row) => (
                    <tr key={`${activeTab}-${row.target}`}>
                      <td className="admin-table-target">{row.target}</td>
                      <td>{row.date}</td>
                      <td>
                        <span className={`admin-table-status ${getStatusTone(row.status)}`}>{row.status}</span>
                      </td>
                      <td>
                        <span className={`admin-table-vuln ${getVulnerabilityTone(row.vulnerabilities)}`}>{row.vulnerabilities}</span>
                      </td>
                      <td className="admin-table-action-cell">
                        <button type="button" className="admin-table-action" onClick={() => onNavigate('admin-reports')}>
                          <Eye size={14} />
                          <span>View Report</span>
                        </button>
                      </td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan={5}>
                        <div className="admin-empty-state">No stored scan reports yet. User scans will populate this table automatically.</div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default AdminDashboardPage;
