import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  DollarSign,
  Download,
  Eye,
  FileBarChart2,
  FileText,
  LayoutDashboard,
  LogOut,
  Moon,
  PenSquare,
  Play,
  RefreshCw,
  SearchX,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';

const topMetrics = [
  {
    label: 'Overall Risk Score',
    value: 'D',
    detail: 'Based on active vulnerabilities',
    breakdown: ['Critical: 8', 'High: 12', 'Medium: 30'],
    icon: ShieldAlert,
    tone: 'admin-tone-red',
    change: null,
  },
  {
    label: 'Active Vulnerabilities',
    value: '47',
    detail: '5 new in last 24h',
    breakdown: ['Critical: 8', 'High: 12', 'Medium: 30'],
    icon: AlertTriangle,
    tone: 'admin-tone-red',
    change: '+12',
  },
  {
    label: 'Vulnerable Assets',
    value: '3 of 10',
    detail: 'Targets with critical / high issues',
    breakdown: ['Targets with Critical', 'High issues'],
    icon: SearchX,
    tone: 'admin-tone-cyan',
    change: null,
  },
  {
    label: '30-Day Trend',
    value: '',
    detail: '',
    breakdown: [],
    icon: Activity,
    tone: 'admin-tone-indigo',
    change: null,
    trend: [8, 22, 16, 13, 12],
  },
];

const quickActions = [
  { title: 'Start New Scan', subtitle: 'Launch a security scan', icon: Play, colors: ['#7b7eff', '#9ba8ff'] },
  { title: 'Export All Reports', subtitle: 'Download as PDF/CSV', icon: Download, colors: ['#00d9ff', '#6d7cff'] },
  { title: 'Rescan All Targets', subtitle: 'Run fresh scans', icon: RefreshCw, colors: ['#34c759', '#00d9ff'] },
  { title: 'Generate Summary', subtitle: 'Executive report', icon: FileBarChart2, colors: ['#ff9500', '#ffd60a'] },
];

const scanStats = [
  { label: 'Total Scans', value: '5', detail: '3 in progress', icon: Activity, tone: 'admin-tone-indigo' },
  { label: 'Success Rate', value: '80%', detail: 'Scan completion rate', icon: CheckCircle2, tone: 'admin-tone-green' },
  { label: 'Total Vulnerabilities', value: '8', detail: 'Found across all scans', icon: AlertTriangle, tone: 'admin-tone-orange' },
  { label: 'Avg. per Scan', value: '1.6', detail: 'Vulnerabilities per scan', icon: BarChart3, tone: 'admin-tone-indigo' },
];

const chartBars = [
  { label: 'Jun', value: 21 },
  { label: 'Jul', value: 26 },
  { label: 'Aug', value: 23 },
  { label: 'Sep', value: 13 },
  { label: 'Oct', value: 7 },
];

const severityLegend = [
  { label: 'High', value: 19, color: '#fb2c36' },
  { label: 'Critical', value: 8, color: '#ff9500' },
  { label: 'Medium', value: 48, color: '#ffd60a' },
  { label: 'Low', value: 24, color: '#34c759' },
];

const alerts = [
  {
    title: 'Critical SQL Injection Found',
    detail: 'Found in https://example.com/login. Immediate action required',
    time: '2 hours ago',
    icon: AlertTriangle,
    tone: 'danger',
  },
  {
    title: 'SSL Certificate Expiring Soon',
    detail: '3 certificates will expire within 30 days',
    time: '5 hours ago',
    icon: Shield,
    tone: 'warning',
  },
  {
    title: 'XSS Vulnerability Fixed',
    detail: 'Verified fix on https://test-site.org/search',
    time: '1 day ago',
    icon: ShieldCheck,
    tone: 'success',
  },
];

const scanRows = {
  recent: [
    { target: 'https://example.com', date: 'Oct 28, 2025', status: 'Completed', vulnerabilities: 2 },
    { target: 'https://test-site.org', date: 'Oct 25, 2025', status: 'Completed', vulnerabilities: 0 },
  ],
  vulnerable: [
    { target: 'https://legacy-payments.app', date: 'Oct 27, 2025', status: 'Critical', vulnerabilities: 9 },
    { target: 'https://partner-portal.net', date: 'Oct 24, 2025', status: 'Needs review', vulnerabilities: 6 },
  ],
  oldest: [
    { target: 'https://archive.example.org', date: 'Aug 09, 2025', status: 'Pending fix', vulnerabilities: 3 },
    { target: 'https://staging.test-site.org', date: 'Aug 03, 2025', status: 'Pending fix', vulnerabilities: 1 },
  ],
};

const sidebarItems = [
  { id: 'admin-dashboard', label: 'Admin Dashboard', icon: LayoutDashboard, route: 'admin-dashboard' },
  { id: 'admin-team', label: 'Admin Team', icon: Shield, route: 'admin-team' },
  { id: 'users', label: 'Users', icon: Users, route: 'admin-users' },
  { id: 'reports', label: 'Reports', icon: FileText, route: 'admin-reports' },
  { id: 'web-edit', label: 'Web edit', icon: PenSquare, route: 'admin-web-edit', expandable: true },
  { id: 'pricing', label: 'pricing', icon: DollarSign, route: 'admin-pricing' },
  { id: 'settings', label: 'Settings', icon: Settings, route: 'admin-settings' },
];

const topNavItems = [
  { label: 'Home', route: 'dashboard' },
  { label: 'More Tools', route: 'tools' },
  { label: 'Security Awareness', route: 'awareness' },
  { label: 'Blog', route: 'blog' },
  { label: 'Admin Dashboard', route: 'admin-dashboard' },
];

function Sparkline({ values }) {
  const max = Math.max(...values);
  const stepX = 84 / Math.max(values.length - 1, 1);
  const points = values
    .map((value, index) => {
      const x = index * stepX;
      const y = 24 - (value / max) * 18;
      return `${x},${y.toFixed(2)}`;
    })
    .join(' ');

  return (
    <svg viewBox="0 0 84 28" aria-hidden="true">
      <polyline className="admin-mini-trend-line" points={points} />
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

function AdminDashboardPage({ onNavigate }) {
  const [activeTab, setActiveTab] = useState('recent');
  const { theme, toggleTheme } = useTheme();

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
                className={`admin-nav-link ${item.route === 'admin-dashboard' ? 'is-active' : ''}`}
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
            <button type="button" className="admin-logout-btn" onClick={() => onNavigate('home')}>
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
                        <Sparkline values={metric.trend} />
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
              <p>Perform common tasks with one click</p>
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
              <h2>Scan Management</h2>
              <p>View and manage all your security scans with powerful filtering and batch actions</p>
            </div>

            <div className="admin-actions-grid admin-scan-grid">
              {scanStats.map((item) => {
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
                {chartBars.map((bar) => (
                  <div key={bar.label} className="admin-bar-group">
                    <span className="admin-bar-value">{bar.value}</span>
                    <div className="admin-bar-track">
                      <div className="admin-bar-fill" style={{ '--bar-height': `${(bar.value / 26) * 100}%` }} />
                    </div>
                    <span className="admin-bar-label">{bar.label}</span>
                  </div>
                ))}
              </div>
            </article>

            <article className="admin-chart-card admin-card">
              <div className="admin-section-head">
                <h2>Severity Distribution</h2>
                <p>Breakdown by vulnerability severity</p>
              </div>

              <div className="admin-donut-layout">
                <div
                  className="admin-donut-chart"
                  style={{ '--donut-gradient': getSeverityGradient(severityLegend) }}
                  aria-label="Severity distribution"
                />

                <div className="admin-donut-legend">
                  {severityLegend.map((item) => (
                    <div key={item.label} className="admin-donut-legend-row">
                      <span className="admin-donut-label">
                        <i style={{ backgroundColor: item.color }} />
                        {item.label}
                      </span>
                      <strong>{item.value}%</strong>
                    </div>
                  ))}
                </div>
              </div>
            </article>
          </section>

          <section className="admin-section">
            <div className="admin-section-head admin-cardless">
              <h2>Security Alerts</h2>
              <p>Recent security events and notifications</p>
            </div>

            <div className="admin-alert-grid">
              {alerts.map((alert) => {
                const Icon = alert.icon;

                return (
                  <article key={alert.title} className={`admin-alert-card admin-card is-${alert.tone}`}>
                    <div className="admin-alert-title">
                      <Icon size={16} />
                      <h3>{alert.title}</h3>
                    </div>
                    <p>{alert.detail}</p>
                    <span>{alert.time}</span>
                  </article>
                );
              })}
            </div>
          </section>

          <section className="admin-table-panel admin-card">
            <div className="admin-table-top">
              <div className="admin-section-head">
                <h2>Recent Scans</h2>
                <p>Your latest security scan results</p>
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
                  {scanRows[activeTab].map((row) => (
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
                        <button type="button" className="admin-table-action">
                          <Eye size={14} />
                          <span>View Report</span>
                        </button>
                      </td>
                    </tr>
                  ))}
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
