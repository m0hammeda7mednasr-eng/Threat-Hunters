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
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';
import './AdminReportsPage.css';

const topNavItems = [
  { label: 'Home', route: 'dashboard' },
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
  { id: 'web-edit', label: 'Web edit', icon: PenSquare, route: 'admin-web-edit', expandable: true },
  { id: 'pricing', label: 'pricing', icon: DollarSign, route: 'admin-pricing' },
  { id: 'settings', label: 'Settings', icon: Settings, route: 'admin-settings' },
];

const stats = [
  { label: 'Total Reports', value: '156', icon: FileText, tone: 'admin-tone-indigo' },
  { label: 'Generated This Month', value: '23', icon: CalendarDays, tone: 'admin-tone-green' },
  { label: 'Downloads', value: '892', icon: Download, tone: 'admin-tone-orange' },
  { label: 'Avg. Report Size', value: '3.2 MB', icon: BarChart3, tone: 'admin-tone-indigo' },
];

const scanActivity = [
  { label: 'Jan', value: 4.2 },
  { label: 'Feb', value: 5.1 },
  { label: 'Mar', value: 6.3 },
  { label: 'Apr', value: 5.9 },
  { label: 'May', value: 7.4 },
  { label: 'Jun', value: 7.2 },
];

const vulnerabilityTrends = [
  { label: 'Jan', value: 8 },
  { label: 'Feb', value: 7 },
  { label: 'Mar', value: 8.4 },
  { label: 'Apr', value: 6.2 },
  { label: 'May', value: 7.4 },
  { label: 'Jun', value: 5.4 },
];

const reports = [
  {
    title: 'Monthly Security Report',
    subtitle: 'Comprehensive security analysis for June 2025',
    date: 'Jul 1, 2025',
    size: '2.4 MB',
    type: 'PDF',
  },
  {
    title: 'Vulnerability Assessment Q2',
    subtitle: 'Quarterly vulnerability trends and analysis',
    date: 'Jul 1, 2025',
    size: '5.1 MB',
    type: 'PDF',
  },
  {
    title: 'Executive Summary',
    subtitle: 'High-level security overview for stakeholders',
    date: 'Jun 30, 2025',
    size: '1.2 MB',
    type: 'PDF',
  },
  {
    title: 'Compliance Report',
    subtitle: 'OWASP Top 10 compliance check results',
    date: 'Jun 28, 2025',
    size: '3.8 MB',
    type: 'PDF',
  },
];

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
  const max = Math.max(...bars.map((item) => item.value));

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

function AdminReportsPage({ onNavigate }) {
  const { theme, toggleTheme } = useTheme();

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

            <button type="button" className="admin-reports-generate-btn">
              <Plus size={18} />
              <span>Generate New Report</span>
            </button>
          </section>

          <section className="admin-reports-stats">
            {stats.map((item) => {
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
              {reports.map((report) => (
                <article key={report.title} className="admin-reports-list-item">
                  <div className="admin-reports-item-left">
                    <span className="admin-reports-file-icon">
                      <FileText size={18} />
                    </span>

                    <div className="admin-reports-item-copy">
                      <strong>{report.title}</strong>
                      <p>{report.subtitle}</p>
                      <div className="admin-reports-item-meta">
                        <span>{report.date}</span>
                        <span className="admin-reports-dot">•</span>
                        <span>{report.size}</span>
                        <span className="admin-reports-dot">•</span>
                        <span className="admin-reports-filetype">{report.type}</span>
                      </div>
                    </div>
                  </div>

                  <button type="button" className="admin-reports-download-btn">
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
