import {
  ChevronDown,
  Crown,
  DollarSign,
  FileText,
  LayoutDashboard,
  LogOut,
  Mail,
  Moon,
  PenSquare,
  Settings,
  Settings2,
  Shield,
  ShieldCheck,
  Sun,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';
import './AdminTeamPage.css';

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

const teamStats = [
  { label: 'Total Admins', value: '4', icon: ShieldCheck, tone: 'admin-tone-indigo' },
  { label: 'Active Now', value: '2', icon: Crown, tone: 'admin-tone-green' },
  { label: 'Pending Invites', value: '1', icon: Mail, tone: 'admin-tone-orange' },
];

const teamMembers = [
  {
    initials: 'AH',
    name: 'Ahmed Hassan',
    email: 'ahmed@threathunters.com',
    status: 'active',
    time: 'Online now',
    role: 'Super Admin',
    badges: ['Full Access', 'User Management', 'System Config'],
  },
  {
    initials: 'SM',
    name: 'Sarah Mohamed',
    email: 'sarah@threathunters.com',
    status: 'active',
    time: '2 hours ago',
    role: 'Admin',
    badges: ['Scan Management', 'Reports', 'User Support'],
  },
  {
    initials: 'OA',
    name: 'Omar Ali',
    email: 'omar@threathunters.com',
    status: 'away',
    time: '1 day ago',
    role: 'Security Analyst',
    badges: ['Scan Management', 'Reports'],
  },
  {
    initials: 'LI',
    name: 'Laila Ibrahim',
    email: 'laila@threathunters.com',
    status: 'active',
    time: '5 hours ago',
    role: 'Admin',
    badges: ['User Management', 'Reports'],
  },
];

const recentActivity = [
  { actor: 'Ahmed Hassan', action: 'Updated system settings', time: '5 minutes ago' },
  { actor: 'Sarah Mohamed', action: 'Added new user: John Doe', time: '1 hour ago' },
  { actor: 'Omar Ali', action: 'Generated security report', time: '3 hours ago' },
  { actor: 'Laila Ibrahim', action: 'Modified user permissions', time: '5 hours ago' },
];

function AdminTeamPage({ onNavigate }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="admin-team-page">
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
              const isActive = item.id === 'admin-team';

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

        <main className="admin-main admin-team-main">
          <section className="admin-team-header">
            <div className="admin-section-head admin-cardless">
              <h1>Admin Team Management</h1>
              <p>Manage your administrative team members and their permissions</p>
            </div>

            <button type="button" className="admin-team-add-btn">
              <UserPlus size={18} />
              <span>Add New Admin</span>
            </button>
          </section>

          <section className="admin-team-stats">
            {teamStats.map((item) => {
              const Icon = item.icon;

              return (
                <article key={item.label} className="admin-team-stat-card admin-card">
                  <div>
                    <p className="admin-team-stat-label">{item.label}</p>
                    <strong className="admin-team-stat-value">{item.value}</strong>
                  </div>
                  <span className={`admin-stat-icon ${item.tone}`}>
                    <Icon size={16} />
                  </span>
                </article>
              );
            })}
          </section>

          <section className="admin-team-members-panel admin-card">
            <div className="admin-section-head">
              <h2>Team Members</h2>
            </div>

            <div className="admin-team-members-list">
              {teamMembers.map((member) => (
                <article key={member.email} className="admin-team-member-card">
                  <div className="admin-team-member-left">
                    <div className="admin-team-avatar">{member.initials}</div>

                    <div className="admin-team-member-meta">
                      <div className="admin-team-member-line">
                        <strong>{member.name}</strong>
                        <span className={`admin-team-status is-${member.status}`}>{member.status}</span>
                      </div>
                      <a href={`mailto:${member.email}`} className="admin-team-email">
                        {member.email}
                      </a>
                      <span className="admin-team-time">{member.time}</span>
                    </div>
                  </div>

                  <div className="admin-team-member-center">
                    <div className="admin-team-badges">
                      {member.badges.map((badge) => (
                        <span key={`${member.email}-${badge}`} className="admin-team-badge">
                          {badge}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="admin-team-member-right">
                    <span className="admin-team-role">{member.role}</span>
                    <div className="admin-team-actions">
                      <button type="button" className="admin-team-icon-btn" aria-label={`Edit ${member.name}`}>
                        <Settings2 size={15} />
                      </button>
                      <button type="button" className="admin-team-icon-btn is-danger" aria-label={`Remove ${member.name}`}>
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="admin-team-activity-panel admin-card">
            <div className="admin-section-head">
              <h2>Recent Activity</h2>
            </div>

            <div className="admin-team-activity-list">
              {recentActivity.map((entry) => (
                <article key={`${entry.actor}-${entry.time}`} className="admin-team-activity-item">
                  <div className="admin-team-activity-copy">
                    <span className="admin-team-activity-actor">{entry.actor}</span>
                    <p>{entry.action}</p>
                  </div>
                  <span className="admin-team-activity-time">{entry.time}</span>
                </article>
              ))}
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default AdminTeamPage;
