import { useMemo, useState } from 'react';
import {
  ChevronDown,
  DollarSign,
  FileText,
  Filter,
  LayoutDashboard,
  Lock,
  LogOut,
  Mail,
  Moon,
  MoreVertical,
  PenSquare,
  Search,
  Settings,
  Shield,
  Sun,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';
import './AdminUsersPage.css';

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

const statCards = [
  { label: 'Total Users', value: '1,247', change: '+12%' },
  { label: 'Active Users', value: '1,089', change: '+8%' },
  { label: 'Enterprise Plans', value: '234', change: '+15%' },
  { label: 'Free Plans', value: '456', change: '+5%' },
];

const users = [
  {
    initials: 'M',
    name: 'Mohamed Ahmed',
    email: 'mohamed@example.com',
    plan: 'Professional',
    scans: 24,
    vulnerabilities: 12,
    joined: 'Jan 15, 2025',
    status: 'active',
  },
  {
    initials: 'F',
    name: 'Fatima Ali',
    email: 'fatima@example.com',
    plan: 'Enterprise',
    scans: 156,
    vulnerabilities: 43,
    joined: 'Dec 3, 2024',
    status: 'active',
  },
  {
    initials: 'H',
    name: 'Hassan Ibrahim',
    email: 'hassan@example.com',
    plan: 'Free',
    scans: 5,
    vulnerabilities: 2,
    joined: 'Feb 1, 2025',
    status: 'active',
  },
  {
    initials: 'N',
    name: 'Nour Salem',
    email: 'nour@example.com',
    plan: 'Professional',
    scans: 87,
    vulnerabilities: 31,
    joined: 'Nov 20, 2024',
    status: 'inactive',
  },
  {
    initials: 'K',
    name: 'Khaled Mahmoud',
    email: 'khaled@example.com',
    plan: 'Enterprise',
    scans: 203,
    vulnerabilities: 67,
    joined: 'Oct 10, 2024',
    status: 'active',
  },
];

function getPlanTone(plan) {
  if (plan === 'Enterprise') return 'is-enterprise';
  if (plan === 'Professional') return 'is-professional';
  return 'is-free';
}

function AdminUsersPage({ onNavigate }) {
  const { theme, toggleTheme } = useTheme();
  const [query, setQuery] = useState('');

  const filteredUsers = useMemo(() => {
    const normalized = query.trim().toLowerCase();

    if (!normalized) {
      return users;
    }

    return users.filter((user) => {
      return (
        user.name.toLowerCase().includes(normalized)
        || user.email.toLowerCase().includes(normalized)
      );
    });
  }, [query]);

  return (
    <div className="admin-users-page">
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
              const isActive = item.id === 'users';

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

        <main className="admin-main admin-users-main">
          <section className="admin-users-header">
            <div className="admin-section-head admin-cardless">
              <h1>User Management</h1>
              <p>Manage all users, their subscriptions and activity</p>
            </div>

            <button type="button" className="admin-users-add-btn">
              <UserPlus size={18} />
              <span>Add New User</span>
            </button>
          </section>

          <section className="admin-users-stats">
            {statCards.map((item) => (
              <article key={item.label} className="admin-users-stat-card admin-card">
                <div className="admin-users-stat-copy">
                  <p>{item.label}</p>
                  <strong>{item.value}</strong>
                </div>
                <span className="admin-users-stat-change">{item.change}</span>
              </article>
            ))}
          </section>

          <section className="admin-users-filter-panel admin-card">
            <label className="admin-users-search" htmlFor="admin-user-search">
              <Search size={16} />
              <input
                id="admin-user-search"
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search users by name or email..."
              />
            </label>

            <button type="button" className="admin-users-filter-btn">
              <Filter size={16} />
              <span>Filters</span>
            </button>
          </section>

          <section className="admin-users-table-panel admin-card">
            <div className="admin-section-head">
              <h2>All Users</h2>
            </div>

            <div className="admin-users-table-scroll">
              <table className="admin-users-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Plan</th>
                    <th>Scans</th>
                    <th>Vulnerabilities</th>
                    <th>Joined</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((user) => (
                    <tr key={user.email}>
                      <td>
                        <div className="admin-users-usercell">
                          <span className="admin-users-avatar">{user.initials}</span>
                          <div className="admin-users-usercopy">
                            <strong>{user.name}</strong>
                            <span>{user.email}</span>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={`admin-users-plan ${getPlanTone(user.plan)}`}>{user.plan}</span>
                      </td>
                      <td>{user.scans}</td>
                      <td>{user.vulnerabilities}</td>
                      <td className="admin-users-muted">{user.joined}</td>
                      <td>
                        <span className={`admin-users-status is-${user.status}`}>{user.status}</span>
                      </td>
                      <td>
                        <div className="admin-users-actions">
                          <button type="button" className="admin-users-icon-btn" aria-label={`Email ${user.name}`}>
                            <Mail size={14} />
                          </button>
                          <button type="button" className="admin-users-icon-btn" aria-label={`Security ${user.name}`}>
                            <Lock size={14} />
                          </button>
                          <button type="button" className="admin-users-icon-btn is-danger" aria-label={`Delete ${user.name}`}>
                            <Trash2 size={14} />
                          </button>
                          <button type="button" className="admin-users-icon-btn" aria-label={`More actions for ${user.name}`}>
                            <MoreVertical size={14} />
                          </button>
                        </div>
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

export default AdminUsersPage;
