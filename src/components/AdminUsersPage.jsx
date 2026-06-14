import { useCallback, useEffect, useMemo, useState } from 'react';
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
import { userAPI } from '../services/api';
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
  const [managedUsers, setManagedUsers] = useState(users);
  const [notice, setNotice] = useState('');

  const loadUsers = useCallback(async () => {
    try {
      setNotice('Loading users...');
      const payload = await userAPI.getUsers(1, 100);
      const items = payload.items || payload.users || [];
      setManagedUsers(items.length ? items.map((user) => ({
        ...user,
        initials: (user.name || user.email || 'U').slice(0, 1).toUpperCase(),
        name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email,
        plan: user.plan || 'Free',
        scans: user.scans || 0,
        vulnerabilities: user.vulnerabilities || 0,
        joined: user.joined ? new Date(user.joined).toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
        }) : 'New',
        status: user.status || 'active',
      })) : users);
      setNotice('');
    } catch (error) {
      setNotice(error.message || 'Using local user data until the backend is available.');
      setManagedUsers(users);
    }
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      loadUsers();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [loadUsers]);

  const filteredUsers = useMemo(() => {
    const normalized = query.trim().toLowerCase();

    if (!normalized) {
      return managedUsers;
    }

    return managedUsers.filter((user) => {
      return (
        user.name.toLowerCase().includes(normalized)
        || user.email.toLowerCase().includes(normalized)
      );
    });
  }, [managedUsers, query]);

  const computedStatCards = useMemo(() => {
    const total = managedUsers.length;
    const active = managedUsers.filter((user) => user.status === 'active').length;
    const enterprise = managedUsers.filter((user) => user.plan === 'Enterprise').length;
    const free = managedUsers.filter((user) => user.plan === 'Free').length;

    return [
      { label: 'Total Users', value: String(total), change: 'live' },
      { label: 'Active Users', value: String(active), change: 'live' },
      { label: 'Enterprise Plans', value: String(enterprise), change: 'live' },
      { label: 'Free Plans', value: String(free), change: 'live' },
    ];
  }, [managedUsers]);

  const toggleUserStatus = async (user) => {
    const nextStatus = user.status === 'disabled' ? 'active' : 'disabled';

    try {
      setNotice(nextStatus === 'disabled' ? 'Disabling user...' : 'Activating user...');
      await userAPI.updateUser(user.id, { status: nextStatus });
      await loadUsers();
      setNotice(nextStatus === 'disabled' ? 'User disabled.' : 'User activated.');
    } catch (error) {
      setNotice(error.message || 'Unable to update user status.');
    }
  };

  const deleteUser = async (user) => {
    try {
      setNotice('Deleting user...');
      await userAPI.deleteUser(user.id);
      await loadUsers();
      setNotice('User deleted.');
    } catch (error) {
      setNotice(error.message || 'Unable to delete user.');
    }
  };

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

            <button type="button" className="admin-users-add-btn" onClick={loadUsers}>
              <UserPlus size={18} />
              <span>Refresh Users</span>
            </button>
          </section>

          <section className="admin-users-stats">
            {computedStatCards.map((item) => (
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

          {notice && <div className="admin-users-notice admin-card">{notice}</div>}

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
                          <button type="button" className="admin-users-icon-btn" onClick={() => toggleUserStatus(user)} aria-label={`Toggle access for ${user.name}`}>
                            <Lock size={14} />
                          </button>
                          <button type="button" className="admin-users-icon-btn is-danger" onClick={() => deleteUser(user)} aria-label={`Delete ${user.name}`}>
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
