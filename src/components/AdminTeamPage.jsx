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
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { adminAPI } from '../services/api';
import './AdminDashboardPage.css';
import './AdminTeamPage.css';

const topNavItems = [
  { label: 'Home', route: 'admin-dashboard' },
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

function AdminTeamPage({ onNavigate, onLogout, currentPage = 'admin-team' }) {
  const { theme, toggleTheme } = useTheme();
  const [members, setMembers] = useState(teamMembers);
  const [activity, setActivity] = useState(recentActivity);
  const [notice, setNotice] = useState('');

  const loadTeam = useCallback(async () => {
    try {
      setNotice('Loading admin team...');
      const payload = await adminAPI.getTeam();
      const items = payload.items || payload.team || [];
      setMembers(items.length ? items : teamMembers);
      setActivity((items.length ? items : teamMembers).slice(0, 4).map((member) => ({
        actor: member.name,
        action: `${member.role} is ${member.status}`,
        time: member.time || 'Synced from backend',
      })));
      setNotice('');
    } catch (error) {
      setMembers(teamMembers);
      setActivity(recentActivity);
      setNotice(error.message || 'Using local team data until the backend is available.');
    }
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      loadTeam();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [loadTeam]);

  const computedTeamStats = useMemo(() => {
    const totalAdmins = members.length;
    const activeNow = members.filter((member) => member.status === 'active').length;
    const pendingInvites = members.filter((member) => member.status === 'pending').length;

    return [
      { label: 'Total Admins', value: String(totalAdmins), icon: ShieldCheck, tone: 'admin-tone-indigo' },
      { label: 'Active Now', value: String(activeNow), icon: Crown, tone: 'admin-tone-green' },
      { label: 'Pending Invites', value: String(pendingInvites), icon: Mail, tone: 'admin-tone-orange' },
    ];
  }, [members]);

  const addTeamMember = async () => {
    const suffix = Date.now().toString().slice(-5);
    try {
      setNotice('Creating admin invite...');
      await adminAPI.addTeamMember({
        name: 'New Admin',
        email: `new.admin.${suffix}@threathunters.com`,
        role: 'Admin',
        status: 'pending',
        badges: ['Reports', 'User Support'],
      });
      await loadTeam();
      setNotice('Admin invite created. Edit the member from the backend data when ready.');
    } catch (error) {
      setNotice(error.message || 'Unable to create admin invite.');
    }
  };

  const toggleMemberStatus = async (member) => {
    const nextStatus = member.status === 'active' ? 'away' : 'active';
    try {
      setNotice('Updating team member...');
      await adminAPI.updateTeamMember(member.id, { ...member, status: nextStatus, time: nextStatus === 'active' ? 'Online now' : 'Away' });
      await loadTeam();
      setNotice(`${member.name} is now ${nextStatus}.`);
    } catch (error) {
      setNotice(error.message || 'Unable to update team member.');
    }
  };

  const removeTeamMember = async (member) => {
    if (!window.confirm(`Remove ${member.name} from the admin team?`)) {
      return;
    }

    try {
      setNotice('Removing team member...');
      await adminAPI.deleteTeamMember(member.id);
      await loadTeam();
      setNotice('Team member removed.');
    } catch (error) {
      setNotice(error.message || 'Unable to remove team member.');
    }
  };

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

            <button type="button" className="admin-team-add-btn" onClick={addTeamMember}>
              <UserPlus size={18} />
              <span>Add New Admin</span>
            </button>
          </section>

          {notice && <div className="admin-users-notice admin-card">{notice}</div>}

          <section className="admin-team-stats">
            {computedTeamStats.map((item) => {
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
              {members.map((member) => (
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
                      <button type="button" className="admin-team-icon-btn" onClick={() => toggleMemberStatus(member)} aria-label={`Toggle ${member.name} status`}>
                        <Settings2 size={15} />
                      </button>
                      <button type="button" className="admin-team-icon-btn is-danger" onClick={() => removeTeamMember(member)} aria-label={`Remove ${member.name}`}>
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
              {activity.map((entry) => (
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
