import { useState } from 'react';
import {
  Bell,
  ChevronDown,
  Globe,
  LayoutDashboard,
  Lock,
  LogOut,
  Mail,
  Moon,
  PenSquare,
  Save,
  Settings,
  Shield,
  Sun,
  DollarSign,
  FileText,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';
import './AdminSettingsPage.css';

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

const tabs = [
  {
    id: 'general',
    label: 'General',
    icon: Globe,
    title: 'General Settings',
    description: 'Manage your platform name, description, locale, and timezone defaults.',
  },
  {
    id: 'notifications',
    label: 'Notifications',
    icon: Bell,
    title: 'Notification Settings',
    description: 'Choose how admins receive alerts, reports, and digest emails.',
  },
  {
    id: 'security',
    label: 'Security',
    icon: Lock,
    title: 'Security Settings',
    description: 'Control authentication rules, session limits, and access policies.',
  },
  {
    id: 'email',
    label: 'Email',
    icon: Mail,
    title: 'Email Settings',
    description: 'Configure sender identity and default email copy used by the platform.',
  },
];

const initialSettings = {
  general: {
    siteName: 'Threat Hunters',
    siteDescription: 'Smart AI-Powered Web Vulnerability Scanner',
    language: 'English',
    timezone: 'UTC+02:00 Cairo',
  },
  notifications: {
    emailAlerts: true,
    criticalOnly: true,
    weeklyReports: true,
    productUpdates: false,
    digestFrequency: 'Daily digest',
  },
  security: {
    requireTwoFactor: true,
    loginAlerts: true,
    sessionTimeout: '30 minutes',
    passwordRotation: 'Every 90 days',
  },
  email: {
    senderName: 'Threat Hunters',
    senderAddress: 'alerts@threathunters.ai',
    replyTo: 'support@threathunters.ai',
    footerNote: 'AI-powered vulnerability scanning to protect your web applications.',
  },
};

function Toggle({ checked, onToggle, label, description }) {
  return (
    <div className="admin-settings-toggle-card">
      <div className="admin-settings-toggle-copy">
        <strong>{label}</strong>
        <p>{description}</p>
      </div>

      <button
        type="button"
        className={`admin-settings-toggle ${checked ? 'is-on' : ''}`}
        onClick={onToggle}
        aria-pressed={checked}
      >
        <span className="admin-settings-toggle-thumb" />
      </button>
    </div>
  );
}

function SelectField({ label, value, options, onChange }) {
  return (
    <label className="admin-settings-field">
      <span>{label}</span>
      <div className="admin-settings-select-wrap">
        <select value={value} onChange={(event) => onChange(event.target.value)}>
          {options.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
        <ChevronDown size={16} className="admin-settings-select-icon" />
      </div>
    </label>
  );
}

function AdminSettingsPage({ onNavigate }) {
  const { theme, toggleTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('general');
  const [settingsState, setSettingsState] = useState(initialSettings);

  const currentTab = tabs.find((tab) => tab.id === activeTab) ?? tabs[0];

  const updateField = (section, field, value) => {
    setSettingsState((prev) => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value,
      },
    }));
  };

  const toggleField = (section, field) => {
    setSettingsState((prev) => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: !prev[section][field],
      },
    }));
  };

  const renderPanel = () => {
    if (activeTab === 'general') {
      return (
        <div className="admin-settings-form-grid">
          <label className="admin-settings-field admin-settings-field-full">
            <span>Site Name</span>
            <input
              type="text"
              value={settingsState.general.siteName}
              onChange={(event) => updateField('general', 'siteName', event.target.value)}
            />
          </label>

          <label className="admin-settings-field admin-settings-field-full">
            <span>Site Description</span>
            <textarea
              rows={4}
              value={settingsState.general.siteDescription}
              onChange={(event) => updateField('general', 'siteDescription', event.target.value)}
            />
          </label>

          <SelectField
            label="Language"
            value={settingsState.general.language}
            options={['English', 'Arabic', 'French']}
            onChange={(value) => updateField('general', 'language', value)}
          />

          <SelectField
            label="Timezone"
            value={settingsState.general.timezone}
            options={['UTC+02:00 Cairo', 'UTC+00:00 London', 'UTC-05:00 New York']}
            onChange={(value) => updateField('general', 'timezone', value)}
          />
        </div>
      );
    }

    if (activeTab === 'notifications') {
      return (
        <div className="admin-settings-stack">
          <div className="admin-settings-toggle-grid">
            <Toggle
              checked={settingsState.notifications.emailAlerts}
              onToggle={() => toggleField('notifications', 'emailAlerts')}
              label="Email Alerts"
              description="Send admin alerts for new scans, incidents, and unusual activity."
            />
            <Toggle
              checked={settingsState.notifications.criticalOnly}
              onToggle={() => toggleField('notifications', 'criticalOnly')}
              label="Critical Alerts Only"
              description="Limit instant notifications to high-priority security issues."
            />
            <Toggle
              checked={settingsState.notifications.weeklyReports}
              onToggle={() => toggleField('notifications', 'weeklyReports')}
              label="Weekly Reports"
              description="Email a weekly summary of scans, vulnerabilities, and fixes."
            />
            <Toggle
              checked={settingsState.notifications.productUpdates}
              onToggle={() => toggleField('notifications', 'productUpdates')}
              label="Product Updates"
              description="Receive release updates about new tools, reports, and features."
            />
          </div>

          <div className="admin-settings-form-grid">
            <SelectField
              label="Digest Frequency"
              value={settingsState.notifications.digestFrequency}
              options={['Daily digest', 'Twice per week', 'Weekly only']}
              onChange={(value) => updateField('notifications', 'digestFrequency', value)}
            />
          </div>
        </div>
      );
    }

    if (activeTab === 'security') {
      return (
        <div className="admin-settings-stack">
          <div className="admin-settings-toggle-grid">
            <Toggle
              checked={settingsState.security.requireTwoFactor}
              onToggle={() => toggleField('security', 'requireTwoFactor')}
              label="Require Two-Factor Authentication"
              description="Force all admin accounts to use 2FA for dashboard access."
            />
            <Toggle
              checked={settingsState.security.loginAlerts}
              onToggle={() => toggleField('security', 'loginAlerts')}
              label="Login Alerts"
              description="Notify admins whenever a new device signs in to the platform."
            />
          </div>

          <div className="admin-settings-form-grid">
            <SelectField
              label="Session Timeout"
              value={settingsState.security.sessionTimeout}
              options={['15 minutes', '30 minutes', '60 minutes']}
              onChange={(value) => updateField('security', 'sessionTimeout', value)}
            />

            <SelectField
              label="Password Rotation"
              value={settingsState.security.passwordRotation}
              options={['Every 30 days', 'Every 90 days', 'Every 180 days']}
              onChange={(value) => updateField('security', 'passwordRotation', value)}
            />
          </div>
        </div>
      );
    }

    return (
      <div className="admin-settings-form-grid">
        <label className="admin-settings-field">
          <span>Sender Name</span>
          <input
            type="text"
            value={settingsState.email.senderName}
            onChange={(event) => updateField('email', 'senderName', event.target.value)}
          />
        </label>

        <label className="admin-settings-field">
          <span>Sender Email</span>
          <input
            type="email"
            value={settingsState.email.senderAddress}
            onChange={(event) => updateField('email', 'senderAddress', event.target.value)}
          />
        </label>

        <label className="admin-settings-field admin-settings-field-full">
          <span>Reply-To Address</span>
          <input
            type="email"
            value={settingsState.email.replyTo}
            onChange={(event) => updateField('email', 'replyTo', event.target.value)}
          />
        </label>

        <label className="admin-settings-field admin-settings-field-full">
          <span>Email Footer Note</span>
          <textarea
            rows={4}
            value={settingsState.email.footerNote}
            onChange={(event) => updateField('email', 'footerNote', event.target.value)}
          />
        </label>
      </div>
    );
  };

  return (
    <div className="admin-settings-page">
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
              const isActive = item.id === 'settings';

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

        <main className="admin-main admin-settings-main">
          <section className="admin-settings-header">
            <div className="admin-section-head admin-cardless">
              <h1>Settings</h1>
              <p>Manage your system settings and preferences</p>
            </div>

            <button type="button" className="admin-settings-save-btn">
              <Save size={18} />
              <span>Save All Changes</span>
            </button>
          </section>

          <section className="admin-settings-layout">
            <div className="admin-settings-tab-list">
              {tabs.map((tab) => {
                const Icon = tab.icon;

                return (
                  <button
                    key={tab.id}
                    type="button"
                    className={`admin-settings-tab ${activeTab === tab.id ? 'is-active' : ''}`}
                    onClick={() => setActiveTab(tab.id)}
                  >
                    <Icon size={17} />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            <article className="admin-settings-panel admin-card">
              <div className="admin-section-head">
                <h2>{currentTab.title}</h2>
                <p>{currentTab.description}</p>
              </div>
              {renderPanel()}
            </article>
          </section>
        </main>
      </div>
    </div>
  );
}

export default AdminSettingsPage;
