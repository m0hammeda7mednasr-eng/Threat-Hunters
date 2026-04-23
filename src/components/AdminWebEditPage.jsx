import { useMemo, useState } from 'react';
import {
  ChevronDown,
  DollarSign,
  FileText,
  LayoutDashboard,
  LogOut,
  Moon,
  PenSquare,
  Plus,
  Settings,
  Shield,
  Sparkles,
  Sun,
  Trophy,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';
import './AdminWebEditPage.css';

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

const pageOptions = [
  { key: 'home', label: 'Home Page' },
  { key: 'blog', label: 'Blog' },
  { key: 'awareness', label: 'Security Awareness' },
  { key: 'tools', label: 'More Tools' },
];

const initialContent = {
  home: {
    title: 'Protect Your Digital Assets with Advanced Security Testing',
    subtitle: 'Comprehensive vulnerability scanning and penetration testing platform',
    description: 'Start proactive testing that surfaces misconfigurations, weak endpoints, and risky flows before attackers do.',
    primaryButton: 'Start Free Scan',
    secondaryButton: 'View Live Demo',
    features: [
      'Automated Security Scanning',
      'Real-time Threat Intelligence',
      'Comprehensive Reports',
      'API Security Testing',
    ],
    stats: [
      { value: '100,000+', label: 'Scans Completed' },
      { value: '500,000+', label: 'Vulnerabilities Found' },
      { value: '10,000+', label: 'Active Users' },
      { value: '150+', label: 'Countries Served' },
    ],
    ctaTitle: 'Ready to Secure Your Applications?',
    ctaDescription: 'Start your free security scan today. No credit card required.',
    ctaButton: 'Get Started Free',
  },
  blog: {
    title: 'Stay Ahead of Emerging Security Threats',
    subtitle: 'Editorial insights, incident breakdowns, and practical mitigation guides',
    description: 'Keep the blog fresh with high-signal analysis that helps teams react faster and build safer systems.',
    primaryButton: 'Explore Articles',
    secondaryButton: 'Browse Topics',
    features: [
      'Expert-written breakdowns',
      'Fresh vulnerability coverage',
      'Curated reading lists',
      'Actionable response playbooks',
    ],
    stats: [
      { value: '320+', label: 'Published Articles' },
      { value: '45k+', label: 'Monthly Readers' },
      { value: '18', label: 'Contributing Experts' },
      { value: '12', label: 'Featured Categories' },
    ],
    ctaTitle: 'Want alerts for every new post?',
    ctaDescription: 'Subscribe to receive practical security reads directly in your inbox.',
    ctaButton: 'Subscribe Now',
  },
  awareness: {
    title: 'Train Teams to Recognize Real-World Threats',
    subtitle: 'Security awareness content built for modern phishing, malware, and social engineering risks',
    description: 'Shape educational content that keeps employees alert without overwhelming them.',
    primaryButton: 'Launch Awareness Hub',
    secondaryButton: 'Preview Modules',
    features: [
      'Phishing readiness guides',
      'Role-based learning paths',
      'Downloadable checklists',
      'Bite-sized video lessons',
    ],
    stats: [
      { value: '90%', label: 'Completion Rate' },
      { value: '1,200+', label: 'Learners Enrolled' },
      { value: '64', label: 'Training Modules' },
      { value: '28', label: 'Interactive Scenarios' },
    ],
    ctaTitle: 'Make security awareness a weekly habit',
    ctaDescription: 'Publish concise lessons and downloadable assets that teams actually use.',
    ctaButton: 'Enable Training',
  },
  tools: {
    title: 'Give Users More Powerful Security Tools',
    subtitle: 'Expand the utility suite with focused scanners, validators, and quick-win helpers',
    description: 'Control how each tool page positions value, workflows, and future roadmap messaging.',
    primaryButton: 'Open Tool Workbench',
    secondaryButton: 'See Upcoming Tools',
    features: [
      'Domain intelligence checks',
      'Certificate validation',
      'Header and config audits',
      'Fast incident triage helpers',
    ],
    stats: [
      { value: '14', label: 'Tools Available' },
      { value: '52k+', label: 'Monthly Runs' },
      { value: '7', label: 'Tools In Progress' },
      { value: '4.9/5', label: 'Average Rating' },
    ],
    ctaTitle: 'Need a custom security utility next?',
    ctaDescription: 'Use the roadmap section to direct users toward the tools that ship next.',
    ctaButton: 'Request a Tool',
  },
};

function AdminWebEditPage({ onNavigate }) {
  const { theme, toggleTheme } = useTheme();
  const [selectedPage, setSelectedPage] = useState('home');
  const [content, setContent] = useState(initialContent);

  const pageContent = useMemo(() => content[selectedPage], [content, selectedPage]);

  const updateField = (key, value) => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        [key]: value,
      },
    }));
  };

  const updateFeature = (index, value) => {
    setContent((prev) => {
      const nextFeatures = [...prev[selectedPage].features];
      nextFeatures[index] = value;

      return {
        ...prev,
        [selectedPage]: {
          ...prev[selectedPage],
          features: nextFeatures,
        },
      };
    });
  };

  const addFeature = () => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        features: [...prev[selectedPage].features, 'New feature'],
      },
    }));
  };

  const updateStat = (index, field, value) => {
    setContent((prev) => {
      const nextStats = prev[selectedPage].stats.map((item, itemIndex) => (
        itemIndex === index ? { ...item, [field]: value } : item
      ));

      return {
        ...prev,
        [selectedPage]: {
          ...prev[selectedPage],
          stats: nextStats,
        },
      };
    });
  };

  return (
    <div className="admin-web-edit-page">
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
        <aside className="admin-sidebar admin-card admin-web-sidebar">
          <div className="admin-sidebar-group">
            {sidebarItems.map((item) => {
              const Icon = item.icon;
              const isActive = item.id === 'web-edit';

              return (
                <div key={item.id} className="admin-web-sidebar-block">
                  <button
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

                  {item.id === 'web-edit' && (
                    <div className="admin-web-subnav">
                      {pageOptions.map((option) => (
                        <button
                          key={option.key}
                          type="button"
                          className={`admin-web-subnav-link ${selectedPage === option.key ? 'is-active' : ''}`}
                          onClick={() => setSelectedPage(option.key)}
                        >
                          <span className="admin-web-subnav-dot" />
                          <span>{option.label}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </aside>

        <main className="admin-main admin-web-main">
          <section className="admin-web-header">
            <div className="admin-section-head admin-cardless">
              <h1>Website Content Editor</h1>
              <p>Edit and customize your website pages</p>
            </div>

            <div className="admin-web-header-actions">
              <label className="admin-web-page-picker" htmlFor="admin-web-page">
                <Sparkles size={14} />
                <select
                  id="admin-web-page"
                  value={selectedPage}
                  onChange={(event) => setSelectedPage(event.target.value)}
                >
                  {pageOptions.map((option) => (
                    <option key={option.key} value={option.key}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>

              <button type="button" className="admin-web-publish-btn">
                <Plus size={16} />
                <span>Publish Changes</span>
              </button>
            </div>
          </section>

          <section className="admin-web-panel admin-card">
            <div className="admin-web-panel-head">
              <span className="admin-web-panel-icon">
                <Sparkles size={14} />
              </span>
              <h2>Hero Section</h2>
            </div>

            <div className="admin-web-form-grid">
              <label className="admin-web-field admin-web-field-full">
                <span>Main Heading</span>
                <input value={pageContent.title} onChange={(event) => updateField('title', event.target.value)} />
              </label>

              <label className="admin-web-field admin-web-field-full">
                <span>Subheadline</span>
                <input value={pageContent.subtitle} onChange={(event) => updateField('subtitle', event.target.value)} />
              </label>

              <label className="admin-web-field admin-web-field-full">
                <span>Description</span>
                <textarea rows={3} value={pageContent.description} onChange={(event) => updateField('description', event.target.value)} />
              </label>

              <label className="admin-web-field">
                <span>Primary Button Text</span>
                <input value={pageContent.primaryButton} onChange={(event) => updateField('primaryButton', event.target.value)} />
              </label>

              <label className="admin-web-field">
                <span>Secondary Button Text</span>
                <input value={pageContent.secondaryButton} onChange={(event) => updateField('secondaryButton', event.target.value)} />
              </label>
            </div>
          </section>

          <section className="admin-web-panel admin-card">
            <div className="admin-web-panel-head admin-web-panel-head-between">
              <div className="admin-web-panel-head-main">
                <span className="admin-web-panel-icon">
                  <Trophy size={14} />
                </span>
                <h2>Key Features</h2>
              </div>

              <button type="button" className="admin-web-mini-btn" onClick={addFeature}>
                <Plus size={13} />
                <span>Add Feature</span>
              </button>
            </div>

            <div className="admin-web-stack">
              {pageContent.features.map((feature, index) => (
                <label key={`${selectedPage}-feature-${index}`} className="admin-web-feature-field">
                  <textarea rows={2} value={feature} onChange={(event) => updateFeature(index, event.target.value)} />
                </label>
              ))}
            </div>
          </section>

          <section className="admin-web-panel admin-card">
            <div className="admin-web-panel-head">
              <span className="admin-web-panel-icon">
                <FileText size={14} />
              </span>
              <h2>Statistics Section</h2>
            </div>

            <div className="admin-web-stats-grid">
              {pageContent.stats.map((item, index) => (
                <div key={`${selectedPage}-stat-${index}`} className="admin-web-stat-card">
                  <label className="admin-web-field">
                    <span>Value</span>
                    <input value={item.value} onChange={(event) => updateStat(index, 'value', event.target.value)} />
                  </label>
                  <label className="admin-web-field">
                    <span>Label</span>
                    <input value={item.label} onChange={(event) => updateStat(index, 'label', event.target.value)} />
                  </label>
                </div>
              ))}
            </div>
          </section>

          <section className="admin-web-panel admin-card">
            <div className="admin-web-panel-head">
              <span className="admin-web-panel-icon">
                <Plus size={14} />
              </span>
              <h2>Call to Action Section</h2>
            </div>

            <div className="admin-web-form-grid">
              <label className="admin-web-field admin-web-field-full">
                <span>CTA Title</span>
                <input value={pageContent.ctaTitle} onChange={(event) => updateField('ctaTitle', event.target.value)} />
              </label>

              <label className="admin-web-field admin-web-field-full">
                <span>CTA Description</span>
                <textarea rows={3} value={pageContent.ctaDescription} onChange={(event) => updateField('ctaDescription', event.target.value)} />
              </label>

              <label className="admin-web-field admin-web-field-full">
                <span>Button Text</span>
                <input value={pageContent.ctaButton} onChange={(event) => updateField('ctaButton', event.target.value)} />
              </label>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default AdminWebEditPage;
