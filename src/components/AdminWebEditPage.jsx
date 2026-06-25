import { useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  DollarSign,
  Eye,
  EyeOff,
  Download,
  FileText,
  LayoutDashboard,
  LogOut,
  Moon,
  PenSquare,
  Plus,
  RefreshCw,
  Settings,
  Shield,
  Sparkles,
  Sun,
  Trash2,
  Trophy,
  Users,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { blogAPI, contentAPI } from '../services/api';
import './AdminDashboardPage.css';
import './AdminWebEditPage.css';

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
    title: 'Security Insights & Best Practices',
    description: '',
    sectionTitle: 'Featured Articles',
    postsToDisplay: '3',
    categories: [
      'Vulnerability Reports',
      'Security Best Practices',
      'Threat Intelligence',
      'Penetration Testing',
      'Web Application Security',
      'API Security',
    ],
  },
  awareness: {
    title: 'Security Awareness Training Hub',
    description: 'Curated awareness content, practical defenses, and training resources for teams that want security habits to stick.',
    owasp: [
      { rank: '01', name: 'Broken Access Control', link: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
      { rank: '02', name: 'Cryptographic Failures', link: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { rank: '03', name: 'Injection', link: 'https://owasp.org/Top10/A03_2021-Injection/' },
      { rank: '04', name: 'Insecure Design', link: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
      { rank: '05', name: 'Security Misconfiguration', link: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
    ],
    resources: [
      {
        title: 'Phishing Response Essentials',
        type: 'Video',
        url: 'https://www.youtube.com/results?search_query=cisa+phishing+awareness',
        description: 'Short video guidance for spotting and reporting suspicious emails.',
      },
      {
        title: 'MFA Rollout Playbook',
        type: 'Guide',
        url: 'https://www.cisa.gov/secure-our-world/turn-mfa',
        description: 'Step-by-step guidance for rolling out multi-factor authentication.',
      },
      {
        title: 'Secure Coding Foundations',
        type: 'Article',
        url: 'https://owasp.org/www-project-top-ten/',
        description: 'Practical coding habits that reduce common web app risk.',
      },
      {
        title: 'Incident Readiness Checklist',
        type: 'PDF',
        url: 'https://www.cisa.gov/stopransomware',
        description: 'A quick checklist for response, evidence, and recovery.',
      },
      {
        title: 'Password Manager Adoption Guide',
        type: 'Video',
        url: 'https://www.youtube.com/results?search_query=secure+password+manager+guide',
        description: 'How to standardize credential storage for teams and individuals.',
      },
    ],
    downloads: [
      {
        title: 'Security Awareness Checklist',
        description: 'Daily security practices checklist',
        fileMeta: 'PDF | generated instantly',
      },
      {
        title: 'Incident Response Plan Template',
        description: 'Template for handling security incidents',
        fileMeta: 'PDF | generated instantly',
      },
      {
        title: 'Password Manager Comparison',
        description: 'Compare popular password managers',
        fileMeta: 'PDF | generated instantly',
      },
    ],
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

const WEB_EDITOR_STORAGE_KEY = 'threatHuntersAdminWebContent';
const MOJIBAKE_CODES = new Set([195, 194, 216, 217, 197, 65533]);

const looksCorruptedText = (value) => {
  const text = String(value || '').trim();
  if (!text) return false;
  const mojibakeHits = [...text].filter((char) => MOJIBAKE_CODES.has(char.charCodeAt(0))).length;
  const readableHits = (text.match(/[a-z0-9\u0600-\u06ff]/gi) || []).length;
  return mojibakeHits >= 2 || (mojibakeHits >= 1 && readableHits < 4);
};

const cleanAdminText = (value, fallback) => {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return !text || looksCorruptedText(text) ? fallback : text;
};

const sanitizeModerationPost = (post) => ({
  ...post,
  title: cleanAdminText(post.title, 'Community Security Update'),
  description: cleanAdminText(
    post.description || post.content,
    'This post needs an editorial pass before it is highlighted publicly.',
  ),
});

const getInitialEditorContent = () => {
  try {
    const saved = window.localStorage.getItem(WEB_EDITOR_STORAGE_KEY);
    return saved ? { ...initialContent, ...JSON.parse(saved) } : initialContent;
  } catch {
    return initialContent;
  }
};

function AdminWebEditPage({ onNavigate, onLogout, currentPage = 'admin-web-edit' }) {
  const { theme, toggleTheme } = useTheme();
  const [selectedPage, setSelectedPage] = useState('blog');
  const [content, setContent] = useState(getInitialEditorContent);
  const [saveStatus, setSaveStatus] = useState('');
  const [blogPosts, setBlogPosts] = useState([]);
  const [blogPostStatus, setBlogPostStatus] = useState('');

  const pageContent = useMemo(() => content[selectedPage], [content, selectedPage]);

  useEffect(() => {
    let isMounted = true;
    const loadContent = async () => {
      try {
        const remoteContent = await contentAPI.getContent();
        if (isMounted && remoteContent) {
          setContent((prev) => ({ ...prev, ...remoteContent }));
        }
      } catch {
        // Keep local fallback if the API is offline.
      }
    };

    loadContent();

    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(WEB_EDITOR_STORAGE_KEY, JSON.stringify(content));
    } catch {
      // Keep editing usable even if browser storage is blocked.
    }
  }, [content]);

  useEffect(() => {
    if (selectedPage !== 'blog') {
      return;
    }

    let isMounted = true;
    const loadBlogPosts = async () => {
      try {
        setBlogPostStatus('Loading posts...');
        const payload = await blogAPI.getPosts({ includeHidden: true });
        const nextPosts = Array.isArray(payload) ? payload : payload?.posts || [];
        if (isMounted) {
          setBlogPosts(nextPosts.map(sanitizeModerationPost));
          setBlogPostStatus('');
        }
      } catch (error) {
        if (isMounted) {
          setBlogPostStatus(error.message || 'Unable to load blog posts.');
        }
      }
    };

    loadBlogPosts();

    return () => {
      isMounted = false;
    };
  }, [selectedPage]);

  const handlePublish = async () => {
    if (!String(pageContent.title || '').trim()) {
      setSaveStatus('Page title is required before publishing.');
      return;
    }

    if (Array.isArray(pageContent.features) && pageContent.features.some((feature) => !String(feature || '').trim())) {
      setSaveStatus('Feature rows cannot be empty.');
      return;
    }

    if (Array.isArray(pageContent.stats) && pageContent.stats.some((item) => !String(item.value || '').trim() || !String(item.label || '').trim())) {
      setSaveStatus('Statistic value and label are required.');
      return;
    }

    if (selectedPage === 'awareness') {
      const invalidLink = (pageContent.owasp || []).some((item) => item.link && !/^https?:\/\//i.test(item.link));
      if (invalidLink) {
        setSaveStatus('OWASP links must start with http:// or https://.');
        return;
      }
    }

    if (selectedPage === 'blog') {
      const postCount = Number(pageContent.postsToDisplay || 0);
      if (!Number.isFinite(postCount) || postCount < 1) {
        setSaveStatus('Number of posts to display must be at least 1.');
        return;
      }
    }

    try {
      setSaveStatus('Saving to backend...');
      await contentAPI.updateContent(selectedPage, pageContent);
      setSaveStatus('Changes saved to backend.');
    } catch (error) {
      setSaveStatus(error.message || 'Unable to publish changes.');
    }
  };

  const reloadBlogPosts = async () => {
    try {
      setBlogPostStatus('Refreshing posts...');
      const payload = await blogAPI.getPosts({ includeHidden: true });
      const nextPosts = Array.isArray(payload) ? payload : payload?.posts || [];
      setBlogPosts(nextPosts.map(sanitizeModerationPost));
      setBlogPostStatus('');
    } catch (error) {
      setBlogPostStatus(error.message || 'Unable to refresh blog posts.');
    }
  };

  const togglePostVisibility = async (post) => {
    const nextStatus = post.status === 'hidden' ? 'published' : 'hidden';

    try {
      setBlogPostStatus(nextStatus === 'hidden' ? 'Hiding post...' : 'Publishing post...');
      await blogAPI.setPostStatus(post.id, nextStatus);
      await reloadBlogPosts();
      setBlogPostStatus(nextStatus === 'hidden' ? 'Post hidden from public blog.' : 'Post published successfully.');
    } catch (error) {
      setBlogPostStatus(error.message || 'Unable to update post visibility.');
    }
  };

  const deleteBlogPost = async (postId) => {
    if (!window.confirm('Delete this blog post permanently?')) {
      return;
    }

    try {
      setBlogPostStatus('Deleting post...');
      await blogAPI.deletePost(postId);
      await reloadBlogPosts();
      setBlogPostStatus('Post deleted.');
    } catch (error) {
      setBlogPostStatus(error.message || 'Unable to delete post.');
    }
  };

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

  const removeFeature = (index) => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        features: prev[selectedPage].features.filter((_, itemIndex) => itemIndex !== index),
      },
    }));
  };

  const updateListItem = (listKey, index, value) => {
    setContent((prev) => {
      const nextItems = [...prev[selectedPage][listKey]];
      nextItems[index] = value;

      return {
        ...prev,
        [selectedPage]: {
          ...prev[selectedPage],
          [listKey]: nextItems,
        },
      };
    });
  };

  const updateAwarenessItem = (listKey, index, field, value) => {
    setContent((prev) => ({
      ...prev,
      awareness: {
        ...prev.awareness,
        [listKey]: prev.awareness[listKey].map((item, itemIndex) => (
          itemIndex === index ? { ...item, [field]: value } : item
        )),
      },
    }));
  };

  const addListItem = (listKey, value) => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        [listKey]: [...prev[selectedPage][listKey], value],
      },
    }));
  };

  const addAwarenessItem = (listKey) => {
    const baseItem = listKey === 'downloads'
      ? { title: 'New Download', description: 'Update this resource', fileMeta: 'PDF | generated instantly' }
      : { title: 'New Resource', type: 'Guide', url: 'https://example.com', description: 'Describe this training resource.' };

    setContent((prev) => ({
      ...prev,
      awareness: {
        ...prev.awareness,
        [listKey]: [...prev.awareness[listKey], baseItem],
      },
    }));
  };

  const removeListItem = (listKey, index) => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        [listKey]: prev[selectedPage][listKey].filter((_, itemIndex) => itemIndex !== index),
      },
    }));
  };

  const updateOwasp = (index, field, value) => {
    setContent((prev) => ({
      ...prev,
      awareness: {
        ...prev.awareness,
        owasp: prev.awareness.owasp.map((item, itemIndex) => (
          itemIndex === index ? { ...item, [field]: value } : item
        )),
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

  const addStat = () => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        stats: [...prev[selectedPage].stats, { value: '0', label: 'New metric' }],
      },
    }));
  };

  const removeStat = (index) => {
    setContent((prev) => ({
      ...prev,
      [selectedPage]: {
        ...prev[selectedPage],
        stats: prev[selectedPage].stats.filter((_, itemIndex) => itemIndex !== index),
      },
    }));
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

              <button type="button" className="admin-web-publish-btn" onClick={handlePublish}>
                <FileText size={16} />
                <span>Publish Changes</span>
              </button>
            </div>
          </section>
          {saveStatus && <div className="admin-web-save-status">{saveStatus}</div>}

          {selectedPage === 'blog' && (
            <>
              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head">
                  <span className="admin-web-panel-icon">
                    <FileText size={14} />
                  </span>
                  <h2>Blog Page Header</h2>
                </div>

                <div className="admin-web-form-grid">
                  <label className="admin-web-field admin-web-field-full">
                    <span>Page Title</span>
                    <input value={pageContent.title} onChange={(event) => updateField('title', event.target.value)} />
                  </label>

                  <label className="admin-web-field admin-web-field-full">
                    <span>Description</span>
                    <textarea rows={4} value={pageContent.description} onChange={(event) => updateField('description', event.target.value)} />
                  </label>
                </div>
              </section>

              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head admin-web-panel-head-between">
                  <div className="admin-web-panel-head-main">
                    <span className="admin-web-panel-icon">
                      <Sparkles size={14} />
                    </span>
                    <h2>Blog Categories</h2>
                  </div>

                  <button type="button" className="admin-web-mini-btn" onClick={() => addListItem('categories', 'New Category')}>
                    <Plus size={13} />
                    <span>Add Category</span>
                  </button>
                </div>

                <div className="admin-web-stack">
                  {pageContent.categories.map((category, index) => (
                    <div key={`${selectedPage}-category-${category}`} className="admin-web-removable-row">
                      <input value={category} onChange={(event) => updateListItem('categories', index, event.target.value)} />
                      <button type="button" onClick={() => removeListItem('categories', index)} aria-label={`Remove ${category}`}>
                        x
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head">
                  <span className="admin-web-panel-icon">
                    <FileText size={14} />
                  </span>
                  <h2>Featured Posts Section</h2>
                </div>

                <div className="admin-web-form-grid">
                  <label className="admin-web-field admin-web-field-full">
                    <span>Section Title</span>
                    <input value={pageContent.sectionTitle} onChange={(event) => updateField('sectionTitle', event.target.value)} />
                  </label>
                  <label className="admin-web-field admin-web-field-full">
                    <span>Number of Posts to Display</span>
                    <input value={pageContent.postsToDisplay} onChange={(event) => updateField('postsToDisplay', event.target.value)} />
                  </label>
                </div>
              </section>

              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head admin-web-panel-head-between">
                  <div className="admin-web-panel-head-main">
                    <span className="admin-web-panel-icon">
                      <PenSquare size={14} />
                    </span>
                    <h2>Post Moderation</h2>
                  </div>

                  <button type="button" className="admin-web-mini-btn" onClick={reloadBlogPosts}>
                    <RefreshCw size={13} />
                    <span>Refresh</span>
                  </button>
                </div>

                <div className="admin-web-post-list">
                  {blogPosts.map((post) => {
                    const isHidden = (post.status || 'published') === 'hidden';

                    return (
                      <article key={post.id} className={`admin-web-post-row ${isHidden ? 'is-hidden' : ''}`}>
                        <div className="admin-web-post-copy">
                          <div className="admin-web-post-title-line">
                            <strong>{post.title}</strong>
                            <span className={`admin-web-post-status ${isHidden ? 'is-hidden' : 'is-published'}`}>
                              {isHidden ? 'Hidden' : 'Published'}
                            </span>
                          </div>
                          <p>{post.description || post.content || 'No description yet.'}</p>
                        </div>

                        <div className="admin-web-post-actions">
                          <button
                            type="button"
                            className="admin-web-icon-btn"
                            onClick={() => togglePostVisibility(post)}
                            aria-label={isHidden ? `Publish ${post.title}` : `Hide ${post.title}`}
                          >
                            {isHidden ? <Eye size={15} /> : <EyeOff size={15} />}
                          </button>
                          <button
                            type="button"
                            className="admin-web-icon-btn is-danger"
                            onClick={() => deleteBlogPost(post.id)}
                            aria-label={`Delete ${post.title}`}
                          >
                            <Trash2 size={15} />
                          </button>
                        </div>
                      </article>
                    );
                  })}

                  {!blogPosts.length && (
                    <div className="admin-web-empty-posts">
                      No posts found yet.
                    </div>
                  )}
                </div>

                {blogPostStatus && <div className="admin-web-save-status">{blogPostStatus}</div>}
              </section>
            </>
          )}

          {selectedPage === 'awareness' && (
            <>
              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head">
                  <span className="admin-web-panel-icon">
                    <Shield size={14} />
                  </span>
                  <h2>Security Awareness Header</h2>
                </div>

                <div className="admin-web-form-grid">
                  <label className="admin-web-field admin-web-field-full">
                    <span>Page Title</span>
                    <input value={pageContent.title} onChange={(event) => updateField('title', event.target.value)} />
                  </label>
                  <label className="admin-web-field admin-web-field-full">
                    <span>Description</span>
                    <textarea rows={4} value={pageContent.description} onChange={(event) => updateField('description', event.target.value)} />
                  </label>
                </div>
              </section>

              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head">
                  <span className="admin-web-panel-icon">
                    <Shield size={14} />
                  </span>
                  <h2>OWASP Top 10 Vulnerabilities</h2>
                </div>

                <div className="admin-web-stack">
                  {pageContent.owasp.map((item, index) => (
                    <div key={item.rank} className="admin-web-owasp-row">
                      <span>{item.rank}</span>
                      <input value={item.name} onChange={(event) => updateOwasp(index, 'name', event.target.value)} />
                      <input value={item.link} onChange={(event) => updateOwasp(index, 'link', event.target.value)} />
                    </div>
                  ))}
                </div>
              </section>

              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head admin-web-panel-head-between">
                  <div className="admin-web-panel-head-main">
                    <span className="admin-web-panel-icon">
                      <FileText size={14} />
                    </span>
                    <h2>Training Resources</h2>
                  </div>
                  <button type="button" className="admin-web-mini-btn" onClick={() => addAwarenessItem('resources')}>
                    <Plus size={13} />
                    <span>Add Resource</span>
                  </button>
                </div>
                <div className="admin-web-stack">
                  {pageContent.resources.map((resource, index) => (
                    <div key={`${selectedPage}-resource-${resource.title || index}`} className="admin-web-resource-card">
                      <div className="admin-web-form-grid">
                        <label className="admin-web-field">
                          <span>Title</span>
                          <input value={resource.title} onChange={(event) => updateAwarenessItem('resources', index, 'title', event.target.value)} />
                        </label>
                        <label className="admin-web-field">
                          <span>Type</span>
                          <input value={resource.type} onChange={(event) => updateAwarenessItem('resources', index, 'type', event.target.value)} />
                        </label>
                        <label className="admin-web-field admin-web-field-full">
                          <span>Link</span>
                          <input value={resource.url} onChange={(event) => updateAwarenessItem('resources', index, 'url', event.target.value)} />
                        </label>
                        <label className="admin-web-field admin-web-field-full">
                          <span>Description</span>
                          <textarea rows={2} value={resource.description} onChange={(event) => updateAwarenessItem('resources', index, 'description', event.target.value)} />
                        </label>
                      </div>
                      <button type="button" onClick={() => removeListItem('resources', index)} aria-label={`Remove ${resource.title}`}>
                        x
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="admin-web-panel admin-card">
                <div className="admin-web-panel-head admin-web-panel-head-between">
                  <div className="admin-web-panel-head-main">
                    <span className="admin-web-panel-icon">
                      <Download size={14} />
                    </span>
                    <h2>Downloadable PDFs</h2>
                  </div>
                  <button type="button" className="admin-web-mini-btn" onClick={() => addAwarenessItem('downloads')}>
                    <Plus size={13} />
                    <span>Add PDF</span>
                  </button>
                </div>
                <div className="admin-web-stack">
                  {pageContent.downloads.map((download, index) => (
                    <div key={`${selectedPage}-download-${download.title || index}`} className="admin-web-resource-card">
                      <div className="admin-web-form-grid">
                        <label className="admin-web-field">
                          <span>Title</span>
                          <input value={download.title} onChange={(event) => updateAwarenessItem('downloads', index, 'title', event.target.value)} />
                        </label>
                        <label className="admin-web-field">
                          <span>File Meta</span>
                          <input value={download.fileMeta} onChange={(event) => updateAwarenessItem('downloads', index, 'fileMeta', event.target.value)} />
                        </label>
                        <label className="admin-web-field admin-web-field-full">
                          <span>Description</span>
                          <textarea rows={2} value={download.description} onChange={(event) => updateAwarenessItem('downloads', index, 'description', event.target.value)} />
                        </label>
                      </div>
                      <button type="button" onClick={() => removeListItem('downloads', index)} aria-label={`Remove ${download.title}`}>
                        x
                      </button>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}

          {(selectedPage === 'home' || selectedPage === 'tools') && (
            <>
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
                <div key={`${selectedPage}-feature-${index}`} className="admin-web-removable-row">
                  <textarea rows={2} value={feature} onChange={(event) => updateFeature(index, event.target.value)} />
                  <button type="button" onClick={() => removeFeature(index)} aria-label={`Remove feature ${index + 1}`}>
                    x
                  </button>
                </div>
              ))}
            </div>
          </section>

          <section className="admin-web-panel admin-card">
            <div className="admin-web-panel-head admin-web-panel-head-between">
              <div className="admin-web-panel-head-main">
                <span className="admin-web-panel-icon">
                  <FileText size={14} />
                </span>
                <h2>Statistics Section</h2>
              </div>

              <button type="button" className="admin-web-mini-btn" onClick={addStat}>
                <Plus size={13} />
                <span>Add Statistic</span>
              </button>
            </div>

            <div className="admin-web-stats-grid">
              {pageContent.stats.map((item, index) => (
                <div key={`${selectedPage}-stat-${index}`} className="admin-web-stat-card">
                  <button type="button" className="admin-web-stat-remove" onClick={() => removeStat(index)} aria-label={`Remove ${item.label}`}>
                    x
                  </button>
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
            </>
          )}
        </main>
      </div>
    </div>
  );
}

export default AdminWebEditPage;
