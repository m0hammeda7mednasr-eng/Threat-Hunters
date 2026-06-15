import { memo, useCallback, useEffect, useMemo, useState } from 'react';
import {
  BookOpen,
  Bot,
  Bug,
  Clock3,
  Download,
  ExternalLink,
  FileText,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Mail,
  Search,
  Shield,
  ShieldCheck,
  ShieldX,
  Smartphone,
  TriangleAlert,
  Video,
  Wifi,
  Zap,
} from 'lucide-react';
import './SecurityAwarenessPage.css';
import Navbar from './Navbar';
import Footer from './Footer';
import { securityAPI } from '../services/api';

const securityTips = [
  {
    id: 'passwords',
    icon: LockKeyhole,
    title: 'Use Strong Passwords',
    description:
      'Create unique passwords with at least 12 characters including numbers, symbols, and mixed case letters.',
  },
  {
    id: 'two-factor',
    icon: KeyRound,
    title: 'Enable Two-Factor Authentication',
    description:
      'Add an extra layer of security by enabling 2FA on all your important accounts.',
  },
  {
    id: 'phishing',
    icon: Mail,
    title: 'Beware of Phishing',
    description: "Don't click suspicious links or download attachments from unknown senders.",
  },
  {
    id: 'network',
    icon: Wifi,
    title: 'Secure Your Network',
    description:
      'Use WPA3 encryption for WiFi and avoid using public networks for sensitive tasks.',
  },
  {
    id: 'updates',
    icon: Smartphone,
    title: 'Keep Software Updated',
    description:
      'Regularly update your operating system and applications to patch security vulnerabilities.',
  },
  {
    id: 'backups',
    icon: ShieldCheck,
    title: 'Backup Your Data',
    description:
      'Create regular backups of important files and store them in multiple secure locations.',
  },
];

const knowledgeBadges = [
  { id: 'offensive', icon: Shield, label: 'Offensive Security', tone: 'blue' },
  { id: 'website', icon: ShieldX, label: 'Protect Your Website', tone: 'red' },
  { id: 'behavior', icon: Fingerprint, label: 'Understands attacker behavior', tone: 'violet' },
  { id: 'actionable', icon: TriangleAlert, label: 'Actionable Security', tone: 'red' },
  { id: 'web', icon: Bug, label: 'Web Exploit Analysis', tone: 'blue' },
  { id: 'agent', icon: Bot, label: 'AI Security Agent', tone: 'blue' },
];

const cyberThreats = [
  {
    id: 'phishing-attacks',
    icon: TriangleAlert,
    title: 'Phishing Attacks',
    badge: 'High',
    tone: 'high',
    description:
      'Fraudulent emails or messages designed to steal your credentials or personal information.',
    howToAvoid: [
      'Verify sender email addresses carefully',
      "Don't click on suspicious links",
      'Check for spelling and grammar errors',
      'Contact the company directly if unsure',
    ],
  },
  {
    id: 'malware-ransomware',
    icon: Bug,
    title: 'Malware & Ransomware',
    badge: 'Critical',
    tone: 'critical',
    description:
      'Malicious software that can damage your system or encrypt your files for ransom.',
    howToAvoid: [
      'Install reputable antivirus software',
      "Don't download from untrusted sources",
      'Keep your system updated',
      'Backup important files regularly',
    ],
  },
  {
    id: 'social-engineering',
    icon: Zap,
    title: 'Social Engineering',
    badge: 'Medium',
    tone: 'medium',
    description:
      'Manipulating people into revealing confidential information or performing actions.',
    howToAvoid: [
      'Be skeptical of unexpected requests',
      'Verify identity before sharing info',
      "Don't share passwords or codes",
      'Trust your instincts',
    ],
  },
  {
    id: 'weak-passwords',
    icon: Smartphone,
    title: 'Weak Passwords',
    badge: 'Low',
    tone: 'low',
    description: 'Using simple or reused passwords makes your accounts vulnerable to attacks.',
    howToAvoid: [
      'Use password managers',
      'Create unique passwords per account',
      'Use passphrases instead of passwords',
      'Enable multi-factor authentication',
    ],
  },
];

const learningResources = [
  {
    id: 'password-guide',
    icon: FileText,
    type: 'Article',
    topic: 'Basics',
    title: 'Complete Guide to Password Security',
    description: 'Everything you need to know about creating and managing secure passwords.',
    duration: '8 min read',
  },
  {
    id: 'phishing-video',
    icon: Video,
    type: 'Video',
    topic: 'Threats',
    title: 'Understanding Phishing Attacks',
    description: 'Learn to identify and avoid phishing attempts with real examples.',
    duration: '12 min',
  },
  {
    id: 'two-factor-guide',
    icon: BookOpen,
    type: 'Guide',
    topic: 'Basics',
    title: 'Setting Up Two-Factor Authentication',
    description: 'Step-by-step guide to enable 2FA on popular platforms.',
    duration: '5 min read',
  },
  {
    id: 'ransomware-article',
    icon: FileText,
    type: 'Article',
    topic: 'Threats',
    title: 'Ransomware: Prevention and Recovery',
    description: 'How to protect against ransomware and what to do if infected.',
    duration: '10 min read',
  },
  {
    id: 'network-video',
    icon: Video,
    type: 'Video',
    topic: 'Network',
    title: 'Secure Your Home Network',
    description: 'Best practices for securing your WiFi and home devices.',
    duration: '15 min',
  },
  {
    id: 'social-guide',
    icon: BookOpen,
    type: 'Guide',
    topic: 'Threats',
    title: 'Social Engineering Tactics',
    description: 'Recognize and defend against social engineering attacks.',
    duration: '7 min read',
  },
];

const downloadableResources = [
  {
    id: 'checklist',
    title: 'Security Awareness Checklist',
    description: 'Daily security practices checklist',
    fileMeta: 'PDF • 2.4 MB',
  },
  {
    id: 'incident-plan',
    title: 'Incident Response Plan Template',
    description: 'Template for handling security incidents',
    fileMeta: 'PDF • 1.8 MB',
  },
  {
    id: 'password-managers',
    title: 'Password Manager Comparison',
    description: 'Compare popular password managers',
    fileMeta: 'PDF • 3.2 MB',
  },
];

const normalizeList = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.vulnerabilities)) return payload.vulnerabilities;
  if (Array.isArray(payload?.news)) return payload.news;
  return [];
};

const SecurityAwarenessPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToTools,
  isLoggedIn,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [liveFeed, setLiveFeed] = useState({
    latestCves: [],
    criticalCves: [],
    kev: [],
    news: [],
  });
  const [liveLoading, setLiveLoading] = useState(true);
  const [liveError, setLiveError] = useState('');
  const [liveUpdatedAt, setLiveUpdatedAt] = useState('');
  const badgeTrack = [...knowledgeBadges, ...knowledgeBadges];
  const normalizedSearch = searchQuery.trim().toLowerCase();

  const itemMatchesSearch = useCallback(
    (fields) => !normalizedSearch || fields.join(' ').toLowerCase().includes(normalizedSearch),
    [normalizedSearch],
  );

  const filteredSecurityTips = useMemo(
    () => securityTips.filter((tip) => itemMatchesSearch([tip.title, tip.description])),
    [itemMatchesSearch],
  );
  const filteredCyberThreats = useMemo(
    () =>
      cyberThreats.filter((threat) =>
        itemMatchesSearch([threat.title, threat.description, threat.badge, ...threat.howToAvoid]),
      ),
    [itemMatchesSearch],
  );
  const filteredLearningResources = useMemo(
    () =>
      learningResources.filter((resource) =>
        itemMatchesSearch([resource.type, resource.topic, resource.title, resource.description]),
      ),
    [itemMatchesSearch],
  );
  const filteredDownloadableResources = useMemo(
    () =>
      downloadableResources.filter((resource) =>
        itemMatchesSearch([resource.title, resource.description, resource.fileMeta]),
      ),
    [itemMatchesSearch],
  );

  const loadLiveFeed = useCallback(async () => {
    setLiveLoading(true);
    setLiveError('');

    const [latestResult, criticalResult, kevResult, newsResult] = await Promise.allSettled([
      securityAPI.getLatestCVEs(),
      securityAPI.getCriticalCVEs(),
      securityAPI.getKEV(),
      securityAPI.getSecurityNews(),
    ]);

    const nextFeed = {
      latestCves: latestResult.status === 'fulfilled' ? normalizeList(latestResult.value) : [],
      criticalCves: criticalResult.status === 'fulfilled' ? normalizeList(criticalResult.value) : [],
      kev: kevResult.status === 'fulfilled' ? normalizeList(kevResult.value) : [],
      news: newsResult.status === 'fulfilled' ? normalizeList(newsResult.value) : [],
    };

    const failedFeeds = [];
    if (latestResult.status === 'rejected') failedFeeds.push('latest CVEs');
    if (criticalResult.status === 'rejected') failedFeeds.push('critical CVEs');
    if (kevResult.status === 'rejected') failedFeeds.push('KEV');
    if (newsResult.status === 'rejected') failedFeeds.push('security news');

    setLiveFeed(nextFeed);
    setLiveUpdatedAt(new Date().toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    }));
    setLiveError(
      failedFeeds.length
        ? `Some live security feeds failed to load: ${failedFeeds.join(', ')}.`
        : '',
    );
    setLiveLoading(false);
  }, []);

  useEffect(() => {
    queueMicrotask(() => {
      void loadLiveFeed();
    });
  }, [loadLiveFeed]);

  return (
    <div className="security-awareness-page">
      {!isLoggedIn && (
        <Navbar
          onNavigateToSignUp={onNavigateToSignUp}
          onNavigateToHome={onNavigateToHome}
          onNavigateToBlog={onNavigateToBlog}
          onNavigateToTools={onNavigateToTools}
          currentPage="awareness"
        />
      )}

      <section className="awareness-hero">
        <div className="awareness-shell awareness-hero__shell">
          <div className="awareness-hero__icon" aria-hidden="true">
            <BookOpen strokeWidth={1.8} />
          </div>
          <h1 className="awareness-hero__title">Security Awareness</h1>
          <p className="awareness-hero__subtitle">
            Learn how to protect yourself and your organization from cyber threats
          </p>
          <label className="awareness-hero__search" aria-label="Search for security topics">
            <Search strokeWidth={2} />
            <input
              type="text"
              placeholder="Search for security topics..."
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
            />
          </label>
        </div>
      </section>

      <section className="awareness-section awareness-section--live">
        <div className="awareness-shell">
          <header className="awareness-live__header">
            <div>
              <p className="awareness-live__eyebrow">Live Security Intelligence</p>
              <h2 className="awareness-section__title">API-backed threat feed</h2>
              <p className="awareness-section__subtitle">
                Pulled live from NVD, CISA KEV, and security news endpoints.
              </p>
            </div>

            <div className="awareness-live__actions">
              <span className="awareness-live__status">
                {liveLoading ? 'Refreshing feed...' : `Updated ${liveUpdatedAt || 'just now'}`}
              </span>
              <button type="button" className="awareness-live__refresh" onClick={loadLiveFeed} disabled={liveLoading}>
                {liveLoading ? 'Loading...' : 'Refresh feed'}
              </button>
            </div>
          </header>

          {liveError && <div className="awareness-empty-state awareness-empty-state--live">{liveError}</div>}

          <div className="awareness-live-grid">
            <article className="awareness-live-card">
              <div className="awareness-live-card__header">
                <span>Latest CVEs</span>
                <span className="awareness-live-card__count">{liveFeed.latestCves.length}</span>
              </div>
              <ul className="awareness-live-card__list">
                {liveLoading && !liveFeed.latestCves.length ? (
                  <li className="awareness-live-card__placeholder">Loading latest CVEs...</li>
                ) : (
                  liveFeed.latestCves.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.cve || index}`} className="awareness-live-card__item">
                      <strong>{item.id || item.cve || item.cve_id || 'Unknown CVE'}</strong>
                      <span>{item.severity || item.score ? `${item.severity || 'Unknown'}${item.score ? ` | ${item.score}` : ''}` : 'Unrated'}</span>
                      <p>{item.description || item.short_description || 'No description provided.'}</p>
                    </li>
                  ))
                )}
              </ul>
            </article>

            <article className="awareness-live-card">
              <div className="awareness-live-card__header">
                <span>Critical CVEs</span>
                <span className="awareness-live-card__count">{liveFeed.criticalCves.length}</span>
              </div>
              <ul className="awareness-live-card__list">
                {liveLoading && !liveFeed.criticalCves.length ? (
                  <li className="awareness-live-card__placeholder">Loading critical CVEs...</li>
                ) : (
                  liveFeed.criticalCves.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.cve || item.cve_id || index}`} className="awareness-live-card__item">
                      <strong>{item.id || item.cve || item.cve_id || 'Unknown CVE'}</strong>
                      <span>{item.component || item.category || item.score ? `${item.component || item.category || 'High priority'}${item.score ? ` | ${item.score}` : ''}` : 'Critical priority'}</span>
                      <p>{item.description || item.short_description || 'Immediate review recommended.'}</p>
                    </li>
                  ))
                )}
              </ul>
            </article>

            <article className="awareness-live-card">
              <div className="awareness-live-card__header">
                <span>Known Exploited</span>
                <span className="awareness-live-card__count">{liveFeed.kev.length}</span>
              </div>
              <ul className="awareness-live-card__list">
                {liveLoading && !liveFeed.kev.length ? (
                  <li className="awareness-live-card__placeholder">Loading KEV list...</li>
                ) : (
                  liveFeed.kev.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.cveID || item.cve_id || index}`} className="awareness-live-card__item">
                      <strong>{item.id || item.cveID || item.cve_id || 'Unknown CVE'}</strong>
                      <span>{item.dueDate || item.due_date || 'No due date'}</span>
                      <p>{item.status || item.required_action || item.short_description || 'Exploited vulnerability tracked by CISA.'}</p>
                    </li>
                  ))
                )}
              </ul>
            </article>

            <article className="awareness-live-card">
              <div className="awareness-live-card__header">
                <span>Security News</span>
                <span className="awareness-live-card__count">{liveFeed.news.length}</span>
              </div>
              <ul className="awareness-live-card__list">
                {liveLoading && !liveFeed.news.length ? (
                  <li className="awareness-live-card__placeholder">Loading security news...</li>
                ) : (
                  liveFeed.news.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.title || index}`} className="awareness-live-card__item">
                      <strong>{item.title || item.headline || 'Untitled update'}</strong>
                      <span>{item.source || item.publisher || 'Security feed'}</span>
                      <p>{item.summary || item.description || item.short_description || 'Fresh threat intelligence update.'}</p>
                    </li>
                  ))
                )}
              </ul>
            </article>
          </div>
        </div>
      </section>

      <section className="awareness-section awareness-section--tips">
        <div className="awareness-shell">
          <header className="awareness-section__header">
            <h2 className="awareness-section__title">Essential Security Tips</h2>
            <p className="awareness-section__subtitle">
              Simple steps to improve your security posture
            </p>
          </header>

          <div className="tips-grid">
            {filteredSecurityTips.map((tip) => {
              const Icon = tip.icon;

              return (
                <article key={tip.id} className="tip-card">
                  <div className="tip-card__icon-box" aria-hidden="true">
                    <Icon strokeWidth={1.85} />
                  </div>
                  <h3 className="tip-card__title">{tip.title}</h3>
                  <p className="tip-card__description">{tip.description}</p>
                </article>
              );
            })}
            {!filteredSecurityTips.length && (
              <div className="awareness-empty-state">No security tips match this search.</div>
            )}
          </div>
        </div>
      </section>

      <section className="awareness-marquee" aria-label="Security topics">
        <div className="awareness-marquee__row">
          <div className="awareness-marquee__track awareness-marquee__track--forward">
            {badgeTrack.map((item, index) => {
              const Icon = item.icon;

              return (
                <div
                  key={`${item.id}-forward-${index}`}
                  className={`awareness-marquee__item awareness-marquee__item--${item.tone}`}
                >
                  <Icon strokeWidth={1.8} />
                  <span>{item.label}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="awareness-marquee__row">
          <div className="awareness-marquee__track awareness-marquee__track--reverse">
            {badgeTrack.map((item, index) => {
              const Icon = item.icon;

              return (
                <div
                  key={`${item.id}-reverse-${index}`}
                  className={`awareness-marquee__item awareness-marquee__item--${item.tone}`}
                >
                  <Icon strokeWidth={1.8} />
                  <span>{item.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="awareness-section awareness-section--threats">
        <div className="awareness-shell">
          <header className="awareness-section__header">
            <h2 className="awareness-section__title">Common Cyber Threats</h2>
            <p className="awareness-section__subtitle">
              Learn about the most common threats and how to protect yourself
            </p>
          </header>

          <div className="threats-grid">
            {filteredCyberThreats.map((threat) => {
              const Icon = threat.icon;

              return (
                <article key={threat.id} className={`threat-card threat-card--${threat.tone}`}>
                  <div className="threat-card__intro">
                    <div className="threat-card__icon-box" aria-hidden="true">
                      <Icon strokeWidth={1.85} />
                    </div>
                    <div className="threat-card__heading">
                      <div className="threat-card__heading-row">
                        <h3>{threat.title}</h3>
                        <span className="threat-card__badge">{threat.badge}</span>
                      </div>
                      <p>{threat.description}</p>
                    </div>
                  </div>

                  <div className="threat-card__details">
                    <p className="threat-card__details-title">How to avoid:</p>
                    <ul className="threat-card__list">
                      {threat.howToAvoid.map((tip) => (
                        <li key={tip}>{tip}</li>
                      ))}
                    </ul>
                  </div>
                </article>
              );
            })}
            {!filteredCyberThreats.length && (
              <div className="awareness-empty-state">No cyber threats match this search.</div>
            )}
          </div>
        </div>
      </section>

      <section className="awareness-section awareness-section--resources">
        <div className="awareness-shell">
          <header className="awareness-section__header">
            <h2 className="awareness-section__title">Learning Resources</h2>
            <p className="awareness-section__subtitle">
              Guides, articles, and videos to enhance your security knowledge
            </p>
          </header>

          <div className="resources-grid">
            {filteredLearningResources.map((resource) => {
              const Icon = resource.icon;

              return (
                <article key={resource.id} className="resource-card">
                  <div className="resource-card__meta">
                    <div className="resource-card__pill-group">
                      <span className="resource-card__pill resource-card__pill--type">
                        <Icon strokeWidth={1.8} />
                        <span>{resource.type}</span>
                      </span>
                    </div>
                    <span className="resource-card__pill resource-card__pill--topic">
                      {resource.topic}
                    </span>
                  </div>

                  <h3 className="resource-card__title">{resource.title}</h3>
                  <p className="resource-card__description">{resource.description}</p>

                  <div className="resource-card__footer">
                    <span className="resource-card__duration">
                      <Clock3 strokeWidth={1.8} />
                      <span>{resource.duration}</span>
                    </span>

                    <button
                      type="button"
                      className="resource-card__action"
                      aria-label={`Open ${resource.title}`}
                    >
                      <ExternalLink strokeWidth={1.8} />
                    </button>
                  </div>
                </article>
              );
            })}
            {!filteredLearningResources.length && (
              <div className="awareness-empty-state">No learning resources match this search.</div>
            )}
          </div>

          <section className="downloads-panel">
            <header className="downloads-panel__header">
              <div className="downloads-panel__title-wrap">
                <Download strokeWidth={1.9} />
                <div>
                  <h3>Downloadable Resources</h3>
                  <p>Free templates and guides</p>
                </div>
              </div>
            </header>

            <div className="downloads-grid">
              {filteredDownloadableResources.map((resource) => (
                <article key={resource.id} className="download-card">
                  <div className="download-card__content">
                    <div className="download-card__heading-row">
                      <h4>{resource.title}</h4>
                      <button
                        type="button"
                        className="download-card__action"
                        aria-label={`Download ${resource.title}`}
                      >
                        <Download strokeWidth={1.9} />
                      </button>
                    </div>
                    <p>{resource.description}</p>
                    <span className="download-card__meta">{resource.fileMeta}</span>
                  </div>
                </article>
              ))}
              {!filteredDownloadableResources.length && (
                <div className="awareness-empty-state">No downloads match this search.</div>
              )}
            </div>
          </section>
        </div>
      </section>

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(SecurityAwarenessPage);
