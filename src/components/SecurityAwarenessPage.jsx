import { memo, useCallback, useEffect, useMemo, useState } from 'react';
import {
  BookOpen,
  Bot,
  Bug,
  Clock3,
  Download,
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
import { buildBrandedPdfBlob, downloadPdfBlob } from '../utils/pdfBuilder';

const securityTips = [
  {
    id: 'passwords',
    icon: LockKeyhole,
    title: 'Strengthen Passwords',
    description: 'Use unique passphrases with 12+ characters and a mix of symbols, numbers, and letter cases.',
  },
  {
    id: 'two-factor',
    icon: KeyRound,
    title: 'Enable Multi-Factor Authentication',
    description: 'Turn on MFA for accounts that support it to reduce account takeover risk.',
  },
  {
    id: 'phishing',
    icon: Mail,
    title: 'Verify Messages Before Acting',
    description: 'Treat unexpected links, attachments, and login prompts as suspicious until verified.',
  },
  {
    id: 'network',
    icon: Wifi,
    title: 'Secure Network Access',
    description: 'Prefer WPA3, segment sensitive devices, and avoid public Wi-Fi for critical work.',
  },
  {
    id: 'updates',
    icon: Smartphone,
    title: 'Keep Systems Updated',
    description: 'Apply operating system and application updates promptly to reduce known exposure.',
  },
  {
    id: 'backups',
    icon: ShieldCheck,
    title: 'Maintain Backups',
    description: 'Keep validated backups offline or in protected storage and test recovery regularly.',
  },
];

const knowledgeBadges = [
  { id: 'offensive', icon: Shield, label: 'Threat Analysis', tone: 'blue' },
  { id: 'website', icon: ShieldX, label: 'Web Protection', tone: 'red' },
  { id: 'behavior', icon: Fingerprint, label: 'Attacker Patterns', tone: 'violet' },
  { id: 'actionable', icon: TriangleAlert, label: 'Prioritized Actions', tone: 'red' },
  { id: 'web', icon: Bug, label: 'Web Risk Review', tone: 'blue' },
  { id: 'agent', icon: Bot, label: 'Security Intelligence', tone: 'blue' },
];

const cyberThreats = [
  {
    id: 'phishing-attacks',
    icon: TriangleAlert,
    title: 'Phishing Attacks',
    badge: 'High',
    tone: 'high',
    description: 'Messages that impersonate trusted senders to steal credentials or trigger unsafe actions.',
    howToAvoid: [
      'Verify the sender through a known channel',
      'Inspect URLs before clicking',
      'Watch for urgency and pressure tactics',
      'Escalate uncertain messages to security',
    ],
  },
  {
    id: 'malware-ransomware',
    icon: Bug,
    title: 'Malware & Ransomware',
    badge: 'Critical',
    tone: 'critical',
    description: 'Malicious code that can disrupt systems, steal data, or encrypt files for ransom.',
    howToAvoid: [
      'Use reputable endpoint protection',
      'Avoid untrusted downloads and extensions',
      'Patch systems and browsers quickly',
      'Keep offline recovery copies available',
    ],
  },
  {
    id: 'social-engineering',
    icon: Zap,
    title: 'Social Engineering',
    badge: 'Medium',
    tone: 'medium',
    description: 'Psychological manipulation used to bypass controls and extract sensitive information.',
    howToAvoid: [
      'Validate unusual requests independently',
      'Confirm identity before sharing information',
      'Never disclose passwords or OTPs',
      'Escalate anything that feels off',
    ],
  },
  {
    id: 'weak-passwords',
    icon: Smartphone,
    title: 'Weak Passwords',
    badge: 'Low',
    tone: 'low',
    description: 'Simple or reused passwords make account compromise much easier.',
    howToAvoid: [
      'Use a password manager',
      'Create unique credentials per account',
      'Prefer long passphrases',
      'Enable MFA wherever possible',
    ],
  },
];

const learningResources = [
  {
    id: 'password-guide',
    icon: FileText,
    type: 'Article',
    topic: 'Basics',
    audience: 'Individuals',
    priority: 'Foundation',
    title: 'Password Security Guide',
    description: 'Best practices for creating, storing, and rotating high-value credentials.',
    duration: '8 min read',
    takeaways: [
      'Build long passphrases that are easy to remember and hard to guess.',
      'Use a password manager instead of reusing credentials across services.',
      'Rotate only when risk changes or credentials are exposed.',
    ],
    bestFor: 'New users, admins, and anyone managing multiple accounts.',
    nextSteps: [
      'Audit reused passwords',
      'Turn on MFA for sensitive accounts',
      'Move credentials into a password manager',
    ],
  },
  {
    id: 'phishing-video',
    icon: Video,
    type: 'Video',
    topic: 'Threats',
    audience: 'Teams',
    priority: 'High leverage',
    title: 'Phishing Detection Guide',
    description: 'Recognize common lures and respond safely to suspicious messages.',
    duration: '12 min',
    takeaways: [
      'Spot urgency, impersonation, and mismatched links fast.',
      'Pause before opening attachments or approving logins.',
      'Report suspicious messages early so others do not get hit.',
    ],
    bestFor: 'Front-line staff, support teams, and phishing drills.',
    nextSteps: [
      'Run a mock phishing exercise',
      'Review sender domains before clicking',
      'Create a reporting shortcut for the team',
    ],
  },
  {
    id: 'two-factor-guide',
    icon: BookOpen,
    type: 'Guide',
    topic: 'Basics',
    audience: 'All users',
    priority: 'Essential',
    title: 'MFA Setup Guide',
    description: 'Enable multi-factor authentication across the services you rely on most.',
    duration: '5 min read',
    takeaways: [
      'Pick app-based or hardware-based factors over SMS when possible.',
      'Protect the account that secures your recovery options first.',
      'Store backup codes somewhere secure and reachable.',
    ],
    bestFor: 'Account owners, IT admins, and onboarding sessions.',
    nextSteps: [
      'Enable MFA on email first',
      'Save recovery codes offline',
      'Test a backup login method',
    ],
  },
  {
    id: 'ransomware-article',
    icon: FileText,
    type: 'Article',
    topic: 'Threats',
    audience: 'Operations',
    priority: 'Critical',
    title: 'Ransomware Response Guide',
    description: 'Reduce ransomware risk and prepare a practical recovery path.',
    duration: '10 min read',
    takeaways: [
      'Keep offline or immutable backups for the data that matters most.',
      'Know who can isolate devices and preserve evidence quickly.',
      'Practice recovery before an incident turns into panic.',
    ],
    bestFor: 'Incident response plans and business continuity reviews.',
    nextSteps: [
      'Validate backup restoration',
      'Document escalation contacts',
      'Review device isolation steps',
    ],
  },
  {
    id: 'network-video',
    icon: Video,
    type: 'Video',
    topic: 'Network',
    audience: 'Home offices',
    priority: 'Practical',
    title: 'Network Hardening Guide',
    description: 'Practical steps for securing Wi-Fi and connected devices.',
    duration: '15 min',
    takeaways: [
      'Use WPA3 or the strongest mode your router supports.',
      'Separate guest and work devices from sensitive systems.',
      'Patch routers and IoT devices instead of leaving them stale.',
    ],
    bestFor: 'Remote work setups and shared home networks.',
    nextSteps: [
      'Change the default router password',
      'Update firmware',
      'Remove unused connected devices',
    ],
  },
  {
    id: 'social-guide',
    icon: BookOpen,
    type: 'Guide',
    topic: 'Threats',
    audience: 'Business users',
    priority: 'High leverage',
    title: 'Social Engineering Guide',
    description: 'How to identify manipulation and protect sensitive processes.',
    duration: '7 min read',
    takeaways: [
      'Validate unusual requests through a separate trusted channel.',
      'Slow down when someone pushes urgency or secrecy.',
      'Protect payment, credential, and approval workflows carefully.',
    ],
    bestFor: 'Finance, HR, support, and executive assistants.',
    nextSteps: [
      'Add call-back verification',
      'Review payment approval steps',
      'Teach escalation paths for suspicious requests',
    ],
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

const iconRegistry = {
  BookOpen,
  Bot,
  Bug,
  FileText,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Mail,
  Shield,
  ShieldCheck,
  ShieldX,
  Smartphone,
  TriangleAlert,
  Video,
  Wifi,
  Zap,
};

const normalizeList = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.vulnerabilities)) return payload.vulnerabilities;
  if (Array.isArray(payload?.news)) return payload.news;
  return [];
};

const resolveIcon = (icon) => {
  if (typeof icon === 'function') {
    return icon;
  }

  return iconRegistry[icon] || ShieldCheck;
};

const buildPdfBlob = (resource) => {
  const checklist = resource.sections?.length ? resource.sections : [
    'Start with the highest risk behavior and turn it into a weekly habit.',
    'Use the checklist during onboarding and quarterly awareness refreshers.',
    'Escalate suspicious activity early and keep evidence in one place.',
  ];

  return buildBrandedPdfBlob({
    title: resource.title,
    subtitle: resource.description,
    eyebrow: 'Security Awareness Playbook',
    metrics: [
      { label: 'Format', value: 'PDF', fill: '#ffffff', valueColor: '#141935' },
      { label: 'Level', value: 'Team', fill: '#f3f0ff', valueColor: '#6c5ce7' },
      { label: 'Use Case', value: 'Training', fill: '#eefbf7', valueColor: '#11855d' },
      { label: 'Action', value: 'Ready', fill: '#fff4e4', valueColor: '#b35d00' },
    ],
    sections: [
      {
        title: 'Executive Brief',
        body: 'This Threat Hunters resource converts security awareness into practical behaviors teams can repeat during onboarding, reviews, and incident readiness sessions.',
        accent: '#8b7cff',
      },
      {
        title: 'Checklist',
        items: checklist,
        accent: '#00b8d9',
      },
      {
        title: 'Recommended Follow-Up',
        items: [
          'Assign an owner for the next awareness review.',
          'Turn the top two checklist items into weekly operating habits.',
          'Use the Threat Hunters scanner and reports when technical validation is needed.',
        ],
        accent: '#18a058',
      },
    ],
  });
};

const downloadPdfResource = (resource) => {
  const blob = buildPdfBlob(resource);
  downloadPdfBlob(blob, `${resource.id || 'security-awareness'}.pdf`);
};

const SecurityAwarenessPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToTools,
  onOpenAwarenessDetail,
  isLoggedIn,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [awarenessContent, setAwarenessContent] = useState({
    tips: securityTips,
    threats: cyberThreats,
    resources: learningResources,
    downloads: downloadableResources,
  });
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
    () => awarenessContent.tips.filter((tip) => itemMatchesSearch([tip.title, tip.description])),
    [awarenessContent.tips, itemMatchesSearch],
  );
  const filteredCyberThreats = useMemo(
    () =>
      awarenessContent.threats.filter((threat) =>
        itemMatchesSearch([
          threat.title,
          threat.description,
          threat.badge,
          ...(Array.isArray(threat.howToAvoid) ? threat.howToAvoid : []),
        ]),
      ),
    [awarenessContent.threats, itemMatchesSearch],
  );
  const filteredLearningResources = useMemo(
    () =>
      awarenessContent.resources.filter((resource) =>
        itemMatchesSearch([resource.type, resource.topic, resource.title, resource.description]),
      ),
    [awarenessContent.resources, itemMatchesSearch],
  );
  const filteredDownloadableResources = useMemo(
    () =>
      awarenessContent.downloads.filter((resource) =>
        itemMatchesSearch([resource.title, resource.description, resource.fileMeta || 'PDF']),
      ),
    [awarenessContent.downloads, itemMatchesSearch],
  );

  const openAwarenessDetail = useCallback(
    (kind, item) => {
      if (!kind || !item) {
        return;
      }

      try {
        window.sessionStorage.setItem(
          'awareness-detail-cache',
          JSON.stringify({ kind, item, savedAt: new Date().toISOString() }),
        );
      } catch {
        // Ignore storage errors and continue with the route only.
      }

      onOpenAwarenessDetail?.({
        kind,
        id: item.id || item.cve || item.cve_id || item.cveID || item.title || item.headline || '',
      });
    },
    [onOpenAwarenessDetail],
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
      securityAPI.getAwarenessContent()
        .then((content) => {
          setAwarenessContent({
            tips: normalizeList(content?.tips).length ? normalizeList(content.tips) : securityTips,
            threats: normalizeList(content?.threats).length ? normalizeList(content.threats) : cyberThreats,
            resources: normalizeList(content?.resources).length ? normalizeList(content.resources) : learningResources,
            downloads: normalizeList(content?.downloads).length ? normalizeList(content.downloads) : downloadableResources,
          });
        })
        .catch(() => {
          setAwarenessContent({
            tips: securityTips,
            threats: cyberThreats,
            resources: learningResources,
            downloads: downloadableResources,
          });
        });
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
            Practical guidance to strengthen day-to-day security habits.
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
              <p className="awareness-live__eyebrow">Live Threat Intelligence</p>
              <h2 className="awareness-section__title">Backend-backed intelligence feed</h2>
              <p className="awareness-section__subtitle">
                Aggregated from NVD, CISA KEV, and trusted security news sources.
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
                <span>Recent CVEs</span>
                <span className="awareness-live-card__count">{liveFeed.latestCves.length}</span>
              </div>
              <ul className="awareness-live-card__list">
                {liveLoading && !liveFeed.latestCves.length ? (
                  <li className="awareness-live-card__placeholder">Loading latest CVEs...</li>
                ) : !liveFeed.latestCves.length ? (
                  <li className="awareness-live-card__placeholder">
                    No recent CVEs loaded yet. Refresh the feed after the backend is available.
                  </li>
                ) : (
                  liveFeed.latestCves.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.cve || index}`} className="awareness-live-card__item">
                      <button
                        type="button"
                        className="awareness-live-card__item-button"
                        onClick={() => openAwarenessDetail('latest-cves', item)}
                      >
                        <strong>{item.id || item.cve || item.cve_id || 'Unknown CVE'}</strong>
                        <span>{item.severity || item.score ? `${item.severity || 'Unknown'}${item.score ? ` | ${item.score}` : ''}` : 'Unrated'}</span>
                        <p>{item.description || item.short_description || 'No description provided.'}</p>
                      </button>
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
                ) : !liveFeed.criticalCves.length ? (
                  <li className="awareness-live-card__placeholder">
                    No critical CVEs loaded yet. This card will surface the highest-priority issues.
                  </li>
                ) : (
                  liveFeed.criticalCves.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.cve || item.cve_id || index}`} className="awareness-live-card__item">
                      <button
                        type="button"
                        className="awareness-live-card__item-button"
                        onClick={() => openAwarenessDetail('critical-cves', item)}
                      >
                        <strong>{item.id || item.cve || item.cve_id || 'Unknown CVE'}</strong>
                        <span>{item.component || item.category || item.score ? `${item.component || item.category || 'High priority'}${item.score ? ` | ${item.score}` : ''}` : 'Critical priority'}</span>
                        <p>{item.description || item.short_description || 'Immediate review recommended.'}</p>
                      </button>
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
                ) : !liveFeed.kev.length ? (
                  <li className="awareness-live-card__placeholder">
                    No KEV items loaded yet. When connected, this card shows exploited vulnerabilities and due dates.
                  </li>
                ) : (
                  liveFeed.kev.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.cveID || item.cve_id || index}`} className="awareness-live-card__item">
                      <button
                        type="button"
                        className="awareness-live-card__item-button"
                        onClick={() => openAwarenessDetail('kev', item)}
                      >
                        <strong>{item.id || item.cveID || item.cve_id || 'Unknown CVE'}</strong>
                        <span>{item.dueDate || item.due_date || 'No due date'}</span>
                        <p>{item.status || item.required_action || item.short_description || 'Exploited vulnerability tracked by CISA.'}</p>
                      </button>
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
                ) : !liveFeed.news.length ? (
                  <li className="awareness-live-card__placeholder">
                    No security news loaded yet. This feed will summarize fresh advisories and reports.
                  </li>
                ) : (
                  liveFeed.news.slice(0, 4).map((item, index) => (
                    <li key={`${item.id || item.title || index}`} className="awareness-live-card__item">
                      <button
                        type="button"
                        className="awareness-live-card__item-button"
                        onClick={() => openAwarenessDetail('news', item)}
                      >
                        <strong>{item.title || item.headline || 'Untitled update'}</strong>
                        <span>{item.source || item.publisher || 'Security feed'}</span>
                        <p>{item.summary || item.description || item.short_description || 'Fresh threat intelligence update.'}</p>
                      </button>
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
            <h2 className="awareness-section__title">Security Practices</h2>
            <p className="awareness-section__subtitle">
              Practical actions to reduce common risk.
            </p>
          </header>

          <div className="tips-grid">
            {filteredSecurityTips.map((tip) => {
              const Icon = resolveIcon(tip.icon);

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
            <h2 className="awareness-section__title">Common Threats</h2>
            <p className="awareness-section__subtitle">
              Review the threats that matter most and how to mitigate them.
            </p>
          </header>

          <div className="threats-grid">
            {filteredCyberThreats.map((threat) => {
              const Icon = resolveIcon(threat.icon);

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
                      {(Array.isArray(threat.howToAvoid) ? threat.howToAvoid : []).map((tip) => (
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
              Curated guidance for awareness, response, and prevention.
            </p>
          </header>

          <div className="resources-grid">
            {filteredLearningResources.map((resource) => {
              const Icon = resolveIcon(resource.icon);

              return (
                <article
                  key={resource.id}
                  className="resource-card"
                  role="button"
                  tabIndex={0}
                  onClick={() => openAwarenessDetail('resource', resource)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      openAwarenessDetail('resource', resource);
                    }
                  }}
                >
                  <div className="resource-card__meta">
                    <div className="resource-card__pill-group">
                      <span className="resource-card__pill resource-card__pill--type">
                        <Icon strokeWidth={1.8} />
                        <span>{resource.type}</span>
                      </span>
                      <span className="resource-card__pill resource-card__pill--tone">
                        {resource.priority}
                      </span>
                    </div>
                    <span className="resource-card__pill resource-card__pill--topic">
                      {resource.topic}
                    </span>
                  </div>

                  <h3 className="resource-card__title">{resource.title}</h3>
                  <p className="resource-card__description">{resource.description}</p>

                  <ul className="resource-card__preview">
                    {(Array.isArray(resource.takeaways) ? resource.takeaways : []).slice(0, 2).map((takeaway) => (
                      <li key={takeaway}>{takeaway}</li>
                    ))}
                  </ul>

                  <div className="resource-card__footer">
                    <span className="resource-card__duration">
                      <Clock3 strokeWidth={1.8} />
                      <span>{resource.duration}</span>
                    </span>

                    <button
                      type="button"
                      className="resource-card__action"
                      aria-label={`View details for ${resource.title}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        openAwarenessDetail('resource', resource);
                      }}
                    >
                      <FileText strokeWidth={1.8} />
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
                  <p>Downloadable checklists and team-ready templates.</p>
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
                        onClick={() => downloadPdfResource(resource)}
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
