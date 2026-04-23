import { memo } from 'react';
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

const SecurityAwarenessPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToTools,
  isLoggedIn,
}) => {
  const badgeTrack = [...knowledgeBadges, ...knowledgeBadges];

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
            <input type="text" placeholder="Search for security topics..." />
          </label>
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
            {securityTips.map((tip) => {
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
            {cyberThreats.map((threat) => {
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
            {learningResources.map((resource) => {
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
              {downloadableResources.map((resource) => (
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
            </div>
          </section>
        </div>
      </section>

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(SecurityAwarenessPage);
