import { memo, useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Gauge,
  Globe,
  KeyRound,
  Mail,
  Play,
  RotateCcw,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import './MoreToolsPage.css';
import Navbar from './Navbar';
import Footer from './Footer';
import { securityAPI } from '../services/api';

const tabContent = {
  password: {
    label: 'Password Checker',
    shortLabel: 'Password',
    icon: KeyRound,
    eyebrow: 'Credential hygiene',
    inputLabel: 'Enter your password',
    inputType: 'password',
    placeholder: 'Enter a password',
    heroCopy: 'Audit password quality, weak construction patterns, and policy fit before reuse becomes a real risk.',
    detailCopy: 'A fast way to preview strength, reuse, and exposure-style hints through the backend.',
    idleTitle: 'Password review is standing by',
    idleCopy: 'Run the checker to see live breach counts, risk level, and reuse-style guidance.',
    helperCopy: 'The password check runs through the backend against the live Pwned Passwords API.',
    signalTags: ['Entropy score', 'Length policy', 'Weak patterns'],
    examples: ['CorrectHorseBattery!42', 'Vault-Access-2026!'],
    heroStats: [
      { label: 'Typical run', value: '< 2 sec' },
      { label: 'Checks surfaced', value: '4 layers' },
      { label: 'Storage', value: '0 data' },
    ],
    summary: [
      { label: 'Entropy', value: 'Strong', note: '116-bit est.', tone: 'safe' },
      { label: 'Reuse risk', value: 'Low', note: 'No obvious hints', tone: 'safe' },
      { label: 'Pattern flags', value: '0', note: 'No trivial sequences', tone: 'info' },
    ],
    insights: [
      {
        title: 'Length baseline is healthy',
        copy: 'The sample exceeds a safer length threshold, which reduces low-effort brute-force exposure.',
        tone: 'safe',
      },
      {
        title: 'Composition looks balanced',
        copy: 'Uppercase, lowercase, digits, and symbols are all present without obvious repetition.',
        tone: 'info',
      },
      {
        title: 'No common pattern detected',
        copy: 'The live review did not flag dates, keyboard walks, or simple suffix habits.',
        tone: 'safe',
      },
    ],
    checklist: [
      'Structure and length review',
      'Weak pattern detection',
      'Policy fit and reuse hints',
    ],
    successTitle: 'Password posture has been analyzed',
    successCopy: 'The live review now shows breach counts and a risk label from HIBP.',
  },
  email: {
    label: 'Email Checker',
    shortLabel: 'Email',
    icon: Mail,
    eyebrow: 'Exposure review',
    inputLabel: 'Enter your email',
    inputType: 'email',
    placeholder: 'you@example.com',
    heroCopy: 'Run a fast exposure-style review for email addresses and see live breach intelligence in one pass.',
    detailCopy: 'Powered by the backend so the browser never talks to the HIBP API key directly.',
    idleTitle: 'Exposure review is ready',
    idleCopy: 'Start a check to preview breach results, data classes, and account hygiene hints.',
    helperCopy: 'Live HIBP lookup through the backend. Use a test address from the HIBP docs if needed.',
    signalTags: ['Breach hints', 'Domain posture', 'Alias hygiene'],
    examples: ['security.team@company.com', 'alias+alerts@example.org'],
    heroStats: [
      { label: 'Typical run', value: '< 2 sec' },
      { label: 'Signal lanes', value: '3 sources' },
      { label: 'API calls', value: 'Live backend' },
    ],
    summary: [
      { label: 'Exposure', value: '0 hits', note: 'Live result', tone: 'safe' },
      { label: 'Domain health', value: 'Healthy', note: 'Valid pattern', tone: 'safe' },
      { label: 'Alias hygiene', value: 'Stable', note: 'No obvious issue', tone: 'info' },
    ],
    insights: [
      {
        title: 'No breach-style signal surfaced',
        copy: 'The live lookup returned a clean result set for the sample address.',
        tone: 'safe',
      },
      {
        title: 'Domain shape looks valid',
        copy: 'The address structure supports domain-level checks and exposure grouping in a real pipeline.',
        tone: 'info',
      },
      {
        title: 'Good fit for quick triage',
        copy: 'This flow gives users a fast answer before escalating to deeper identity or account monitoring.',
        tone: 'safe',
      },
    ],
    checklist: [
      'Address and domain validation',
      'Exposure-style signal matching',
      'Alias and posture review',
    ],
    successTitle: 'Email posture has been analyzed',
    successCopy: 'The live review now shows breach count, verified hits, and exposed data classes.',
  },
};

const workflowCards = [
  {
    icon: Search,
    title: 'Quick triage first',
    copy: 'Check obvious signals before you spend time on a deeper assessment or manual review.',
  },
  {
    icon: ShieldCheck,
    title: 'Safe product checks',
    copy: 'Everything here is backend-backed and kept focused, which makes it suitable for real checks without noisy UI behavior.',
  },
  {
    icon: Gauge,
    title: 'Better escalation',
    copy: 'The output gives enough direction to decide whether a user should move to a stronger scan flow.',
  },
];

const roadmapCards = [
  {
    icon: Globe,
    title: 'Domain posture snapshots',
    copy: 'DNS and security-header style checks presented with the same product language.',
  },
  {
    icon: Sparkles,
    title: 'Identity hygiene checks',
    copy: 'Username reuse, alias quality, and recovery-surface hints for higher-risk accounts.',
  },
  {
    icon: Activity,
    title: 'Trend-based scoring',
    copy: 'Repeat checks, historical comparison, and smarter escalation signals over time.',
  },
];

const statItems = [
  { value: '10+', label: 'New tools planned' },
  { value: '24/7', label: 'Fast utility access' },
  { value: '100%', label: 'Live backend checks' },
];

const scanStatusMeta = {
  idle: { label: 'Awaiting input', tone: 'idle' },
  checking: { label: 'Running preview', tone: 'checking' },
  success: { label: 'Signals clear', tone: 'success' },
  error: { label: 'Check failed', tone: 'watch' },
};

const getEmailLiveNote = (value) => {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Enter a full address to unlock domain and exposure-style checks.';
  }

  if (!trimmedValue.includes('@')) {
    return 'Add a domain so the preview can reason about posture and exposure grouping.';
  }

  const [, domain = 'this domain'] = trimmedValue.split('@');
  return `Ready to inspect ${domain.toLowerCase()} for exposure-style signals and domain hygiene hints.`;
};

const getPasswordLiveNote = (value) => {
  const length = value.length;

  if (!length) {
    return 'Try a longer passphrase-style sample to preview stronger scoring and clearer guidance.';
  }

  if (length < 10) {
    return `${length} characters entered. Add more length before you trust the result.`;
  }

  if (!/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/\d/.test(value)) {
    return 'The structure is usable, but more variation would improve resilience and scoring.';
  }

  return 'Good structure detected. Run the checker to preview policy fit and reuse-style hints.';
};

const formatCount = (value) => Number(value || 0).toLocaleString();

const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value.trim());

const validateToolInput = (activeTab, value) => {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Enter a value before starting the check.';
  }

  if (activeTab === 'email' && !isValidEmail(trimmedValue)) {
    return 'Enter a valid email address like name@example.com.';
  }

  if (activeTab === 'password' && value.length < 8) {
    return 'Enter at least 8 characters so the password check can be useful.';
  }

  return '';
};

const buildPasswordResultView = (result) => {
  const count = Number(result?.count || 0);
  const breached = Boolean(result?.breached);
  const riskLevel = result?.risk_level || (breached ? 'Low' : 'Safe');
  const safeTone = breached ? 'watch' : 'safe';

  return {
    title: breached ? 'Password is present in breach data' : 'No breach match found',
    copy: breached
      ? `This password appeared ${formatCount(count)} times in known breaches. Rotate it immediately.`
      : 'No match returned from the live Pwned Passwords corpus. Keep using unique passwords.',
    summary: [
      {
        label: 'Exposure',
        value: breached ? 'Pwned' : 'Clean',
        note: breached ? `${formatCount(count)} hits` : 'No match in corpus',
        tone: safeTone,
      },
      {
        label: 'Risk level',
        value: riskLevel,
        note: breached ? 'Change it now' : 'Looks better',
        tone: safeTone,
      },
      {
        label: 'Count',
        value: formatCount(count),
        note: 'Known breach hits',
        tone: 'info',
      },
    ],
    insights: breached
      ? [
          {
            title: 'Rotate this password',
            copy: 'A live HIBP match means the password should be replaced with a unique passphrase immediately.',
            tone: 'watch',
          },
          {
            title: 'Avoid reuse everywhere',
            copy: 'If this password has been exposed once, reuse across other accounts becomes the bigger risk.',
            tone: 'info',
          },
          {
            title: 'Use a manager',
            copy: 'A password manager will help generate and store stronger unique credentials per account.',
            tone: 'safe',
          },
        ]
      : [
          {
            title: 'No live breach hit surfaced',
            copy: 'The Pwned Passwords check did not find this secret in the known corpus.',
            tone: 'safe',
          },
          {
            title: 'Keep the length high',
            copy: 'Long passphrases still matter, even when no current breach match is returned.',
            tone: 'info',
          },
          {
            title: 'Stay unique',
            copy: 'The safest next step is still a unique password per account, stored in a manager.',
            tone: 'safe',
          },
        ],
    tags: breached
      ? ['Rotate now', 'No reuse', 'Password manager']
      : ['No direct hit', 'Unique password', 'Passphrase'],
  };
};

const buildEmailResultView = (result) => {
  const breachCount = Number(result?.breach_count || 0);
  const verifiedCount = Number(result?.verified_breach_count || 0);
  const stealerCount = Number(result?.stealer_log_count || 0);
  const breached = Boolean(result?.breached);
  const latestBreach = result?.latest_breach || null;
  const riskLevel = result?.risk_level || (breached ? 'Medium' : 'Safe');
  const exposedData = Array.isArray(result?.exposed_data) ? result.exposed_data : [];
  const latestLabel = latestBreach?.title || latestBreach?.name || 'No breach';
  const latestDate = latestBreach?.breach_date || 'Not found';
  const safeTone = breached ? 'watch' : 'safe';

  return {
    title: breached ? 'Email appears in breach data' : 'No breach match found',
    copy: breached
      ? `This email appears in ${formatCount(breachCount)} breach record(s). Review the latest match and exposed data classes.`
      : 'The live HIBP lookup did not surface breach records for this email address.',
    summary: [
      {
        label: 'Exposure',
        value: breached ? `${formatCount(breachCount)} breaches` : 'Clear',
        note: riskLevel,
        tone: safeTone,
      },
      {
        label: 'Verified',
        value: formatCount(verifiedCount),
        note: 'Verified breaches',
        tone: 'info',
      },
      {
        label: 'Stealer logs',
        value: formatCount(stealerCount),
        note: stealerCount > 0 ? 'Critical' : 'No hits',
        tone: stealerCount > 0 ? 'watch' : 'safe',
      },
    ],
    insights: breached
      ? [
          {
            title: `Latest breach: ${latestLabel}`,
            copy: `Breach date: ${latestDate}. Use the latest incident details to decide the next remediation step.`,
            tone: 'watch',
          },
          {
            title: 'Exposed data classes',
            copy: exposedData.length
              ? exposedData.slice(0, 6).join(', ')
              : 'No data class metadata was returned.',
            tone: 'info',
          },
          {
            title: 'Verified and stealer signals',
            copy: `${formatCount(verifiedCount)} verified breach(s) and ${formatCount(stealerCount)} stealer-log hit(s) were found for this address.`,
            tone: stealerCount > 0 ? 'watch' : 'safe',
          },
        ]
      : [
          {
            title: 'No live breach hit surfaced',
            copy: 'The email address was not found in the breach corpus returned by HIBP.',
            tone: 'safe',
          },
          {
            title: 'Use a real inbox carefully',
            copy: 'If you test a real address, keep in mind the response may reveal sensitive account exposure details.',
            tone: 'info',
          },
          {
            title: 'Keep monitoring',
            copy: 'Regular checks and password hygiene are still the safest next steps for a clean result.',
            tone: 'safe',
          },
        ],
    tags: breached
      ? exposedData.slice(0, 6)
      : ['No direct hit', 'Exposure review', 'Hygiene'],
  };
};

const MoreToolsPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools,
  isLoggedIn,
}) => {
  const [activeTab, setActiveTab] = useState('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [scanState, setScanState] = useState('idle');
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState('');
  const checkTimeoutRef = useRef(null);
  const activeContent = tabContent[activeTab];
  const currentValue = activeTab === 'email' ? email : password;
  const canScan = currentValue.trim().length > 0;
  const statusMeta = scanStatusMeta[scanState];
  const liveNote = activeTab === 'email' ? getEmailLiveNote(email) : getPasswordLiveNote(password);
  const ToolIcon = activeContent.icon;
  const resultView = scanState === 'success'
    ? (activeTab === 'email'
        ? buildEmailResultView(scanResult)
        : buildPasswordResultView(scanResult))
    : null;

  useEffect(() => () => {
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
      checkTimeoutRef.current = null;
    }
  }, []);

  const resetScanState = useCallback(() => {
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
      checkTimeoutRef.current = null;
    }

    setScanState('idle');
    setScanResult(null);
    setScanError('');
  }, []);

  const runLiveCheck = useCallback(async () => {
    const validationError = validateToolInput(activeTab, currentValue);

    if (validationError) {
      resetScanState();
      setScanError(validationError);
      setScanState('error');
      return;
    }

    resetScanState();
    setScanState('checking');

    try {
      const result = activeTab === 'email'
        ? await securityAPI.checkEmailBreach({ email: currentValue.trim() })
        : await securityAPI.checkPasswordBreach({ password: currentValue });

      setScanResult(result);
      setScanError('');
      setScanState('success');
    } catch (error) {
      setScanResult(null);
      setScanError(error.message || 'Unable to complete the check.');
      setScanState('error');
    } finally {
      checkTimeoutRef.current = null;
    }
  }, [activeTab, currentValue, resetScanState]);

  const handleTabChange = useCallback(
    (nextTab) => {
      setActiveTab(nextTab);
      resetScanState();
    },
    [resetScanState],
  );

  const handleScan = async () => {
    await runLiveCheck();
  };

  const handleInputChange = (nextValue) => {
    resetScanState();

    if (activeTab === 'email') {
      setEmail(nextValue);
      return;
    }

    setPassword(nextValue);
  };

  const handleReset = useCallback(() => {
    resetScanState();

    if (activeTab === 'email') {
      setEmail('');
      return;
    }

    setPassword('');
  }, [activeTab, resetScanState]);

  return (
    <div className="more-tools-page">
      {!isLoggedIn && (
        <Navbar
          onNavigateToSignUp={onNavigateToSignUp}
          onNavigateToHome={onNavigateToHome}
          onNavigateToBlog={onNavigateToBlog}
          onNavigateToAwareness={onNavigateToAwareness}
          onNavigateToTools={onNavigateToTools}
          currentPage="tools"
        />
      )}

      <section className="more-tools-hero">
        <div className="more-tools-hero-shell">
          <div className="more-tools-hero-copy">
            <div className="more-tools-hero-badge">
              <span className="more-tools-hero-badge-dot" aria-hidden="true" />
              <span>Fast utility checks</span>
            </div>

            <h1>Security tools that feel sharper and faster</h1>
            <p>{activeContent.heroCopy}</p>
            <p className="more-tools-hero-detail">{activeContent.detailCopy}</p>

            <div className="more-tools-hero-tags" aria-label={`${activeContent.label} capabilities`}>
              {activeContent.signalTags.map((tag) => (
                <span className="more-tools-hero-tag" key={tag}>
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <aside className="more-tools-hero-panel">
            <div className="more-tools-hero-panel-head">
              <span className="more-tools-hero-panel-icon" aria-hidden="true">
                <ToolIcon size={20} />
              </span>

              <div>
                <span className="more-tools-hero-panel-eyebrow">Selected utility</span>
                <strong className="more-tools-hero-panel-title">{activeContent.label}</strong>
              </div>
            </div>

            <div className="more-tools-hero-metrics">
              {activeContent.heroStats.map((item) => (
                <article className="more-tools-hero-metric" key={item.label}>
                  <strong>{item.value}</strong>
                  <span>{item.label}</span>
                </article>
              ))}
            </div>
          </aside>
        </div>
      </section>

      <section className="more-tools-workbench-section">
        <div className="more-tools-workbench">
          <div className="more-tools-tabbar" role="tablist" aria-label="Security tools">
            {Object.entries(tabContent).map(([key, item]) => {
              const TabIcon = item.icon;

              return (
                <button
                  key={key}
                  className={`more-tools-tab ${activeTab === key ? 'is-active' : ''}`}
                  onClick={() => handleTabChange(key)}
                  role="tab"
                  type="button"
                >
                  <span className="more-tools-tab-icon" aria-hidden="true">
                    <TabIcon size={16} />
                  </span>
                  <span className="more-tools-tab-copy">
                    <strong>{item.shortLabel}</strong>
                    <span>{item.eyebrow}</span>
                  </span>
                </button>
              );
            })}
          </div>

          <div className="more-tools-workbench-grid">
            <div className="more-tools-form-panel">
              <div className="more-tools-panel-head">
                <span className="more-tools-panel-kicker">{activeContent.eyebrow}</span>
                <h2>{activeContent.label}</h2>
                <p>{activeContent.detailCopy}</p>
              </div>

              <label className="more-tools-label" htmlFor="more-tools-input">
                {activeContent.inputLabel}
              </label>

              <input
                id="more-tools-input"
                className="more-tools-input"
                onChange={(event) => handleInputChange(event.target.value)}
                placeholder={activeContent.placeholder}
                type={activeContent.inputType}
                value={currentValue}
              />

              <div className="more-tools-live-note">
                <Activity aria-hidden="true" size={16} />
                <p>{liveNote}</p>
              </div>

              <div className="more-tools-example-block">
                <span className="more-tools-example-label">Quick examples</span>

                <div className="more-tools-example-list">
                  {activeContent.examples.map((example) => (
                    <button
                      key={example}
                      className="more-tools-example-chip"
                      onClick={() => handleInputChange(example)}
                      type="button"
                    >
                      {example}
                    </button>
                  ))}
                </div>
              </div>

              <div className="more-tools-action-row">
                <button
                  className="more-tools-scan-button"
                  disabled={scanState === 'checking' || !canScan}
                  onClick={handleScan}
                  type="button"
                >
                  <Play aria-hidden="true" fill="currentColor" />
                  <span>{scanState === 'checking' ? 'Scanning...' : 'Start scan'}</span>
                </button>

                <button
                  className="more-tools-reset-button"
                  disabled={!currentValue && scanState === 'idle'}
                  onClick={handleReset}
                  type="button"
                >
                  <RotateCcw aria-hidden="true" size={16} />
                  <span>Reset</span>
                </button>
              </div>

              <div className="more-tools-helper-row">
                <span className="more-tools-helper-badge">Live backend</span>
                <p>{activeContent.helperCopy}</p>
              </div>
            </div>

            <div className="more-tools-output-panel">
              <div className="more-tools-output-head">
                <span className="more-tools-output-badge">Result preview</span>
                <span className={`more-tools-output-status tone-${statusMeta.tone}`}>
                  {statusMeta.label}
                </span>
              </div>

              <div className="more-tools-output-state" aria-live="polite">
                <div
                  className={`more-tools-output-icon ${scanState === 'checking' ? 'is-scanning' : ''}`}
                  aria-hidden="true"
                >
                  {scanState === 'error' ? <AlertTriangle size={34} /> : scanState === 'success' ? <CheckCircle2 size={34} /> : <Shield size={34} />}
                </div>

                <p>
                  {scanState === 'success'
                    ? resultView?.title
                    : scanState === 'error'
                      ? 'Check could not complete'
                      : activeContent.idleTitle}
                </p>
                <span>
                  {scanState === 'success'
                    ? resultView?.copy
                    : scanState === 'error'
                      ? scanError
                      : activeContent.idleCopy}
                </span>
              </div>

              {scanState === 'checking' && (
                <div className="more-tools-progress-list" aria-label="Scan stages">
                  {activeContent.checklist.map((item) => (
                    <article className="more-tools-progress-item" key={item}>
                      <span className="more-tools-progress-mark" aria-hidden="true" />
                      <div>
                        <strong>{item}</strong>
                        <span>Analyzing backend-backed security signals for this stage.</span>
                      </div>
                    </article>
                  ))}
                </div>
              )}

              {scanState === 'error' && (
                <div className="more-tools-insight-list">
                  <article className="more-tools-insight-card tone-watch" role="alert">
                    <div className="more-tools-insight-head">
                      <AlertTriangle aria-hidden="true" size={16} />
                      <strong>Request failed</strong>
                    </div>
                    <p>{scanError || 'The backend could not complete the check.'}</p>
                  </article>
                </div>
              )}

              {scanState === 'idle' && (
                <>
                  <div className="more-tools-output-tags">
                    {activeContent.signalTags.map((tag) => (
                      <span className="more-tools-output-tag" key={tag}>
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="more-tools-summary-grid is-preview">
                    {activeContent.summary.map((item) => (
                      <article className={`more-tools-summary-card tone-${item.tone}`} key={item.label}>
                        <strong>{item.value}</strong>
                        <span>{item.label}</span>
                        <small>{item.note}</small>
                      </article>
                    ))}
                  </div>
                </>
              )}

              {scanState === 'success' && (
                <>
                  <div className="more-tools-summary-grid">
                    {resultView.summary.map((item) => (
                      <article className={`more-tools-summary-card tone-${item.tone}`} key={item.label}>
                        <strong>{item.value}</strong>
                        <span>{item.label}</span>
                        <small>{item.note}</small>
                      </article>
                    ))}
                  </div>

                  <div className="more-tools-output-tags">
                    {resultView.tags.map((tag) => (
                      <span className="more-tools-output-tag" key={tag}>
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="more-tools-insight-list">
                    {resultView.insights.map((item) => (
                      <article className={`more-tools-insight-card tone-${item.tone}`} key={item.title}>
                        <div className="more-tools-insight-head">
                          {item.tone === 'safe' ? (
                            <ShieldCheck aria-hidden="true" size={16} />
                          ) : (
                            <AlertTriangle aria-hidden="true" size={16} />
                          )}
                          <strong>{item.title}</strong>
                        </div>
                        <p>{item.copy}</p>
                      </article>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="more-tools-lanes-section">
        <div className="more-tools-lanes-shell">
          <div className="more-tools-lanes-copy">
            <span className="more-tools-section-badge">Where it fits</span>
            <h2>Quick checks before deeper security workflows</h2>
            <p>
              This page works best as a first-pass utility layer: fast enough for onboarding and clean enough
              to guide users toward more advanced scans when needed.
            </p>
          </div>

          <div className="more-tools-lanes-grid">
            {workflowCards.map((item) => {
              const Icon = item.icon;

              return (
                <article className="more-tools-lane-card" key={item.title}>
                  <span className="more-tools-lane-icon" aria-hidden="true">
                    <Icon size={18} />
                  </span>
                  <h3>{item.title}</h3>
                  <p>{item.copy}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section className="more-tools-roadmap-section">
        <div className="more-tools-roadmap">
          <div className="more-tools-roadmap-badge">
            <span className="more-tools-roadmap-dot" aria-hidden="true" />
            <span>More tools coming soon</span>
          </div>

          <h2>We can push this toolkit further</h2>
          <p>
            The current page is now stronger as a product surface, but it also sets up a cleaner path for
            deeper checks, more realistic telemetry, and broader utility coverage later.
          </p>

          <div className="more-tools-roadmap-grid">
            {roadmapCards.map((item) => {
              const Icon = item.icon;

              return (
                <article className="more-tools-roadmap-card" key={item.title}>
                  <span className="more-tools-roadmap-icon" aria-hidden="true">
                    <Icon size={18} />
                  </span>
                  <h3>{item.title}</h3>
                  <p>{item.copy}</p>
                </article>
              );
            })}
          </div>

          <div className="more-tools-stats-panel">
            {statItems.map((item) => (
              <article className="more-tools-stat" key={item.label}>
                <strong>{item.value}</strong>
                <span>{item.label}</span>
              </article>
            ))}
          </div>
        </div>
      </section>

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(MoreToolsPage);
