import { memo, useCallback, useEffect, useRef, useState } from 'react';
import { Play, Shield } from 'lucide-react';
import './MoreToolsPage.css';
import Navbar from './Navbar';
import Footer from './Footer';

const tabContent = {
  password: {
    label: 'Password Checker',
    inputLabel: 'Enter Your Password',
    inputType: 'password',
    placeholder: 'Enter a password',
    heroCopy: 'Check password strength, weak patterns, and common exposure signals before reuse becomes a risk.',
    idleTitle: 'Password insights will appear here',
    idleCopy: 'Enter a password and start a simulated security check.',
    helperCopy: 'This preview uses a safe front-end simulation. No credentials are stored or transmitted.',
    signalTags: ['Entropy score', 'Pattern check', 'Reuse hints'],
    summary: [
      { label: 'Entropy', value: 'Strong' },
      { label: 'Reuse risk', value: 'Low' },
      { label: 'Leaks', value: '0' },
    ],
    successTitle: 'Password appears secure',
    successCopy: 'No obvious exposure was detected for this password in our simulated check.',
  },
  email: {
    label: 'Email Checker',
    inputLabel: 'Enter Your Email',
    inputType: 'email',
    placeholder: 'you@example.com',
    heroCopy: 'Run a quick exposure check for email addresses, domain posture, and breach-style signals in seconds.',
    idleTitle: 'Exposure results will appear here',
    idleCopy: 'Enter an email address and start a simulated security check.',
    helperCopy: 'Use a test address if you want to preview the flow. This demo does not call a real breach API.',
    signalTags: ['Breach signals', 'Domain posture', 'Alias hygiene'],
    summary: [
      { label: 'Exposure', value: '0' },
      { label: 'Domain', value: 'Healthy' },
      { label: 'Matches', value: '2' },
    ],
    successTitle: 'Email appears secure',
    successCopy: 'No breach indicators were found for this email in our simulated scan.',
  },
};

const statItems = [
  { value: '10+', label: 'New Tools' },
  { value: '24/7', label: 'Coverage' },
  { value: '100%', label: 'Free' },
];

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
  const checkTimeoutRef = useRef(null);

  useEffect(() => () => {
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
      checkTimeoutRef.current = null;
    }
  }, []);

  const resetSimulation = useCallback(() => {
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
      checkTimeoutRef.current = null;
    }

    setScanState('idle');
  }, []);

  const runSimulatedCheck = useCallback(() => {
    resetSimulation();
    setScanState('checking');

    checkTimeoutRef.current = setTimeout(() => {
      setScanState('success');
      checkTimeoutRef.current = null;
    }, 1800);
  }, [resetSimulation]);

  const handleTabChange = useCallback(
    (nextTab) => {
      setActiveTab(nextTab);
      resetSimulation();
    },
    [resetSimulation],
  );

  const handleScan = () => {
    runSimulatedCheck();
  };

  const activeContent = tabContent[activeTab];
  const currentValue = activeTab === 'email' ? email : password;
  const canScan = currentValue.trim().length > 0;

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
        <div className="more-tools-hero-content">
          <div className="more-tools-hero-badge">
            <span className="more-tools-hero-badge-dot" aria-hidden="true" />
            <span>Fast utility checks</span>
          </div>

          <h1>More Security Tools</h1>

          <p>{activeContent.heroCopy}</p>

          <div className="more-tools-hero-tags" aria-label={`${activeContent.label} capabilities`}>
            {activeContent.signalTags.map((tag) => (
              <span className="more-tools-hero-tag" key={tag}>
                {tag}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="more-tools-workbench-section">
        <div className="more-tools-workbench">
          <div className="more-tools-tabbar" role="tablist" aria-label="Security tools">
            {Object.entries(tabContent).map(([key, item]) => (
              <button
                key={key}
                className={`more-tools-tab ${activeTab === key ? 'is-active' : ''}`}
                onClick={() => handleTabChange(key)}
                role="tab"
                type="button"
              >
                {item.label}
              </button>
            ))}
          </div>

          <div className="more-tools-form-panel">
            <label className="more-tools-label" htmlFor="more-tools-input">
              {activeContent.inputLabel}
            </label>

            <input
              id="more-tools-input"
              className="more-tools-input"
              onChange={(event) => {
                resetSimulation();

                if (activeTab === 'email') {
                  setEmail(event.target.value);
                  return;
                }

                setPassword(event.target.value);
              }}
              placeholder={activeContent.placeholder}
              type={activeContent.inputType}
              value={currentValue}
            />

            <button
              className="more-tools-scan-button"
              disabled={scanState === 'checking' || !canScan}
              onClick={handleScan}
              type="button"
            >
              <Play aria-hidden="true" fill="currentColor" />
              <span>Start scan</span>
            </button>

            <div className="more-tools-helper-row">
              <span className="more-tools-helper-badge">Demo mode</span>
              <p>{activeContent.helperCopy}</p>
            </div>
          </div>

          <div className="more-tools-output-panel">
            {scanState === 'checking' && (
              <div className="more-tools-output-state">
                <div className="more-tools-spinner" aria-hidden="true" />
                <p>Checking security signals...</p>
                <span>This simulated scan will finish in a moment.</span>
              </div>
            )}

            {scanState === 'success' && (
              <div className="more-tools-output-state">
                <div className="more-tools-output-icon" aria-hidden="true">
                  <Shield />
                </div>
                <p>{activeContent.successTitle}</p>
                <span>{activeContent.successCopy}</span>

                <div className="more-tools-summary-grid">
                  {activeContent.summary.map((item) => (
                    <article className="more-tools-summary-card" key={item.label}>
                      <strong>{item.value}</strong>
                      <span>{item.label}</span>
                    </article>
                  ))}
                </div>
              </div>
            )}

            {scanState === 'idle' && (
              <div className="more-tools-output-state">
                <div className="more-tools-output-icon" aria-hidden="true">
                  <Shield />
                </div>
                <p>{activeContent.idleTitle}</p>
                <span>{activeContent.idleCopy}</span>

                <div className="more-tools-output-tags">
                  {activeContent.signalTags.map((tag) => (
                    <span className="more-tools-output-tag" key={tag}>
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="more-tools-roadmap-section">
        <div className="more-tools-roadmap">
          <div className="more-tools-roadmap-badge">
            <span className="more-tools-roadmap-dot" aria-hidden="true" />
            <span>MORE TOOLS COMING SOON</span>
          </div>

          <h2>We&apos;re Just Getting Started</h2>
          <p>
            We&apos;re constantly expanding our security toolkit with new features and capabilities. Stay tuned
            for more powerful tools designed to keep you safe online.
          </p>

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
