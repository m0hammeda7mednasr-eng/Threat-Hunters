import { memo, useCallback } from 'react';
import {
  Activity,
  ArrowRight,
  BrainCircuit,
  ClipboardList,
  FileText,
  Link2,
  Lock,
  MonitorSmartphone,
  Radar,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import './HomePage.css';
import Navbar from './Navbar';
import Footer from './Footer';

const processSteps = [
  {
    icon: Link2,
    number: '1',
    title: 'Enter Your URL',
    description: 'Simply paste your website URL and choose a scan profile (Quick, Full, or Custom).',
  },
  {
    icon: Zap,
    number: '2',
    title: 'Run the Scan',
    description: 'Our security tools analyze your site. Watch real-time progress and live logs as they run.',
  },
  {
    icon: FileText,
    number: '3',
    title: 'Get Your AI-Powered Report',
    description: 'Review vulnerabilities with plain-English explanations and code fixes. Download as PDF.',
  },
];

const featureCards = [
  {
    icon: Radar,
    title: 'Advanced Scanning',
    description: 'Deep vulnerability detection using cutting-edge scanning algorithms to identify security weaknesses.',
  },
  {
    icon: BrainCircuit,
    title: 'AI-Powered Insights',
    description: 'Intelligent threat analysis powered by machine learning to prioritize critical vulnerabilities.',
  },
  {
    icon: MonitorSmartphone,
    title: 'User Friendly',
    description: '100% Web based application',
  },
  {
    icon: ClipboardList,
    title: 'Actionable Reports',
    description: 'Detailed reports with step-by-step remediation guidance to fix vulnerabilities quickly.',
  },
  {
    icon: Lock,
    title: 'Privacy First',
    description: 'Your data stays private and secure. We never store sensitive information from your scans.',
  },
  {
    icon: Activity,
    title: 'Automated Monitoring',
    description: 'Continuous monitoring with real-time alerts to keep your applications protected 24/7.',
  },
];

const marqueeItems = [
  { icon: Radar, label: 'Offensive Security', tone: 'blue' },
  { icon: ShieldCheck, label: 'Protect Your Website', tone: 'red' },
  { icon: BrainCircuit, label: 'Understands attacker behavior', tone: 'blue' },
  { icon: Activity, label: 'Actionable Security', tone: 'red' },
  { icon: ClipboardList, label: 'Web Exploit Analysis', tone: 'blue' },
  { icon: Zap, label: 'AI Security Agent', tone: 'blue' },
];

const heroHighlights = [
  { value: '<2 min', label: 'average first scan' },
  { value: 'OWASP', label: 'aligned checks' },
  { value: 'AI fixes', label: 'guided remediation' },
];

const previewMetrics = [
  { value: '0', label: 'Critical', tone: 'safe' },
  { value: '3', label: 'Warnings', tone: 'warn' },
  { value: '9', label: 'Suggested fixes', tone: 'info' },
];

const duplicatedMarqueeItems = [...marqueeItems, ...marqueeItems, ...marqueeItems];

const HomePage = ({ onNavigateToSignUp, onNavigateToHome, onNavigateToBlog, onNavigateToAwareness, onNavigateToTools }) => {
  const handleExploreFeatures = useCallback(() => {
    const featuresSection = document.querySelector('.home-benefits-section');
    if (featuresSection) {
      featuresSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, []);

  return (
    <div className="home-page">
      <Navbar
        onNavigateToSignUp={onNavigateToSignUp}
        onNavigateToHome={onNavigateToHome}
        onNavigateToBlog={onNavigateToBlog}
        onNavigateToAwareness={onNavigateToAwareness}
        onNavigateToTools={onNavigateToTools}
        currentPage="home"
      />

      <section className="home-hero-section">
        <div className="home-shell">
          <div className="home-hero-card">
            <div className="home-hero-badge">
              <span className="home-hero-badge-dot" aria-hidden="true" />
              <span>Live AI security analysis for modern web apps</span>
            </div>

            <h1 className="home-hero-title">Smart AI-Powered Web Vulnerability Scanner</h1>

            <p className="home-hero-lead">Scan, detect, and secure your web applications in seconds.</p>

            <p className="home-hero-subtext">
              Identify vulnerabilities before hackers do powered by intelligent automation.
            </p>

            <div className="home-hero-highlights" aria-label="Threat Hunters highlights">
              {heroHighlights.map((item) => (
                <div className="home-hero-highlight" key={item.label}>
                  <strong>{item.value}</strong>
                  <span>{item.label}</span>
                </div>
              ))}
            </div>

            <div className="home-scan-shell">
              <div className="home-scan-input-row">
                <div className="home-browser-window">
                  <div className="home-browser-dots" aria-hidden="true">
                    <span className="home-browser-dot home-browser-dot-red"></span>
                    <span className="home-browser-dot home-browser-dot-yellow"></span>
                    <span className="home-browser-dot home-browser-dot-green"></span>
                  </div>
                  <input
                    aria-label="Website URL"
                    className="home-url-input"
                    placeholder="https://yourwebsite.com"
                    readOnly
                    type="text"
                  />
                </div>

                <button className="home-primary-button home-hero-button" onClick={onNavigateToSignUp} type="button">
                  <span>Scan Now</span>
                </button>
              </div>

              <div className="home-scan-preview">
                <div className="home-scan-preview-header">
                  <span className="home-scan-preview-pill">Preview report</span>
                  <span className="home-scan-preview-risk">Risk score 24/100</span>
                </div>

                <div className="home-scan-preview-main">
                  <div className="home-scan-preview-icon" aria-hidden="true">
                    <ShieldCheck />
                  </div>

                  <div className="home-scan-preview-copy">
                    <h3>Quick scan found a few issues worth fixing</h3>
                    <p>Headers, public assets, and exposed routes were prioritized into one clean report.</p>
                  </div>
                </div>

                <div className="home-scan-metrics">
                  {previewMetrics.map((item) => (
                    <article className={`home-scan-metric home-scan-metric--${item.tone}`} key={item.label}>
                      <strong>{item.value}</strong>
                      <span>{item.label}</span>
                    </article>
                  ))}
                </div>
              </div>
            </div>

            <button className="home-secondary-button" onClick={handleExploreFeatures} type="button">
              Explore Features
            </button>
          </div>
        </div>
      </section>

      <section className="home-process-section">
        <div className="home-shell">
          <div className="home-section-intro">
            <span className="home-section-badge">How It Works</span>
            <h2 className="home-section-title">Simple 3-Step Process</h2>
            <p className="home-section-copy">Get comprehensive security insights in minutes</p>
          </div>

          <div className="home-process-grid">
            {processSteps.map(({ icon: Icon, number, title, description }) => (
              <article className="home-process-card" key={title}>
                <div className="home-process-icon-wrap">
                  <div className="home-process-icon" aria-hidden="true">
                    <Icon />
                  </div>
                  <span className="home-process-number">{number}</span>
                </div>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>

          <button className="home-primary-button home-process-button" onClick={onNavigateToSignUp} type="button">
            <span>Try It Now - It&apos;s Free</span>
            <ArrowRight aria-hidden="true" className="home-button-arrow" />
          </button>
        </div>
      </section>

      <section className="home-marquee-section" aria-label="Threat Hunter highlights">
        <div className="home-marquee-row">
          <div className="home-marquee-track">
            {duplicatedMarqueeItems.map(({ icon: Icon, label, tone }, index) => (
              <div className={`home-marquee-item home-marquee-item-${tone}`} key={`top-${label}-${index}`}>
                <Icon aria-hidden="true" />
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="home-marquee-row home-marquee-row-reverse">
          <div className="home-marquee-track">
            {duplicatedMarqueeItems.map(({ icon: Icon, label, tone }, index) => (
              <div className={`home-marquee-item home-marquee-item-${tone}`} key={`bottom-${label}-${index}`}>
                <Icon aria-hidden="true" />
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="home-benefits-section">
        <div className="home-shell">
          <div className="home-section-intro">
            <span className="home-section-badge">Why Choose Us</span>
            <h2 className="home-section-title">Why Choose Threat Hunter</h2>
            <p className="home-section-copy">Advanced security features built for modern web applications</p>
          </div>

          <div className="home-feature-grid">
            {featureCards.map(({ icon: Icon, title, description }) => (
              <article className="home-feature-card" key={title}>
                <div className="home-feature-icon" aria-hidden="true">
                  <Icon />
                </div>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="home-final-cta-section">
        <span className="home-final-word home-final-word-left">Fast.</span>
        <span className="home-final-word home-final-word-center">Secure.</span>
        <span className="home-final-word home-final-word-right">simple.</span>

        <div className="home-shell">
          <div className="home-final-cta-content">
            <h2>Ready to Secure Your Applications?</h2>
            <p>Join thousands of developers protecting their web applications with Threat Hunter</p>
            <button className="home-primary-button home-final-button" onClick={onNavigateToSignUp} type="button">
              <span>Start Scanning Free</span>
              <ArrowRight aria-hidden="true" className="home-button-arrow" />
            </button>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
};

export default memo(HomePage);
