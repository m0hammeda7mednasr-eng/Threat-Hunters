import { memo } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  FileText,
  HelpCircle,
  LifeBuoy,
  LockKeyhole,
  Mail,
  Scale,
  ShieldCheck,
} from 'lucide-react';
import Navbar from './Navbar';
import Footer from './Footer';
import './SupportPage.css';

const pageContent = {
  'help-center': {
    eyebrow: 'Support Center',
    title: 'Help Center',
    description: 'Fast answers for scanning, reports, accounts, and admin workflows inside Threat Hunters.',
    icon: LifeBuoy,
    accent: '#8b7cff',
    cards: [
      { title: 'Scanner setup', body: 'Paste a public URL, choose a scan mode, and review the generated risk profile.' },
      { title: 'Reports', body: 'Download branded PDF reports, track findings, and review remediation guidance.' },
      { title: 'Admin controls', body: 'Manage users, pricing, team access, web content, and platform settings.' },
    ],
    steps: ['Check your API/backend status first.', 'Run the action again after fixing validation errors.', 'Contact support with the report ID or exact page name.'],
  },
  documentation: {
    eyebrow: 'Product Docs',
    title: 'Documentation',
    description: 'A clean map of the frontend, backend, database, environment variables, and local workflow.',
    icon: BookOpen,
    accent: '#00b8d9',
    cards: [
      { title: 'Frontend', body: 'React, Vite, hash routing, theme context, and shared API client.' },
      { title: 'Backend', body: 'Flask, MongoDB, JWT authentication, scanner routes, blog routes, and admin APIs.' },
      { title: 'Local run', body: 'Use npm run dev to start the Vite frontend and local mock backend together.' },
    ],
    steps: ['Read PROJECT_HANDOFF.md for the full architecture.', 'Keep secrets in .env only.', 'Point VITE_API_BASE_URL to the deployed backend for production.'],
    ctaHref: 'https://github.com/m0hammeda7mednasr-eng/Threat-Hunters#readme',
    ctaLabel: 'Open GitHub README',
  },
  faqs: {
    eyebrow: 'Common Questions',
    title: 'FAQs',
    description: 'Answers to the questions users ask most about security checks and the dashboard.',
    icon: HelpCircle,
    accent: '#18a058',
    cards: [
      { title: 'Does the browser see my HIBP key?', body: 'No. Breach checks run through the backend so keys stay server-side.' },
      { title: 'Can admins edit content?', body: 'Yes. Admin Web Edit saves public page content to the backend.' },
      { title: 'Are reports real?', body: 'Reports are generated from live scan/admin data and downloaded as branded PDFs.' },
    ],
    steps: ['Use a valid URL for scanner input.', 'Use valid email formats in account/admin forms.', 'Regenerate reports after major changes.'],
  },
  'report-issue': {
    eyebrow: 'Issue Desk',
    title: 'Report an Issue',
    description: 'Send a clear bug report with page name, expected behavior, and screenshots when possible.',
    icon: AlertTriangle,
    accent: '#ffb020',
    cards: [
      { title: 'What to include', body: 'Page route, browser, action taken, expected result, actual result, and console error if visible.' },
      { title: 'Security issue', body: 'Do not post secrets publicly. Use responsible disclosure for sensitive vulnerabilities.' },
      { title: 'Product issue', body: 'For normal bugs, open a GitHub issue with reproduction steps.' },
    ],
    steps: ['Reproduce the issue once.', 'Capture the route and exact message.', 'Submit through GitHub or support email.'],
    ctaHref: 'https://github.com/m0hammeda7mednasr-eng/Threat-Hunters/issues/new',
    ctaLabel: 'Open GitHub Issue',
  },
  'contact-support': {
    eyebrow: 'Support',
    title: 'Contact Support',
    description: 'Reach the Threat Hunters team for account, scan, billing, or report help.',
    icon: Mail,
    accent: '#8b7cff',
    cards: [
      { title: 'Response focus', body: 'We prioritize login problems, failed scans, report downloads, and admin access issues.' },
      { title: 'Before sending', body: 'Include your email, page name, and a short description of what went wrong.' },
      { title: 'Security note', body: 'Never send passwords, OTPs, HIBP keys, or private tokens through plain text.' },
    ],
    steps: ['Collect the affected page route.', 'Include the latest report ID if relevant.', 'Send a short support request.'],
    ctaHref: 'mailto:admin@threathunters.com?subject=Threat%20Hunters%20Support%20Request',
    ctaLabel: 'Email Support',
  },
  'privacy-policy': {
    eyebrow: 'Security & Legal',
    title: 'Privacy Policy',
    description: 'How Threat Hunters treats account, scan, report, and support data.',
    icon: LockKeyhole,
    accent: '#00b8d9',
    cards: [
      { title: 'Data minimization', body: 'We only use submitted data to provide scans, reports, support, and account features.' },
      { title: 'Backend secrets', body: 'API keys and email credentials must stay server-side and out of client code.' },
      { title: 'Retention', body: 'Local mock data is development-only; production retention should follow your deployment policy.' },
    ],
    steps: ['Keep secrets out of git.', 'Delete test accounts when no longer needed.', 'Use responsible disclosure for sensitive findings.'],
  },
  'terms-of-service': {
    eyebrow: 'Security & Legal',
    title: 'Terms of Service',
    description: 'Safe and authorized use rules for scanning and security tooling.',
    icon: Scale,
    accent: '#8b7cff',
    cards: [
      { title: 'Authorized targets only', body: 'Only scan assets you own or have explicit permission to assess.' },
      { title: 'No abuse', body: 'Do not use Threat Hunters for spam, harassment, exploitation, or unauthorized testing.' },
      { title: 'Report accuracy', body: 'Security reports guide remediation but should be validated before high-risk decisions.' },
    ],
    steps: ['Confirm target ownership.', 'Use results for defensive remediation.', 'Document fixes and rerun validation scans.'],
  },
  'responsible-disclosure': {
    eyebrow: 'Security & Legal',
    title: 'Responsible Disclosure',
    description: 'A safe channel for reporting vulnerabilities in the Threat Hunters project.',
    icon: ShieldCheck,
    accent: '#18a058',
    cards: [
      { title: 'Good faith research', body: 'Avoid data access, persistence, destructive testing, and public disclosure before review.' },
      { title: 'What to send', body: 'Share impact, affected route, reproduction steps, and any safe proof of concept.' },
      { title: 'Coordination', body: 'We review reports, confirm impact, and coordinate remediation before public details.' },
    ],
    steps: ['Do not expose user data.', 'Send minimal reproduction details.', 'Wait for confirmation before publishing.'],
  },
  'data-protection': {
    eyebrow: 'Security & Legal',
    title: 'Data Protection',
    description: 'Operational controls for protecting scan data, accounts, reports, and admin actions.',
    icon: FileText,
    accent: '#00b8d9',
    cards: [
      { title: 'Access control', body: 'Admin-only routes require authenticated admin tokens.' },
      { title: 'Report handling', body: 'Downloaded PDFs should be shared only with authorized team members.' },
      { title: 'Operational hygiene', body: 'Rotate secrets, keep MongoDB protected, and avoid committing local data.' },
    ],
    steps: ['Protect environment variables.', 'Limit admin access.', 'Audit reports and user actions regularly.'],
  },
};

const fallbackPage = pageContent['help-center'];

function SupportPage({
  pageKey = 'help-center',
  isLoggedIn = false,
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools,
}) {
  const content = pageContent[pageKey] || fallbackPage;
  const Icon = content.icon;

  return (
    <div className="support-page">
      {!isLoggedIn && (
        <Navbar
          onNavigateToSignUp={onNavigateToSignUp}
          onNavigateToHome={onNavigateToHome}
          onNavigateToBlog={onNavigateToBlog}
          onNavigateToAwareness={onNavigateToAwareness}
          onNavigateToTools={onNavigateToTools}
          currentPage={pageKey}
        />
      )}

      <main className="support-main">
        <section className="support-hero">
          <div className="support-hero__copy">
            <span className="support-eyebrow">{content.eyebrow}</span>
            <h1>{content.title}</h1>
            <p>{content.description}</p>
            {content.ctaHref && (
              <a className="support-cta" href={content.ctaHref} target={content.ctaHref.startsWith('http') ? '_blank' : undefined} rel={content.ctaHref.startsWith('http') ? 'noreferrer' : undefined}>
                <span>{content.ctaLabel}</span>
                <ArrowRight size={16} />
              </a>
            )}
          </div>

          <div className="support-hero__badge" style={{ '--support-accent': content.accent }}>
            <Icon size={40} />
            <span>Threat Hunters</span>
          </div>
        </section>

        <section className="support-card-grid">
          {content.cards.map((card) => (
            <article className="support-card" key={card.title}>
              <CheckCircle2 size={18} />
              <h2>{card.title}</h2>
              <p>{card.body}</p>
            </article>
          ))}
        </section>

        <section className="support-process">
          <div>
            <span className="support-eyebrow">Recommended Flow</span>
            <h2>What to do next</h2>
          </div>
          <div className="support-step-list">
            {content.steps.map((step, index) => (
              <div className="support-step" key={step}>
                <span>{String(index + 1).padStart(2, '0')}</span>
                <p>{step}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      {!isLoggedIn && <Footer />}
    </div>
  );
}

export default memo(SupportPage);
