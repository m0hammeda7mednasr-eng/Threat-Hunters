import { memo, useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  BookOpen,
  CalendarDays,
  Clock3,
  ExternalLink,
  FileText,
  Globe,
  ListChecks,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Tag,
  TriangleAlert,
} from 'lucide-react';
import './AwarenessDetailPage.css';
import Navbar from './Navbar';
import Footer from './Footer';
import { securityAPI } from '../services/api';

const kindLabels = {
  'latest-cves': 'Recent CVE',
  'critical-cves': 'Critical CVE',
  kev: 'Known Exploited Vulnerability',
  news: 'Security News',
  resource: 'Learning Resource',
};

const kindSources = {
  'latest-cves': 'NVD',
  'critical-cves': 'NVD',
  kev: 'CISA KEV',
  news: 'Security News Feed',
  resource: 'Curated Resource',
};

const normalizeList = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.vulnerabilities)) return payload.vulnerabilities;
  if (Array.isArray(payload?.news)) return payload.news;
  return [];
};

const slugify = (value) =>
  String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');

const pickIdentifier = (item) =>
  item?.id ||
  item?.cve ||
  item?.cve_id ||
  item?.cveID ||
  item?.title ||
  item?.headline ||
  '';

const labelIconMap = {
  'latest-cves': ShieldAlert,
  'critical-cves': TriangleAlert,
  kev: ShieldCheck,
  news: Globe,
  resource: BookOpen,
};

const parseCachedDetail = () => {
  try {
    const raw = window.sessionStorage.getItem('awareness-detail-cache');
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

const detailFieldGroups = {
  'latest-cves': (item) => [
    { label: 'Severity', value: item.severity || 'Unknown' },
    { label: 'Score', value: item.score ?? 'Unknown' },
    { label: 'CWE', value: item.cwe || 'Unknown' },
    { label: 'Category', value: item.category || 'Unknown' },
    { label: 'Published', value: item.published || 'Unknown' },
  ],
  'critical-cves': (item) => [
    { label: 'Severity', value: item.severity || 'Unknown' },
    { label: 'Score', value: item.score ?? 'Unknown' },
    { label: 'CWE', value: item.cwe || 'Unknown' },
    { label: 'Category', value: item.category || 'Unknown' },
    { label: 'Published', value: item.published || 'Unknown' },
  ],
  kev: (item) => [
    { label: 'Vendor', value: item.vendor || 'Unknown' },
    { label: 'Product', value: item.product || 'Unknown' },
    { label: 'Date Added', value: item.date_added || item.dateAdded || 'Unknown' },
    { label: 'Due Date', value: item.due_date || item.dueDate || 'Unknown' },
    { label: 'Required Action', value: item.required_action || 'Unknown' },
  ],
  news: (item) => [
    { label: 'Source', value: item.source || item.publisher || 'Unknown' },
    { label: 'Published', value: item.published || 'Unknown' },
    { label: 'Link', value: item.link || 'Unknown' },
  ],
  resource: (item) => [
    { label: 'Type', value: item.type || 'Unknown' },
    { label: 'Topic', value: item.topic || 'Unknown' },
    { label: 'Audience', value: item.audience || 'Unknown' },
    { label: 'Priority', value: item.priority || 'Unknown' },
    { label: 'Duration', value: item.duration || 'Unknown' },
  ],
};

const detailActionCopy = {
  'latest-cves': 'Review the vulnerability details, validate exposure, and prioritize any affected services.',
  'critical-cves': 'Treat these findings as high priority and move from review to mitigation quickly.',
  kev: 'CISA tracks these as exploited in the wild, so focus on patching and containment first.',
  news: 'Use the article to understand the context, then cross-check the advisory or vendor guidance.',
  resource: 'Apply the guide to your team workflow and turn the checklist into an operating habit.',
};

const detailChecklist = {
  'latest-cves': [
    'Confirm whether the affected product is present in your environment.',
    'Check whether the vulnerable version is exposed to the internet.',
    'Track remediation in your vulnerability backlog.',
  ],
  'critical-cves': [
    'Patch or mitigate the issue with the fastest safe path available.',
    'Document compensating controls if the fix needs coordination.',
    'Re-scan after the change to verify the exposure is gone.',
  ],
  kev: [
    'Prioritize affected assets over lower-risk backlog items.',
    'Review whether the vendor has released a fix or workaround.',
    'Validate that the exploit path is closed after remediation.',
  ],
  news: [
    'Read the full article and trace it back to an official source if possible.',
    'Capture the dates, vendor names, and products mentioned.',
    'Use the update to inform scanning and patching priorities.',
  ],
  resource: [
    'Turn the guide into a team checklist or onboarding task.',
    'Assign ownership for the next review cycle.',
    'Keep the PDF or guide linked in your internal playbook.',
  ],
};

const HIDDEN_CAPTURED_FIELD_KEYS = new Set(['link', 'url']);

const isUrlValue = (value) => /^https?:\/\//i.test(String(value || '').trim());

const renderCapturedFieldValue = (value) => {
  const text = String(value || '');
  if (isUrlValue(text)) {
    return (
      <a className="awareness-detail-field-link" href={text} target="_blank" rel="noreferrer">
        {text}
      </a>
    );
  }
  return text;
};

const buildRawEntries = (item) =>
  Object.entries(item || {})
    .filter(([key, value]) => (
      !HIDDEN_CAPTURED_FIELD_KEYS.has(String(key || '').trim().toLowerCase()) &&
      value !== undefined &&
      value !== null &&
      value !== ''
    ))
    .map(([key, value]) => ({
      key,
      value: Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value),
    }));

const AwarenessDetailPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToTools,
  onNavigateToAwareness,
  detail,
  isLoggedIn,
}) => {
  const [awarenessContent, setAwarenessContent] = useState({
    resources: [],
  });
  const [liveFeed, setLiveFeed] = useState({
    latestCves: [],
    criticalCves: [],
    kev: [],
    news: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const cachedDetail = useMemo(() => parseCachedDetail(), []);

  useEffect(() => {
    let mounted = true;

    const loadData = async () => {
      setLoading(true);
      setError('');

      const [awarenessResult, latestResult, criticalResult, kevResult, newsResult] = await Promise.allSettled([
        securityAPI.getAwarenessContent(),
        securityAPI.getLatestCVEs(),
        securityAPI.getCriticalCVEs(),
        securityAPI.getKEV(),
        securityAPI.getSecurityNews(),
      ]);

      if (!mounted) return;

      if (awarenessResult.status === 'fulfilled') {
        setAwarenessContent({
          resources: normalizeList(awarenessResult.value?.resources),
        });
      } else {
        setError('Some detail data could not be loaded from the backend. Showing what is available.');
      }

      setLiveFeed({
        latestCves: latestResult.status === 'fulfilled' ? normalizeList(latestResult.value) : [],
        criticalCves: criticalResult.status === 'fulfilled' ? normalizeList(criticalResult.value) : [],
        kev: kevResult.status === 'fulfilled' ? normalizeList(kevResult.value) : [],
        news: newsResult.status === 'fulfilled' ? normalizeList(newsResult.value) : [],
      });

      setLoading(false);
    };

    loadData();

    return () => {
      mounted = false;
    };
  }, []);

  const routeKind = detail?.kind || cachedDetail?.kind || 'resource';
  const routeId = detail?.id || cachedDetail?.item?.id || cachedDetail?.item?.cve || cachedDetail?.item?.title || '';

  const selectedItem = useMemo(() => {
    if (cachedDetail?.kind === routeKind && cachedDetail?.item) {
      const cachedId = pickIdentifier(cachedDetail.item);
      if (!routeId || cachedId === routeId || slugify(cachedId) === slugify(routeId)) {
        return cachedDetail.item;
      }
    }

    if (routeKind === 'resource') {
      return awarenessContent.resources.find((resource) => {
        const candidate = pickIdentifier(resource);
        return candidate === routeId || slugify(candidate) === slugify(routeId);
      });
    }

    const liveCollections = {
      'latest-cves': liveFeed.latestCves,
      'critical-cves': liveFeed.criticalCves,
      kev: liveFeed.kev,
      news: liveFeed.news,
    };

    const items = liveCollections[routeKind] || [];
    return items.find((item) => {
      const candidate = pickIdentifier(item);
      return candidate === routeId || slugify(candidate) === slugify(routeId);
    });
  }, [awarenessContent.resources, cachedDetail?.item, cachedDetail?.kind, liveFeed.criticalCves, liveFeed.kev, liveFeed.latestCves, liveFeed.news, routeId, routeKind]);

  const Icon = labelIconMap[routeKind] || ShieldAlert;
  const title = selectedItem
    ? selectedItem.title || selectedItem.headline || selectedItem.id || selectedItem.cve || selectedItem.cveID || 'Detail'
    : 'Security Detail';
  const summary = selectedItem?.description || selectedItem?.summary || selectedItem?.short_description || selectedItem?.content || 'A full detail view for this security item.';
  const sourceLabel = kindSources[routeKind] || 'Security Intelligence';
  const label = kindLabels[routeKind] || 'Security Item';
  const fields = selectedItem
    ? (detailFieldGroups[routeKind] ? detailFieldGroups[routeKind](selectedItem) : [])
        .filter((field) => String(field.label || '').toLowerCase() !== 'link')
    : [];
  const checklist = detailChecklist[routeKind] || [];
  const rawEntries = selectedItem ? buildRawEntries(selectedItem) : [];

  return (
    <div className="security-awareness-detail-page">
      {!isLoggedIn && (
        <Navbar
          onNavigateToSignUp={onNavigateToSignUp}
          onNavigateToHome={onNavigateToHome}
          onNavigateToBlog={onNavigateToBlog}
          onNavigateToTools={onNavigateToTools}
          currentPage="awareness"
        />
      )}

      <main className="awareness-detail">
        <div className="awareness-shell">
          <button type="button" className="awareness-detail__back" onClick={onNavigateToAwareness}>
            <ArrowLeft strokeWidth={1.9} />
            <span>Back to awareness</span>
          </button>

          <section className="awareness-detail-hero">
            <div className="awareness-detail-hero__icon" aria-hidden="true">
              <Icon strokeWidth={1.8} />
            </div>
            <div className="awareness-detail-hero__content">
              <p className="awareness-detail-hero__eyebrow">{label}</p>
              <h1>{title}</h1>
              <p>{summary}</p>
            </div>
            <div className="awareness-detail-hero__badge">
              <span>{sourceLabel}</span>
              <span>{routeKind}</span>
            </div>
          </section>

          {error && <div className="awareness-detail__notice">{error}</div>}

          <section className="awareness-detail-grid">
            <article className="awareness-detail-card">
              <p className="awareness-detail-card__title">Overview</p>
              <div className="awareness-detail-card__metrics">
                {fields.map((field) => (
                  <div key={field.label} className="awareness-detail-metric">
                    <span>{field.label}</span>
                    <strong>{field.value}</strong>
                  </div>
                ))}
              </div>
            </article>

            <article className="awareness-detail-card">
              <p className="awareness-detail-card__title">What to do</p>
              <p className="awareness-detail-card__copy">{detailActionCopy[routeKind]}</p>
              <ul className="awareness-detail-list">
                {checklist.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
          </section>

          <section className="awareness-detail-grid awareness-detail-grid--stacked">
            <article className="awareness-detail-card awareness-detail-card--wide">
              <div className="awareness-detail-card__header">
                <p className="awareness-detail-card__title">Raw data</p>
                <span>{loading ? 'Refreshing...' : `${rawEntries.length} fields`}</span>
              </div>
              {selectedItem ? (
                <pre className="awareness-detail-pre">{JSON.stringify(selectedItem, null, 2)}</pre>
              ) : (
                <div className="awareness-empty-state">No matching item was found for this route.</div>
              )}
            </article>

            <article className="awareness-detail-card awareness-detail-card--wide">
              <div className="awareness-detail-card__header">
                <p className="awareness-detail-card__title">Captured fields</p>
                <span>{routeKind}</span>
              </div>
              <div className="awareness-detail-fields">
                {rawEntries.map((entry) => (
                  <div key={entry.key} className="awareness-detail-field">
                    <span>{entry.key}</span>
                    <strong>{renderCapturedFieldValue(entry.value)}</strong>
                  </div>
                ))}
              </div>
            </article>
          </section>

          <section className="awareness-detail-grid">
            <article className="awareness-detail-card">
              <p className="awareness-detail-card__title">Source context</p>
              <div className="awareness-detail-source">
                <span><Clock3 strokeWidth={1.7} /> {selectedItem?.published || selectedItem?.dateAdded || selectedItem?.date_added || 'No date available'}</span>
                <span><Tag strokeWidth={1.7} /> {selectedItem?.category || selectedItem?.topic || selectedItem?.product || 'No category available'}</span>
                <span><Sparkles strokeWidth={1.7} /> {selectedItem?.severity || selectedItem?.priority || selectedItem?.type || 'No severity label'}</span>
              </div>
            </article>

            <article className="awareness-detail-card">
              <p className="awareness-detail-card__title">Quick actions</p>
              <div className="awareness-detail-actions">
                {selectedItem?.url || selectedItem?.link ? (
                  <a className="awareness-detail-action" href={selectedItem.url || selectedItem.link} target="_blank" rel="noreferrer">
                    <ExternalLink strokeWidth={1.8} />
                    <span>Open source</span>
                  </a>
                ) : null}
                <button type="button" className="awareness-detail-action awareness-detail-action--ghost" onClick={onNavigateToAwareness}>
                  <ListChecks strokeWidth={1.8} />
                  <span>Back to feed</span>
                </button>
              </div>
            </article>
          </section>

          <section className="awareness-detail-grid awareness-detail-grid--two">
            <article className="awareness-detail-card">
              <p className="awareness-detail-card__title">Next review</p>
              <p className="awareness-detail-card__copy">
                {routeKind === 'resource'
                  ? 'Use the resource as part of onboarding, awareness refreshers, or team training.'
                  : 'Re-run your scanner, validate exposure, and keep a remediation note attached to this item.'}
              </p>
            </article>

            <article className="awareness-detail-card">
              <p className="awareness-detail-card__title">Reference</p>
              <p className="awareness-detail-card__copy">
                {routeKind === 'resource'
                  ? selectedItem?.bestFor || 'No extra reference text was provided.'
                  : selectedItem?.description || selectedItem?.summary || 'No extra reference text was provided.'}
              </p>
            </article>
          </section>
        </div>
      </main>

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(AwarenessDetailPage);
