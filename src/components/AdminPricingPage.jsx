import {
  BarChart3,
  Check,
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
  Star,
  Sun,
  TrendingUp,
  Users,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { adminAPI } from '../services/api';
import './AdminDashboardPage.css';
import './AdminPricingPage.css';

const topNavItems = [
  { label: 'Home', route: 'admin-dashboard' },
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

const statCards = [
  { label: 'Total Revenue', value: '$47,892', change: '+23%', icon: DollarSign, tone: 'admin-tone-indigo', changeTone: 'is-positive' },
  { label: 'Active Subscriptions', value: '813', change: '+12%', icon: Users, tone: 'admin-tone-green', changeTone: 'is-positive' },
  { label: 'MRR', value: '$38,450', change: '+18%', icon: TrendingUp, tone: 'admin-tone-orange', changeTone: 'is-positive' },
  { label: 'Churn Rate', value: '2.3%', change: '-0.5%', icon: BarChart3, tone: 'admin-tone-indigo', changeTone: 'is-positive' },
];

const plans = [
  {
    name: 'Free',
    price: '$0',
    description: 'Perfect for trying out our service',
    subscribers: '456',
    badge: null,
    tone: 'is-free',
    features: [
      { label: 'Basic vulnerability scanning', included: true },
      { label: '1 active project', included: true },
      { label: 'Email notifications', included: true },
      { label: 'Advanced reporting', included: false },
      { label: 'Priority support', included: false },
    ],
  },
  {
    name: 'Professional',
    price: '$49',
    description: 'For professionals and small teams',
    subscribers: '234',
    badge: 'Most Popular',
    tone: 'is-professional',
    features: [
      { label: 'Advanced vulnerability scanning', included: true },
      { label: '10 active projects', included: true },
      { label: 'Detailed PDF reports', included: true },
      { label: 'Priority email support', included: true },
      { label: 'Team collaboration tools', included: false },
    ],
  },
  {
    name: 'Enterprise',
    price: '$199',
    description: 'For large teams and organizations',
    subscribers: '123',
    badge: null,
    tone: 'is-enterprise',
    features: [
      { label: 'Unlimited vulnerability scans', included: true },
      { label: 'Unlimited active projects', included: true },
      { label: 'Custom reports and exports', included: true },
      { label: 'Dedicated success manager', included: true },
      { label: 'SSO and advanced access control', included: true },
    ],
  },
];

const transactions = [
  { customer: 'Mohamed Ahmed', plan: 'Professional', amount: '$49', date: 'Jul 1, 2025', status: 'completed' },
  { customer: 'Sarah Ali', plan: 'Enterprise', amount: '$199', date: 'Jul 1, 2025', status: 'completed' },
  { customer: 'Hassan Omar', plan: 'Professional', amount: '$49', date: 'Jun 30, 2025', status: 'completed' },
  { customer: 'Nour Salem', plan: 'Enterprise', amount: '$199', date: 'Jun 29, 2025', status: 'pending' },
];

const emptyPlanForm = {
  name: '',
  price: '$99',
  description: '',
  subscribers: '0',
  badge: '',
  tone: 'is-professional',
  featuresText: 'Security scanning | yes\nPDF reports | yes\nPriority support | no',
};

const featuresToText = (features = []) => features
  .map((feature) => `${feature.label || ''} | ${feature.included ? 'yes' : 'no'}`)
  .join('\n');

const planToForm = (plan) => ({
  name: plan.name || '',
  price: plan.price || '$0',
  description: plan.description || '',
  subscribers: String(plan.subscribers ?? 0),
  badge: plan.badge || '',
  tone: plan.tone || getPlanTone(plan.name),
  featuresText: featuresToText(plan.features || []),
});

const parseFeatures = (value) => String(value || '')
  .split('\n')
  .map((line) => line.trim())
  .filter(Boolean)
  .map((line) => {
    const [labelPart, includedPart = 'yes'] = line.split('|').map((part) => part.trim());
    return {
      label: labelPart,
      included: !['no', 'false', '0', 'disabled'].includes(includedPart.toLowerCase()),
    };
  })
  .filter((feature) => feature.label);

function getPlanTone(plan) {
  if (plan === 'Enterprise') {
    return 'is-enterprise';
  }

  if (plan === 'Professional') {
    return 'is-professional';
  }

  return 'is-free';
}

function formatPricingDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value || 'Recently';
  }

  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function AdminPricingPage({ onNavigate, onLogout, currentPage = 'admin-pricing' }) {
  const { theme, toggleTheme } = useTheme();
  const [planItems, setPlanItems] = useState(plans);
  const [transactionItems, setTransactionItems] = useState(transactions);
  const [pricingStats, setPricingStats] = useState(null);
  const [notice, setNotice] = useState('');
  const [isPlanEditorOpen, setIsPlanEditorOpen] = useState(false);
  const [editingPlan, setEditingPlan] = useState(null);
  const [planForm, setPlanForm] = useState(emptyPlanForm);
  const [isSavingPlan, setIsSavingPlan] = useState(false);

  const loadPricing = useCallback(async () => {
    try {
      setNotice('Loading pricing from backend...');
      const payload = await adminAPI.getPricing();
      setPlanItems(payload.plans?.length ? payload.plans : plans);
      setTransactionItems(payload.transactions?.length ? payload.transactions : transactions);
      setPricingStats(payload.stats || null);
      setNotice('');
    } catch (error) {
      setPlanItems(plans);
      setTransactionItems(transactions);
      setPricingStats(null);
      setNotice(error.message || 'Using local pricing data until the backend is available.');
    }
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      loadPricing();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [loadPricing]);

  const computedStatCards = useMemo(() => {
    if (!pricingStats) {
      return statCards;
    }

    return [
      { label: 'Total Revenue', value: pricingStats.totalRevenue || '$0', change: 'live', icon: DollarSign, tone: 'admin-tone-indigo', changeTone: 'is-positive' },
      { label: 'Active Subscriptions', value: String(pricingStats.activeSubscriptions || 0), change: 'live', icon: Users, tone: 'admin-tone-green', changeTone: 'is-positive' },
      { label: 'MRR', value: pricingStats.mrr || '$0', change: 'live', icon: TrendingUp, tone: 'admin-tone-orange', changeTone: 'is-positive' },
      { label: 'Churn Rate', value: pricingStats.churnRate || '0%', change: 'live', icon: BarChart3, tone: 'admin-tone-indigo', changeTone: 'is-positive' },
    ];
  }, [pricingStats]);

  const openAddPlan = () => {
    setEditingPlan(null);
    setPlanForm(emptyPlanForm);
    setNotice('');
    setIsPlanEditorOpen(true);
  };

  const openEditPlan = (plan) => {
    setEditingPlan(plan);
    setPlanForm(planToForm(plan));
    setNotice('');
    setIsPlanEditorOpen(true);
  };

  const updatePlanField = (field, value) => {
    setPlanForm((prev) => ({ ...prev, [field]: value }));
  };

  const closePlanEditor = () => {
    setIsPlanEditorOpen(false);
    setEditingPlan(null);
    setPlanForm(emptyPlanForm);
  };

  const savePricingPlan = async () => {
    const trimmedPrice = planForm.price.trim();
    const trimmedName = planForm.name.trim();

    if (!trimmedName) {
      setNotice('Plan name is required.');
      return;
    }

    if (!/^\$?\d+(\.\d{1,2})?$/.test(trimmedPrice)) {
      setNotice('Enter a valid price, for example $49 or 49.99.');
      return;
    }

    const subscribers = Number(planForm.subscribers || 0);
    if (!Number.isFinite(subscribers) || subscribers < 0) {
      setNotice('Subscribers must be a positive number.');
      return;
    }

    const features = parseFeatures(planForm.featuresText);
    if (!features.length) {
      setNotice('Add at least one feature. Use: Feature label | yes/no');
      return;
    }

    const payload = {
      name: trimmedName,
      price: trimmedPrice.startsWith('$') ? trimmedPrice : `$${trimmedPrice}`,
      description: planForm.description.trim(),
      subscribers,
      badge: planForm.badge.trim(),
      tone: planForm.tone,
      features,
    };

    try {
      setIsSavingPlan(true);
      setNotice('Saving pricing plan...');
      if (editingPlan?.id) {
        await adminAPI.updatePricingPlan(editingPlan.id, payload);
      } else {
        await adminAPI.addPricingPlan(payload);
      }
      await loadPricing();
      closePlanEditor();
      setNotice(editingPlan ? `${payload.name} plan updated.` : `${payload.name} plan added.`);
    } catch (error) {
      setNotice(error.message || 'Unable to save pricing plan.');
    } finally {
      setIsSavingPlan(false);
    }
  };

  const deletePricingPlan = async () => {
    if (!editingPlan?.id) {
      return;
    }

    if (!window.confirm(`Delete ${editingPlan.name} plan?`)) {
      return;
    }

    try {
      setIsSavingPlan(true);
      setNotice('Deleting pricing plan...');
      await adminAPI.deletePricingPlan(editingPlan.id);
      await loadPricing();
      closePlanEditor();
      setNotice('Pricing plan deleted.');
    } catch (error) {
      setNotice(error.message || 'Unable to delete pricing plan.');
    } finally {
      setIsSavingPlan(false);
    }
  };

  return (
    <div className="admin-pricing-page">
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
        <aside className="admin-sidebar admin-card">
          <div className="admin-sidebar-group">
            {sidebarItems.map((item) => {
              const Icon = item.icon;
              const isActive = item.id === 'pricing';

              return (
                <button
                  key={item.id}
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
              );
            })}
          </div>
        </aside>

        <main className="admin-main admin-pricing-main">
          <section className="admin-pricing-header">
            <div className="admin-section-head admin-cardless">
              <h1>Pricing Management</h1>
              <p>Manage subscription plans and pricing</p>
            </div>

            <button type="button" className="admin-pricing-add-btn" onClick={openAddPlan}>
              <Plus size={18} />
              <span>Add New Plan</span>
            </button>
          </section>

          {notice && <div className="admin-users-notice admin-card">{notice}</div>}

          {isPlanEditorOpen && (
            <section className="admin-editor-panel admin-card">
              <div className="admin-editor-topline">
                <div>
                  <h2>{editingPlan ? 'Edit pricing plan' : 'Add pricing plan'}</h2>
                  <p>Manage plan copy, price, subscribers, badge, and feature availability.</p>
                </div>
                <button type="button" className="admin-editor-secondary" onClick={closePlanEditor}>
                  Close
                </button>
              </div>

              <div className="admin-editor-grid">
                <label className="admin-editor-field">
                  <span>Plan name</span>
                  <input value={planForm.name} onChange={(event) => updatePlanField('name', event.target.value)} placeholder="Growth" />
                </label>
                <label className="admin-editor-field">
                  <span>Monthly price</span>
                  <input value={planForm.price} onChange={(event) => updatePlanField('price', event.target.value)} placeholder="$99" />
                </label>
                <label className="admin-editor-field">
                  <span>Subscribers</span>
                  <input type="number" min="0" value={planForm.subscribers} onChange={(event) => updatePlanField('subscribers', event.target.value)} />
                </label>
                <label className="admin-editor-field">
                  <span>Badge</span>
                  <input value={planForm.badge} onChange={(event) => updatePlanField('badge', event.target.value)} placeholder="Most Popular" />
                </label>
                <label className="admin-editor-field">
                  <span>Tone</span>
                  <select value={planForm.tone} onChange={(event) => updatePlanField('tone', event.target.value)}>
                    <option value="is-free">Free</option>
                    <option value="is-professional">Professional</option>
                    <option value="is-enterprise">Enterprise</option>
                  </select>
                </label>
                <label className="admin-editor-field admin-editor-field-full">
                  <span>Description</span>
                  <textarea value={planForm.description} onChange={(event) => updatePlanField('description', event.target.value)} placeholder="For growing security teams" />
                </label>
                <label className="admin-editor-field admin-editor-field-full">
                  <span>Features</span>
                  <textarea value={planForm.featuresText} onChange={(event) => updatePlanField('featuresText', event.target.value)} />
                  <span className="admin-editor-help">One feature per line. Format: Feature name | yes/no</span>
                </label>
              </div>

              <div className="admin-editor-actions">
                {editingPlan?.id && (
                  <button type="button" className="admin-editor-danger" onClick={deletePricingPlan} disabled={isSavingPlan}>
                    Delete Plan
                  </button>
                )}
                <button type="button" className="admin-editor-secondary" onClick={closePlanEditor}>Cancel</button>
                <button type="button" className="admin-editor-primary" onClick={savePricingPlan} disabled={isSavingPlan}>
                  {isSavingPlan ? 'Saving...' : editingPlan ? 'Save Plan' : 'Add Plan'}
                </button>
              </div>
            </section>
          )}

          <section className="admin-pricing-stats">
            {computedStatCards.map((item) => {
              const Icon = item.icon;

              return (
                <article key={item.label} className="admin-pricing-stat-card admin-card">
                  <div className="admin-pricing-stat-head">
                    <span className={`admin-stat-icon ${item.tone}`}>
                      <Icon size={16} />
                    </span>
                    <span className={`admin-pricing-stat-change ${item.changeTone}`}>{item.change}</span>
                  </div>

                  <div className="admin-pricing-stat-copy">
                    <strong>{item.value}</strong>
                    <p>{item.label}</p>
                  </div>
                </article>
              );
            })}
          </section>

          <section className="admin-pricing-plan-grid">
            {planItems.map((plan) => (
              <article
                key={plan.id || plan.name}
                className={`admin-pricing-plan-card admin-card ${plan.badge ? 'is-featured' : ''}`}
              >
                <div className="admin-pricing-plan-head">
                  <div className="admin-pricing-plan-titles">
                    <h2>{plan.name}</h2>
                    {plan.badge && (
                      <span className="admin-pricing-popular-badge">
                        <Star size={13} />
                        <span>{plan.badge}</span>
                      </span>
                    )}
                  </div>

                  <div className="admin-pricing-price-block">
                    <strong>{plan.price}</strong>
                    <span>/month</span>
                  </div>
                </div>

                <p className="admin-pricing-plan-description">{plan.description}</p>

                <div className="admin-pricing-feature-list">
                  {plan.features.map((feature) => (
                    <div
                      key={feature.label}
                      className={`admin-pricing-feature-item ${feature.included ? 'is-included' : 'is-disabled'}`}
                    >
                      <span className="admin-pricing-feature-icon" aria-hidden="true">
                        {feature.included ? <Check size={14} /> : <X size={14} />}
                      </span>
                      <span>{feature.label}</span>
                    </div>
                  ))}
                </div>

                <div className="admin-pricing-plan-footer">
                  <div className="admin-pricing-subscribers">
                    <span>Subscribers</span>
                    <strong>{plan.subscribers}</strong>
                  </div>

                  <button type="button" className={`admin-pricing-edit-btn ${plan.tone}`} onClick={() => openEditPlan(plan)}>
                    Edit Plan
                  </button>
                </div>
              </article>
            ))}
          </section>

          <section className="admin-pricing-transactions admin-card">
            <div className="admin-section-head">
              <h2>Recent Transactions</h2>
            </div>

            <div className="admin-pricing-table-scroll">
              <table className="admin-pricing-table">
                <thead>
                  <tr>
                    <th>Customer</th>
                    <th>Plan</th>
                    <th>Amount</th>
                    <th>Date</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {transactionItems.map((transaction) => (
                    <tr key={transaction.id || `${transaction.customer}-${transaction.date}`}>
                      <td>{transaction.customer}</td>
                      <td>
                        <span className={`admin-pricing-plan-pill ${getPlanTone(transaction.plan)}`}>
                          {transaction.plan}
                        </span>
                      </td>
                      <td>{transaction.amount}</td>
                      <td>{formatPricingDate(transaction.date)}</td>
                      <td>
                        <span className={`admin-pricing-status is-${transaction.status}`}>
                          {transaction.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default AdminPricingPage;
