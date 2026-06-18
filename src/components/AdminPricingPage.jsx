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

  const addPricingPlan = async () => {
    try {
      setNotice('Adding new pricing plan...');
      await adminAPI.addPricingPlan({
        name: 'Growth',
        price: '$99',
        description: 'For growing security teams that need more automation',
        subscribers: 0,
        badge: 'New',
        tone: 'is-professional',
      });
      await loadPricing();
      setNotice('Pricing plan added.');
    } catch (error) {
      setNotice(error.message || 'Unable to add pricing plan.');
    }
  };

  const editPricingPlan = async (plan) => {
    const nextPrice = window.prompt(`New monthly price for ${plan.name}`, plan.price);
    if (nextPrice === null) {
      return;
    }

    const trimmedPrice = nextPrice.trim();
    if (!/^\$?\d+(\.\d{1,2})?$/.test(trimmedPrice)) {
      setNotice('Enter a valid price, for example $49 or 49.99.');
      return;
    }

    try {
      setNotice('Saving pricing plan...');
      await adminAPI.updatePricingPlan(plan.id, {
        ...plan,
        price: trimmedPrice.startsWith('$') ? trimmedPrice : `$${trimmedPrice}`,
      });
      await loadPricing();
      setNotice(`${plan.name} plan updated.`);
    } catch (error) {
      setNotice(error.message || 'Unable to update pricing plan.');
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

            <button type="button" className="admin-pricing-add-btn" onClick={addPricingPlan}>
              <Plus size={18} />
              <span>Add New Plan</span>
            </button>
          </section>

          {notice && <div className="admin-users-notice admin-card">{notice}</div>}

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
                key={plan.name}
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

                  <button type="button" className={`admin-pricing-edit-btn ${plan.tone}`} onClick={() => editPricingPlan(plan)}>
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
