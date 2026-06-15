import { memo, useMemo } from 'react';
import { LogOut, Moon, Shield, Sun } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './AdminDashboardPage.css';

const topNavItems = [
  { label: 'Home', route: 'admin-dashboard' },
  { label: 'More Tools', route: 'tools' },
  { label: 'Security Awareness', route: 'awareness' },
  { label: 'Blog', route: 'blog' },
  { label: 'Admin Dashboard', route: 'admin-dashboard' },
];

function AdminTopNav({ onNavigate, onLogout, currentPage = 'admin-dashboard' }) {
  const { theme, toggleTheme } = useTheme();

  const activeRoute = useMemo(() => {
    return currentPage || 'admin-dashboard';
  }, [currentPage]);

  return (
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
              className={`admin-nav-link ${item.route === activeRoute ? 'is-active' : ''}`}
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
  );
}

export default memo(AdminTopNav);
