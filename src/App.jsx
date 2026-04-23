import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react';
import './App.css';
import AuthNavbar from './components/AuthNavbar';
import BootSplash from './components/BootSplash';
import Footer from './components/Footer';

const HomePage = lazy(() => import('./components/HomePage'));
const SignUpPage = lazy(() => import('./components/SignUpPage'));
const SignInPage = lazy(() => import('./components/SignInPage'));
const BlogPage = lazy(() => import('./components/BlogPage'));
const SecurityAwarenessPage = lazy(() => import('./components/SecurityAwarenessPage'));
const MoreToolsPage = lazy(() => import('./components/MoreToolsPage'));
const DashboardPage = lazy(() => import('./components/DashboardPage'));
const AdminDashboardPage = lazy(() => import('./components/AdminDashboardPage'));
const AdminTeamPage = lazy(() => import('./components/AdminTeamPage'));
const AdminUsersPage = lazy(() => import('./components/AdminUsersPage'));
const AdminReportsPage = lazy(() => import('./components/AdminReportsPage'));
const AdminWebEditPage = lazy(() => import('./components/AdminWebEditPage'));
const AdminPricingPage = lazy(() => import('./components/AdminPricingPage'));
const AdminSettingsPage = lazy(() => import('./components/AdminSettingsPage'));

const STORAGE_KEYS = Object.freeze({
  loginState: 'isLoggedIn',
});

const SESSION_KEYS = Object.freeze({
  splashSeen: 'threatHuntersSplashSeen',
});

const PUBLIC_PAGES = new Set(['home', 'signin', 'signup', 'blog', 'awareness', 'tools']);
const PRIVATE_PAGES = new Set(['dashboard', 'admin-dashboard', 'admin-team', 'admin-users', 'admin-reports', 'admin-web-edit', 'admin-pricing', 'admin-settings', 'blog', 'awareness', 'tools']);
const DASHBOARD_SECTIONS = new Set(['dashboard', 'reports', 'settings', 'profile']);

const safeStorage = {
  get(key) {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // Ignore storage access errors (private mode, blocked storage, etc.)
    }
  },
  remove(key) {
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Ignore storage access errors (private mode, blocked storage, etc.)
    }
  },
};

const safeSessionStorage = {
  get(key) {
    try {
      return window.sessionStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key, value) {
    try {
      window.sessionStorage.setItem(key, value);
    } catch {
      // Ignore storage access errors.
    }
  },
};

const getInitialLoginState = () => safeStorage.get(STORAGE_KEYS.loginState) === 'true';
const getInitialSplashState = () => safeSessionStorage.get(SESSION_KEYS.splashSeen) !== 'true';

const normalizeHash = (hashValue) => {
  const rawHash = typeof hashValue === 'string' ? hashValue : '';
  const withoutPrefix = rawHash.startsWith('#') ? rawHash.slice(1) : rawHash;

  try {
    return decodeURIComponent(withoutPrefix).trim().toLowerCase();
  } catch {
    return withoutPrefix.trim().toLowerCase();
  }
};

const parseRouteFromHash = (hashValue) => {
  const normalizedHash = normalizeHash(hashValue);

  if (!normalizedHash) {
    return { page: 'home', section: 'dashboard' };
  }

  if (normalizedHash === 'dashboard') {
    return { page: 'dashboard', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-dashboard') {
    return { page: 'admin-dashboard', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-team') {
    return { page: 'admin-team', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-users') {
    return { page: 'admin-users', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-reports') {
    return { page: 'admin-reports', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-web-edit') {
    return { page: 'admin-web-edit', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-pricing') {
    return { page: 'admin-pricing', section: 'dashboard' };
  }

  if (normalizedHash === 'admin-settings') {
    return { page: 'admin-settings', section: 'dashboard' };
  }

  if (normalizedHash.startsWith('dashboard-')) {
    const sectionCandidate = normalizedHash.replace('dashboard-', '');
    const section = DASHBOARD_SECTIONS.has(sectionCandidate) ? sectionCandidate : 'dashboard';
    return { page: 'dashboard', section };
  }

  if (PUBLIC_PAGES.has(normalizedHash)) {
    return { page: normalizedHash, section: 'dashboard' };
  }

  return { page: 'home', section: 'dashboard' };
};

const createHash = (page, section = 'dashboard') => {
  if (page === 'dashboard' && section !== 'dashboard') {
    return `#dashboard-${section}`;
  }

  return `#${page}`;
};

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(getInitialLoginState);
  const [showBootSplash, setShowBootSplash] = useState(getInitialSplashState);
  const [scrollProgress, setScrollProgress] = useState(0);
  const [currentPage, setCurrentPage] = useState(() => parseRouteFromHash(window.location.hash).page);
  const [dashboardSection, setDashboardSection] = useState(
    () => parseRouteFromHash(window.location.hash).section,
  );

  const routeTransitionKey = useMemo(() => {
    const sectionKey = currentPage === 'dashboard' ? dashboardSection : 'page';
    return `${isLoggedIn ? 'auth' : 'guest'}-${currentPage}-${sectionKey}`;
  }, [currentPage, dashboardSection, isLoggedIn]);

  useEffect(() => {
    if (isLoggedIn) {
      safeStorage.set(STORAGE_KEYS.loginState, 'true');
      return;
    }

    safeStorage.remove(STORAGE_KEYS.loginState);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!showBootSplash) {
      return undefined;
    }

    const timeoutId = window.setTimeout(() => {
      setShowBootSplash(false);
      safeSessionStorage.set(SESSION_KEYS.splashSeen, 'true');
    }, 1900);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [showBootSplash]);

  useEffect(() => {
    const syncRouteFromHash = () => {
      const { page, section } = parseRouteFromHash(window.location.hash);

      if ((page === 'dashboard' || page === 'admin-dashboard' || page === 'admin-team' || page === 'admin-users' || page === 'admin-reports' || page === 'admin-web-edit' || page === 'admin-pricing' || page === 'admin-settings') && !isLoggedIn) {
        setCurrentPage('signin');
        setDashboardSection('dashboard');

        if (window.location.hash !== '#signin') {
          window.location.hash = '#signin';
        }

        return;
      }

      if (page === 'home' && isLoggedIn) {
        setCurrentPage('dashboard');
        setDashboardSection('dashboard');

        if (window.location.hash !== '#dashboard') {
          window.location.hash = '#dashboard';
        }

        return;
      }

      setCurrentPage(page);

      if (page === 'dashboard') {
        setDashboardSection(section);
      }
    };

    syncRouteFromHash();
    window.addEventListener('hashchange', syncRouteFromHash);

    return () => {
      window.removeEventListener('hashchange', syncRouteFromHash);
    };
  }, [isLoggedIn]);

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
  }, [currentPage, dashboardSection, isLoggedIn]);

  useEffect(() => {
    let frameId = null;

    const syncProgress = () => {
      const scrollRoot = document.documentElement;
      const maxScroll = Math.max(scrollRoot.scrollHeight - window.innerHeight, 0);
      setScrollProgress(maxScroll ? Math.min(window.scrollY / maxScroll, 1) : 0);
      frameId = null;
    };

    const handleScroll = () => {
      if (frameId !== null) {
        return;
      }

      frameId = window.requestAnimationFrame(syncProgress);
    };

    syncProgress();
    window.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('resize', handleScroll);

    return () => {
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleScroll);

      if (frameId !== null) {
        window.cancelAnimationFrame(frameId);
      }
    };
  }, [routeTransitionKey]);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return undefined;
    }

    const revealSelectors = [
      '.home-process-card',
      '.home-feature-card',
      '.home-final-cta-content',
      '.blog-sidebar-card',
      '.blog-featured-card',
      '.blog-trending-card',
      '.blog-list-card',
      '.tip-card',
      '.threat-card',
      '.resource-card',
      '.download-card',
      '.more-tools-workbench',
      '.more-tools-stat',
      '.signin-intro',
      '.signin-form-container',
      '.signup-intro',
      '.signup-form-container',
      '.db-panel',
      '.db-user-profile-card',
      '.db-user-profile-delete-card',
      '.db-settings-panel',
      '.db-reports-history-panel',
      '.db-report-card',
      '.admin-card',
    ];

    const elements = Array.from(document.querySelectorAll(revealSelectors.join(',')));

    if (!elements.length) {
      return undefined;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) {
            return;
          }

          entry.target.classList.add('scroll-reveal-in');
          observer.unobserve(entry.target);
        });
      },
      {
        threshold: 0.14,
        rootMargin: '0px 0px -10% 0px',
      },
    );

    elements.forEach((element, index) => {
      element.classList.add('scroll-reveal');
      element.style.setProperty('--reveal-delay', `${Math.min((index % 8) * 45, 240)}ms`);
      observer.observe(element);
    });

    return () => {
      observer.disconnect();
    };
  }, [routeTransitionKey]);

  const handleLogin = useCallback(() => {
    setIsLoggedIn(true);
    setCurrentPage('dashboard');
    setDashboardSection('dashboard');
    window.location.hash = '#dashboard';
  }, []);

  const handleLogout = useCallback(() => {
    setIsLoggedIn(false);
    setCurrentPage('home');
    setDashboardSection('dashboard');
    window.location.hash = '#home';
  }, []);

  const handleNavigation = useCallback(
    (page) => {
      if (page === 'home' && isLoggedIn) {
        handleLogout();
        return;
      }

      if (page === 'settings' || page === 'profile' || page === 'reports') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('dashboard');
        setDashboardSection(page);
        window.location.hash = createHash('dashboard', page);
        return;
      }

      if (page === 'dashboard') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('dashboard');
        setDashboardSection('dashboard');
        window.location.hash = '#dashboard';
        return;
      }

      if (page === 'admin-dashboard') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-dashboard');
        window.location.hash = '#admin-dashboard';
        return;
      }

      if (page === 'admin-team') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-team');
        window.location.hash = '#admin-team';
        return;
      }

      if (page === 'admin-users') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-users');
        window.location.hash = '#admin-users';
        return;
      }

      if (page === 'admin-reports') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-reports');
        window.location.hash = '#admin-reports';
        return;
      }

      if (page === 'admin-web-edit') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-web-edit');
        window.location.hash = '#admin-web-edit';
        return;
      }

      if (page === 'admin-pricing') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-pricing');
        window.location.hash = '#admin-pricing';
        return;
      }

      if (page === 'admin-settings') {
        if (!isLoggedIn) {
          setCurrentPage('signin');
          window.location.hash = '#signin';
          return;
        }

        setCurrentPage('admin-settings');
        window.location.hash = '#admin-settings';
        return;
      }

      if (isLoggedIn) {
        const nextPage = PRIVATE_PAGES.has(page) ? page : 'dashboard';

        setCurrentPage(nextPage);

        if (nextPage === 'dashboard') {
          setDashboardSection('dashboard');
        }

        window.location.hash = createHash(nextPage);
        return;
      }

      const nextPage = PUBLIC_PAGES.has(page) ? page : 'home';
      setCurrentPage(nextPage);
      window.location.hash = createHash(nextPage);
    },
    [handleLogout, isLoggedIn],
  );

  const publicNavigationProps = useMemo(
    () => ({
      onNavigateToSignUp: () => handleNavigation('signup'),
      onNavigateToHome: () => handleNavigation('home'),
      onNavigateToBlog: () => handleNavigation('blog'),
      onNavigateToAwareness: () => handleNavigation('awareness'),
      onNavigateToTools: () => handleNavigation('tools'),
    }),
    [handleNavigation],
  );

  return (
    <div className="App">
      <div className="app-progress" aria-hidden="true">
        <span style={{ transform: `scaleX(${showBootSplash ? 0 : scrollProgress})` }} />
      </div>

      {showBootSplash && <BootSplash />}

      <Suspense
        fallback={(
          <div className="route-loading" role="status" aria-live="polite">
            <div className="route-loading__bar" />
            <p>Loading secure workspace...</p>
          </div>
        )}
      >
        <div key={routeTransitionKey} className="route-transition">
          {currentPage === 'dashboard' && isLoggedIn && (
            <>
              <DashboardPage
                key={`dashboard-${dashboardSection}`}
                onNavigate={handleNavigation}
                currentPage={currentPage}
                initialSection={dashboardSection}
              />
              <Footer />
            </>
          )}

          {currentPage === 'admin-dashboard' && isLoggedIn && (
            <>
              <AdminDashboardPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {currentPage === 'admin-team' && isLoggedIn && (
            <>
              <AdminTeamPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {currentPage === 'admin-users' && isLoggedIn && (
            <>
              <AdminUsersPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {currentPage === 'admin-reports' && isLoggedIn && (
            <>
              <AdminReportsPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {currentPage === 'admin-web-edit' && isLoggedIn && (
            <>
              <AdminWebEditPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {currentPage === 'admin-pricing' && isLoggedIn && (
            <>
              <AdminPricingPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {currentPage === 'admin-settings' && isLoggedIn && (
            <>
              <AdminSettingsPage onNavigate={handleNavigation} />
              <Footer />
            </>
          )}

          {isLoggedIn && currentPage === 'blog' && (
            <div className="logged-in-page">
              <AuthNavbar onNavigate={handleNavigation} currentPage={currentPage} />
              <BlogPage {...publicNavigationProps} onLogin={handleLogin} isLoggedIn />
              <Footer />
            </div>
          )}

          {isLoggedIn && currentPage === 'awareness' && (
            <div className="logged-in-page">
              <AuthNavbar onNavigate={handleNavigation} currentPage={currentPage} />
              <SecurityAwarenessPage {...publicNavigationProps} onLogin={handleLogin} isLoggedIn />
              <Footer />
            </div>
          )}

          {isLoggedIn && currentPage === 'tools' && (
            <div className="logged-in-page">
              <AuthNavbar onNavigate={handleNavigation} currentPage={currentPage} />
              <MoreToolsPage {...publicNavigationProps} onLogin={handleLogin} isLoggedIn />
              <Footer />
            </div>
          )}

          {!isLoggedIn && currentPage === 'home' && (
            <HomePage {...publicNavigationProps} onLogin={handleLogin} />
          )}

          {!isLoggedIn && currentPage === 'signin' && (
            <SignInPage
              {...publicNavigationProps}
              onSwitchToSignUp={() => handleNavigation('signup')}
              onLogin={handleLogin}
            />
          )}

          {!isLoggedIn && currentPage === 'signup' && (
            <SignUpPage
              {...publicNavigationProps}
              onSwitchToSignIn={() => handleNavigation('signin')}
              onLogin={handleLogin}
            />
          )}

          {!isLoggedIn && currentPage === 'blog' && (
            <BlogPage {...publicNavigationProps} onLogin={handleLogin} isLoggedIn={false} />
          )}

          {!isLoggedIn && currentPage === 'awareness' && (
            <SecurityAwarenessPage {...publicNavigationProps} onLogin={handleLogin} isLoggedIn={false} />
          )}

          {!isLoggedIn && currentPage === 'tools' && (
            <MoreToolsPage {...publicNavigationProps} onLogin={handleLogin} isLoggedIn={false} />
          )}

          {isLoggedIn && !PRIVATE_PAGES.has(currentPage) && (
            <DashboardPage
              key="dashboard-fallback"
              onNavigate={handleNavigation}
              currentPage="dashboard"
              initialSection="dashboard"
            />
          )}

          {!isLoggedIn && !PUBLIC_PAGES.has(currentPage) && (
            <HomePage {...publicNavigationProps} onLogin={handleLogin} />
          )}
        </div>
      </Suspense>
    </div>
  );
}

export default App;
