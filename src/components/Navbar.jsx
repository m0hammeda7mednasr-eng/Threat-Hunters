import { memo, useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import './Navbar.css';

const Navbar = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools,
  currentPage = 'home',
}) => {
  const { theme, toggleTheme } = useTheme();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen((isOpen) => !isOpen);
  };

  const handleNavigation = (callback) => {
    setIsMobileMenuOpen(false);
    callback?.();
  };

  const isActive = (page) => currentPage === page;

  return (
    <nav className="navbar">
      <div className="nav-container">
        <div className="nav-left">
          <button
            type="button"
            className="mobile-menu-btn"
            onClick={toggleMobileMenu}
            aria-label="Toggle menu"
            aria-expanded={isMobileMenuOpen}
            aria-controls="public-mobile-menu"
          >
            {isMobileMenuOpen ? (
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <line x1="3" y1="6" x2="21" y2="6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="3" y1="12" x2="21" y2="12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="3" y1="18" x2="21" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            )}
          </button>

          <button type="button" className="logo" onClick={() => handleNavigation(onNavigateToHome)}>
            <div className="logo-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M12 2L4 6V12C4 16.5 7.5 20.5 12 22C16.5 20.5 20 16.5 20 12V6L12 2Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            <span className="logo-text">Threat Hunters</span>
          </button>
        </div>

        <div className="nav-center">
          <a
            href="#"
            className={`nav-link ${isActive('home') ? 'active' : ''}`}
            aria-current={isActive('home') ? 'page' : undefined}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToHome);
            }}
          >
            Home
          </a>
          <a
            href="#"
            className={`nav-link ${isActive('tools') ? 'active' : ''}`}
            aria-current={isActive('tools') ? 'page' : undefined}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToTools);
            }}
          >
            More Tools
          </a>
          <a
            href="#"
            className={`nav-link ${isActive('awareness') ? 'active' : ''}`}
            aria-current={isActive('awareness') ? 'page' : undefined}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToAwareness);
            }}
          >
            Security Awareness
          </a>
          <a
            href="#"
            className={`nav-link ${isActive('blog') ? 'active' : ''}`}
            aria-current={isActive('blog') ? 'page' : undefined}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToBlog);
            }}
          >
            Blog
          </a>
        </div>

        <div className="nav-right">
          <button
            type="button"
            className="theme-toggle"
            onClick={toggleTheme}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? (
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12" cy="12" r="5" stroke="currentColor" strokeWidth="2" />
                <line x1="12" y1="1" x2="12" y2="3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="12" y1="21" x2="12" y2="23" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="1" y1="12" x2="3" y2="12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="21" y1="12" x2="23" y2="12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            )}
          </button>

          <button type="button" className="btn-signup" onClick={() => handleNavigation(onNavigateToSignUp)}>
            Join us
          </button>
        </div>
      </div>

      <div id="public-mobile-menu" className={`mobile-menu ${isMobileMenuOpen ? 'open' : ''}`}>
        <div className="mobile-menu-content">
          <a
            href="#"
            className={`mobile-nav-link ${isActive('home') ? 'active' : ''}`}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToHome);
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              <polyline points="9 22 9 12 15 12 15 22" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span>Home</span>
          </a>
          <a
            href="#"
            className={`mobile-nav-link ${isActive('tools') ? 'active' : ''}`}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToTools);
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span>More Tools</span>
          </a>
          <a
            href="#"
            className={`mobile-nav-link ${isActive('awareness') ? 'active' : ''}`}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToAwareness);
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L4 6V12C4 16.5 7.5 20.5 12 22C16.5 20.5 20 16.5 20 12V6L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span>Security Awareness</span>
          </a>
          <a
            href="#"
            className={`mobile-nav-link ${isActive('blog') ? 'active' : ''}`}
            onClick={(event) => {
              event.preventDefault();
              handleNavigation(onNavigateToBlog);
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              <polyline points="14 2 14 8 20 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              <line x1="16" y1="13" x2="8" y2="13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="16" y1="17" x2="8" y2="17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <polyline points="10 9 9 9 8 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
            <span>Blog</span>
          </a>

          <div className="mobile-menu-divider"></div>

          <button type="button" className="mobile-menu-btn-signup" onClick={() => handleNavigation(onNavigateToSignUp)}>
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="12" cy="7" r="4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span>Join us</span>
          </button>
        </div>
      </div>

      {isMobileMenuOpen && <div className="mobile-menu-overlay" onClick={toggleMobileMenu} aria-hidden="true"></div>}
    </nav>
  );
};

export default memo(Navbar);
