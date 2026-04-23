import './HomePage.css';
import Navbar from './Navbar';
import Footer from './Footer';

const HomePage = ({ onNavigateToSignUp, onNavigateToHome, onNavigateToBlog, onNavigateToAwareness, onNavigateToTools }) => {
  return (
    <div className="home-page">
      <Navbar 
        onNavigateToSignUp={onNavigateToSignUp} 
        onNavigateToHome={onNavigateToHome} 
        onNavigateToBlog={onNavigateToBlog}
        onNavigateToAwareness={onNavigateToAwareness}
        onNavigateToTools={onNavigateToTools}
      />
      
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-container">
          <div className="hero-card-wrapper">
            <div className="hero-icon-small">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L4 6V12C4 16.5 7.5 20.5 12 22C16.5 20.5 20 16.5 20 12V6L12 2Z" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            
            <h1 className="hero-title">Smart AI-Powered Web<br />Vulnerability Scanner</h1>
            <p className="hero-subtitle">
              Scan, detect, and secure your web applications in seconds.<br />
              Identify vulnerabilities before hackers do powered by intelligent automation.
            </p>
            
            <div className="hero-scan-box">
              <div className="browser-mockup">
                <div className="browser-header">
                  <div className="browser-dots">
                    <span className="dot red"></span>
                    <span className="dot yellow"></span>
                    <span className="dot green"></span>
                  </div>
                  <input 
                    type="url" 
                    placeholder="https://yourwebsite.com" 
                    className="url-input"
                  />
                </div>
              </div>
              <button className="scan-btn-hero">Scan Now</button>
            </div>
            
            <div className="scan-result-box">
              <div className="result-icon-wrapper">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 2L4 6V12C4 16.5 7.5 20.5 12 22C16.5 20.5 20 16.5 20 12V6L12 2Z" 
                        stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <div className="result-content">
                <h4>Scanning results will appear here</h4>
                <p>Enter a URL and click 'Scan Now' to begin</p>
              </div>
            </div>
            
            <button className="explore-features-btn">Explore Features</button>
          </div>
        </div>
      </section>

      {/* Process Section */}
      <section className="process-section">
        <span className="section-label">How It Works</span>
        <h2 className="section-title">Simple 3-Step Process</h2>
        <p className="section-subtitle">Get comprehensive security insights in minutes</p>
        
        <div className="process-cards">
          <div className="process-card">
            <div className="process-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span className="step-number">1</span>
            </div>
            <h3>Enter Your URL</h3>
            <p>Simply paste your website URL and choose a scan profile (Quick, Full, or Custom)</p>
          </div>

          <div className="process-card">
            <div className="process-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span className="step-number">2</span>
            </div>
            <h3>Run the Scan</h3>
            <p>Our security tools analyze your site. Watch real-time progress and live logs as they run.</p>
          </div>

          <div className="process-card">
            <div className="process-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <polyline points="14 2 14 8 20 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span className="step-number">3</span>
            </div>
            <h3>Get Your AI-Powered Report</h3>
            <p>Review vulnerabilities with plain-English explanations and code fixes. Download as PDF.</p>
          </div>
        </div>

        <button className="cta-btn" onClick={onNavigateToSignUp}>Try It Now - It's Free →</button>
      </section>

      {/* Security Badges */}
      <div className="security-badges">
        <div className="badge-scroll badge-scroll-right">
          <div className="badge badge-purple">
            <span className="badge-icon">🎯</span>
            <span>Understands attacker behavior</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">⚠️</span>
            <span>Actionable Security</span>
          </div>
          <div className="badge badge-blue">
            <span className="badge-icon">🔷</span>
            <span>Web Exploitation</span>
          </div>
          <div className="badge badge-blue">
            <span className="badge-icon">🔵</span>
            <span>Offensive Security</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">🛡️</span>
            <span>Protect Your Website</span>
          </div>
          {/* Duplicate for seamless scroll */}
          <div className="badge badge-purple">
            <span className="badge-icon">🎯</span>
            <span>Understands attacker behavior</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">⚠️</span>
            <span>Actionable Security</span>
          </div>
          <div className="badge badge-blue">
            <span className="badge-icon">🔷</span>
            <span>Web Exploitation</span>
          </div>
          <div className="badge badge-blue">
            <span className="badge-icon">🔵</span>
            <span>Offensive Security</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">🛡️</span>
            <span>Protect Your Website</span>
          </div>
        </div>
        
        <div className="badge-scroll badge-scroll-left">
          <div className="badge badge-blue">
            <span className="badge-icon">🔵</span>
            <span>Offensive Security</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">🛡️</span>
            <span>Protect Your Website</span>
          </div>
          <div className="badge badge-purple">
            <span className="badge-icon">🎯</span>
            <span>Understands attacker behavior</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">⚠️</span>
            <span>Actionable Security</span>
          </div>
          <div className="badge badge-blue">
            <span className="badge-icon">🔷</span>
            <span>Web Exploitation</span>
          </div>
          {/* Duplicate for seamless scroll */}
          <div className="badge badge-blue">
            <span className="badge-icon">🔵</span>
            <span>Offensive Security</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">🛡️</span>
            <span>Protect Your Website</span>
          </div>
          <div className="badge badge-purple">
            <span className="badge-icon">🎯</span>
            <span>Understands attacker behavior</span>
          </div>
          <div className="badge badge-red">
            <span className="badge-icon">⚠️</span>
            <span>Actionable Security</span>
          </div>
          <div className="badge badge-blue">
            <span className="badge-icon">🔷</span>
            <span>Web Exploitation</span>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <section className="features-section">
        <span className="section-label">Why Choose Us</span>
        <h2 className="section-title">Why Choose Threat Hunter</h2>
        <p className="section-subtitle">Advanced security features built for modern web applications</p>
        
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h3>Advanced Scanning</h3>
            <p>Deep analysis using cutting-edge scanning algorithms to identify security vulnerabilities.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="2"/>
                <path d="M12 1v6m0 6v6M23 12h-6m-6 0H1" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              </svg>
            </div>
            <h3>AI-Powered Insights</h3>
            <p>Intelligent threat analysis powered by machine learning to prioritize critical vulnerabilities.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M9 11l3 3L22 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h3>User Friendly</h3>
            <p>100% Web-based application</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <polyline points="14 2 14 8 20 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h3>Actionable Reports</h3>
            <p>Detailed reports with step-by-step remediation guidance to fix vulnerabilities quickly.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" 
                      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h3>Privacy First</h3>
            <p>Your data stays private and secure. We never store or share your scans.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h3>Automated Monitoring</h3>
            <p>Continuous monitoring with real-time alerts to keep your applications protected 24/7.</p>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <h2>Ready to Secure Your Applications?</h2>
        <p>Join thousands of developers protecting their web applications with Threat Hunter</p>
        <button className="cta-btn-large" onClick={onNavigateToSignUp}>Start Scanning Free →</button>
      </section>

      <Footer />
    </div>
  );
};

export default HomePage;
