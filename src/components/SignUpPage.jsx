import { memo } from 'react';
import './SignUpPage.css';
import Navbar from './Navbar';
import SignUpForm from './SignUpForm';
import Footer from './Footer';

const SignUpPage = ({ onSwitchToSignIn, onNavigateToHome, onNavigateToBlog, onNavigateToAwareness, onNavigateToTools, onLogin }) => {
  return (
    <div className="signup-page">
      <Navbar 
        onNavigateToHome={onNavigateToHome} 
        onNavigateToBlog={onNavigateToBlog}
        onNavigateToAwareness={onNavigateToAwareness}
        onNavigateToTools={onNavigateToTools}
        currentPage="signup"
      />
      
      <main className="main-content">
        <div className="content-wrapper">
          <div className="left-section">
            <div className="logo-large">
              <div className="shield-icon">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 2L4 6V12C4 16.5 7.5 20.5 12 22C16.5 20.5 20 16.5 20 12V6L12 2Z" 
                        stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
            </div>
            
            <h1 className="welcome-title">Welcome Back to Threat Hunters</h1>
            <p className="welcome-subtitle">
              Secure your digital assets with AI-powered threat detection and<br />
              real-time monitoring.
            </p>
          </div>

          <div className="right-section">
            <SignUpForm onSwitchToSignIn={onSwitchToSignIn} onLogin={onLogin} />
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default memo(SignUpPage);
