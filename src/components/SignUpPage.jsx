import { memo } from 'react';
import { Shield } from 'lucide-react';
import './SignUpPage.css';
import Navbar from './Navbar';
import SignUpForm from './SignUpForm';
import Footer from './Footer';

const SignUpPage = ({
  onSwitchToSignIn,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools,
  onLogin,
}) => {
  return (
    <div className="signup-page">
      <Navbar
        onNavigateToHome={onNavigateToHome}
        onNavigateToBlog={onNavigateToBlog}
        onNavigateToAwareness={onNavigateToAwareness}
        onNavigateToTools={onNavigateToTools}
        currentPage="signup"
      />

      <main className="signup-main">
        <div className="signup-shell">
          <section className="signup-intro">
            <span className="signup-intro-kicker">Create your security workspace</span>
            <div className="signup-intro-icon" aria-hidden="true">
              <Shield />
            </div>

            <h1>Create Your Threat Hunters Account</h1>
            <p>
              Launch AI-powered scans, reports, and monitoring from one focused security workspace.
            </p>
          </section>

          <section className="signup-form-column">
            <SignUpForm onSwitchToSignIn={onSwitchToSignIn} onLogin={onLogin} />
          </section>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default memo(SignUpPage);
