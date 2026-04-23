import { memo } from 'react';
import { Shield } from 'lucide-react';
import './SignInPage.css';
import Navbar from './Navbar';
import SignInForm from './SignInForm';
import Footer from './Footer';

const SignInPage = ({
  onSwitchToSignUp,
  onNavigateToHome,
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools,
  onLogin,
}) => {
  return (
    <div className="signin-page">
      <Navbar
        onNavigateToSignUp={onSwitchToSignUp}
        onNavigateToHome={onNavigateToHome}
        onNavigateToBlog={onNavigateToBlog}
        onNavigateToAwareness={onNavigateToAwareness}
        onNavigateToTools={onNavigateToTools}
        currentPage="signin"
      />

      <main className="signin-main">
        <div className="signin-shell">
          <section className="signin-intro">
            <div className="signin-intro-icon" aria-hidden="true">
              <Shield />
            </div>

            <h1>Welcome Back to Threat Hunters</h1>
            <p>
              Secure your digital assets with AI-powered threat detection and real-time monitoring.
            </p>
          </section>

          <section className="signin-form-column">
            <SignInForm onSwitchToSignUp={onSwitchToSignUp} onLogin={onLogin} />
          </section>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default memo(SignInPage);
