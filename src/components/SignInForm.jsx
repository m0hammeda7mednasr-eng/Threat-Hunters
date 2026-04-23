import { memo, useCallback, useState } from 'react';
import { Chrome, Eye, EyeOff, Github, Lock, Mail } from 'lucide-react';
import './SignInForm.css';

const SignInForm = ({ onSwitchToSignUp, onLogin }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false,
  });

  const handleChange = useCallback((event) => {
    const { name, value, type, checked } = event.target;

    setFormData((current) => ({
      ...current,
      [name]: type === 'checkbox' ? checked : value,
    }));
  }, []);

  const handleSubmit = useCallback(
    (event) => {
      event.preventDefault();

      const sanitizedEmail = formData.email.trim();
      if (!sanitizedEmail || !formData.password || !onLogin) {
        return;
      }

      onLogin();
    },
    [formData.email, formData.password, onLogin],
  );

  return (
    <div className="signin-form-container">
      <div className="signin-form-tabs" role="tablist" aria-label="Authentication">
        <button aria-selected="true" className="signin-form-tab is-active" role="tab" type="button">
          Sign In
        </button>
        <button
          aria-selected="false"
          className="signin-form-tab"
          onClick={() => {
            onSwitchToSignUp?.();
          }}
          role="tab"
          tabIndex={-1}
          type="button"
        >
          Sign Up
        </button>
      </div>

      <form className="signin-form" onSubmit={handleSubmit}>
        <label className="signin-field">
          <span>Email Address</span>
          <div className="signin-input-shell">
            <Mail aria-hidden="true" className="signin-input-icon" />
            <input
              autoComplete="email"
              maxLength={254}
              name="email"
              onChange={handleChange}
              placeholder="you@example.com"
              required
              type="email"
              value={formData.email}
            />
          </div>
        </label>

        <label className="signin-field">
          <span>Password</span>
          <div className="signin-input-shell">
            <Lock aria-hidden="true" className="signin-input-icon" />
            <input
              autoComplete="current-password"
              maxLength={128}
              minLength={8}
              name="password"
              onChange={handleChange}
              placeholder="••••••••"
              required
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
            />
            <button
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              className="signin-password-toggle"
              onClick={() => setShowPassword((current) => !current)}
              type="button"
            >
              {showPassword ? <EyeOff /> : <Eye />}
            </button>
          </div>
        </label>

        <div className="signin-form-options">
          <label className="signin-remember">
            <input
              checked={formData.rememberMe}
              name="rememberMe"
              onChange={handleChange}
              type="checkbox"
            />
            <span>Remember me</span>
          </label>

          <a className="signin-forgot-link" href="#signin">
            Forgot Password?
          </a>
        </div>

        <button className="signin-submit-button" type="submit">
          Sign In
        </button>

        <div className="signin-divider">
          <span>Or continue with</span>
        </div>

        <div className="signin-socials">
          <button aria-label="Continue with Chrome" className="signin-social-button" type="button">
            <Chrome />
          </button>
          <button aria-label="Continue with GitHub" className="signin-social-button" type="button">
            <Github />
          </button>
        </div>
      </form>
    </div>
  );
};

export default memo(SignInForm);
