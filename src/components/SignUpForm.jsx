import { memo, useCallback, useState } from 'react';
import { Chrome, Eye, EyeOff, Github, Lock, Mail } from 'lucide-react';
import './SignUpForm.css';

const SignUpForm = ({ onSwitchToSignIn, onLogin }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: '',
    agreeToTerms: false,
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

      if (!onLogin) {
        return;
      }

      const sanitizedEmail = formData.email.trim();
      const sanitizedFirstName = formData.firstName.trim();
      const sanitizedLastName = formData.lastName.trim();

      if (!sanitizedFirstName || !sanitizedLastName || !sanitizedEmail) {
        return;
      }

      if (!formData.password || formData.password.length < 8) {
        return;
      }

      if (formData.password !== formData.confirmPassword) {
        return;
      }

      if (!formData.agreeToTerms) {
        return;
      }

      onLogin();
    },
    [formData, onLogin],
  );

  return (
    <div className="signup-form-container">
      <div className="signup-form-tabs" role="tablist" aria-label="Authentication">
        <button
          aria-selected="false"
          className="signup-form-tab"
          onClick={() => {
            onSwitchToSignIn?.();
          }}
          role="tab"
          tabIndex={-1}
          type="button"
        >
          Sign In
        </button>
        <button aria-selected="true" className="signup-form-tab is-active" role="tab" type="button">
          Sign Up
        </button>
      </div>

      <form className="signup-form" onSubmit={handleSubmit}>
        <div className="signup-form-row">
          <label className="signup-field">
            <span>First Name</span>
            <div className="signup-input-shell signup-input-shell-plain">
              <input
                autoComplete="given-name"
                maxLength={64}
                name="firstName"
                onChange={handleChange}
                placeholder="John"
                required
                type="text"
                value={formData.firstName}
              />
            </div>
          </label>

          <label className="signup-field">
            <span>Last Name</span>
            <div className="signup-input-shell signup-input-shell-plain">
              <input
                autoComplete="family-name"
                maxLength={64}
                name="lastName"
                onChange={handleChange}
                placeholder="Doe"
                required
                type="text"
                value={formData.lastName}
              />
            </div>
          </label>
        </div>

        <label className="signup-field">
          <span>Email Address</span>
          <div className="signup-input-shell">
            <Mail aria-hidden="true" className="signup-input-icon" />
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

        <label className="signup-field">
          <span>Password</span>
          <div className="signup-input-shell">
            <Lock aria-hidden="true" className="signup-input-icon" />
            <input
              autoComplete="new-password"
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
              className="signup-password-toggle"
              onClick={() => setShowPassword((current) => !current)}
              type="button"
            >
              {showPassword ? <EyeOff /> : <Eye />}
            </button>
          </div>
        </label>

        <label className="signup-field">
          <span>Confirm Password</span>
          <div className="signup-input-shell">
            <Lock aria-hidden="true" className="signup-input-icon" />
            <input
              autoComplete="new-password"
              maxLength={128}
              minLength={8}
              name="confirmPassword"
              onChange={handleChange}
              placeholder="••••••••"
              required
              type="password"
              value={formData.confirmPassword}
            />
          </div>
        </label>

        <label className="signup-terms">
          <input
            checked={formData.agreeToTerms}
            id="signup-terms"
            name="agreeToTerms"
            onChange={handleChange}
            required
            type="checkbox"
          />
          <span>
            I agree to the <a href="#signup">Terms of Service</a> and <a href="#signup">Privacy Policy</a>
          </span>
        </label>

        <button className="signup-submit-button" type="submit">
          Create Account
        </button>

        <div className="signup-divider">
          <span>Or sign up with</span>
        </div>

        <div className="signup-socials">
          <button aria-label="Sign up with Chrome" className="signup-social-button" type="button">
            <Chrome />
          </button>
          <button aria-label="Sign up with GitHub" className="signup-social-button" type="button">
            <Github />
          </button>
        </div>
      </form>
    </div>
  );
};

export default memo(SignUpForm);
