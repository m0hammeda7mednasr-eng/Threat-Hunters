import { memo, useCallback, useState } from "react";
import { Chrome, Eye, EyeOff, Github, Lock, Mail } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import "./SignUpForm.css";

const SignUpForm = ({ onSwitchToSignIn }) => {
  const { register, loading, error: authError } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
    confirmPassword: "",
    agreeToTerms: false,
  });

  const handleChange = useCallback(
    (event) => {
      const { name, value, type, checked } = event.target;

      setFormData((current) => ({
        ...current,
        [name]: type === "checkbox" ? checked : value,
      }));

      // Clear errors when user starts typing
      if (error || authError) {
        setError("");
      }
      if (success) {
        setSuccess("");
      }
    },
    [error, authError, success],
  );

  const handleSubmit = useCallback(
    async (event) => {
      event.preventDefault();

      const sanitizedEmail = formData.email.trim();
      const sanitizedFirstName = formData.firstName.trim();
      const sanitizedLastName = formData.lastName.trim();

      // Client-side validation
      if (!sanitizedFirstName || !sanitizedLastName || !sanitizedEmail) {
        setError("Please fill in all required fields.");
        return;
      }

      if (!formData.password || formData.password.length < 8) {
        setError("Password must be at least 8 characters long.");
        return;
      }

      if (formData.password !== formData.confirmPassword) {
        setError("Passwords do not match.");
        return;
      }

      if (!formData.agreeToTerms) {
        setError("Please agree to the terms and conditions.");
        return;
      }

      try {
        const result = await register({
          firstName: sanitizedFirstName,
          lastName: sanitizedLastName,
          email: sanitizedEmail,
          password: formData.password,
        });

        if (result.success) {
          setError("");
          setSuccess("Account created successfully! Please sign in.");

          // Reset form
          setFormData({
            firstName: "",
            lastName: "",
            email: "",
            password: "",
            confirmPassword: "",
            agreeToTerms: false,
          });

          // Optionally auto-switch to sign in after a delay
          setTimeout(() => {
            onSwitchToSignIn?.();
          }, 2000);
        } else {
          setError(result.error || "Registration failed. Please try again.");
        }
      } catch (err) {
        setError("An unexpected error occurred. Please try again.");
        console.error("Registration error:", err);
      }
    },
    [formData, register, onSwitchToSignIn],
  );

  return (
    <div className="signup-form-container">
      <div
        className="signup-form-tabs"
        role="tablist"
        aria-label="Authentication"
      >
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
        <button
          aria-selected="true"
          className="signup-form-tab is-active"
          role="tab"
          type="button"
        >
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
              type={showPassword ? "text" : "password"}
              value={formData.password}
            />
            <button
              aria-label={showPassword ? "Hide password" : "Show password"}
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
            I agree to the <a href="#signup">Terms of Service</a> and{" "}
            <a href="#signup">Privacy Policy</a>
          </span>
        </label>

        <button
          className="signup-submit-button"
          type="submit"
          disabled={loading}
        >
          {loading ? "Creating Account..." : "Create Account"}
        </button>

        {(error || authError) && (
          <p className="signup-error" role="alert">
            {error || authError}
          </p>
        )}

        {success && (
          <p className="signup-success" role="alert">
            {success}
          </p>
        )}

        <div className="signup-divider">
          <span>Or sign up with</span>
        </div>

        <div className="signup-socials">
          <button
            aria-label="Sign up with Chrome"
            className="signup-social-button"
            type="button"
          >
            <Chrome />
          </button>
          <button
            aria-label="Sign up with GitHub"
            className="signup-social-button"
            type="button"
          >
            <Github />
          </button>
        </div>
      </form>
    </div>
  );
};

export default memo(SignUpForm);
