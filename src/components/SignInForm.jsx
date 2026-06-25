import { memo, useCallback, useState } from "react";
import { Eye, EyeOff, Lock, Mail } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import "./SignInForm.css";

const SignInForm = ({ onSwitchToSignUp, onLogin }) => {
  const { login, loading, error: authError, requestPasswordReset, resetPassword } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [forgotOpen, setForgotOpen] = useState(false);
  const [forgotStatus, setForgotStatus] = useState("");
  const [forgotStep, setForgotStep] = useState("request");
  const [forgotForm, setForgotForm] = useState({
    email: "",
    code: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    rememberMe: false,
  });

  const handleChange = useCallback(
    (event) => {
      const { name, value, type, checked } = event.target;

      setFormData((current) => ({
        ...current,
        [name]: type === "checkbox" ? checked : value,
      }));

      if (error || authError) {
        setError("");
      }
    },
    [error, authError],
  );

  const handleForgotChange = useCallback(
    (event) => {
      const { name, value } = event.target;
      setForgotForm((current) => ({
        ...current,
        [name]: value,
      }));

      if (forgotStatus) {
        setForgotStatus("");
      }
    },
    [forgotStatus],
  );

  const handleSubmit = useCallback(
    async (event) => {
      event.preventDefault();

      const sanitizedEmail = formData.email.trim();
      if (!sanitizedEmail || !formData.password) {
        setError("Please fill in all fields.");
        return;
      }

      try {
        const result = await login({
          email: sanitizedEmail,
          password: formData.password,
        });

        if (result.success) {
          setError("");
          if (onLogin) {
            onLogin({
              email: sanitizedEmail,
              role: result.data.role || "user",
            });
          }
        } else {
          setError(result.error || "Login failed. Please try again.");
        }
      } catch (err) {
        setError("An unexpected error occurred. Please try again.");
        console.error("Login error:", err);
      }
    },
    [formData.email, formData.password, login, onLogin],
  );

  const handleForgotRequest = useCallback(async () => {
    const email = forgotForm.email.trim();
    if (!email) {
      setForgotStatus("Enter the email tied to your account.");
      return;
    }

    const result = await requestPasswordReset({ email });
    if (result.success) {
      setForgotStep("reset");
      setForgotStatus(`OTP sent to ${result.data.email}. Check your inbox and paste it below.`);
    } else {
      setForgotStatus(result.error || "Unable to prepare password reset.");
    }
  }, [forgotForm.email, requestPasswordReset]);

  const handleForgotReset = useCallback(async () => {
    if (!forgotForm.email.trim() || !forgotForm.code.trim()) {
      setForgotStatus("Email and OTP are required.");
      return;
    }

    if (!forgotForm.newPassword || forgotForm.newPassword.length < 8) {
      setForgotStatus("New password must be at least 8 characters.");
      return;
    }

    if (forgotForm.newPassword !== forgotForm.confirmPassword) {
      setForgotStatus("Passwords do not match.");
      return;
    }

    const result = await resetPassword({
      email: forgotForm.email.trim(),
      code: forgotForm.code.trim(),
      token: forgotForm.code.trim(),
      newPassword: forgotForm.newPassword,
    });

    if (result.success) {
      setForgotStatus("Password reset successfully. You can sign in now.");
      setForgotOpen(false);
      setForgotStep("request");
      setForgotForm({
        email: "",
        code: "",
        newPassword: "",
        confirmPassword: "",
      });
    } else {
      setForgotStatus(result.error || "Unable to reset password.");
    }
  }, [forgotForm, resetPassword]);

  return (
    <div className="signin-form-container">
      <div className="signin-form-tabs" role="tablist" aria-label="Authentication">
        <button
          aria-selected="true"
          className="signin-form-tab is-active"
          role="tab"
          type="button"
        >
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
              type={showPassword ? "text" : "password"}
              value={formData.password}
            />
            <button
              aria-label={showPassword ? "Hide password" : "Show password"}
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

          <button
            type="button"
            className="signin-forgot-link"
            onClick={() => setForgotOpen((current) => !current)}
          >
            Forgot Password?
          </button>
        </div>

        {forgotOpen && (
          <div className="signin-forgot-panel" aria-live="polite">
              <p className="signin-forgot-panel__title">Password recovery</p>
              <p className="signin-forgot-panel__copy">
                1. Request an OTP for your email.
                <br />
                2. Paste the OTP below, choose a new password, and confirm it.
            </p>

            <label className="signin-field">
              <span>Recovery Email</span>
              <div className="signin-input-shell">
                <Mail aria-hidden="true" className="signin-input-icon" />
                <input
                  autoComplete="email"
                  name="email"
                  onChange={handleForgotChange}
                  placeholder="you@example.com"
                  type="email"
                  value={forgotForm.email}
                />
              </div>
            </label>

            {forgotStep === "reset" && (
              <>
                <label className="signin-field">
                  <span>OTP Code</span>
                  <div className="signin-input-shell">
                    <Lock aria-hidden="true" className="signin-input-icon" />
                    <input
                      autoComplete="one-time-code"
                      name="code"
                      onChange={handleForgotChange}
                      placeholder="Enter the OTP code"
                      type="text"
                      value={forgotForm.code}
                    />
                  </div>
                </label>

                <label className="signin-field">
                  <span>New Password</span>
                  <div className="signin-input-shell">
                    <Lock aria-hidden="true" className="signin-input-icon" />
                    <input
                      name="newPassword"
                      onChange={handleForgotChange}
                      placeholder="Enter a new password"
                      type="password"
                      value={forgotForm.newPassword}
                    />
                  </div>
                </label>

                <label className="signin-field">
                  <span>Confirm New Password</span>
                  <div className="signin-input-shell">
                    <Lock aria-hidden="true" className="signin-input-icon" />
                    <input
                      name="confirmPassword"
                      onChange={handleForgotChange}
                      placeholder="Confirm new password"
                      type="password"
                      value={forgotForm.confirmPassword}
                    />
                  </div>
                </label>
              </>
            )}

            <div className="signin-forgot-actions">
              <button type="button" className="signin-forgot-action" onClick={handleForgotRequest}>
                {forgotStep === "reset" ? "Resend OTP" : "Send OTP"}
              </button>
              <button
                type="button"
                className="signin-forgot-action primary"
                onClick={handleForgotReset}
                disabled={forgotStep !== "reset"}
              >
                Reset password
              </button>
            </div>

            {forgotStatus && <p className="signin-forgot-status">{forgotStatus}</p>}
          </div>
        )}

        <button className="signin-submit-button" type="submit" disabled={loading}>
          {loading ? "Signing In..." : "Sign In"}
        </button>

        {(error || authError) && (
          <p className="signin-error" role="alert">
            {error || authError}
          </p>
        )}

      </form>
    </div>
  );
};

export default memo(SignInForm);
