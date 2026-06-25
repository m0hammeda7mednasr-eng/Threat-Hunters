import { memo, useCallback, useEffect, useRef, useState } from "react";
import { Eye, EyeOff, Lock, Mail } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import "./SignUpForm.css";

const SignUpForm = ({ onSwitchToSignIn }) => {
  const { register, verifyEmail, resendVerificationOtp, loading, error: authError } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [step, setStep] = useState("register");
  const [pendingEmail, setPendingEmail] = useState("");
  const [activePolicy, setActivePolicy] = useState("");
  const otpInputRef = useRef(null);
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
    confirmPassword: "",
    otp: "",
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
          setPendingEmail(sanitizedEmail);
          setStep("verify");
          setSuccess(`Account created successfully. We sent an OTP to ${sanitizedEmail}. Enter it below to activate your account.`);
        } else {
          setError(result.error || "Registration failed. Please try again.");
        }
      } catch (err) {
        setError("An unexpected error occurred. Please try again.");
        console.error("Registration error:", err);
      }
    },
    [formData, register],
  );

  const handleVerify = useCallback(
    async (event) => {
      event.preventDefault();

      const email = (pendingEmail || formData.email).trim().toLowerCase();
      const otp = formData.otp.trim();

      if (!email || !otp) {
        setError("Email and OTP are required.");
        return;
      }

      try {
        const result = await verifyEmail({
          email,
          code: otp,
        });

        if (result.success) {
          setError("");
          setSuccess("Email verified successfully. You can sign in now.");
          setStep("register");
          setPendingEmail("");
          setFormData({
            firstName: "",
            lastName: "",
            email: "",
            password: "",
            confirmPassword: "",
            otp: "",
            agreeToTerms: false,
          });
          onSwitchToSignIn?.();
        } else {
          setError(result.error || "OTP verification failed.");
        }
      } catch (err) {
        setError("An unexpected error occurred. Please try again.");
        console.error("Verification error:", err);
      }
    },
    [formData.email, formData.otp, onSwitchToSignIn, pendingEmail, verifyEmail],
  );

  useEffect(() => {
    if (step === "verify") {
      otpInputRef.current?.focus();
    }
  }, [step]);

  const policySections = {
    terms: {
      title: "Terms of Service",
      items: [
        "Only scan assets you own or have explicit permission to assess.",
        "Use reports for defensive remediation and validation only.",
        "Do not use the platform for abuse, harassment, or unauthorized testing.",
      ],
    },
    privacy: {
      title: "Privacy Policy",
      items: [
        "We use account, scan, and support data to provide product features.",
        "Secrets, tokens, and OTPs should stay server-side and out of client code.",
        "Downloaded reports and logs should be shared only with authorized users.",
      ],
    },
  };

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

      <form className="signup-form" onSubmit={step === "verify" ? handleVerify : handleSubmit}>
        {step === "register" ? (
          <>
        <div className="signup-verification-note" role="note">
          <strong>Step 1:</strong> create your account.
          <strong>Step 2:</strong> we send an OTP to your email.
          <strong>Step 3:</strong> enter the OTP below to verify.
        </div>

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
              placeholder="Enter password"
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
              placeholder="Confirm password"
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
            I agree to the{" "}
            <button
              type="button"
              className="signup-inline-link"
              onClick={() => setActivePolicy((current) => (current === "terms" ? "" : "terms"))}
            >
              Terms of Service
            </button>{" "}
            and{" "}
            <button
              type="button"
              className="signup-inline-link"
              onClick={() => setActivePolicy((current) => (current === "privacy" ? "" : "privacy"))}
            >
              Privacy Policy
            </button>
          </span>
        </label>

        {activePolicy && (
          <div className="signup-policy-panel" role="region" aria-label={policySections[activePolicy].title}>
            <div className="signup-policy-panel__head">
              <strong>{policySections[activePolicy].title}</strong>
              <button type="button" className="signup-policy-close" onClick={() => setActivePolicy("")}>
                Close
              </button>
            </div>
            <ul className="signup-policy-list">
              {policySections[activePolicy].items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        )}

        <button
          className="signup-submit-button"
          type="submit"
          disabled={loading}
        >
          {loading ? "Creating Account..." : "Create Account"}
        </button>
          </>
        ) : (
          <>
            <label className="signup-field">
              <span>Verification Email</span>
              <div className="signup-input-shell signup-input-shell-plain">
                <input
                  readOnly
                  type="email"
                  value={pendingEmail || formData.email}
                />
              </div>
            </label>

            <label className="signup-field">
              <span>OTP Code</span>
              <div className="signup-input-shell signup-input-shell-plain">
                <input
                  ref={otpInputRef}
                  autoComplete="one-time-code"
                  maxLength={6}
                  name="otp"
                  onChange={handleChange}
                  placeholder="Paste the OTP from your email"
                  required
                  inputMode="numeric"
                  type="text"
                  value={formData.otp}
                />
              </div>
            </label>

            <button
              className="signup-submit-button"
              type="submit"
              disabled={loading}
            >
              {loading ? "Verifying..." : "Verify Email"}
            </button>

            <button
              type="button"
              className="signup-submit-button signup-submit-button-secondary"
              onClick={async () => {
                const email = (pendingEmail || formData.email).trim();
                if (!email) {
                  setError("Enter your email before resending the OTP.");
                  return;
                }

                const result = await resendVerificationOtp({ email });
                if (result.success) {
                  setSuccess(`OTP resent to ${email}. Check your inbox.`);
                } else {
                  setError(result.error || "Unable to resend OTP.");
                }
              }}
              disabled={loading}
            >
              Send OTP again
            </button>
          </>
        )}

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

      </form>
    </div>
  );
};

export default memo(SignUpForm);
