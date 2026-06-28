export const DEFAULT_ADMIN_SETTINGS = {
  general: {
    siteName: "Threat Hunters",
    siteDescription: "Smart AI-Powered Web Vulnerability Scanner",
    language: "English",
    timezone: "UTC+02:00 Cairo",
  },
  notifications: {
    emailAlerts: true,
    criticalOnly: true,
    weeklyReports: true,
    productUpdates: false,
    digestFrequency: "Daily digest",
  },
  security: {
    requireTwoFactor: true,
    loginAlerts: true,
    sessionTimeout: "30 minutes",
    passwordRotation: "Every 90 days",
  },
  email: {
    senderName: "Threat Hunters",
    senderAddress: "alerts@threathunters.ai",
    replyTo: "support@threathunters.ai",
    footerNote: "AI-powered vulnerability scanning to protect your web applications.",
  },
};

export const DEFAULT_ADMIN_TEAM = [
  {
    id: "team-super-admin",
    initials: "MN",
    name: "Mohamed Nasr",
    email: "admin@threathunters.com",
    status: "active",
    time: "Online now",
    role: "Super Admin",
    badges: ["Full Access", "User Management", "System Config"],
  },
  {
    id: "team-security-lead",
    initials: "SA",
    name: "Sarah Ahmed",
    email: "sarah@threathunters.com",
    status: "active",
    time: "2 hours ago",
    role: "Admin",
    badges: ["Scan Management", "Reports", "User Support"],
  },
];

export const DEFAULT_ADMIN_PRICING = {
  plans: [
    {
      id: "plan-free",
      name: "Free",
      price: "$0",
      description: "Perfect for trying out our service",
      subscribers: 456,
      badge: "",
      tone: "is-free",
      features: [
        { label: "Basic vulnerability scanning", included: true },
        { label: "1 active project", included: true },
        { label: "Email notifications", included: true },
        { label: "Advanced reporting", included: false },
        { label: "Priority support", included: false },
      ],
    },
    {
      id: "plan-professional",
      name: "Professional",
      price: "$49",
      description: "For professionals and small teams",
      subscribers: 234,
      badge: "Most Popular",
      tone: "is-professional",
      features: [
        { label: "Advanced vulnerability scanning", included: true },
        { label: "10 active projects", included: true },
        { label: "Detailed PDF reports", included: true },
        { label: "Priority email support", included: true },
        { label: "Team collaboration tools", included: false },
      ],
    },
    {
      id: "plan-enterprise",
      name: "Enterprise",
      price: "$199",
      description: "For large teams and organizations",
      subscribers: 123,
      badge: "",
      tone: "is-enterprise",
      features: [
        { label: "Unlimited vulnerability scans", included: true },
        { label: "Unlimited active projects", included: true },
        { label: "Custom reports and exports", included: true },
        { label: "Dedicated success manager", included: true },
        { label: "SSO and advanced access control", included: true },
      ],
    },
  ],
  transactions: [
    { id: "txn-1", customer: "Mohamed Ahmed", plan: "Professional", amount: "$49", date: "2026-06-11T09:20:00Z", status: "completed" },
    { id: "txn-2", customer: "Sarah Ali", plan: "Enterprise", amount: "$199", date: "2026-06-10T14:10:00Z", status: "completed" },
    { id: "txn-3", customer: "Hassan Omar", plan: "Professional", amount: "$49", date: "2026-06-09T16:45:00Z", status: "completed" },
  ],
};

export const DEFAULT_CONTENT = {
  home: {
    title: "Protect Your Digital Assets with Advanced Security Testing",
    subtitle: "Comprehensive vulnerability scanning and penetration testing platform",
    description: "Start proactive testing that surfaces misconfigurations, weak endpoints, and risky flows before attackers do.",
    primaryButton: "Start Free Scan",
    secondaryButton: "View Live Demo",
    features: [
      "Automated Security Scanning",
      "Real-time Threat Intelligence",
      "Comprehensive Reports",
      "API Security Testing",
    ],
    stats: [
      { value: "100,000+", label: "Scans Completed" },
      { value: "500,000+", label: "Vulnerabilities Found" },
      { value: "10,000+", label: "Active Users" },
      { value: "150+", label: "Countries Served" },
    ],
    ctaTitle: "Ready to Secure Your Applications?",
    ctaDescription: "Start your free security scan today. No credit card required.",
    ctaButton: "Get Started Free",
  },
  blog: {
    title: "Security Insights & Best Practices",
    description: "Publish and edit the latest threat briefings, commentary, and response guides.",
    sectionTitle: "Featured Articles",
    postsToDisplay: "3",
    categories: [
      "Vulnerability Reports",
      "Security Best Practices",
      "Threat Intelligence",
      "Penetration Testing",
      "Web Application Security",
      "API Security",
    ],
  },
  awareness: {
    title: "Security Awareness Training Hub",
    description: "Curated awareness content, practical defenses, and training resources for teams that want security habits to stick.",
    owasp: [
      { rank: "01", name: "Broken Access Control", link: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
      { rank: "02", name: "Cryptographic Failures", link: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
      { rank: "03", name: "Injection", link: "https://owasp.org/Top10/A03_2021-Injection/" },
      { rank: "04", name: "Insecure Design", link: "https://owasp.org/Top10/A04_2021-Insecure_Design/" },
      { rank: "05", name: "Security Misconfiguration", link: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
    ],
    resources: [
      {
        title: "Phishing Response Essentials",
        type: "Video",
        url: "https://www.youtube.com/results?search_query=cisa+phishing+awareness",
        description: "Short video guidance for spotting and reporting suspicious emails.",
      },
      {
        title: "MFA Rollout Playbook",
        type: "Guide",
        url: "https://www.cisa.gov/secure-our-world/turn-mfa",
        description: "Step-by-step guidance for rolling out multi-factor authentication.",
      },
      {
        title: "Secure Coding Foundations",
        type: "Article",
        url: "https://owasp.org/www-project-top-ten/",
        description: "Practical coding habits that reduce common web app risk.",
      },
      {
        title: "Incident Readiness Checklist",
        type: "PDF",
        url: "https://www.cisa.gov/stopransomware",
        description: "A quick checklist for response, evidence, and recovery.",
      },
      {
        title: "Password Manager Adoption Guide",
        type: "Video",
        url: "https://www.youtube.com/results?search_query=secure+password+manager+guide",
        description: "How to standardize credential storage for teams and individuals.",
      },
    ],
    downloads: [
      {
        title: "Security Awareness Checklist",
        description: "Daily security practices checklist",
        fileMeta: "PDF | generated instantly",
      },
      {
        title: "Incident Response Plan Template",
        description: "Template for handling security incidents",
        fileMeta: "PDF | generated instantly",
      },
      {
        title: "Password Manager Comparison",
        description: "Compare popular password managers",
        fileMeta: "PDF | generated instantly",
      },
    ],
  },
  tools: {
    title: "Give Users More Powerful Security Tools",
    subtitle: "Expand the utility suite with focused scanners, validators, and quick-win helpers",
    description: "Control how each tool page positions value, workflows, and future roadmap messaging.",
    primaryButton: "Open Tool Workbench",
    secondaryButton: "See Upcoming Tools",
    features: [
      "Domain intelligence checks",
      "Certificate validation",
      "Header and config audits",
      "Fast incident triage helpers",
    ],
    stats: [
      { value: "14", label: "Tools Available" },
      { value: "52k+", label: "Monthly Runs" },
      { value: "7", label: "Tools In Progress" },
      { value: "4.9/5", label: "Average Rating" },
    ],
    ctaTitle: "Need a custom security utility next?",
    ctaDescription: "Use the roadmap section to direct users toward the tools that ship next.",
    ctaButton: "Request a Tool",
  },
};

export function mergeNested(defaults, payload) {
  const result = { ...defaults };
  for (const [key, value] of Object.entries(payload || {})) {
    if (value && typeof value === "object" && !Array.isArray(value) && result[key] && typeof result[key] === "object" && !Array.isArray(result[key])) {
      result[key] = mergeNested(result[key], value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

export function initialsFor(name) {
  const initials = String(name || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
  return (initials || "NA").slice(0, 2);
}

export function parseNonNegativeInt(value, label) {
  const parsed = Number.parseInt(value ?? 0, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return [null, `${label} must be zero or a positive number`];
  }
  return [parsed, null];
}

export function normalizeAwarenessItem(item, kind) {
  if (typeof item === "string") {
    if (kind === "download") {
      return {
        title: item,
        description: "Downloadable security resource.",
        fileMeta: "PDF | generated instantly",
      };
    }

    return {
      title: item,
      type: "Guide",
      description: "Security awareness resource.",
      url: "",
    };
  }

  return item;
}

export function normalizeAwarenessContent(content) {
  const nextContent = { ...(content || {}) };
  if ("resources" in nextContent) {
    nextContent.resources = (nextContent.resources || []).map((item) => normalizeAwarenessItem(item, "resource"));
  }
  if ("downloads" in nextContent) {
    nextContent.downloads = (nextContent.downloads || []).map((item) => normalizeAwarenessItem(item, "download"));
  }
  return nextContent;
}

export function isLegacyAwarenessContent(content) {
  const resources = content?.resources || [];
  const downloads = content?.downloads || [];
  return (
    content?.title === "Security Awareness Training & Resources"
    || !downloads.length
    || resources.some((item) => typeof item === "string")
  );
}
