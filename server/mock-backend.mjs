import http from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, 'data');
const dataFile = path.join(dataDir, 'mock-db.json');
const port = Number(process.env.API_PORT || 5000);
const APP_USER_AGENT = 'Threat Hunters Security Tools';
const HIBP_BREACH_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}';

const baseNow = new Date('2026-06-14T12:00:00.000Z');
const demoUsers = [
  {
    id: 'u-admin',
    firstName: 'Mohamed',
    lastName: 'Nasr',
    email: 'admin@threathunters.com',
    password: 'Admin@12345',
    role: 'admin',
    phone: '+20 100 000 0000',
    bio: 'Platform administrator and security lead.',
  },
  {
    id: 'u-user',
    firstName: 'Amina',
    lastName: 'Hassan',
    email: 'user@threathunters.com',
    password: 'User@12345',
    role: 'user',
    phone: '+20 111 222 3333',
    bio: 'Security analyst focused on awareness and reporting.',
  },
];

const defaultUserSettings = {
  language: 'English (US)',
  timezone: 'UTC+02:00 (Cairo)',
  scanMode: 'quick',
  twoFactorEnabled: false,
  notifications: {
    completion: true,
    critical: true,
    weekly: true,
    cve: true,
  },
  reports: {
    technical: true,
    aiSummary: true,
    autoPdf: false,
  },
};

const defaultAdminSettings = {
  general: {
    siteName: 'Threat Hunters',
    siteDescription: 'Smart AI-Powered Web Vulnerability Scanner',
    language: 'English',
    timezone: 'UTC+02:00 Cairo',
  },
  notifications: {
    emailAlerts: true,
    criticalOnly: true,
    weeklyReports: true,
    productUpdates: false,
    digestFrequency: 'Daily digest',
  },
  security: {
    requireTwoFactor: true,
    loginAlerts: true,
    sessionTimeout: '30 minutes',
    passwordRotation: 'Every 90 days',
  },
  email: {
    senderName: 'Threat Hunters',
    senderAddress: 'alerts@threathunters.ai',
    replyTo: 'support@threathunters.ai',
    footerNote: 'AI-powered vulnerability scanning to protect your web applications.',
  },
};

const defaultAdminTeam = [
  {
    id: 'team-super-admin',
    initials: 'MN',
    name: 'Mohamed Nasr',
    email: 'admin@threathunters.com',
    status: 'active',
    time: 'Online now',
    role: 'Super Admin',
    badges: ['Full Access', 'User Management', 'System Config'],
  },
  {
    id: 'team-security-lead',
    initials: 'SA',
    name: 'Sarah Ahmed',
    email: 'sarah@threathunters.com',
    status: 'active',
    time: '2 hours ago',
    role: 'Admin',
    badges: ['Scan Management', 'Reports', 'User Support'],
  },
  {
    id: 'team-analyst',
    initials: 'OA',
    name: 'Omar Ali',
    email: 'omar@threathunters.com',
    status: 'away',
    time: '1 day ago',
    role: 'Security Analyst',
    badges: ['Scan Management', 'Reports'],
  },
];

const defaultAdminPricing = {
  plans: [
    {
      id: 'plan-free',
      name: 'Free',
      price: '$0',
      description: 'Perfect for trying out our service',
      subscribers: 456,
      badge: '',
      tone: 'is-free',
      features: [
        { label: 'Basic vulnerability scanning', included: true },
        { label: '1 active project', included: true },
        { label: 'Email notifications', included: true },
        { label: 'Advanced reporting', included: false },
        { label: 'Priority support', included: false },
      ],
    },
    {
      id: 'plan-professional',
      name: 'Professional',
      price: '$49',
      description: 'For professionals and small teams',
      subscribers: 234,
      badge: 'Most Popular',
      tone: 'is-professional',
      features: [
        { label: 'Advanced vulnerability scanning', included: true },
        { label: '10 active projects', included: true },
        { label: 'Detailed PDF reports', included: true },
        { label: 'Priority email support', included: true },
        { label: 'Team collaboration tools', included: false },
      ],
    },
    {
      id: 'plan-enterprise',
      name: 'Enterprise',
      price: '$199',
      description: 'For large teams and organizations',
      subscribers: 123,
      badge: '',
      tone: 'is-enterprise',
      features: [
        { label: 'Unlimited vulnerability scans', included: true },
        { label: 'Unlimited active projects', included: true },
        { label: 'Custom reports and exports', included: true },
        { label: 'Dedicated success manager', included: true },
        { label: 'SSO and advanced access control', included: true },
      ],
    },
  ],
  transactions: [
    { id: 'txn-1', customer: 'Mohamed Ahmed', plan: 'Professional', amount: '$49', date: '2026-06-11T09:20:00.000Z', status: 'completed' },
    { id: 'txn-2', customer: 'Sarah Ali', plan: 'Enterprise', amount: '$199', date: '2026-06-10T14:10:00.000Z', status: 'completed' },
    { id: 'txn-3', customer: 'Hassan Omar', plan: 'Professional', amount: '$49', date: '2026-06-09T16:45:00.000Z', status: 'completed' },
    { id: 'txn-4', customer: 'Nour Salem', plan: 'Enterprise', amount: '$199', date: '2026-06-08T11:30:00.000Z', status: 'pending' },
  ],
};

const defaultAdminReports = [
  {
    id: 'report-monthly-security',
    title: 'Monthly Security Report',
    subtitle: 'Comprehensive security analysis for the current workspace',
    date: '2026-06-14T12:00:00.000Z',
    size: '2.4 MB',
    type: 'PDF',
    status: 'ready',
    scanCount: 135,
    vulnerabilities: 168,
    critical: 12,
    score: 82,
    downloads: 18,
    findings: [
      'Review high-risk public endpoints weekly.',
      'Keep blog moderation and account controls audited.',
      'Prioritize critical and high severity issues first.',
    ],
  },
  {
    id: 'report-blog-risk',
    title: 'Content & Blog Moderation Report',
    subtitle: 'Admin view of published posts, comments, likes, and shares',
    date: '2026-06-11T10:00:00.000Z',
    size: '1.8 MB',
    type: 'PDF',
    status: 'ready',
    scanCount: 42,
    vulnerabilities: 36,
    critical: 2,
    score: 91,
    downloads: 9,
    findings: [
      'Published posts are visible to users.',
      'Hidden posts remain admin-only.',
      'Engagement counters are backed by the API.',
    ],
  },
];

const seedDb = () => ({
  users: [
    {
      id: 'u-admin',
      firstName: 'Mohamed',
      lastName: 'Nasr',
      email: 'admin@threathunters.com',
      passwordHash: hashPassword('Admin@12345'),
      role: 'admin',
      phone: '+20 100 000 0000',
      bio: 'Platform administrator and security lead.',
      plan: 'Enterprise',
      scans: 76,
      vulnerabilities: 18,
      createdAt: baseNow.toISOString(),
    },
    {
      id: 'u-user',
      firstName: 'Amina',
      lastName: 'Hassan',
      email: 'user@threathunters.com',
      passwordHash: hashPassword('User@12345'),
      role: 'user',
      phone: '+20 111 222 3333',
      bio: 'Security analyst focused on awareness and reporting.',
      plan: 'Professional',
      scans: 24,
      vulnerabilities: 5,
      createdAt: baseNow.toISOString(),
    },
  ],
  resetTokens: [],
  sessions: [],
  posts: [
    {
      id: 'post-1',
      title: 'Incident Response Playbook for Small Security Teams',
      description: 'A practical blueprint for handling suspicious activity without burning out your team.',
      content:
        'The first 60 minutes after a security alert decide most outcomes. Build a triage checklist, preserve evidence, and keep communications tight.',
      category: 'threat-intelligence',
      tags: ['IR', 'Playbook', 'SOC'],
      author: 'Sarah Johnson',
      authorInitial: 'S',
      badge: 'Featured',
      tone: 'blue',
      imageTone: 'blue',
      publishedAt: '2026-05-28T10:30:00.000Z',
      updatedAt: '2026-06-01T11:45:00.000Z',
      status: 'published',
      views: 15240,
      likes: 128,
      shares: 41,
      likedBy: ['admin@threathunters.com'],
      comments: [
        {
          id: 'c-1',
          author: 'Amina Hassan',
          authorEmail: 'user@threathunters.com',
          text: 'Nice checklist. We added this to our on-call runbook.',
          createdAt: '2026-06-02T07:30:00.000Z',
          replies: [
            {
              id: 'r-1',
              author: 'Mohamed Nasr',
              authorEmail: 'admin@threathunters.com',
              text: 'Great to hear. Keep the evidence chain short and consistent.',
              createdAt: '2026-06-02T08:05:00.000Z',
            },
          ],
        },
      ],
    },
    {
      id: 'post-2',
      title: 'Zero Trust for Modern Web Apps',
      description: 'Practical steps for shrinking trust boundaries across identity, network, and browser layers.',
      content:
        'Zero Trust is not a product. It is a design discipline that treats every request as untrusted until verified.',
      category: 'web-security',
      tags: ['Zero Trust', 'IAM', 'Browser'],
      author: 'Michael Chen',
      authorInitial: 'M',
      badge: 'Trending',
      tone: 'pink',
      imageTone: 'pink',
      publishedAt: '2026-06-05T12:00:00.000Z',
      updatedAt: '2026-06-06T09:00:00.000Z',
      status: 'published',
      views: 23880,
      likes: 206,
      shares: 63,
      likedBy: [],
      comments: [],
    },
    {
      id: 'post-3',
      title: 'CVE Triage: What to Fix First',
      description: 'How to prioritize vulnerabilities using asset exposure, exploitability, and business impact.',
      content:
        'A CVE list is only useful when it is ordered by exposure. Start with internet-facing assets, then chainable issues, then hygiene fixes.',
      category: 'threat-intelligence',
      tags: ['CVE', 'Prioritization', 'Risk'],
      author: 'Sarah Johnson',
      authorInitial: 'S',
      badge: 'Latest',
      tone: 'blue',
      imageTone: 'blue',
      publishedAt: '2026-06-10T14:10:00.000Z',
      updatedAt: '2026-06-11T16:20:00.000Z',
      status: 'published',
      views: 8802,
      likes: 84,
      shares: 22,
      likedBy: [],
      comments: [],
    },
  ],
  webContent: {
    home: {
      title: 'Protect Your Digital Assets with Advanced Security Testing',
      subtitle: 'Comprehensive vulnerability scanning and penetration testing platform',
      description:
        'Start proactive testing that surfaces misconfigurations, weak endpoints, and risky flows before attackers do.',
      primaryButton: 'Start Free Scan',
      secondaryButton: 'View Live Demo',
      features: [
        'Automated Security Scanning',
        'Real-time Threat Intelligence',
        'Comprehensive Reports',
        'API Security Testing',
      ],
      stats: [
        { value: '100,000+', label: 'Scans Completed' },
        { value: '500,000+', label: 'Vulnerabilities Found' },
        { value: '10,000+', label: 'Active Users' },
        { value: '150+', label: 'Countries Served' },
      ],
      ctaTitle: 'Ready to Secure Your Applications?',
      ctaDescription: 'Start your free security scan today. No credit card required.',
      ctaButton: 'Get Started Free',
    },
    blog: {
      title: 'Security Insights & Best Practices',
      description: 'Publish and edit the latest threat briefings, commentary, and response guides.',
      sectionTitle: 'Featured Articles',
      postsToDisplay: '3',
      categories: [
        'Vulnerability Reports',
        'Security Best Practices',
        'Threat Intelligence',
        'Penetration Testing',
        'Web Application Security',
        'API Security',
      ],
    },
    awareness: {
      title: 'Security Awareness Training & Resources',
      description: '',
      owasp: [
        { rank: '01', name: 'Broken Access Control', link: '' },
        { rank: '02', name: 'Cryptographic Failures', link: '' },
        { rank: '03', name: 'Injection', link: '' },
        { rank: '04', name: 'Insecure Design', link: '' },
        { rank: '05', name: 'Security Misconfiguration', link: '' },
      ],
      resources: [
        'Secure Coding Fundamentals',
        'Penetration Testing Basics',
        'Web Application Security',
        'API Security Best Practices',
      ],
    },
    tools: {
      title: 'Give Users More Powerful Security Tools',
      subtitle: 'Expand the utility suite with focused scanners, validators, and quick-win helpers',
      description:
        'Control how each tool page positions value, workflows, and future roadmap messaging.',
      primaryButton: 'Open Tool Workbench',
      secondaryButton: 'See Upcoming Tools',
      features: [
        'Domain intelligence checks',
        'Certificate validation',
        'Header and config audits',
        'Fast incident triage helpers',
      ],
      stats: [
        { value: '14', label: 'Tools Available' },
        { value: '52k+', label: 'Monthly Runs' },
        { value: '7', label: 'Tools In Progress' },
        { value: '4.9/5', label: 'Average Rating' },
      ],
      ctaTitle: 'Need a custom security utility next?',
      ctaDescription: 'Use the roadmap section to direct users toward the tools that ship next.',
      ctaButton: 'Request a Tool',
    },
  },
  passwordResetRequests: [],
  adminSettings: defaultAdminSettings,
  adminTeam: defaultAdminTeam,
  adminPricing: defaultAdminPricing,
  adminReports: defaultAdminReports,
});

function hashPassword(password) {
  const salt = 'threat-hunters-salt';
  return crypto.createHash('sha256').update(`${salt}:${password}`).digest('hex');
}

function createToken(user) {
  return `th-${crypto.randomBytes(18).toString('hex')}-${user.id}`;
}

function sanitizeUser(user) {
  const fullName = `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email || 'User';

  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    name: fullName,
    email: user.email,
    role: user.role,
    status: user.disabled ? 'disabled' : 'active',
    plan: user.plan || (user.role === 'admin' ? 'Enterprise' : 'Free'),
    scans: Number(user.scans || 0),
    vulnerabilities: Number(user.vulnerabilities || 0),
    phone: user.phone || '',
    bio: user.bio || '',
    createdAt: user.createdAt,
    joined: user.createdAt,
    lastLogin: user.lastLogin || null,
  };
}

function userSettings(user) {
  const settings = user.settings || {};
  return {
    ...defaultUserSettings,
    ...settings,
    notifications: {
      ...defaultUserSettings.notifications,
      ...(settings.notifications || {}),
    },
    reports: {
      ...defaultUserSettings.reports,
      ...(settings.reports || {}),
    },
  };
}

function serializePost(post) {
  return {
    ...post,
    status: post.status || 'published',
    publishedAt: post.publishedAt,
    updatedAt: post.updatedAt,
    comments: post.comments.map((comment) => ({
      ...comment,
      content: comment.content || comment.text || '',
      replies: (comment.replies ?? []).map((reply) => ({
        ...reply,
        content: reply.content || reply.text || '',
      })),
    })),
  };
}

async function ensureDataFile() {
  if (!existsSync(dataDir)) {
    await mkdir(dataDir, { recursive: true });
  }

  if (!existsSync(dataFile)) {
    await writeFile(dataFile, JSON.stringify(seedDb(), null, 2), 'utf8');
  }
}

function reconcileDemoAuth(db) {
  let changed = false;

  for (const demoUser of demoUsers) {
    const existingUser = db.users.find((user) => user.email?.toLowerCase() === demoUser.email.toLowerCase());

    if (!existingUser) {
      db.users.push({
        id: demoUser.id,
        firstName: demoUser.firstName,
        lastName: demoUser.lastName,
        email: demoUser.email,
        passwordHash: hashPassword(demoUser.password),
        role: demoUser.role,
        phone: demoUser.phone,
        bio: demoUser.bio,
        createdAt: baseNow.toISOString(),
      });
      changed = true;
      continue;
    }

    const expectedHash = hashPassword(demoUser.password);
    if (existingUser.passwordHash !== expectedHash) {
      existingUser.passwordHash = expectedHash;
      changed = true;
    }

    if (!existingUser.role) {
      existingUser.role = demoUser.role;
      changed = true;
    }

    if (!existingUser.phone) {
      existingUser.phone = demoUser.phone;
      changed = true;
    }

    if (!existingUser.bio) {
      existingUser.bio = demoUser.bio;
      changed = true;
    }

    if (!existingUser.plan) {
      existingUser.plan = demoUser.role === 'admin' ? 'Enterprise' : 'Professional';
      changed = true;
    }

    if (existingUser.scans === undefined) {
      existingUser.scans = demoUser.role === 'admin' ? 76 : 24;
      changed = true;
    }

    if (existingUser.vulnerabilities === undefined) {
      existingUser.vulnerabilities = demoUser.role === 'admin' ? 18 : 5;
      changed = true;
    }
  }

  if (!Array.isArray(db.sessions)) {
    db.sessions = [];
    changed = true;
  }

  if (!Array.isArray(db.resetTokens)) {
    db.resetTokens = [];
    changed = true;
  }

  if (!Array.isArray(db.posts)) {
    db.posts = seedDb().posts;
    changed = true;
  }

  if (!db.webContent) {
    db.webContent = seedDb().webContent;
    changed = true;
  }

  if (!Array.isArray(db.passwordResetRequests)) {
    db.passwordResetRequests = [];
    changed = true;
  }

  if (!db.adminSettings) {
    db.adminSettings = defaultAdminSettings;
    changed = true;
  }

  if (!Array.isArray(db.adminTeam)) {
    db.adminTeam = defaultAdminTeam;
    changed = true;
  }

  if (!db.adminPricing) {
    db.adminPricing = defaultAdminPricing;
    changed = true;
  }

  if (!Array.isArray(db.adminReports)) {
    db.adminReports = defaultAdminReports;
    changed = true;
  }

  return changed;
}

async function loadDb() {
  await ensureDataFile();
  const raw = (await readFile(dataFile, 'utf8')).replace(/^\uFEFF/, '');
  const db = JSON.parse(raw);
  const changed = reconcileDemoAuth(db);

  if (changed) {
    await saveDb(db);
  }

  return db;
}

async function saveDb(db) {
  await writeFile(dataFile, JSON.stringify(db, null, 2), 'utf8');
}

function json(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function text(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      if (!chunks.length) {
        resolve({});
        return;
      }

      try {
        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(payload);
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function getToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return '';
  return header.slice(7);
}

function findSession(db, token) {
  return db.sessions.find((session) => session.token === token) || null;
}

function requireUser(db, req) {
  const token = getToken(req);
  const session = findSession(db, token);
  if (!session) return null;
  const user = db.users.find((item) => item.id === session.userId);
  return user || null;
}

function isAdmin(user) {
  return user?.role === 'admin';
}

function articleCounts(db) {
  const totalLikes = db.posts.reduce((sum, post) => sum + (post.likes || 0), 0);
  const totalComments = db.posts.reduce(
    (sum, post) =>
      sum + (post.comments || []).reduce((commentSum, comment) => commentSum + 1 + (comment.replies?.length || 0), 0),
    0,
  );

  return { totalLikes, totalComments };
}

function totalVulnerabilityCount(db) {
  return db.users.reduce((sum, user) => sum + Number(user.vulnerabilities || 0), 0)
    + db.posts.filter((post) => post.status === 'hidden').length * 2
    + Math.max(db.posts.length - 1, 0);
}

function buildDashboardStats(db) {
  const { totalLikes, totalComments } = articleCounts(db);
  const activeUsers = db.users.filter((user) => !user.disabled).length;
  const totalScans = db.users.reduce((sum, user) => sum + Number(user.scans || 0), 0);
  const totalReports = db.adminReports?.length || 0;

  return [
    { label: 'Total Users', value: String(db.users.length), subtitle: `${activeUsers} active account(s)` },
    { label: 'Total Scans', value: String(totalScans || 0), subtitle: 'User scan activity tracked by backend' },
    { label: 'Admin Reports', value: String(totalReports), subtitle: 'Generated reports available for download' },
    { label: 'Blog Likes', value: String(totalLikes), subtitle: 'Across published articles' },
    { label: 'Comments', value: String(totalComments), subtitle: 'Reader discussions' },
  ];
}

function buildRecentActivities(db) {
  const latestPosts = [...db.posts]
    .sort((a, b) => new Date(b.updatedAt || b.publishedAt || 0) - new Date(a.updatedAt || a.publishedAt || 0))
    .slice(0, 2)
    .map((post) => ({
      title: 'Blog content updated',
      detail: `${post.title} is ${post.status || 'published'}`,
      time: post.updatedAt || post.publishedAt || new Date().toISOString(),
    }));

  const latestReports = [...(db.adminReports || [])]
    .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
    .slice(0, 2)
    .map((report) => ({
      title: 'Admin report ready',
      detail: `${report.title} scored ${report.score || 'N/A'}/100`,
      time: report.date || new Date().toISOString(),
    }));

  return [
    ...latestReports,
    ...latestPosts,
    { title: 'Account activity synced', detail: `${db.users.length} account(s) available for admin review`, time: new Date().toISOString() },
  ].slice(0, 5);
}

function buildSecurityMetrics(db = null) {
  const total = db ? totalVulnerabilityCount(db) : 168;
  const critical = Math.max(db?.posts?.filter((post) => post.status === 'hidden').length || 0, 2);
  const high = Math.max(Math.round(total * 0.25), 4);
  const medium = Math.max(Math.round(total * 0.45), 8);
  const low = Math.max(total - critical - high - medium, 0);

  return [
    { label: 'Critical', value: critical, subtitle: 'Needs immediate remediation' },
    { label: 'High', value: high, subtitle: 'Prioritize in this sprint' },
    { label: 'Medium', value: medium, subtitle: 'Track and schedule fixes' },
    { label: 'Low', value: low, subtitle: 'Hygiene and hardening backlog' },
  ];
}

function buildAdminReport(db, options = {}) {
  const now = new Date();
  const { totalLikes, totalComments } = articleCounts(db);
  const vulnerabilities = totalVulnerabilityCount(db);
  const critical = buildSecurityMetrics(db).find((metric) => metric.label === 'Critical')?.value || 0;
  const scanCount = db.users.reduce((sum, user) => sum + Number(user.scans || 0), 0);
  const score = Math.max(50, Math.min(98, 100 - critical * 3 - Math.round(vulnerabilities / 12)));
  const title = String(options.title || 'Admin Security Snapshot').trim() || 'Admin Security Snapshot';

  return {
    id: `report-${crypto.randomUUID()}`,
    title,
    subtitle: String(options.subtitle || 'Generated from current users, blog, reports, and security metrics').trim(),
    date: now.toISOString(),
    size: `${(1.6 + Math.min(vulnerabilities, 120) / 100).toFixed(1)} MB`,
    type: 'PDF',
    status: 'ready',
    scanCount,
    vulnerabilities,
    critical,
    score,
    downloads: 0,
    findings: [
      `${db.users.length} account(s) under admin management.`,
      `${db.posts.length} blog post(s), ${totalLikes} like(s), and ${totalComments} comment/reply item(s).`,
      `${critical} critical signal(s) need immediate review.`,
      'Use admin user controls to disable risky accounts and content moderation to hide unsafe posts.',
    ],
  };
}

function pricingStats(pricing) {
  const plans = pricing?.plans || [];
  const transactions = pricing?.transactions || [];
  const activeSubscriptions = plans.reduce((sum, plan) => sum + Number(plan.subscribers || 0), 0);
  const monthlyRevenue = plans.reduce((sum, plan) => {
    const price = Number(String(plan.price || '0').replace(/[^0-9.]/g, '')) || 0;
    return sum + price * Number(plan.subscribers || 0);
  }, 0);
  const completed = transactions.filter((item) => item.status === 'completed').length;
  const churnRate = activeSubscriptions ? Math.max(1.2, Math.min(4.5, 100 / activeSubscriptions)).toFixed(1) : '0.0';

  return {
    totalRevenue: `$${monthlyRevenue.toLocaleString('en-US')}`,
    activeSubscriptions,
    mrr: `$${monthlyRevenue.toLocaleString('en-US')}`,
    churnRate: `${churnRate}%`,
    completedTransactions: completed,
  };
}

function parseNonNegativeNumber(value, label) {
  const parsed = Number(value ?? 0);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return { ok: false, message: `${label} must be zero or a positive number.` };
  }

  return { ok: true, value: parsed };
}

function buildAwarenessContent() {
  return {
    tips: [
      {
        id: 'passwords',
        icon: 'LockKeyhole',
        title: 'Use Strong Passwords',
        description: 'Create unique passwords with at least 12 characters including numbers, symbols, and mixed case letters.',
      },
      {
        id: 'two-factor',
        icon: 'KeyRound',
        title: 'Enable Two-Factor Authentication',
        description: 'Add an extra layer of security by enabling 2FA on all your important accounts.',
      },
      {
        id: 'phishing',
        icon: 'Mail',
        title: 'Beware of Phishing',
        description: 'Do not click suspicious links or download attachments from unknown senders.',
      },
      {
        id: 'network',
        icon: 'Wifi',
        title: 'Secure Your Network',
        description: 'Use WPA3 encryption for WiFi and avoid using public networks for sensitive tasks.',
      },
      {
        id: 'updates',
        icon: 'Smartphone',
        title: 'Keep Software Updated',
        description: 'Regularly update your operating system and applications to patch security vulnerabilities.',
      },
      {
        id: 'backups',
        icon: 'ShieldCheck',
        title: 'Backup Your Data',
        description: 'Create regular backups of important files and store them in multiple secure locations.',
      },
    ],
    threats: [
      {
        id: 'phishing-attacks',
        icon: 'TriangleAlert',
        title: 'Phishing Attacks',
        badge: 'High',
        tone: 'high',
        description: 'Fraudulent emails or messages designed to steal your credentials or personal information.',
        howToAvoid: [
          'Verify sender email addresses carefully',
          'Do not click on suspicious links',
          'Check for spelling and grammar errors',
          'Contact the company directly if unsure',
        ],
      },
      {
        id: 'malware-ransomware',
        icon: 'Bug',
        title: 'Malware & Ransomware',
        badge: 'Critical',
        tone: 'critical',
        description: 'Malicious software that can damage your system or encrypt your files for ransom.',
        howToAvoid: [
          'Install reputable antivirus software',
          'Do not download from untrusted sources',
          'Keep your system updated',
          'Backup important files regularly',
        ],
      },
      {
        id: 'social-engineering',
        icon: 'Zap',
        title: 'Social Engineering',
        badge: 'Medium',
        tone: 'medium',
        description: 'Manipulating people into revealing confidential information or performing actions.',
        howToAvoid: [
          'Be skeptical of unexpected requests',
          'Verify identity before sharing info',
          'Do not share passwords or codes',
          'Trust your instincts',
        ],
      },
      {
        id: 'weak-passwords',
        icon: 'Smartphone',
        title: 'Weak Passwords',
        badge: 'Low',
        tone: 'low',
        description: 'Using simple or reused passwords makes your accounts vulnerable to attacks.',
        howToAvoid: [
          'Use password managers',
          'Create unique passwords per account',
          'Use passphrases instead of passwords',
          'Enable multi-factor authentication',
        ],
      },
    ],
    resources: [
      {
        id: 'password-guide',
        icon: 'FileText',
        type: 'Article',
        topic: 'Basics',
        title: 'Complete Guide to Password Security',
        description: 'Everything you need to know about creating and managing secure passwords.',
        duration: '8 min read',
        url: 'https://www.cisa.gov/secure-our-world/use-strong-passwords',
      },
      {
        id: 'phishing-video',
        icon: 'Video',
        type: 'Video',
        topic: 'Threats',
        title: 'Understanding Phishing Attacks',
        description: 'Learn to identify and avoid phishing attempts with real examples.',
        duration: '12 min',
        url: 'https://www.youtube.com/results?search_query=cisa+phishing+awareness',
      },
      {
        id: 'two-factor-guide',
        icon: 'BookOpen',
        type: 'Guide',
        topic: 'Basics',
        title: 'Setting Up Two-Factor Authentication',
        description: 'Step-by-step guide to enable 2FA on popular platforms.',
        duration: '5 min read',
        url: 'https://www.cisa.gov/secure-our-world/turn-mfa',
      },
      {
        id: 'ransomware-article',
        icon: 'FileText',
        type: 'Article',
        topic: 'Threats',
        title: 'Ransomware: Prevention and Recovery',
        description: 'How to protect against ransomware and what to do if infected.',
        duration: '10 min read',
        url: 'https://www.cisa.gov/stopransomware',
      },
      {
        id: 'network-video',
        icon: 'Video',
        type: 'Video',
        topic: 'Network',
        title: 'Secure Your Home Network',
        description: 'Best practices for securing your WiFi and home devices.',
        duration: '15 min',
        url: 'https://www.youtube.com/results?search_query=secure+home+network+cybersecurity',
      },
      {
        id: 'social-guide',
        icon: 'BookOpen',
        type: 'Guide',
        topic: 'Threats',
        title: 'Social Engineering Tactics',
        description: 'Recognize and defend against social engineering attacks.',
        duration: '7 min read',
        url: 'https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks',
      },
    ],
    downloads: [
      {
        id: 'checklist',
        title: 'Security Awareness Checklist',
        description: 'Daily security practices checklist',
        fileMeta: 'PDF | generated instantly',
        sections: [
          'Use unique passwords and a password manager.',
          'Turn on MFA for email, banking, admin, and cloud accounts.',
          'Verify sender identity before opening links or attachments.',
          'Keep operating systems, browsers, and apps updated.',
          'Back up important files and test recovery periodically.',
        ],
      },
      {
        id: 'incident-plan',
        title: 'Incident Response Plan Template',
        description: 'Template for handling security incidents',
        fileMeta: 'PDF | generated instantly',
        sections: [
          'Identify the affected asset, user, account, and timestamp.',
          'Preserve logs, screenshots, alerts, and suspicious files.',
          'Contain the incident by disabling accounts or isolating devices.',
          'Notify the correct owner, manager, or security contact.',
          'Document root cause, impact, remediation, and lessons learned.',
        ],
      },
      {
        id: 'password-managers',
        title: 'Password Manager Comparison',
        description: 'Compare popular password managers',
        fileMeta: 'PDF | generated instantly',
        sections: [
          'Prefer managers with strong encryption and independent audits.',
          'Check MFA support, recovery options, and device sync controls.',
          'Use sharing features only for team-approved secrets.',
          'Review breach alerts and password health dashboards monthly.',
          'Export recovery codes and store them securely offline.',
        ],
      },
    ],
  };
}

function buildMockPasswordBreach(password) {
  const normalized = String(password || '').trim();
  const hash = crypto.createHash('sha1').update(normalized).digest('hex').toUpperCase();
  const score = parseInt(hash.slice(0, 6), 16);
  const count = score % 2 === 0 ? 0 : (score % 5000) + 1;

  return {
    breached: count > 0,
    count,
    risk_level: count > 1000 ? 'High' : count > 100 ? 'Medium' : count > 0 ? 'Low' : 'Safe',
    message: count > 0
      ? `Password found ${count} times in known breaches`
      : 'Password not found in known breaches',
  };
}

function buildMockEmailBreach(email) {
  const normalized = String(email || '').trim().toLowerCase();
  const breached = normalized.includes('admin') || normalized.includes('user') || normalized.includes('test');
  const baseBreach = {
    name: 'Mock Credential Leak',
    title: 'Mock Credential Leak',
    domain: 'mock.threathunters.local',
    breach_date: '2026-05-14',
    added_date: '2026-05-15T00:00:00Z',
    modified_date: '2026-05-16T00:00:00Z',
    pwn_count: 12840,
    description: 'Mock breach data returned by the local dev server when HIBP is not available.',
    logo_path: '',
    data_classes: ['Emails', 'Passwords', 'Usernames'],
    verified: true,
    fabricated: false,
    sensitive: false,
    retired: false,
    spam_list: false,
    malware: false,
    stealer_log: false,
    subscription_free: true,
    attribution: 'Threat Hunters demo data',
  };

  if (!breached) {
    return {
      email: normalized,
      breached: false,
      risk_level: 'Safe',
      breach_count: 0,
      verified_breach_count: 0,
      stealer_log_count: 0,
      latest_breach: null,
      exposed_data: [],
      summary: {
        verified_breaches: 0,
        stealer_logs: 0,
        latest_breach: null,
        risk_level: 'Safe',
      },
      breaches: [],
    };
  }

  return {
    email: normalized,
    breached: true,
    risk_level: 'Medium',
    breach_count: 1,
    verified_breach_count: 1,
    stealer_log_count: 0,
    latest_breach: baseBreach,
    exposed_data: baseBreach.data_classes,
    summary: {
      verified_breaches: 1,
      stealer_logs: 0,
      latest_breach: baseBreach,
      risk_level: 'Medium',
    },
    breaches: [baseBreach],
  };
}

function normalizeScanUrl(rawTarget) {
  let value = String(rawTarget || '').trim();
  if (!value) {
    throw new Error('Website URL is required.');
  }
  if (!/^https?:\/\//i.test(value)) {
    value = `https://${value}`;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('Enter a valid website URL, for example https://example.com.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || !isValidScanHostname(parsed.hostname)) {
    throw new Error('Enter a valid website URL, for example https://example.com.');
  }
  return parsed.toString();
}

function isValidScanHostname(hostname) {
  const host = String(hostname || '').toLowerCase();
  if (host === 'localhost') return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host) && !host.includes('..');
}

function scanRiskLabel(score) {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 35) return 'Medium';
  return 'Low';
}

function scanFinding(code, severity, title, description, recommendation) {
  return { code, severity, title, description, recommendation };
}

function scanCheck(name, status, details, evidence = '') {
  return { name, status, details, evidence };
}

function headerSnapshot(headers) {
  const interestingHeaders = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'cross-origin-embedder-policy',
    'cache-control',
    'set-cookie',
    'server',
    'x-powered-by',
  ];
  return Object.fromEntries(interestingHeaders.map((header) => [header, headers[header] || 'Missing']));
}

function analyzeHtmlBody(text, finalUrl) {
  const findings = [];
  const checks = [];
  const html = String(text || '').slice(0, 250000);
  if (!html) {
    checks.push(scanCheck('HTML body analysis', 'Skipped', 'The response is not HTML or the body could not be decoded.'));
    return { findings, checks };
  }

  const lowerHtml = html.toLowerCase();
  const formCount = (lowerHtml.match(/<form\b/g) || []).length;
  const passwordFields = (lowerHtml.match(/type=["']?password/g) || []).length;
  const hasCsrf = /name=["']?(csrf|csrf_token|_token|authenticity_token)/i.test(lowerHtml);
  checks.push(scanCheck('Form inventory', formCount ? 'Review' : 'Passed', `Detected ${formCount} form(s) and ${passwordFields} password field(s).`));

  if (formCount && !hasCsrf) {
    findings.push(scanFinding(
      'csrf-token-not-detected',
      'Medium',
      'CSRF token not detected in forms',
      'The HTML contains forms, but no common CSRF token field name was detected in the page source.',
      'Add anti-CSRF tokens to state-changing forms and verify them server-side.',
    ));
  }

  if (new URL(finalUrl).protocol === 'https:' && /(src|href)=["']http:\/\//i.test(lowerHtml)) {
    findings.push(scanFinding(
      'mixed-content-reference',
      'Medium',
      'Possible mixed content reference',
      'The HTTPS page references one or more HTTP resources in src/href attributes.',
      'Serve all scripts, images, styles, and links over HTTPS.',
    ));
  }

  if (/(api[_-]?key|secret|token|password)\s*[:=]/i.test(lowerHtml)) {
    findings.push(scanFinding(
      'possible-secret-pattern',
      'High',
      'Possible secret-like string in page source',
      'The scanner found token/secret/password style patterns in the HTML response.',
      'Review the rendered source and remove credentials, tokens, or sensitive configuration from client output.',
    ));
  }

  checks.push(scanCheck('Client-side exposure review', 'Review', 'Checked HTML for mixed content, common secret patterns, and basic form hygiene.'));
  return { findings, checks };
}

function analyzeCookieFlags(headers) {
  const findings = [];
  const checks = [];
  const cookie = String(headers['set-cookie'] || '').toLowerCase();
  if (!cookie) {
    checks.push(scanCheck('Cookie security', 'Passed', 'No Set-Cookie header was returned on the scanned response.'));
    return { findings, checks };
  }

  checks.push(scanCheck('Cookie security', 'Review', 'Set-Cookie header detected; checking common security flags.'));
  if (!cookie.includes('secure')) {
    findings.push(scanFinding(
      'cookie-missing-secure',
      'Medium',
      'Cookie missing Secure flag',
      'At least one cookie appears to be set without the Secure flag.',
      'Add Secure to cookies so browsers only send them over HTTPS.',
    ));
  }
  if (!cookie.includes('httponly')) {
    findings.push(scanFinding(
      'cookie-missing-httponly',
      'Medium',
      'Cookie missing HttpOnly flag',
      'At least one cookie appears to be set without HttpOnly.',
      'Add HttpOnly to session cookies to reduce script-based theft impact.',
    ));
  }
  if (!cookie.includes('samesite')) {
    findings.push(scanFinding(
      'cookie-missing-samesite',
      'Low',
      'Cookie missing SameSite attribute',
      'At least one cookie appears to be set without SameSite.',
      'Add SameSite=Lax or SameSite=Strict where appropriate.',
    ));
  }
  return { findings, checks };
}

async function safeEndpointCheck(finalUrl, pathValue, label) {
  const baseUrl = new URL(finalUrl);
  const endpointUrl = `${baseUrl.protocol}//${baseUrl.host}${pathValue}`;
  try {
    const response = await fetch(endpointUrl, {
      redirect: 'manual',
      headers: { 'User-Agent': 'ThreatHuntersScanner/1.0' },
      signal: AbortSignal.timeout(6000),
    });
    if ([200, 401, 403].includes(response.status)) {
      return scanCheck(label, 'Review', `${pathValue} returned HTTP ${response.status}.`, endpointUrl);
    }
    if ([301, 302, 307, 308].includes(response.status)) {
      return scanCheck(label, 'Info', `${pathValue} redirected with HTTP ${response.status}.`, response.headers.get('location') || endpointUrl);
    }
    return scanCheck(label, 'Passed', `${pathValue} returned HTTP ${response.status}.`, endpointUrl);
  } catch (error) {
    return scanCheck(label, 'Skipped', `Could not request ${pathValue}: ${error.message || 'network request failed'}`);
  }
}

async function runWebsiteScan(body) {
  const target = normalizeScanUrl(body.target || body.url);
  const mode = String(body.scan_mode || body.mode || 'quick').toLowerCase();
  const startedAt = Date.now();
  let response;
  try {
    response = await fetch(target, {
      redirect: 'follow',
      headers: { 'User-Agent': 'ThreatHuntersScanner/1.0' },
      signal: AbortSignal.timeout(mode === 'deep' ? 18000 : 12000),
    });
  } catch (error) {
    throw new Error(`Could not reach target: ${error.message || 'network request failed'}`);
  }

  const headers = Object.fromEntries([...response.headers.entries()].map(([key, value]) => [key.toLowerCase(), value]));
  const findings = [];
  const checks = [
    scanCheck('Target reachability', 'Passed', `Target returned HTTP ${response.status}.`, response.url),
    scanCheck('Redirect handling', 'Info', `${response.redirected ? 1 : 0} redirect(s) followed.`),
  ];
  const securityHeaders = {
    'content-security-policy': ['High', 'Missing Content Security Policy', 'Add a strict Content-Security-Policy header to reduce XSS and injection impact.'],
    'strict-transport-security': ['High', 'Missing HSTS', 'Add Strict-Transport-Security for HTTPS sites to enforce encrypted connections.'],
    'x-frame-options': ['Medium', 'Missing clickjacking protection', 'Add X-Frame-Options or frame-ancestors in CSP.'],
    'x-content-type-options': ['Medium', 'Missing MIME sniffing protection', 'Add X-Content-Type-Options: nosniff.'],
    'referrer-policy': ['Low', 'Missing Referrer Policy', 'Add Referrer-Policy to limit sensitive URL leakage.'],
    'permissions-policy': ['Low', 'Missing Permissions Policy', 'Add Permissions-Policy to reduce browser feature exposure.'],
  };

  if (new URL(target).protocol !== 'https:') {
    findings.push(scanFinding(
      'plain-http',
      'High',
      'Site is not using HTTPS',
      'The target was scanned over plain HTTP, which exposes traffic to interception.',
      'Redirect all traffic to HTTPS and enable HSTS.',
    ));
  } else {
    checks.push(scanCheck('HTTPS transport', 'Passed', 'The submitted target uses HTTPS.'));
  }

  for (const [header, [severity, title, recommendation]] of Object.entries(securityHeaders)) {
    if (!headers[header]) {
      findings.push(scanFinding(
        `missing-${header}`,
        severity,
        title,
        `The ${header} response header was not present.`,
        recommendation,
      ));
    } else {
      checks.push(scanCheck(title, 'Passed', `${header} is present.`, headers[header]));
    }
  }

  if (headers['x-powered-by']) {
    findings.push(scanFinding(
      'technology-disclosure',
      'Low',
      'Technology header disclosure',
      `The response exposes X-Powered-By: ${headers['x-powered-by']}.`,
      'Remove technology disclosure headers from production responses.',
    ));
  }
  if (headers.server) {
    checks.push(scanCheck('Server fingerprint', 'Review', 'Server header is visible.', headers.server));
  }

  if (response.status >= 500) {
    findings.push(scanFinding(
      'server-error',
      'Medium',
      'Server returned an error',
      `The target returned HTTP ${response.status}.`,
      'Review server logs and avoid exposing unstable endpoints.',
    ));
  }

  const contentType = headers['content-type'] || 'Unknown';
  const bodyText = /text\/html|application\/xhtml/i.test(contentType) ? await response.text() : '';
  const cookieAnalysis = analyzeCookieFlags(headers);
  const bodyAnalysis = analyzeHtmlBody(bodyText, response.url);
  findings.push(...cookieAnalysis.findings, ...bodyAnalysis.findings);
  checks.push(...cookieAnalysis.checks, ...bodyAnalysis.checks);

  const endpointPlan = mode === 'deep'
    ? [
      ['/robots.txt', 'robots.txt'],
      ['/sitemap.xml', 'sitemap.xml'],
      ['/.well-known/security.txt', 'security.txt'],
      ['/admin', 'Admin surface'],
      ['/login', 'Login surface'],
    ]
    : [
      ['/.well-known/security.txt', 'security.txt'],
      ['/robots.txt', 'robots.txt'],
    ];
  const endpointChecks = await Promise.all(endpointPlan.map(([pathValue, label]) => safeEndpointCheck(response.url, pathValue, label)));
  for (const check of endpointChecks) {
    if (check.name === 'Admin surface' && check.status === 'Review') {
      findings.push(scanFinding(
        'admin-surface-detected',
        'Low',
        'Administrative surface may be exposed',
        `The ${check.name} check returned a reachable response: ${check.details}`,
        'Confirm administrative paths require authentication, rate limiting, and monitoring.',
      ));
    }
    checks.push(check);
  }

  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const points = { Critical: 28, High: 18, Medium: 10, Low: 4 };
  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
  }
  const riskScore = Math.min(100, findings.reduce((sum, finding) => sum + points[finding.severity], 0));
  const risk = scanRiskLabel(riskScore);
  const completedAt = new Date();
  const reportId = `RPT-${completedAt.toISOString().replace(/\D/g, '').slice(0, 14)}`;

  return {
    id: reportId,
    reference: reportId.replace('RPT-', 'TH-'),
    target,
    url: response.url,
    status: 'Completed',
    scan_mode: mode,
    http_status: response.status,
    server: headers.server || 'Not disclosed',
    content_type: contentType,
    content_length: headers['content-length'] || String(bodyText.length),
    tls: new URL(response.url).protocol === 'https:' ? { valid: true, issuer: 'Browser trust store', expires: null } : null,
    headers: headerSnapshot(headers),
    risk,
    risk_label: `${risk} Risk`,
    risk_score: riskScore,
    score: `${riskScore}/100`,
    duration: `${Math.max((Date.now() - startedAt) / 1000, 0.1).toFixed(1)}s`,
    date: completedAt.toISOString().slice(0, 10),
    time: completedAt.toTimeString().slice(0, 5),
    created_at: completedAt.toISOString(),
    findings,
    checks,
    summary: {
      total_findings: findings.length,
      severity_counts: severityCounts,
      headers_checked: Object.keys(securityHeaders),
      redirects: response.redirected ? 1 : 0,
      checks_run: checks.length,
      passed_checks: checks.filter((check) => check.status === 'Passed').length,
      review_checks: checks.filter((check) => check.status === 'Review').length,
    },
    recommendations: [...new Set(findings.map((finding) => finding.recommendation))].slice(0, 10),
  };
}

function normalizeBreachDescription(value) {
  return String(value || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/<[^>]+>/g, '')
    .trim();
}

async function checkEmailWithHIBP(email) {
  const apiKey = String(process.env.HIBP_API_KEY || '').trim();
  if (!apiKey) {
    return null;
  }

  const response = await fetch(
    `${HIBP_BREACH_URL.replace('{email}', encodeURIComponent(email))}?truncateResponse=false`,
    {
      headers: {
        'User-Agent': APP_USER_AGENT,
        'hibp-api-key': apiKey,
      },
    },
  );

  if (response.status === 404) {
    return {
      email,
      breached: false,
      risk_level: 'Safe',
      breach_count: 0,
      verified_breach_count: 0,
      stealer_log_count: 0,
      latest_breach: null,
      exposed_data: [],
      summary: {
        verified_breaches: 0,
        stealer_logs: 0,
        latest_breach: null,
        risk_level: 'Safe',
      },
      breaches: [],
    };
  }

  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    const error = new Error(errorText || `HIBP request failed with status ${response.status}`);
    error.status = response.status;
    throw error;
  }

  const breaches = await response.json();
  const normalizedBreaches = [];
  const exposedData = new Set();
  let verifiedBreachCount = 0;
  let stealerLogCount = 0;

  for (const breach of breaches || []) {
    const normalized = {
      name: breach.Name,
      title: breach.Title,
      domain: breach.Domain,
      breach_date: breach.BreachDate,
      added_date: breach.AddedDate,
      modified_date: breach.ModifiedDate,
      pwn_count: breach.PwnCount || 0,
      description: normalizeBreachDescription(breach.Description),
      logo_path: breach.LogoPath,
      data_classes: breach.DataClasses || [],
      verified: Boolean(breach.IsVerified),
      fabricated: Boolean(breach.IsFabricated),
      sensitive: Boolean(breach.IsSensitive),
      retired: Boolean(breach.IsRetired),
      spam_list: Boolean(breach.IsSpamList),
      malware: Boolean(breach.IsMalware),
      stealer_log: Boolean(breach.IsStealerLog),
      subscription_free: Boolean(breach.IsSubscriptionFree),
      attribution: breach.Attribution,
    };

    if (normalized.verified) {
      verifiedBreachCount += 1;
    }
    if (normalized.stealer_log) {
      stealerLogCount += 1;
    }

    for (const dataClass of normalized.data_classes) {
      exposedData.add(dataClass);
    }

    normalizedBreaches.push(normalized);
  }

  normalizedBreaches.sort((left, right) => {
    if (left.breach_date !== right.breach_date) {
      return String(right.breach_date || '').localeCompare(String(left.breach_date || ''));
    }

    return Number(right.pwn_count || 0) - Number(left.pwn_count || 0);
  });

  const breachCount = normalizedBreaches.length;
  let riskLevel = 'Low';
  if (breachCount >= 1) {
    riskLevel = 'Medium';
  }
  if (breachCount >= 5) {
    riskLevel = 'High';
  }
  if (breachCount >= 10 || stealerLogCount > 0) {
    riskLevel = 'Critical';
  }

  const latestBreach = normalizedBreaches[0] || null;

  return {
    email,
    breached: breachCount > 0,
    risk_level: riskLevel,
    breach_count: breachCount,
    verified_breach_count: verifiedBreachCount,
    stealer_log_count: stealerLogCount,
    latest_breach: latestBreach,
    exposed_data: Array.from(exposedData).sort(),
    summary: {
      verified_breaches: verifiedBreachCount,
      stealer_logs: stealerLogCount,
      latest_breach: latestBreach,
      risk_level: riskLevel,
    },
    breaches: normalizedBreaches,
  };
}

function latestBlogsPayload(db, includeHidden = false) {
  const posts = db.posts.map((post) => {
    if (!post.status) {
      post.status = 'published';
    }
    return serializePost(post);
  }).filter((post) => includeHidden || post.status === 'published');
  const featured = posts[0] || null;
  const categories = Array.from(new Set(posts.map((post) => post.category)));
  const trending = [...posts].sort((a, b) => (b.views + b.likes * 4 + b.shares * 2) - (a.views + a.likes * 4 + a.shares * 2));

  return {
    featured,
    trending: trending.slice(0, 4),
    categories,
    posts,
  };
}

async function handleRequest(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    });
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  const db = await loadDb();

  const send = (status, payload) => json(res, status, payload);
  const sendError = (status, message) => send(status, { message });

  if (pathname === '/api/ping') {
    send(200, { ok: true, timestamp: new Date().toISOString() });
    return;
  }

  if (pathname === '/api/register' && req.method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const firstName = String(body.firstName || '').trim();
    const lastName = String(body.lastName || '').trim();

    if (!email || !password || !firstName || !lastName) {
      sendError(400, 'Missing required registration fields.');
      return;
    }

    if (db.users.some((user) => user.email.toLowerCase() === email)) {
      sendError(409, 'An account with this email already exists.');
      return;
    }

    const user = {
      id: `u-${crypto.randomUUID()}`,
      firstName,
      lastName,
      email,
      passwordHash: hashPassword(password),
      role: 'user',
      phone: '',
      bio: '',
      createdAt: new Date().toISOString(),
    };

    db.users.push(user);
    const token = createToken(user);
    db.sessions = db.sessions.filter((session) => session.userId !== user.id);
    db.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
    await saveDb(db);

    send(201, { token, role: user.role, user: sanitizeUser(user) });
    return;
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const user = db.users.find((item) => item.email.toLowerCase() === email);

    if (!user || user.passwordHash !== hashPassword(password)) {
      sendError(401, 'Invalid email or password.');
      return;
    }

    const token = createToken(user);
    db.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
    await saveDb(db);

    send(200, { token, role: user.role, user: sanitizeUser(user) });
    return;
  }

  if (pathname === '/api/password/forgot' && req.method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const user = db.users.find((item) => item.email.toLowerCase() === email);

    if (!user) {
      sendError(404, 'No account found for that email.');
      return;
    }

    const resetToken = crypto.randomBytes(12).toString('hex');
    const resetCode = String(crypto.randomInt(100000, 1000000));
    db.resetTokens = db.resetTokens.filter((item) => item.email !== email);
    db.resetTokens.push({
      email,
      token: resetToken,
      code: resetCode,
      expiresAt: new Date(Date.now() + 1000 * 60 * 20).toISOString(),
    });
    await saveDb(db);

    send(200, {
      message: 'Password reset OTP prepared for demo use.',
      resetToken,
      resetCode,
      email,
    });
    return;
  }

  if (pathname === '/api/password/reset' && req.method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const token = String(body.token || body.code || '').trim();
    const nextPassword = String(body.newPassword || '').trim();

    if (!email || !token || !nextPassword) {
      sendError(400, 'Email, OTP, and new password are required.');
      return;
    }

    const resetRecord = db.resetTokens.find((item) => (
      item.email === email && (item.token === token || item.code === token)
    ));
    if (!resetRecord || new Date(resetRecord.expiresAt).getTime() < Date.now()) {
      sendError(400, 'Invalid or expired OTP.');
      return;
    }

    const user = db.users.find((item) => item.email === email);
    if (!user) {
      sendError(404, 'Account not found.');
      return;
    }

    user.passwordHash = hashPassword(nextPassword);
    db.resetTokens = db.resetTokens.filter((item) => item.email !== email);
    await saveDb(db);
    send(200, { message: 'Password updated successfully.' });
    return;
  }

  if (pathname === '/api/user/profile' && req.method === 'GET') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    send(200, sanitizeUser(user));
    return;
  }

  if (pathname === '/api/user/profile' && req.method === 'PUT') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    const body = await readBody(req);
    user.firstName = String(body.firstName ?? user.firstName).trim() || user.firstName;
    user.lastName = String(body.lastName ?? user.lastName).trim() || user.lastName;
    const nextEmail = String(body.email ?? user.email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(nextEmail)) {
      sendError(400, 'Enter a valid email address.');
      return;
    }
    const emailTaken = db.users.some((item) => item.id !== user.id && item.email === nextEmail);
    if (emailTaken) {
      sendError(400, 'Email address is already in use.');
      return;
    }
    user.email = nextEmail;
    user.phone = String(body.phone ?? user.phone ?? '').trim();
    user.bio = String(body.bio ?? user.bio ?? '').trim();
    await saveDb(db);
    send(200, sanitizeUser(user));
    return;
  }

  if (pathname === '/api/user/settings' && req.method === 'GET') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    send(200, userSettings(user));
    return;
  }

  if (pathname === '/api/user/settings' && req.method === 'PUT') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    const body = await readBody(req);
    const currentSettings = userSettings(user);
    user.settings = {
      ...currentSettings,
      language: String(body.language ?? currentSettings.language).trim() || currentSettings.language,
      timezone: String(body.timezone ?? currentSettings.timezone).trim() || currentSettings.timezone,
      scanMode: ['quick', 'deep'].includes(body.scanMode) ? body.scanMode : currentSettings.scanMode,
      twoFactorEnabled: Boolean(body.twoFactorEnabled ?? currentSettings.twoFactorEnabled),
      notifications: {
        ...currentSettings.notifications,
        ...(body.notifications || {}),
      },
      reports: {
        ...currentSettings.reports,
        ...(body.reports || {}),
      },
    };
    await saveDb(db);
    send(200, user.settings);
    return;
  }

  if (pathname === '/api/user/password' && req.method === 'PUT') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    const body = await readBody(req);
    const currentPassword = String(body.currentPassword || '');
    const nextPassword = String(body.newPassword || '');
    if (user.passwordHash !== hashPassword(currentPassword)) {
      sendError(400, 'Current password is incorrect.');
      return;
    }
    if (nextPassword.length < 8) {
      sendError(400, 'New password must be at least 8 characters long.');
      return;
    }
    user.passwordHash = hashPassword(nextPassword);
    await saveDb(db);
    send(200, { message: 'Password updated successfully.' });
    return;
  }

  if (pathname === '/api/user/account' && req.method === 'DELETE') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    db.users = db.users.filter((item) => item.id !== user.id);
    db.sessions = db.sessions.filter((session) => session.userId !== user.id);
    await saveDb(db);
    send(200, { message: 'Account deleted successfully.' });
    return;
  }

  if ((pathname === '/api/blog' || pathname === '/api/blogs') && req.method === 'GET') {
    const user = requireUser(db, req);
    const includeHidden = url.searchParams.get('include_hidden') === 'true' && isAdmin(user);
    send(200, latestBlogsPayload(db, includeHidden));
    return;
  }

  if ((pathname === '/api/blog' || pathname === '/api/blogs') && req.method === 'POST') {
    const user = requireUser(db, req);
    if (!user) {
      sendError(401, 'Unauthorized.');
      return;
    }
    const body = await readBody(req);
    const title = String(body.title || '').trim();
    const description = String(body.description || '').trim();
    const content = String(body.content || '').trim();
    if (!title || !description) {
      sendError(400, 'Title and description are required.');
      return;
    }

    const post = {
      id: `post-${crypto.randomUUID()}`,
      title,
      description,
      content: content || description,
      category: String(body.category || 'security-awareness').trim(),
      tags: Array.isArray(body.tags) ? body.tags.filter(Boolean).map(String) : [],
      author: `${user.firstName} ${user.lastName}`.trim(),
      authorInitial: `${user.firstName?.[0] || 'U'}`.toUpperCase(),
      badge: body.badge ? String(body.badge) : 'New',
      tone: body.tone ? String(body.tone) : 'blue',
      imageTone: body.imageTone ? String(body.imageTone) : 'blue',
      imageUrl: body.imageUrl ? String(body.imageUrl) : '',
      imageName: body.imageName ? String(body.imageName) : '',
      publishedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      status: ['published', 'hidden'].includes(body.status) ? body.status : 'published',
      views: 0,
      likes: 0,
      shares: 0,
      likedBy: [],
      comments: [],
    };

    db.posts.unshift(post);
    await saveDb(db);
    send(201, serializePost(post));
    return;
  }

  const postMatch = pathname.match(/^\/api\/blogs?\/([^/]+)$/);
  const likeMatch = pathname.match(/^\/api\/blogs?\/([^/]+)\/like$/);
  const shareMatch = pathname.match(/^\/api\/blogs?\/([^/]+)\/share$/);
  const statusMatch = pathname.match(/^\/api\/blogs?\/([^/]+)\/status$/);
  const commentMatch = pathname.match(/^\/api\/blogs?\/([^/]+)\/comments$/);
  const replyMatch = pathname.match(/^\/api\/blogs?\/([^/]+)\/comments\/([^/]+)\/replies$/);

  if (postMatch || likeMatch || shareMatch || statusMatch || commentMatch || replyMatch) {
    const postId = postMatch?.[1] || likeMatch?.[1] || shareMatch?.[1] || statusMatch?.[1] || commentMatch?.[1] || replyMatch?.[1];
    const post = db.posts.find((item) => item.id === postId);
    if (!post) {
      sendError(404, 'Post not found.');
      return;
    }

    if (postMatch && req.method === 'GET') {
      const user = requireUser(db, req);
      if ((post.status || 'published') === 'hidden' && !isAdmin(user)) {
        sendError(404, 'Post not found.');
        return;
      }
      send(200, serializePost(post));
      return;
    }

    if (postMatch && req.method === 'PUT') {
      const user = requireUser(db, req);
      if (!user) {
        sendError(401, 'Unauthorized.');
        return;
      }
      const body = await readBody(req);
      post.title = String(body.title || post.title).trim();
      post.description = String(body.description || post.description).trim();
      post.content = String(body.content || post.content).trim();
      post.category = String(body.category || post.category).trim();
      post.tags = Array.isArray(body.tags) ? body.tags.filter(Boolean).map(String) : post.tags;
      post.badge = body.badge ? String(body.badge) : post.badge;
      if ('imageUrl' in body) {
        post.imageUrl = body.imageUrl ? String(body.imageUrl) : '';
      }
      if ('imageName' in body) {
        post.imageName = body.imageName ? String(body.imageName) : '';
      }
      post.status = ['published', 'hidden'].includes(body.status) ? body.status : (post.status || 'published');
      post.updatedAt = new Date().toISOString();
      await saveDb(db);
      send(200, serializePost(post));
      return;
    }

    if (statusMatch && req.method === 'PATCH') {
      const user = requireUser(db, req);
      if (!isAdmin(user)) {
        sendError(403, 'Admin access required.');
        return;
      }
      const body = await readBody(req);
      const nextStatus = String(body.status || '').trim();
      if (!['published', 'hidden'].includes(nextStatus)) {
        sendError(400, 'Status must be published or hidden.');
        return;
      }
      post.status = nextStatus;
      post.updatedAt = new Date().toISOString();
      await saveDb(db);
      send(200, serializePost(post));
      return;
    }

    if (postMatch && req.method === 'DELETE') {
      const user = requireUser(db, req);
      if (!user) {
        sendError(401, 'Unauthorized.');
        return;
      }
      db.posts = db.posts.filter((item) => item.id !== postId);
      await saveDb(db);
      send(200, { message: 'Post deleted.' });
      return;
    }

    if (likeMatch && req.method === 'POST') {
      const user = requireUser(db, req);
      const userEmail = user?.email || `guest-${crypto.randomUUID()}`;
      const alreadyLiked = post.likedBy.includes(userEmail);
      if (alreadyLiked) {
        post.likedBy = post.likedBy.filter((item) => item !== userEmail);
        post.likes = Math.max((post.likes || 0) - 1, 0);
      } else {
        post.likedBy.push(userEmail);
        post.likes = (post.likes || 0) + 1;
      }
      await saveDb(db);
      send(200, { likes: post.likes, liked: !alreadyLiked, id: post.id });
      return;
    }

    if (shareMatch && req.method === 'POST') {
      post.shares = (post.shares || 0) + 1;
      await saveDb(db);
      send(200, { shares: post.shares, shared: true, id: post.id });
      return;
    }

    if (commentMatch && req.method === 'POST') {
      const user = requireUser(db, req);
      if (!user) {
        sendError(401, 'Unauthorized.');
        return;
      }
      const body = await readBody(req);
      const textValue = String(body.text || body.content || '').trim();
      if (!textValue) {
        sendError(400, 'Comment text is required.');
        return;
      }
      const comment = {
        id: `c-${crypto.randomUUID()}`,
        author: `${user.firstName} ${user.lastName}`.trim(),
        authorEmail: user.email,
        content: textValue,
        createdAt: new Date().toISOString(),
        replies: [],
      };
      post.comments.unshift(comment);
      await saveDb(db);
      send(201, serializePost(post));
      return;
    }

    if (commentMatch && req.method === 'GET') {
      const comments = (post.comments || []).reduce((acc, comment) => {
        if (comment.parentCommentId || comment.parent_comment_id) {
          return acc;
        }

        const replyPool = [
          ...(Array.isArray(comment.replies) ? comment.replies : []),
          ...((post.comments || []).filter((item) => (
            item.parentCommentId === comment.id || item.parent_comment_id === comment.id
          ))),
        ];

        const uniqueReplies = new Map();
        for (const reply of replyPool) {
          const replyId = reply.id || reply._id || `${comment.id}-reply`;
          if (uniqueReplies.has(replyId)) {
            continue;
          }
          uniqueReplies.set(replyId, {
            id: replyId,
            author: reply.author,
            content: reply.content || reply.text || '',
            createdAt: reply.createdAt,
          });
        }

        acc.push({
          id: comment.id,
          author: comment.author,
          content: comment.content || comment.text || '',
          createdAt: comment.createdAt,
          replies: Array.from(uniqueReplies.values()),
        });

        return acc;
      }, []);

      send(200, comments);
      return;
    }

    if (replyMatch && req.method === 'POST') {
      const user = requireUser(db, req);
      if (!user) {
        sendError(401, 'Unauthorized.');
        return;
      }
      const commentId = replyMatch[2];
      const comment = post.comments.find((item) => item.id === commentId);
      if (!comment) {
        sendError(404, 'Comment not found.');
        return;
      }
      const body = await readBody(req);
      const textValue = String(body.text || body.content || '').trim();
      if (!textValue) {
        sendError(400, 'Reply text is required.');
        return;
      }
      comment.replies = comment.replies || [];
      comment.replies.unshift({
        id: `r-${crypto.randomUUID()}`,
        author: `${user.firstName} ${user.lastName}`.trim(),
        authorEmail: user.email,
        content: textValue,
        parentCommentId: commentId,
        parent_comment_id: commentId,
        createdAt: new Date().toISOString(),
      });
      await saveDb(db);
      send(201, serializePost(post));
      return;
    }
  }

  if (pathname === '/api/security/latest-cves') {
    send(200, [
      { cve: 'CVE-2026-1001', severity: 'Critical', description: 'Authentication bypass in exposed admin panels.' },
      { cve: 'CVE-2026-1002', severity: 'High', description: 'Cross-site scripting in legacy content editors.' },
      { cve: 'CVE-2026-1003', severity: 'Medium', description: 'Weak TLS fallback on public APIs.' },
    ]);
    return;
  }

  if (pathname === '/api/security/critical-cves') {
    send(200, [
      { cve: 'CVE-2026-1001', severity: 'Critical', component: 'Auth gateway' },
      { cve: 'CVE-2026-1004', severity: 'Critical', component: 'File upload pipeline' },
    ]);
    return;
  }

  if (pathname === '/api/security/kev') {
    send(200, [
      { cve: 'CVE-2026-1001', dueDate: '2026-06-20', status: 'Known Exploited' },
      { cve: 'CVE-2026-1004', dueDate: '2026-06-25', status: 'Monitoring' },
    ]);
    return;
  }

  if (pathname === '/api/security/news') {
    send(200, [
      { title: 'Fresh phishing wave targets SaaS admins', source: 'Threat Hunters Desk' },
      { title: 'New secure-by-default API headers recommended', source: 'Threat Hunters Desk' },
      { title: 'Ransomware groups pivot to identity compromise', source: 'Threat Hunters Desk' },
    ]);
    return;
  }

  if (pathname === '/api/security/awareness') {
    send(200, buildAwarenessContent());
    return;
  }

  if (pathname === '/api/security/check-password' && req.method === 'POST') {
    const body = await readBody(req);
    const password = String(body.password || '').trim();

    if (!password) {
      sendError(400, 'Password is required');
      return;
    }

    send(200, buildMockPasswordBreach(password));
    return;
  }

  if (pathname === '/api/security/check-email' && req.method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();

    if (!email) {
      sendError(400, 'Email is required');
      return;
    }

    try {
      const liveResult = await checkEmailWithHIBP(email);
      if (liveResult) {
        send(200, liveResult);
        return;
      }
    } catch (error) {
      const status = Number(error.status || 502);
      sendError(status, status === 401 || status === 403
        ? 'HIBP_API_KEY is invalid or unauthorized.'
        : 'Failed to check email breaches from HIBP.');
      return;
    }

    sendError(503, 'HIBP_API_KEY is required for email breach checks.');
    return;
  }

  if (pathname === '/api/scanner/scan' && req.method === 'POST') {
    const body = await readBody(req);
    try {
      const result = await runWebsiteScan(body);
      send(200, result);
    } catch (error) {
      sendError(400, error.message || 'Scan failed.');
    }
    return;
  }

  if (pathname === '/api/dashboard/stats') {
    send(200, buildDashboardStats(db));
    return;
  }

  if (pathname === '/api/dashboard/activities') {
    send(200, buildRecentActivities(db));
    return;
  }

  if (pathname === '/api/dashboard/security-metrics') {
    send(200, buildSecurityMetrics(db));
    return;
  }

  if (pathname === '/api/admin/users' && req.method === 'GET') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }

    const page = Math.max(Number(url.searchParams.get('page') || 1), 1);
    const limit = Math.max(Number(url.searchParams.get('limit') || 10), 1);
    const start = (page - 1) * limit;
    const items = db.users.slice(start, start + limit).map(sanitizeUser);

    send(200, {
      items,
      page,
      limit,
      total: db.users.length,
    });
    return;
  }

  if (pathname === '/api/admin/users' && req.method === 'POST') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }

    const body = await readBody(req);
    const firstName = String(body.firstName || '').trim();
    const lastName = String(body.lastName || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || 'Temp@12345');
    const scans = parseNonNegativeNumber(body.scans, 'Scans');
    const vulnerabilities = parseNonNegativeNumber(body.vulnerabilities, 'Vulnerabilities');
    if (!scans.ok || !vulnerabilities.ok) {
      sendError(400, scans.message || vulnerabilities.message);
      return;
    }

    if (!firstName || !lastName || !email) {
      sendError(400, 'First name, last name, and email are required.');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email)) {
      sendError(400, 'Enter a valid email address.');
      return;
    }

    if (db.users.some((item) => item.email.toLowerCase() === email)) {
      sendError(409, 'Email already exists.');
      return;
    }

    if (password.length < 8) {
      sendError(400, 'Password must be at least 8 characters.');
      return;
    }

    const newUser = {
      id: `u-${crypto.randomUUID()}`,
      firstName,
      lastName,
      email,
      passwordHash: hashPassword(password),
      role: ['user', 'analyst', 'manager', 'admin'].includes(body.role) ? body.role : 'user',
      disabled: body.status === 'disabled',
      plan: String(body.plan || 'Free').trim() || 'Free',
      scans: scans.value,
      vulnerabilities: vulnerabilities.value,
      phone: String(body.phone || '').trim(),
      bio: String(body.bio || '').trim(),
      createdAt: new Date().toISOString(),
    };

    db.users.push(newUser);
    await saveDb(db);
    send(201, sanitizeUser(newUser));
    return;
  }

  const adminUserMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (adminUserMatch) {
    const [, userId] = adminUserMatch;
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const target = db.users.find((item) => item.id === userId);
    if (!target) {
      sendError(404, 'User not found.');
      return;
    }

    if (req.method === 'GET') {
      send(200, sanitizeUser(target));
      return;
    }

    if (req.method === 'PUT') {
      const body = await readBody(req);
      const nextEmail = body.email !== undefined ? String(body.email).trim().toLowerCase() : target.email;
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(nextEmail)) {
        sendError(400, 'Enter a valid email address.');
        return;
      }
      if (db.users.some((item) => item.id !== target.id && item.email.toLowerCase() === nextEmail)) {
        sendError(409, 'Email already exists.');
        return;
      }
      target.email = nextEmail;
      if (body.firstName !== undefined) target.firstName = String(body.firstName).trim() || target.firstName;
      if (body.lastName !== undefined) target.lastName = String(body.lastName).trim() || target.lastName;
      if (body.role) target.role = String(body.role);
      if (body.status) target.disabled = String(body.status) === 'disabled';
      if (body.plan !== undefined) target.plan = String(body.plan || 'Free');
      if (body.scans !== undefined) {
        const scans = parseNonNegativeNumber(body.scans, 'Scans');
        if (!scans.ok) {
          sendError(400, scans.message);
          return;
        }
        target.scans = scans.value;
      }
      if (body.vulnerabilities !== undefined) {
        const vulnerabilities = parseNonNegativeNumber(body.vulnerabilities, 'Vulnerabilities');
        if (!vulnerabilities.ok) {
          sendError(400, vulnerabilities.message);
          return;
        }
        target.vulnerabilities = vulnerabilities.value;
      }
      if (body.phone !== undefined) target.phone = String(body.phone);
      if (body.bio !== undefined) target.bio = String(body.bio);
      await saveDb(db);
      send(200, sanitizeUser(target));
      return;
    }

    if (req.method === 'DELETE') {
      if (target.id === user.id) {
        sendError(400, 'You cannot delete your own admin account.');
        return;
      }
      db.users = db.users.filter((item) => item.id !== userId);
      await saveDb(db);
      send(200, { message: 'User deleted.' });
      return;
    }
  }

  if (pathname === '/api/admin/settings') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }

    if (req.method === 'GET') {
      send(200, db.adminSettings || defaultAdminSettings);
      return;
    }

    if (req.method === 'PUT') {
      const body = await readBody(req);
      db.adminSettings = {
        ...defaultAdminSettings,
        ...(db.adminSettings || {}),
        ...body,
        general: {
          ...defaultAdminSettings.general,
          ...((db.adminSettings || {}).general || {}),
          ...(body.general || {}),
        },
        notifications: {
          ...defaultAdminSettings.notifications,
          ...((db.adminSettings || {}).notifications || {}),
          ...(body.notifications || {}),
        },
        security: {
          ...defaultAdminSettings.security,
          ...((db.adminSettings || {}).security || {}),
          ...(body.security || {}),
        },
        email: {
          ...defaultAdminSettings.email,
          ...((db.adminSettings || {}).email || {}),
          ...(body.email || {}),
        },
      };
      await saveDb(db);
      send(200, db.adminSettings);
      return;
    }
  }

  if (pathname === '/api/admin/team' && req.method === 'GET') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    send(200, { items: db.adminTeam || defaultAdminTeam });
    return;
  }

  if (pathname === '/api/admin/team' && req.method === 'POST') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const body = await readBody(req);
    const name = String(body.name || 'New Admin').trim();
    const email = String(body.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email)) {
      sendError(400, 'Enter a valid admin email address.');
      return;
    }
    if ((db.adminTeam || []).some((item) => item.email?.toLowerCase() === email)) {
      sendError(409, 'Admin team email already exists.');
      return;
    }
    const member = {
      id: `team-${crypto.randomUUID()}`,
      initials: name.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase() || 'NA',
      name,
      email,
      status: body.status || 'pending',
      time: String(body.time || (body.status === 'active' ? 'Online now' : 'Invite pending')).trim(),
      role: body.role || 'Admin',
      badges: Array.isArray(body.badges) ? body.badges : ['Reports', 'User Support'],
    };
    db.adminTeam = [...(db.adminTeam || []), member];
    await saveDb(db);
    send(201, member);
    return;
  }

  const adminTeamMatch = pathname.match(/^\/api\/admin\/team\/([^/]+)$/);
  if (adminTeamMatch) {
    const [, memberId] = adminTeamMatch;
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const member = (db.adminTeam || []).find((item) => item.id === memberId);
    if (!member) {
      sendError(404, 'Team member not found.');
      return;
    }

    if (req.method === 'PUT') {
      const body = await readBody(req);
      const nextEmail = String(body.email ?? member.email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(nextEmail)) {
        sendError(400, 'Enter a valid admin email address.');
        return;
      }
      if ((db.adminTeam || []).some((item) => item.id !== memberId && item.email?.toLowerCase() === nextEmail)) {
        sendError(409, 'Admin team email already exists.');
        return;
      }
      Object.assign(member, {
        name: String(body.name ?? member.name).trim() || member.name,
        email: nextEmail || member.email,
        role: String(body.role ?? member.role).trim() || member.role,
        status: String(body.status ?? member.status).trim() || member.status,
        time: String(body.time ?? member.time).trim() || member.time,
        badges: Array.isArray(body.badges) ? body.badges : member.badges,
      });
      member.initials = member.name.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase() || member.initials;
      await saveDb(db);
      send(200, member);
      return;
    }

    if (req.method === 'DELETE') {
      db.adminTeam = (db.adminTeam || []).filter((item) => item.id !== memberId);
      await saveDb(db);
      send(200, { message: 'Team member removed.' });
      return;
    }
  }

  if (pathname === '/api/admin/pricing') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }

    if (req.method === 'GET') {
      const pricing = db.adminPricing || defaultAdminPricing;
      send(200, { ...pricing, stats: pricingStats(pricing) });
      return;
    }

    if (req.method === 'PUT') {
      const body = await readBody(req);
      db.adminPricing = {
        plans: Array.isArray(body.plans) ? body.plans : (db.adminPricing?.plans || defaultAdminPricing.plans),
        transactions: Array.isArray(body.transactions) ? body.transactions : (db.adminPricing?.transactions || defaultAdminPricing.transactions),
      };
      await saveDb(db);
      send(200, { ...db.adminPricing, stats: pricingStats(db.adminPricing) });
      return;
    }
  }

  if (pathname === '/api/admin/pricing/plans' && req.method === 'POST') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const body = await readBody(req);
    const subscribers = parseNonNegativeNumber(body.subscribers, 'Subscribers');
    if (!subscribers.ok) {
      sendError(400, subscribers.message);
      return;
    }
    const plan = {
      id: `plan-${crypto.randomUUID()}`,
      name: String(body.name || 'New Plan').trim(),
      price: String(body.price || '$99').trim(),
      description: String(body.description || 'Custom security plan').trim(),
      subscribers: subscribers.value,
      badge: String(body.badge || '').trim(),
      tone: body.tone || 'is-professional',
      features: Array.isArray(body.features) ? body.features : [
        { label: 'Security scanning', included: true },
        { label: 'PDF reports', included: true },
        { label: 'Priority support', included: false },
      ],
    };
    db.adminPricing = db.adminPricing || defaultAdminPricing;
    db.adminPricing.plans = [...(db.adminPricing.plans || []), plan];
    await saveDb(db);
    send(201, plan);
    return;
  }

  const pricingPlanMatch = pathname.match(/^\/api\/admin\/pricing\/plans\/([^/]+)$/);
  if (pricingPlanMatch && (req.method === 'PUT' || req.method === 'DELETE')) {
    const [, planId] = pricingPlanMatch;
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    db.adminPricing = db.adminPricing || defaultAdminPricing;
    const plan = (db.adminPricing.plans || []).find((item) => item.id === planId);
    if (!plan) {
      sendError(404, 'Pricing plan not found.');
      return;
    }

    if (req.method === 'DELETE') {
      db.adminPricing.plans = (db.adminPricing.plans || []).filter((item) => item.id !== planId);
      await saveDb(db);
      send(200, { message: 'Pricing plan deleted.' });
      return;
    }

    const body = await readBody(req);
    Object.assign(plan, {
      name: String(body.name ?? plan.name).trim() || plan.name,
      price: String(body.price ?? plan.price).trim() || plan.price,
      description: String(body.description ?? plan.description).trim() || plan.description,
      subscribers: Number(plan.subscribers || 0),
      badge: String(body.badge ?? plan.badge ?? '').trim(),
      tone: String(body.tone ?? plan.tone ?? 'is-professional'),
      features: Array.isArray(body.features) ? body.features : plan.features,
    });
    if (body.subscribers !== undefined) {
      const subscribers = parseNonNegativeNumber(body.subscribers, 'Subscribers');
      if (!subscribers.ok) {
        sendError(400, subscribers.message);
        return;
      }
      plan.subscribers = subscribers.value;
    }
    await saveDb(db);
    send(200, plan);
    return;
  }

  if (pathname === '/api/admin/reports' && req.method === 'GET') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const reports = [...(db.adminReports || [])].sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
    send(200, { items: reports });
    return;
  }

  if (pathname === '/api/admin/reports' && req.method === 'POST') {
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const body = await readBody(req);
    const report = buildAdminReport(db, body);
    db.adminReports = [report, ...(db.adminReports || [])].slice(0, 25);
    await saveDb(db);
    send(201, report);
    return;
  }

  const reportDownloadMatch = pathname.match(/^\/api\/admin\/reports\/([^/]+)\/download$/);
  if (reportDownloadMatch && req.method === 'POST') {
    const [, reportId] = reportDownloadMatch;
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const report = (db.adminReports || []).find((item) => item.id === reportId);
    if (!report) {
      sendError(404, 'Report not found.');
      return;
    }
    report.downloads = Number(report.downloads || 0) + 1;
    await saveDb(db);
    send(200, report);
    return;
  }

  if (pathname === '/api/web-content' && req.method === 'GET') {
    send(200, db.webContent);
    return;
  }

  const webContentMatch = pathname.match(/^\/api\/web-content\/(home|blog|awareness|tools)$/);
  if (webContentMatch && req.method === 'PUT') {
    const [, page] = webContentMatch;
    const user = requireUser(db, req);
    if (!user || !isAdmin(user)) {
      sendError(401, 'Admin access required.');
      return;
    }
    const body = await readBody(req);
    db.webContent[page] = body;
    await saveDb(db);
    send(200, db.webContent[page]);
    return;
  }

  sendError(404, 'Endpoint not found.');
}

await ensureDataFile();

const server = http.createServer((req, res) => {
  Promise.resolve(handleRequest(req, res)).catch((error) => {
    console.error('Backend error:', error);
    if (!res.headersSent) {
      text(res, 500, 'Internal Server Error');
    } else {
      res.end();
    }
  });
});

server.listen(port, () => {
  console.log(`Mock backend listening on http://localhost:${port}`);
});
