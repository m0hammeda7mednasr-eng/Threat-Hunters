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
});

function hashPassword(password) {
  const salt = 'threat-hunters-salt';
  return crypto.createHash('sha256').update(`${salt}:${password}`).digest('hex');
}

function createToken(user) {
  return `th-${crypto.randomBytes(18).toString('hex')}-${user.id}`;
}

function sanitizeUser(user) {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    role: user.role,
    phone: user.phone || '',
    bio: user.bio || '',
    createdAt: user.createdAt,
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

  return changed;
}

async function loadDb() {
  await ensureDataFile();
  const raw = await readFile(dataFile, 'utf8');
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

function buildDashboardStats(db) {
  const { totalLikes, totalComments } = articleCounts(db);
  return [
    { label: 'Total Scans', value: '135', subtitle: 'Completed this month' },
    { label: 'Critical Issues', value: '23', subtitle: 'Need immediate remediation' },
    { label: 'Blog Likes', value: String(totalLikes), subtitle: 'Across published articles' },
    { label: 'Comments', value: String(totalComments), subtitle: 'Reader discussions' },
  ];
}

function buildRecentActivities(db) {
  return [
    { title: 'Blog engagement updated', detail: `Total posts: ${db.posts.length}` },
    { title: 'Security notes published', detail: 'New mitigation tips added to the knowledge base' },
    { title: 'Account activity synced', detail: 'Login and password reset endpoints are active' },
  ];
}

function buildSecurityMetrics() {
  return [
    { label: 'Critical', value: 12 },
    { label: 'High', value: 27 },
    { label: 'Medium', value: 41 },
    { label: 'Low', value: 88 },
  ];
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
    user.phone = String(body.phone ?? user.phone ?? '').trim();
    user.bio = String(body.bio ?? user.bio ?? '').trim();
    await saveDb(db);
    send(200, sanitizeUser(user));
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

  if (pathname === '/api/dashboard/stats') {
    send(200, buildDashboardStats(db));
    return;
  }

  if (pathname === '/api/dashboard/activities') {
    send(200, buildRecentActivities(db));
    return;
  }

  if (pathname === '/api/dashboard/security-metrics') {
    send(200, buildSecurityMetrics());
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
      if (body.role) target.role = String(body.role);
      if (body.phone !== undefined) target.phone = String(body.phone);
      if (body.bio !== undefined) target.bio = String(body.bio);
      await saveDb(db);
      send(200, sanitizeUser(target));
      return;
    }

    if (req.method === 'DELETE') {
      db.users = db.users.filter((item) => item.id !== userId);
      await saveDb(db);
      send(200, { message: 'User deleted.' });
      return;
    }
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
