import { ObjectId } from "mongodb";
import { hashPassword, requireAdmin, serializeUser, validateEmailFormat, validatePassword } from "../_lib/auth.js";
import { DEFAULT_ADMIN_PRICING, DEFAULT_ADMIN_SETTINGS, DEFAULT_ADMIN_TEAM, initialsFor, mergeNested, parseNonNegativeInt } from "../_lib/adminDefaults.js";
import { aggregateScanAnalytics, buildSecurityMetrics, listAdminScanReports } from "../_lib/dashboardAnalytics.js";
import { json, methodNotAllowed, readJson, serverError } from "../_lib/http.js";
import { getDb } from "../_lib/mongo.js";

async function getAdminSingleton(db, key, defaultValue) {
  const record = await db.collection("admin_config").findOne({ key });
  return record?.value ?? defaultValue;
}

async function saveAdminSingleton(db, key, value) {
  await db.collection("admin_config").updateOne(
    { key },
    { $set: { key, value, updated_at: new Date() } },
    { upsert: true },
  );
  return value;
}

function pricingStats(pricing) {
  const plans = pricing.plans || [];
  const transactions = pricing.transactions || [];
  const activeSubscriptions = plans.reduce((sum, plan) => sum + Number(plan.subscribers || 0), 0);
  const monthlyRevenue = plans.reduce((sum, plan) => {
    const price = String(plan.price || "0").replace(/[^0-9.]/g, "");
    return sum + (Number(price || 0) * Number(plan.subscribers || 0));
  }, 0);
  const churnRate = activeSubscriptions ? Math.max(1.2, Math.min(4.5, 100 / activeSubscriptions)).toFixed(1) : "0.0";
  return {
    totalRevenue: `$${monthlyRevenue.toLocaleString("en-US", { maximumFractionDigits: 0 })}`,
    activeSubscriptions,
    mrr: `$${monthlyRevenue.toLocaleString("en-US", { maximumFractionDigits: 0 })}`,
    churnRate: `${churnRate}%`,
    completedTransactions: transactions.filter((item) => item.status === "completed").length,
  };
}

async function blogCommentCount(db) {
  const posts = await db.collection("blogs").find({}).toArray();
  let total = 0;
  for (const blog of posts) {
    if (blog.comments_count != null) {
      total += Number(blog.comments_count || 0);
      continue;
    }
    for (const comment of blog.comments || []) {
      total += 1 + ((comment.replies || []).length);
    }
  }
  return total;
}

async function buildAdminReport(db, payload = {}) {
  const analytics = await aggregateScanAnalytics();
  const [totalUsers, totalPosts, comments, totalLikes] = await Promise.all([
    db.collection("users").countDocuments({}),
    db.collection("blogs").countDocuments({}),
    blogCommentCount(db),
    db.collection("blogs")
      .find({}, { projection: { likes: 1 } })
      .toArray()
      .then((items) => items.reduce((sum, item) => sum + Number(item.likes || 0), 0)),
  ]);

  const severityMetrics = await buildSecurityMetrics();
  const critical = Number(severityMetrics.find((item) => item.label === "Critical")?.value || 0);
  const vulnerabilities = Number(analytics.total_findings || 0);
  const scanCount = Number(analytics.total_scans || 0);
  const score = Math.max(50, Math.min(98, 100 - (critical * 3) - Math.round(vulnerabilities / 12)));
  const title = String(payload.title || "Admin Security Snapshot").trim() || "Admin Security Snapshot";

  return {
    id: `report-${new ObjectId()}`,
    title,
    subtitle: String(payload.subtitle || "Generated from current users, blog, reports, and security metrics").trim(),
    date: new Date(),
    size: `${(1.6 + Math.min(vulnerabilities, 120) / 100).toFixed(1)} MB`,
    type: "PDF",
    status: "ready",
    scanCount,
    vulnerabilities,
    critical,
    score,
    downloads: 0,
    findings: [
      `${totalUsers} account(s) under admin management.`,
      `${totalPosts} blog post(s), ${totalLikes} like(s), and ${comments} comment/reply item(s).`,
      `${critical} critical signal(s) need immediate review.`,
      "Use admin user controls to disable risky accounts and content moderation to hide unsafe posts.",
    ],
  };
}

function serializeAdminReport(report) {
  const dateValue = report.date || report.created_at || new Date();
  const timestamp = dateValue instanceof Date ? dateValue : new Date(dateValue);
  return {
    id: report.id || String(report._id || ""),
    title: report.title || "Admin Security Snapshot",
    subtitle: report.subtitle || "Generated from backend data",
    date: Number.isNaN(timestamp.getTime()) ? String(dateValue) : timestamp.toISOString(),
    size: report.size || "1.8 MB",
    type: report.type || "PDF",
    status: report.status || "ready",
    scanCount: report.scanCount || 0,
    vulnerabilities: report.vulnerabilities || 0,
    critical: report.critical || 0,
    score: report.score || 0,
    downloads: report.downloads || 0,
    findings: Array.isArray(report.findings) ? report.findings : [],
  };
}

export default async function handler(req, res) {
  try {
    const currentUser = await requireAdmin(req, res);
    if (!currentUser) {
      return undefined;
    }

    const path = String(req.query.path || "");
    const db = await getDb();

    if (path === "reports") {
      if (req.method === "GET") {
        return json(res, 200, { items: await listAdminScanReports(25) });
      }
      if (req.method === "POST") {
        const payload = await readJson(req);
        const report = await buildAdminReport(db, payload);
        await db.collection("admin_reports").insertOne(report);
        return json(res, 201, serializeAdminReport(report));
      }
      return methodNotAllowed(res, ["GET", "POST"]);
    }

    if (path === "users") {
      const users = db.collection("users");
      if (req.method === "GET") {
        const page = Math.max(Number.parseInt(req.query.page || "1", 10), 1);
        const limit = Math.max(Math.min(Number.parseInt(req.query.limit || "10", 10), 100), 1);
        const total = await users.countDocuments({});
        const items = await users.find({}).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).toArray();
        return json(res, 200, { items: items.map(serializeUser), page, limit, total });
      }

      if (req.method === "POST") {
        const payload = await readJson(req);
        const firstName = String(payload.firstName || payload.first_name || "").trim();
        const lastName = String(payload.lastName || payload.last_name || "").trim();
        const email = String(payload.email || "").trim().toLowerCase();
        const password = String(payload.password || "Temp@12345");

        if (!firstName || !lastName || !email) {
          return json(res, 400, { message: "First name, last name, and email are required" });
        }
        if (!validateEmailFormat(email)) {
          return json(res, 400, { message: "Enter a valid email address" });
        }
        const passwordError = validatePassword(password);
        if (passwordError) {
          return json(res, 400, { message: passwordError });
        }
        if (await users.findOne({ email })) {
          return json(res, 409, { message: "Email already exists" });
        }

        const [scans, scansError] = parseNonNegativeInt(payload.scans, "Scans");
        const [vulnerabilities, vulnerabilitiesError] = parseNonNegativeInt(payload.vulnerabilities, "Vulnerabilities");
        if (scansError || vulnerabilitiesError) {
          return json(res, 400, { message: scansError || vulnerabilitiesError });
        }

        const now = new Date();
        const user = {
          first_name: firstName,
          last_name: lastName,
          email,
          password: await hashPassword(password),
          role: ["user", "analyst", "manager", "admin"].includes(payload.role) ? payload.role : "user",
          disabled: payload.status === "disabled",
          plan: String(payload.plan || "Free").trim(),
          phone: String(payload.phone || "").trim(),
          bio: String(payload.bio || "").trim(),
          scans,
          vulnerabilities,
          is_verified: true,
          created_at: now,
          updated_at: now,
          failed_attempts: 0,
          lock_until: null,
        };

        const result = await users.insertOne(user);
        user._id = result.insertedId;
        return json(res, 201, serializeUser(user));
      }

      return methodNotAllowed(res, ["GET", "POST"]);
    }

    if (path === "team") {
      if (req.method === "GET") {
        return json(res, 200, { items: await getAdminSingleton(db, "team", DEFAULT_ADMIN_TEAM) });
      }
      if (req.method === "POST") {
        const payload = await readJson(req);
        const name = String(payload.name || "New Admin").trim();
        const email = String(payload.email || "").trim().toLowerCase();
        if (!email.includes("@") || !email.split("@")[1]?.includes(".")) {
          return json(res, 400, { message: "Enter a valid admin email address" });
        }

        const team = [...await getAdminSingleton(db, "team", DEFAULT_ADMIN_TEAM)];
        if (team.some((member) => String(member.email || "").toLowerCase() === email)) {
          return json(res, 409, { message: "Admin team email already exists" });
        }

        const member = {
          id: `team-${new ObjectId()}`,
          initials: initialsFor(name),
          name,
          email,
          status: payload.status || "pending",
          time: payload.time || "Invite pending",
          role: payload.role || "Admin",
          badges: Array.isArray(payload.badges) ? payload.badges : ["Reports", "User Support"],
        };
        team.push(member);
        await saveAdminSingleton(db, "team", team);
        return json(res, 201, member);
      }
      return methodNotAllowed(res, ["GET", "POST"]);
    }

    if (path === "pricing") {
      if (req.method === "GET") {
        const pricing = mergeNested(DEFAULT_ADMIN_PRICING, await getAdminSingleton(db, "pricing", {}));
        return json(res, 200, { ...pricing, stats: pricingStats(pricing) });
      }
      if (req.method === "PUT") {
        const payload = await readJson(req);
        const pricing = mergeNested(DEFAULT_ADMIN_PRICING, payload);
        await saveAdminSingleton(db, "pricing", pricing);
        return json(res, 200, { ...pricing, stats: pricingStats(pricing) });
      }
      return methodNotAllowed(res, ["GET", "PUT"]);
    }

    if (path === "settings") {
      if (req.method === "GET") {
        return json(res, 200, mergeNested(DEFAULT_ADMIN_SETTINGS, await getAdminSingleton(db, "settings", {})));
      }
      if (req.method === "PUT") {
        const payload = await readJson(req);
        const currentSettings = mergeNested(DEFAULT_ADMIN_SETTINGS, await getAdminSingleton(db, "settings", {}));
        const nextSettings = mergeNested(currentSettings, payload);
        await saveAdminSingleton(db, "settings", nextSettings);
        return json(res, 200, nextSettings);
      }
      return methodNotAllowed(res, ["GET", "PUT"]);
    }

    return json(res, 404, { message: "Route not found" });
  } catch (error) {
    return serverError(res, error, "Admin API request failed");
  }
}
