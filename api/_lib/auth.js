/* global process */

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { getDb } from "./mongo.js";
import { json } from "./http.js";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;

export function validateEmailFormat(email) {
  return EMAIL_PATTERN.test(String(email || "").trim());
}

export function validatePassword(password) {
  const value = String(password || "");
  if (value.length < 8) {
    return "Password must be at least 8 characters";
  }
  return "";
}

export async function hashPassword(password) {
  return bcrypt.hash(String(password || ""), 10);
}

export async function comparePassword(password, hashedPassword) {
  return bcrypt.compare(String(password || ""), String(hashedPassword || ""));
}

export function signAuthToken(user) {
  const secret = String(process.env.SECRET_KEY || "").trim();
  if (!secret) {
    throw new Error("SECRET_KEY is not configured");
  }

  return jwt.sign(
    {
      user_id: String(user._id),
      email: user.email,
      role: user.role || "user",
    },
    secret,
    { algorithm: "HS256", expiresIn: "24h" },
  );
}

export function parseObjectId(value) {
  try {
    return new ObjectId(String(value));
  } catch {
    return null;
  }
}

export function serializeUser(user) {
  const firstName = user.first_name || user.firstName || "";
  const lastName = user.last_name || user.lastName || "";
  const email = user.email || "";
  const fullName = `${firstName} ${lastName}`.trim() || email;
  const createdAt = user.created_at || user.createdAt || "";

  return {
    id: String(user._id),
    firstName,
    lastName,
    name: fullName,
    email,
    role: user.role || "user",
    status: user.disabled ? "disabled" : "active",
    plan: user.plan || "Free",
    scans: user.scans || 0,
    vulnerabilities: user.vulnerabilities || 0,
    phone: user.phone || "",
    bio: user.bio || "",
    joined: createdAt instanceof Date ? createdAt.toISOString() : String(createdAt || ""),
  };
}

export function isAdmin(user) {
  return user?.role === "admin";
}

export async function requireAuth(req, res) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader || !String(authHeader).startsWith("Bearer ")) {
    json(res, 401, { message: "Authorization token required" });
    return null;
  }

  try {
    const token = String(authHeader).split(" ")[1];
    const decoded = jwt.verify(token, String(process.env.SECRET_KEY || "").trim());
    const db = await getDb();
    const user = await db.collection("users").findOne({ _id: parseObjectId(decoded.user_id) });
    if (!user) {
      json(res, 401, { message: "Invalid token" });
      return null;
    }
    return user;
  } catch {
    json(res, 401, { message: "Invalid token" });
    return null;
  }
}

export async function requireAdmin(req, res) {
  const user = await requireAuth(req, res);
  if (!user) {
    return null;
  }
  if (!isAdmin(user)) {
    json(res, 403, { message: "Admin access required" });
    return null;
  }
  return user;
}
