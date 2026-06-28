import { comparePassword, signAuthToken, validateEmailFormat } from "./_lib/auth.js";
import { json, methodNotAllowed, readJson, serverError } from "./_lib/http.js";
import { getDb } from "./_lib/mongo.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return methodNotAllowed(res, ["POST"]);
  }

  try {
    const payload = await readJson(req);
    const email = String(payload.email || "").trim().toLowerCase();
    const password = String(payload.password || "");

    if (!validateEmailFormat(email) || !password) {
      return json(res, 400, { message: "Email and password are required" });
    }

    const db = await getDb();
    const user = await db.collection("users").findOne({ email });
    if (!user || user.disabled) {
      return json(res, 401, { message: "Invalid email or password" });
    }

    const passwordMatches = await comparePassword(password, user.password);
    if (!passwordMatches) {
      return json(res, 401, { message: "Invalid email or password" });
    }

    await db.collection("users").updateOne(
      { _id: user._id },
      { $set: { last_login: new Date(), failed_attempts: 0, lock_until: null } },
    );

    return json(res, 200, {
      message: "Login successful",
      token: signAuthToken(user),
      role: user.role || "user",
      user: {
        email: user.email,
        role: user.role || "user",
      },
    });
  } catch (error) {
    return serverError(res, error, "Login failed");
  }
}
