import { requireAuth, serializeUser } from "../_lib/auth.js";
import { json, methodNotAllowed, serverError } from "../_lib/http.js";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return methodNotAllowed(res, ["GET"]);
  }

  try {
    const path = String(req.query.path || "");
    if (path !== "profile") {
      return json(res, 404, { message: "Route not found" });
    }

    const user = await requireAuth(req, res);
    if (!user) {
      return undefined;
    }
    return json(res, 200, serializeUser(user));
  } catch (error) {
    return serverError(res, error, "Could not load user profile");
  }
}
