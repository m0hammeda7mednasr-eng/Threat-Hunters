import { requireAdmin } from "../_lib/auth.js";
import { buildDashboardStats, buildRecentActivities, buildSecurityMetrics } from "../_lib/dashboardAnalytics.js";
import { json, methodNotAllowed, serverError } from "../_lib/http.js";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return methodNotAllowed(res, ["GET"]);
  }

  try {
    const user = await requireAdmin(req, res);
    if (!user) {
      return undefined;
    }

    const path = String(req.query.path || "");
    if (path === "stats") {
      return json(res, 200, await buildDashboardStats());
    }
    if (path === "activities") {
      return json(res, 200, await buildRecentActivities());
    }
    if (path === "security-metrics") {
      return json(res, 200, await buildSecurityMetrics());
    }

    return json(res, 404, { message: "Route not found" });
  } catch (error) {
    return serverError(res, error, "Could not load dashboard data");
  }
}
