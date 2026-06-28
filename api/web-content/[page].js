import { requireAdmin } from "../_lib/auth.js";
import { DEFAULT_CONTENT, isLegacyAwarenessContent, normalizeAwarenessContent } from "../_lib/adminDefaults.js";
import { json, methodNotAllowed, readJson, serverError } from "../_lib/http.js";
import { getDb } from "../_lib/mongo.js";

async function getPageContent(db, page) {
  const record = await db.collection("web_content").findOne({ page }, { projection: { _id: 0, page: 0 } });
  const content = record || DEFAULT_CONTENT[page] || {};
  if (page === "awareness") {
    if (isLegacyAwarenessContent(content)) {
      return normalizeAwarenessContent(DEFAULT_CONTENT.awareness);
    }
    return normalizeAwarenessContent(content);
  }
  return content;
}

export default async function handler(req, res) {
  if (req.method !== "PUT") {
    return methodNotAllowed(res, ["PUT"]);
  }

  try {
    const user = await requireAdmin(req, res);
    if (!user) {
      return undefined;
    }

    const page = String(req.query.page || "");
    if (!(page in DEFAULT_CONTENT)) {
      return json(res, 404, { message: "Unknown content page" });
    }

    const payload = await readJson(req);
    const db = await getDb();
    await db.collection("web_content").updateOne(
      { page },
      { $set: { ...payload, page } },
      { upsert: true },
    );

    return json(res, 200, await getPageContent(db, page));
  } catch (error) {
    return serverError(res, error, "Could not update website content");
  }
}
