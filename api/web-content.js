import { DEFAULT_CONTENT, isLegacyAwarenessContent, normalizeAwarenessContent } from "./_lib/adminDefaults.js";
import { json, methodNotAllowed, serverError } from "./_lib/http.js";
import { getDb } from "./_lib/mongo.js";

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
  if (req.method !== "GET") {
    return methodNotAllowed(res, ["GET"]);
  }

  try {
    const db = await getDb();
    const entries = await Promise.all(
      Object.keys(DEFAULT_CONTENT).map(async (page) => [page, await getPageContent(db, page)]),
    );
    return json(res, 200, Object.fromEntries(entries));
  } catch (error) {
    return serverError(res, error, "Could not load website content");
  }
}
