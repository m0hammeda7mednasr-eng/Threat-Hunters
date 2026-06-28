export async function readJson(req) {
  if (req.body && typeof req.body === "object") {
    return req.body;
  }

  if (typeof req.body === "string" && req.body.trim()) {
    return JSON.parse(req.body);
  }

  return {};
}

export function json(res, status, payload) {
  res.status(status).setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(payload));
}

export function methodNotAllowed(res, allowed) {
  res.setHeader("Allow", allowed.join(", "));
  return json(res, 405, { message: "Method not allowed" });
}

export function serverError(res, error, fallbackMessage) {
  return json(res, 500, {
    message: fallbackMessage,
    error: error instanceof Error ? error.message : String(error),
  });
}
