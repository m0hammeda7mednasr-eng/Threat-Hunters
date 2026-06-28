/* global process */

import { MongoClient } from "mongodb";

let cachedClientPromise;

function resolveMongoUri() {
  const uri = String(process.env.MONGO_URI || "").trim();
  if (!uri) {
    throw new Error("MONGO_URI is not configured");
  }
  return uri;
}

export async function getMongoClient() {
  if (!cachedClientPromise) {
    cachedClientPromise = MongoClient.connect(resolveMongoUri());
  }
  return cachedClientPromise;
}

export async function getDb() {
  const client = await getMongoClient();
  const explicitName = String(process.env.MONGO_DB_NAME || "").trim();
  if (explicitName) {
    return client.db(explicitName);
  }
  return client.db();
}
