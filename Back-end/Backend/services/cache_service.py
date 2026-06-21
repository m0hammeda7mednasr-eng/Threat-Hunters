from datetime import datetime, timedelta
from database.db import mongo


def get_cached_data(cache_key, fetch_function, cache_hours=6):

    db = mongo.db

    cache = db.security_cache.find_one({
        "_id": cache_key
    })

    if cache:

        last_updated = cache.get("last_updated")

        if last_updated:

            age = datetime.utcnow() - last_updated

            if age < timedelta(hours=cache_hours):
                return cache["data"]

    fresh_data = fetch_function()

    db.security_cache.update_one(
        {"_id": cache_key},
        {
            "$set": {
                "data": fresh_data,
                "last_updated": datetime.utcnow()
            }
        },
        upsert=True
    )

    return fresh_data