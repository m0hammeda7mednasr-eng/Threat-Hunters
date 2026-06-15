import feedparser


def get_security_news():

    feed_url = "https://feeds.feedburner.com/TheHackersNews"

    feed = feedparser.parse(feed_url)

    results = []

    for entry in feed.entries[:10]:

        results.append({
            "title": entry.title,
            "summary": entry.summary,
            "link": entry.link,
            "published": entry.published
        })

    return results