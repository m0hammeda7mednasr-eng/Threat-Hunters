from types import SimpleNamespace
from copy import deepcopy
from bson import ObjectId


class FakeCursor:
    def __init__(self, documents):
        self._documents = list(documents)

    def sort(self, *args, **kwargs):
        return self

    def skip(self, amount):
        self._documents = self._documents[amount:]
        return self

    def limit(self, amount):
        self._documents = self._documents[:amount]
        return self

    def __iter__(self):
        return iter(self._documents)


class InMemoryCollection:
    def __init__(self, documents=None):
        self.documents = [deepcopy(doc) for doc in (documents or [])]

    @staticmethod
    def _matches(document, query):
        for key, expected in query.items():
            if key == "$or":
                if not any(InMemoryCollection._matches(document, clause) for clause in expected):
                    return False
                continue

            actual = document.get(key)
            if isinstance(expected, dict) and "$ne" in expected:
                if actual == expected["$ne"]:
                    return False
                continue

            if actual != expected:
                return False

        return True

    def find_one(self, query):
        for document in self.documents:
            if self._matches(document, query):
                return document
        return None

    def find(self, query):
        return FakeCursor([doc for doc in self.documents if self._matches(doc, query)])

    def count_documents(self, query):
        return len([doc for doc in self.documents if self._matches(doc, query)])

    def insert_one(self, document):
        doc = deepcopy(document)
        doc.setdefault("_id", ObjectId())
        self.documents.append(doc)
        return SimpleNamespace(inserted_id=doc["_id"])

    def update_one(self, query, update):
        document = self.find_one(query)
        if not document:
            return SimpleNamespace(matched_count=0, modified_count=0)

        if "$set" in update:
            document.update(deepcopy(update["$set"]))

        if "$inc" in update:
            for key, value in update["$inc"].items():
                document[key] = document.get(key, 0) + value

        if "$unset" in update:
            for key in update["$unset"].keys():
                document.pop(key, None)

        return SimpleNamespace(matched_count=1, modified_count=1)

    def delete_one(self, query):
        for index, document in enumerate(self.documents):
            if self._matches(document, query):
                del self.documents[index]
                return SimpleNamespace(deleted_count=1)
        return SimpleNamespace(deleted_count=0)

    def delete_many(self, query):
        before = len(self.documents)
        self.documents = [doc for doc in self.documents if not self._matches(doc, query)]
        return SimpleNamespace(deleted_count=before - len(self.documents))


def build_fake_db(**collections):
    defaults = {
        "blogs": InMemoryCollection(),
        "comments": InMemoryCollection(),
        "likes": InMemoryCollection(),
        "blog_views": InMemoryCollection(),
        "users": InMemoryCollection(),
        "password_reset_tokens": InMemoryCollection(),
    }
    defaults.update(collections)
    return SimpleNamespace(**defaults)
