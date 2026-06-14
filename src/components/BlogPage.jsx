import { memo, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Bookmark,
  Calendar,
  Edit3,
  Eye,
  Filter,
  MessageSquare,
  Plus,
  Search,
  Share2,
  ShieldCheck,
  ThumbsUp,
  Trash2,
  X,
  TrendingUp,
} from "lucide-react";
import { blogAPI } from "../services/api";
import "./BlogPage.css";
import Navbar from "./Navbar";
import Footer from "./Footer";

const MetaRow = ({ author, authorInitial, date, readTime, views, compact = false }) => (
  <div className={`blog-meta-row ${compact ? "blog-meta-row--compact" : ""}`}>
    {author ? (
      <>
        <div className="blog-meta-row__author">
          <span className="blog-meta-row__avatar">{authorInitial}</span>
          <span>{author}</span>
        </div>
        <span className="blog-meta-row__dot" aria-hidden="true" />
      </>
    ) : null}

    <span className="blog-meta-row__item">
      <Calendar strokeWidth={1.9} />
      <span>{date}</span>
    </span>

    <span className="blog-meta-row__dot" aria-hidden="true" />
    <span>{readTime}</span>

    <span className="blog-meta-row__dot" aria-hidden="true" />
    <span className="blog-meta-row__item">
      <Eye strokeWidth={1.9} />
      <span>{views}</span>
    </span>
  </div>
);

const ImagePlaceholder = ({ badge, tone = "blue", compact = false }) => (
  <div className={`blog-image-placeholder ${compact ? "blog-image-placeholder--compact" : ""}`}>
    {badge ? <span className={`blog-image-placeholder__badge blog-image-placeholder__badge--${tone}`}>{badge}</span> : null}
    <div className="blog-image-placeholder__canvas" aria-hidden="true">
      <div className="blog-cyber-visual">
        <span className="blog-cyber-visual__line blog-cyber-visual__line--top" />
        <span className="blog-cyber-visual__line blog-cyber-visual__line--mid" />
        <span className="blog-cyber-visual__line blog-cyber-visual__line--bottom" />
        <ShieldCheck strokeWidth={1.8} />
      </div>
    </div>
  </div>
);

const emptyForm = {
  title: "",
  description: "",
  content: "",
  category: "web-security",
  tagsText: "",
  badge: "New",
};

const formatDate = (value) => {
  if (!value) return "Today";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Today"
    : date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
      });
};

const formatReadTime = (content = "") => {
  const words = String(content).trim().split(/\s+/).filter(Boolean).length;
  const minutes = Math.max(1, Math.round(words / 180));
  return `${minutes} min read`;
};

const buildTopics = (posts) => {
  const counts = new Map();
  posts.forEach((post) => {
    (post.tags || []).forEach((tag) => {
      counts.set(tag, (counts.get(tag) || 0) + 1);
    });
  });
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tag]) => `#${tag}`);
};

const BlogPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToAwareness,
  onNavigateToTools,
  isLoggedIn,
  userRole = "user",
}) => {
  const [activeCategory, setActiveCategory] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [subscribeEmail, setSubscribeEmail] = useState("");
  const [subscribeStatus, setSubscribeStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [blogData, setBlogData] = useState({
    featured: null,
    trending: [],
    categories: [],
    posts: [],
  });
  const [likeBusy, setLikeBusy] = useState(null);
  const [shareBusy, setShareBusy] = useState(null);
  const [commentDrafts, setCommentDrafts] = useState({});
  const [replyDrafts, setReplyDrafts] = useState({});
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorStatus, setEditorStatus] = useState("");
  const [editingPostId, setEditingPostId] = useState(null);
  const [editorForm, setEditorForm] = useState(emptyForm);

  const isAdmin = userRole === "admin";

  const loadPosts = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await blogAPI.getPosts();
      setBlogData(response);
    } catch (err) {
      setError(err.message || "Failed to load blog posts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPosts();
  }, []);

  const posts = useMemo(() => blogData.posts ?? [], [blogData.posts]);
  const featuredArticle = blogData.featured || posts[0] || null;

  const categories = useMemo(() => {
    const base = [{ id: "all", label: "All Posts", count: posts.length }];
    const categoryCounts = posts.reduce((acc, post) => {
      acc[post.category] = (acc[post.category] || 0) + 1;
      return acc;
    }, {});

    return base.concat(
      Object.entries(categoryCounts).map(([id, count]) => ({
        id,
        label: id.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
        count,
      })),
    );
  }, [posts]);

  const trendingTopics = useMemo(() => buildTopics(posts), [posts]);

  const trendingNowArticles = useMemo(() => {
    return [...posts]
      .sort((a, b) => (b.views + (b.likes || 0) * 4 + (b.shares || 0) * 2) - (a.views + (a.likes || 0) * 4 + (a.shares || 0) * 2))
      .slice(0, 4);
  }, [posts]);

  const filteredLatestArticles = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return posts.filter((article) => {
      const haystack = `${article.title} ${article.description} ${article.content} ${(article.tags || []).join(" ")}`.toLowerCase();
      const matchesSearch = !query || haystack.includes(query);
      const matchesCategory = activeCategory === "all" || article.category === activeCategory;
      return matchesSearch && matchesCategory;
    });
  }, [activeCategory, posts, searchQuery]);

  const openEditor = (post = null) => {
    if (post) {
      setEditingPostId(post.id);
      setEditorForm({
        title: post.title || "",
        description: post.description || "",
        content: post.content || "",
        category: post.category || "web-security",
        tagsText: (post.tags || []).join(", "),
        badge: post.badge || "New",
      });
    } else {
      setEditingPostId(null);
      setEditorForm(emptyForm);
    }

    setEditorStatus("");
    setEditorOpen(true);
  };

  const closeEditor = () => {
    setEditorOpen(false);
    setEditorStatus("");
  };

  const handleEditorSubmit = async () => {
    if (!editorForm.title.trim() || !editorForm.description.trim()) {
      setEditorStatus("Title and description are required.");
      return;
    }

    const payload = {
      title: editorForm.title.trim(),
      description: editorForm.description.trim(),
      content: editorForm.content.trim() || editorForm.description.trim(),
      category: editorForm.category,
      tags: editorForm.tagsText
        .split(",")
        .map((tag) => tag.trim())
        .filter(Boolean),
      badge: editorForm.badge.trim() || "New",
    };

    try {
      if (editingPostId) {
        await blogAPI.updatePost(editingPostId, payload);
        setEditorStatus("Post updated successfully.");
      } else {
        await blogAPI.createPost(payload);
        setEditorStatus("Post created successfully.");
      }
      await loadPosts();
      closeEditor();
    } catch (err) {
      setEditorStatus(err.message || "Unable to save post.");
    }
  };

  const handleDeletePost = async (id) => {
    try {
      await blogAPI.deletePost(id);
      await loadPosts();
    } catch (err) {
      setError(err.message || "Unable to delete post.");
    }
  };

  const handleLike = async (id) => {
    setLikeBusy(id);
    try {
      await blogAPI.toggleLike(id);
      await loadPosts();
    } catch (err) {
      setError(err.message || "Unable to update like count.");
    } finally {
      setLikeBusy(null);
    }
  };

  const handleShare = async (id) => {
    setShareBusy(id);
    try {
      const result = await blogAPI.sharePost(id);
      if (navigator.share) {
        const article = posts.find((item) => item.id === id);
        await navigator.share({
          title: article?.title || "Threat Hunters article",
          text: article?.description || "Cybersecurity insight from Threat Hunters",
          url: window.location.href,
        });
      }
      if (result?.shares !== undefined) {
        await loadPosts();
      }
    } catch (err) {
      setError(err.message || "Unable to share post.");
    } finally {
      setShareBusy(null);
    }
  };

  const handleCommentSubmit = async (postId) => {
    const text = (commentDrafts[postId] || "").trim();
    if (!text) {
      setError("Write a comment first.");
      return;
    }

    try {
      await blogAPI.addComment(postId, { text });
      setCommentDrafts((current) => ({ ...current, [postId]: "" }));
      await loadPosts();
    } catch (err) {
      setError(err.message || "Unable to add comment.");
    }
  };

  const handleReplySubmit = async (postId, commentId) => {
    const key = `${postId}:${commentId}`;
    const text = (replyDrafts[key] || "").trim();
    if (!text) {
      setError("Write a reply first.");
      return;
    }

    try {
      await blogAPI.addReply(postId, commentId, { text });
      setReplyDrafts((current) => ({ ...current, [key]: "" }));
      await loadPosts();
    } catch (err) {
      setError(err.message || "Unable to add reply.");
    }
  };

  const handleSubscribe = () => {
    const email = subscribeEmail.trim();
    if (!email || !email.includes("@") || !email.includes(".")) {
      setSubscribeStatus("Enter a valid email address.");
      return;
    }

    setSubscribeStatus("Subscribed successfully for this demo.");
    setSubscribeEmail("");
  };

  const renderPostCard = (article, compact = false) => {
    const readTime = formatReadTime(article.content || article.description || "");
    const commentsCount = (article.comments || []).reduce((sum, comment) => sum + 1 + (comment.replies?.length || 0), 0);

    return (
      <article key={article.id} className={compact ? "blog-trending-card" : "blog-list-card"}>
        <ImagePlaceholder badge={article.badge} tone={article.imageTone || "blue"} compact={compact} />

        <div className={compact ? "blog-trending-card__content" : "blog-list-card__content"}>
          <MetaRow
            author={article.author}
            authorInitial={article.authorInitial}
            date={formatDate(article.publishedAt)}
            readTime={readTime}
            views={`${Number(article.views || 0).toLocaleString()} views`}
            compact={compact}
          />
          <h3>{article.title}</h3>
          <p>{article.description}</p>

          {!compact && (
            <div className="blog-tag-row">
              {(article.tags || []).map((tag) => (
                <span key={tag} className="blog-tag-pill">
                  {tag}
                </span>
              ))}
            </div>
          )}

          <footer className={compact ? "blog-trending-card__footer" : "blog-list-card__footer"}>
            <button
              type="button"
              className="blog-link-button blog-link-button--small"
              onClick={() => handleLike(article.id)}
              disabled={likeBusy === article.id}
            >
              <ThumbsUp strokeWidth={1.9} />
              <span>{likeBusy === article.id ? "Saving..." : `Like ${article.likes || 0}`}</span>
            </button>

            <button
              type="button"
              className="blog-link-button blog-link-button--small"
              onClick={() => handleShare(article.id)}
              disabled={shareBusy === article.id}
            >
              <Share2 strokeWidth={1.9} />
              <span>{shareBusy === article.id ? "Sharing..." : `Share ${article.shares || 0}`}</span>
            </button>

            <button type="button" className="blog-link-button blog-link-button--small" aria-label="Comments">
              <MessageSquare strokeWidth={1.9} />
              <span>{commentsCount}</span>
            </button>

            <div className="blog-action-row">
              <button type="button" className="blog-icon-button" aria-label="Save article">
                <Bookmark strokeWidth={1.8} />
              </button>
              {isAdmin && !compact && (
                <>
                  <button type="button" className="blog-icon-button" aria-label="Edit article" onClick={() => openEditor(article)}>
                    <Edit3 strokeWidth={1.8} />
                  </button>
                  <button type="button" className="blog-icon-button" aria-label="Delete article" onClick={() => handleDeletePost(article.id)}>
                    <Trash2 strokeWidth={1.8} />
                  </button>
                </>
              )}
            </div>
          </footer>

          {!compact && (
            <div className="blog-comments">
              <div className="blog-comments__composer">
                <textarea
                  className="blog-comments__input"
                  rows={3}
                  placeholder={isLoggedIn ? "Write a comment..." : "Sign in to add comments"}
                  disabled={!isLoggedIn}
                  value={commentDrafts[article.id] || ""}
                  onChange={(event) =>
                    setCommentDrafts((current) => ({ ...current, [article.id]: event.target.value }))
                  }
                />
                <button
                  type="button"
                  className="blog-comments__button"
                  onClick={() => handleCommentSubmit(article.id)}
                  disabled={!isLoggedIn}
                >
                  Post Comment
                </button>
              </div>

              <div className="blog-comments__list">
                {(article.comments || []).map((comment) => {
                  const replyKey = `${article.id}:${comment.id}`;
                  return (
                    <div key={comment.id} className="blog-comment">
                      <div className="blog-comment__head">
                        <strong>{comment.author}</strong>
                        <span>{formatDate(comment.createdAt)}</span>
                      </div>
                      <p>{comment.text}</p>

                      <div className="blog-comment__replies">
                        {(comment.replies || []).map((reply) => (
                          <div key={reply.id} className="blog-comment blog-comment--reply">
                            <div className="blog-comment__head">
                              <strong>{reply.author}</strong>
                              <span>{formatDate(reply.createdAt)}</span>
                            </div>
                            <p>{reply.text}</p>
                          </div>
                        ))}
                      </div>

                      <div className="blog-comment__reply-box">
                        <input
                          type="text"
                          placeholder={isLoggedIn ? "Write a reply..." : "Sign in to reply"}
                          disabled={!isLoggedIn}
                          value={replyDrafts[replyKey] || ""}
                          onChange={(event) =>
                            setReplyDrafts((current) => ({
                              ...current,
                              [replyKey]: event.target.value,
                            }))
                          }
                        />
                        <button
                          type="button"
                          className="blog-comment__reply-button"
                          onClick={() => handleReplySubmit(article.id, comment.id)}
                          disabled={!isLoggedIn}
                        >
                          Reply
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </article>
    );
  };

  return (
    <div className="blog-page">
      {!isLoggedIn && (
        <Navbar
          onNavigateToSignUp={onNavigateToSignUp}
          onNavigateToHome={onNavigateToHome}
          onNavigateToAwareness={onNavigateToAwareness}
          onNavigateToTools={onNavigateToTools}
          currentPage="blog"
        />
      )}

      <div className="blog-shell">
        <aside className="blog-sidebar">
          <section className="blog-sidebar-card">
            <header className="blog-sidebar-card__header">
              <Filter strokeWidth={1.85} />
              <h3>Categories</h3>
            </header>

            <div className="blog-categories">
              {categories.map((category) => (
                <button
                  key={category.id}
                  type="button"
                  className={`blog-category-pill ${activeCategory === category.id ? "active" : ""}`}
                  onClick={() => setActiveCategory(category.id)}
                >
                  <span>{category.label}</span>
                  <span>{category.count}</span>
                </button>
              ))}
            </div>
          </section>

          <section className="blog-sidebar-card">
            <header className="blog-sidebar-card__header">
              <TrendingUp strokeWidth={1.85} />
              <h3>Trending Topics</h3>
            </header>

            <div className="blog-topic-grid">
              {trendingTopics.map((topic) => (
                <span key={topic} className="blog-topic-pill">
                  {topic}
                </span>
              ))}
            </div>
          </section>

          {isAdmin && (
            <section className="blog-sidebar-card blog-sidebar-card--subscribe">
              <h3>Blog Editor</h3>
              <p>Write and publish a new post or open an existing one for editing.</p>
              <button type="button" className="blog-subscribe-button" onClick={() => openEditor()}>
                <Plus size={16} />
                Create Post
              </button>
            </section>
          )}

          <section className="blog-sidebar-card blog-sidebar-card--subscribe">
            <h3>Stay Updated</h3>
            <p>Get weekly security insights delivered to your inbox</p>
            <input
              type="email"
              placeholder="Your email"
              className="blog-subscribe-input"
              value={subscribeEmail}
              onChange={(event) => {
                setSubscribeEmail(event.target.value);
                setSubscribeStatus("");
              }}
            />
            <button type="button" className="blog-subscribe-button" onClick={handleSubscribe}>
              Subscribe
            </button>
            {subscribeStatus && <p className="blog-subscribe-status">{subscribeStatus}</p>}
          </section>
        </aside>

        <main className="blog-main">
          <header className="blog-hero">
            <h1>Security Intelligence Hub</h1>
            <p>
              Expert insights, latest threats, and actionable security advice from industry leaders and practitioners
            </p>

            <label className="blog-search" aria-label="Search articles, topics, or keywords">
              <Search strokeWidth={2} />
              <input
                type="text"
                placeholder="Search articles, topics, or keywords..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
              />
            </label>
          </header>

          {error && <div className="blog-empty-state">{error}</div>}

          {loading ? (
            <div className="blog-empty-state">Loading blog posts...</div>
          ) : (
            <>
              <section className="blog-section">
                <header className="blog-section__label">
                  <TrendingUp strokeWidth={1.85} />
                  <h2>Featured Article</h2>
                </header>

                {featuredArticle ? (
                  <article className="blog-featured-card">
                    <ImagePlaceholder badge={featuredArticle.badge} tone={featuredArticle.imageTone || "blue"} />

                    <div className="blog-featured-card__content">
                      <MetaRow
                        author={featuredArticle.author}
                        authorInitial={featuredArticle.authorInitial}
                        date={formatDate(featuredArticle.publishedAt)}
                        readTime={formatReadTime(featuredArticle.content || featuredArticle.description)}
                        views={`${Number(featuredArticle.views || 0).toLocaleString()} views`}
                      />

                      <h3>{featuredArticle.title}</h3>
                      <p>{featuredArticle.description}</p>

                      <div className="blog-tag-row">
                        {(featuredArticle.tags || []).map((tag) => (
                          <span key={tag} className="blog-tag-pill">
                            {tag}
                          </span>
                        ))}
                      </div>

                      <footer className="blog-featured-card__footer">
                        <button type="button" className="blog-link-button">
                          <span>Read Full Article</span>
                          <ArrowRight strokeWidth={1.9} />
                        </button>

                        <div className="blog-action-row">
                          <button
                            type="button"
                            className="blog-icon-button"
                            aria-label="Save featured article"
                            onClick={() => handleLike(featuredArticle.id)}
                          >
                            <ThumbsUp strokeWidth={1.8} />
                          </button>
                          <button
                            type="button"
                            className="blog-icon-button"
                            aria-label="Share featured article"
                            onClick={() => handleShare(featuredArticle.id)}
                          >
                            <Share2 strokeWidth={1.8} />
                          </button>
                        </div>
                      </footer>
                    </div>
                  </article>
                ) : (
                  <div className="blog-empty-state">No featured article yet.</div>
                )}
              </section>

              <section className="blog-section">
                <header className="blog-section__label">
                  <TrendingUp strokeWidth={1.85} />
                  <h2>Trending Now</h2>
                </header>

                <div className="blog-trending-grid">
                  {trendingNowArticles.map((article) => renderPostCard(article, true))}
                </div>
              </section>

              <section className="blog-list">
                {filteredLatestArticles.map((article) => renderPostCard(article, false))}
                {!filteredLatestArticles.length && (
                  <div className="blog-empty-state">No articles match this filter.</div>
                )}
              </section>

              <div className="blog-load-more">
                <button type="button" className="blog-load-more__button" onClick={loadPosts}>
                  <span>Refresh Articles</span>
                  <ArrowRight strokeWidth={1.9} />
                </button>
              </div>
            </>
          )}
        </main>
      </div>

      {editorOpen && isAdmin && (
        <div className="blog-editor-backdrop" role="dialog" aria-modal="true" aria-label="Blog editor">
          <div className="blog-editor-panel">
            <header className="blog-editor-panel__head">
              <div>
                <p className="blog-editor-panel__kicker">{editingPostId ? "Edit Post" : "Create Post"}</p>
                <h2>{editingPostId ? "Update blog entry" : "Publish a new security article"}</h2>
              </div>
              <button type="button" className="blog-icon-button" onClick={closeEditor} aria-label="Close editor">
                <X />
              </button>
            </header>

            <div className="blog-editor-grid">
              <label className="blog-editor-field">
                <span>Title</span>
                <input
                  value={editorForm.title}
                  onChange={(event) => setEditorForm((current) => ({ ...current, title: event.target.value }))}
                />
              </label>
              <label className="blog-editor-field">
                <span>Category</span>
                <input
                  value={editorForm.category}
                  onChange={(event) => setEditorForm((current) => ({ ...current, category: event.target.value }))}
                />
              </label>
              <label className="blog-editor-field blog-editor-field--full">
                <span>Description</span>
                <textarea
                  rows={3}
                  value={editorForm.description}
                  onChange={(event) => setEditorForm((current) => ({ ...current, description: event.target.value }))}
                />
              </label>
              <label className="blog-editor-field blog-editor-field--full">
                <span>Content</span>
                <textarea
                  rows={6}
                  value={editorForm.content}
                  onChange={(event) => setEditorForm((current) => ({ ...current, content: event.target.value }))}
                />
              </label>
              <label className="blog-editor-field blog-editor-field--full">
                <span>Tags</span>
                <input
                  value={editorForm.tagsText}
                  onChange={(event) => setEditorForm((current) => ({ ...current, tagsText: event.target.value }))}
                  placeholder="OWASP, Zero Trust, API Security"
                />
              </label>
              <label className="blog-editor-field">
                <span>Badge</span>
                <input
                  value={editorForm.badge}
                  onChange={(event) => setEditorForm((current) => ({ ...current, badge: event.target.value }))}
                />
              </label>
            </div>

            {editorStatus && <p className="blog-editor-status">{editorStatus}</p>}

            <footer className="blog-editor-actions">
              <button type="button" className="blog-comments__button" onClick={handleEditorSubmit}>
                {editingPostId ? "Save Changes" : "Publish Post"}
              </button>
            </footer>
          </div>
        </div>
      )}

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(BlogPage);
