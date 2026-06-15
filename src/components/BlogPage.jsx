import { memo, useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Bookmark,
  Calendar,
  Edit3,
  Eye,
  EyeOff,
  Filter,
  MessageSquare,
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

const emptyComposer = {
  title: "",
  description: "",
  content: "",
  category: "web-security",
  tagsText: "",
  badge: "New",
  imageUrl: "",
  imageName: "",
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

const normalizePosts = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.posts)) return payload.posts;
  return [];
};

const normalizeComments = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.comments)) return payload.comments;
  return [];
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
    .map(([tag, count]) => ({
      tag,
      label: `#${tag}`,
      count,
    }));
};

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

const PostImage = ({ badge, tone = "blue", compact = false, imageUrl = "", alt = "Post preview" }) => {
  if (imageUrl) {
    return (
      <div className={`blog-image-placeholder blog-image-placeholder--photo ${compact ? "blog-image-placeholder--compact" : ""}`}>
        {badge ? <span className={`blog-image-placeholder__badge blog-image-placeholder__badge--${tone}`}>{badge}</span> : null}
        <img className="blog-post-image" src={imageUrl} alt={alt} />
      </div>
    );
  }

  return <ImagePlaceholder badge={badge} tone={tone} compact={compact} />;
};

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

const BlogPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToAwareness,
  onNavigateToTools,
  isLoggedIn,
  userRole = "user",
}) => {
  const [posts, setPosts] = useState([]);
  const [selectedPostId, setSelectedPostId] = useState("");
  const [selectedPost, setSelectedPost] = useState(null);
  const [selectedComments, setSelectedComments] = useState([]);
  const [isPostModalOpen, setIsPostModalOpen] = useState(false);
  const [isComposerModalOpen, setIsComposerModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState("all");
  const [activeTag, setActiveTag] = useState("all");
  const [subscribeEmail, setSubscribeEmail] = useState("");
  const [subscribeStatus, setSubscribeStatus] = useState("");
  const [composerMode, setComposerMode] = useState("create");
  const [editingPostId, setEditingPostId] = useState("");
  const [composer, setComposer] = useState(emptyComposer);
  const [composerStatus, setComposerStatus] = useState("");
  const [commentDraft, setCommentDraft] = useState("");
  const [replyDrafts, setReplyDrafts] = useState({});
  const [busyAction, setBusyAction] = useState({ type: "", id: "" });

  const isAdmin = userRole === "admin";
  const topics = useMemo(() => buildTopics(posts), [posts]);

  const categories = useMemo(() => {
    const counts = posts.reduce((acc, post) => {
      acc[post.category] = (acc[post.category] || 0) + 1;
      return acc;
    }, {});

    return [
      { id: "all", label: "All Posts", count: posts.length },
      ...Object.entries(counts).map(([id, count]) => ({
        id,
        label: id.replace(/-/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()),
        count,
      })),
    ];
  }, [posts]);

  const filteredPosts = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return posts.filter((post) => {
      const haystack = `${post.title} ${post.description || ""} ${post.content || ""} ${(post.tags || []).join(" ")}`.toLowerCase();
      const matchesSearch = !query || haystack.includes(query);
      const matchesCategory = activeCategory === "all" || post.category === activeCategory;
      const matchesTag = activeTag === "all" || (post.tags || []).includes(activeTag);
      return matchesSearch && matchesCategory && matchesTag;
    });
  }, [activeCategory, activeTag, posts, searchQuery]);

  const trendingPosts = useMemo(() => {
    return [...posts]
      .sort((a, b) => (b.views + (b.likes || 0) * 4 + (b.shares || 0) * 2) - (a.views + (a.likes || 0) * 4 + (a.shares || 0) * 2))
      .slice(0, 4);
  }, [posts]);

  const loadPostDetail = useCallback(async (postId) => {
    if (!postId) return;
    setDetailLoading(true);
    try {
      const [postPayload, commentsPayload] = await Promise.all([
        blogAPI.getPost(postId),
        blogAPI.getComments(postId).catch(() => []),
      ]);

      const detail = Array.isArray(postPayload) ? postPayload[0] : postPayload;
      setSelectedPost(detail || null);
      setSelectedComments(normalizeComments(commentsPayload));
    } catch (err) {
      setError(err.message || "Failed to load post details.");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const loadPosts = useCallback(async (preferredId = "") => {
    setLoading(true);
    setError("");
    try {
      const response = await blogAPI.getPosts({ includeHidden: isAdmin });
      const nextPosts = normalizePosts(response);
      setPosts(nextPosts);
      const nextSelectedId = preferredId || nextPosts[0]?.id || "";
      setSelectedPostId(nextSelectedId);
      if (!nextSelectedId) {
        setSelectedPost(null);
        setSelectedComments([]);
      }
    } catch (err) {
      setError(err.message || "Failed to load blog posts.");
    } finally {
      setLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    loadPosts();
  }, [loadPosts]);

  useEffect(() => {
    if (selectedPostId) {
      loadPostDetail(selectedPostId);
    }
  }, [selectedPostId, loadPostDetail]);

  useEffect(() => {
    if (!isPostModalOpen && !isComposerModalOpen) return undefined;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleEscape = (event) => {
      if (event.key === "Escape") {
        setIsPostModalOpen(false);
        setIsComposerModalOpen(false);
      }
    };

    window.addEventListener("keydown", handleEscape);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleEscape);
    };
  }, [isPostModalOpen, isComposerModalOpen]);

  useEffect(() => {
    if (!posts.length) {
      return;
    }
    if (!selectedPostId || !posts.some((post) => post.id === selectedPostId)) {
      setSelectedPostId(posts[0].id);
    }
  }, [posts, selectedPostId]);

  useEffect(() => {
    if (!selectedPost || composerMode !== "edit") {
      return;
    }

    setComposer({
      title: selectedPost.title || "",
      description: selectedPost.description || "",
      content: selectedPost.content || "",
      category: selectedPost.category || "web-security",
      tagsText: (selectedPost.tags || []).join(", "),
      badge: selectedPost.badge || "New",
      imageUrl: selectedPost.imageUrl || "",
      imageName: selectedPost.imageName || "",
    });
  }, [composerMode, selectedPost]);

  const openCreateMode = () => {
    setComposerMode("create");
    setEditingPostId("");
    setComposer(emptyComposer);
    setComposerStatus("");
    setIsPostModalOpen(false);
    setIsComposerModalOpen(true);
  };

  const openEditMode = (post = selectedPost) => {
    if (!post) return;
    setComposerMode("edit");
    setEditingPostId(post.id);
    setComposer({
      title: post.title || "",
      description: post.description || "",
      content: post.content || "",
      category: post.category || "web-security",
      tagsText: (post.tags || []).join(", "),
      badge: post.badge || "New",
      imageUrl: post.imageUrl || "",
      imageName: post.imageName || "",
    });
    setComposerStatus("");
    setIsPostModalOpen(false);
    setIsComposerModalOpen(true);
  };

  const handleEditPost = (post) => {
    setSelectedPostId(post.id);
    setSelectedPost(post);
    openEditMode(post);
  };

  const handleComposerImageChange = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      setComposer((current) => ({
        ...current,
        imageUrl: typeof reader.result === "string" ? reader.result : "",
        imageName: file.name,
      }));
    };
    reader.readAsDataURL(file);
  };

  const closeComposerModal = () => {
    setIsComposerModalOpen(false);
  };

  const submitComposer = async () => {
    if (!composer.title.trim() || !composer.description.trim() || !composer.content.trim()) {
      setComposerStatus("Fill title, description, and content first.");
      return;
    }

    const payload = {
      title: composer.title.trim(),
      description: composer.description.trim(),
      content: composer.content.trim(),
      category: composer.category.trim() || "web-security",
      tags: composer.tagsText
        .split(",")
        .map((tag) => tag.trim())
        .filter(Boolean),
      badge: composer.badge.trim() || "New",
      imageUrl: composer.imageUrl.trim(),
      imageName: composer.imageName.trim(),
    };

    try {
      setComposerStatus(composerMode === "edit" ? "Updating post..." : "Publishing post...");
      const result = composerMode === "edit" && editingPostId
        ? await blogAPI.updatePost(editingPostId, payload)
        : await blogAPI.createPost(payload);

      const nextId = result?.id || result?.blog_id || editingPostId;
      await loadPosts(nextId);
      setComposerStatus(composerMode === "edit" ? "Post updated successfully." : "Post published successfully.");
      if (composerMode !== "edit") {
        setComposer(emptyComposer);
      }
      setSelectedPostId(nextId);
      setIsComposerModalOpen(false);
      setIsPostModalOpen(true);
      await loadPostDetail(nextId);
    } catch (err) {
      setComposerStatus(err.message || "Unable to save post.");
    }
  };

  const handleDeletePost = async (id) => {
    try {
      await blogAPI.deletePost(id);
      setComposerMode("create");
      setEditingPostId("");
      await loadPosts();
    } catch (err) {
      setError(err.message || "Unable to delete post.");
    }
  };

  const handleTogglePostStatus = async (post) => {
    if (!post?.id) return;
    const nextStatus = post.status === "hidden" ? "published" : "hidden";

    setBusyAction({ type: "status", id: post.id });
    try {
      await blogAPI.setPostStatus(post.id, nextStatus);
      await loadPosts(post.id);
      setComposerStatus(nextStatus === "hidden" ? "Post hidden from public blog." : "Post published again.");
    } catch (err) {
      setError(err.message || "Unable to update post visibility.");
    } finally {
      setBusyAction({ type: "", id: "" });
    }
  };

  const handleSelectPost = (postId) => {
    setSelectedPostId(postId);
    setIsPostModalOpen(true);
    setCommentDraft("");
    setReplyDrafts({});
    setError("");
  };

  const closePostModal = () => {
    setIsPostModalOpen(false);
  };

  const handleSelectTag = (tag) => {
    setActiveTag((current) => (current === tag ? "all" : tag));
  };

  const handleLike = async (postId) => {
    setBusyAction({ type: "like", id: postId });
    try {
      await blogAPI.toggleLike(postId);
      await loadPosts(postId);
    } catch (err) {
      setError(err.message || "Unable to update like count.");
    } finally {
      setBusyAction({ type: "", id: "" });
    }
  };

  const handleShare = async (postId) => {
    setBusyAction({ type: "share", id: postId });
    try {
      await blogAPI.sharePost(postId);
      await loadPosts(postId);
      const article = posts.find((item) => item.id === postId);
      if (navigator.share && article) {
        await navigator.share({
          title: article.title,
          text: article.description || article.content || "Threat Hunters article",
          url: window.location.href,
        });
      }
    } catch (err) {
      setError(err.message || "Unable to share post.");
    } finally {
      setBusyAction({ type: "", id: "" });
    }
  };

  const handleCommentSubmit = async () => {
    if (!commentDraft.trim()) {
      setError("Write a comment first.");
      return;
    }

    try {
      await blogAPI.addComment(selectedPostId, { content: commentDraft.trim() });
      setCommentDraft("");
      await loadPostDetail(selectedPostId);
      await loadPosts(selectedPostId);
    } catch (err) {
      setError(err.message || "Unable to add comment.");
    }
  };

  const handleReplySubmit = async (commentId) => {
    const key = `${selectedPostId}:${commentId}`;
    const text = (replyDrafts[key] || "").trim();
    if (!text) {
      setError("Write a reply first.");
      return;
    }

    try {
      await blogAPI.addReply(selectedPostId, commentId, { content: text });
      setReplyDrafts((current) => ({ ...current, [key]: "" }));
      await loadPostDetail(selectedPostId);
      await loadPosts(selectedPostId);
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

  const currentPost = selectedPost || posts.find((post) => post.id === selectedPostId) || null;

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
              <button
                type="button"
                className={`blog-topic-pill ${activeTag === "all" ? "active" : ""}`}
                onClick={() => setActiveTag("all")}
              >
                <span>All Topics</span>
              </button>
              {topics.map((topic) => (
                <button
                  key={topic.tag}
                  type="button"
                  className={`blog-topic-pill ${activeTag === topic.tag ? "active" : ""}`}
                  onClick={() => handleSelectTag(topic.tag)}
                  title={`Filter by #${topic.tag}`}
                >
                  <span>{topic.label}</span>
                  <span>{topic.count}</span>
                </button>
              ))}
            </div>
          </section>

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

            <div className="blog-hero-row">
              <label className="blog-search" aria-label="Search articles, topics, or keywords">
                <Search strokeWidth={2} />
                <input
                  type="text"
                  placeholder="Search articles, topics, or keywords..."
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                />
                </label>

              {isLoggedIn && (
                <div className="blog-hero-actions">
                  <button type="button" className="blog-mini-toggle active" onClick={openCreateMode}>
                    New Post
                  </button>
                </div>
              )}
            </div>
          </header>

          {loading && !posts.length ? (
            <div className="blog-empty-state">Loading blog posts...</div>
          ) : null}

          {error && <div className="blog-empty-state">{error}</div>}

          <section className="blog-section">
            <div className="blog-section__label">
              <TrendingUp strokeWidth={1.85} />
              <h2>Trending Now</h2>
            </div>

            <div className="blog-trending-grid">
              {trendingPosts.map((article) => (
                <article
                  key={article.id}
                  className={`blog-trending-card ${selectedPostId === article.id ? "is-selected" : ""}`}
                  onClick={() => handleSelectPost(article.id)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      handleSelectPost(article.id);
                    }
                  }}
                  role="button"
                  tabIndex={0}
                >
                  <PostImage badge={article.badge} tone={article.imageTone || "blue"} imageUrl={article.imageUrl || ""} compact />
                  <div className="blog-trending-card__content">
                    <MetaRow
                      author={article.author}
                      authorInitial={article.authorInitial}
                      date={formatDate(article.publishedAt)}
                      readTime={formatReadTime(article.content || article.description)}
                      views={`${Number(article.views || 0).toLocaleString()} views`}
                      compact
                    />
                    <h3>{article.title}</h3>

                    <footer className="blog-trending-card__footer">
                      <span className="blog-trending-card__views">
                        <Eye strokeWidth={1.9} />
                        <span>{article.views}</span>
                      </span>
                      <div className="blog-card-actions">
                        {isAdmin && (
                          <button
                            type="button"
                            className="blog-icon-button blog-icon-button--ghost"
                            aria-label="Edit post"
                            onClick={(event) => {
                              event.stopPropagation();
                              handleEditPost(article);
                            }}
                          >
                            <Edit3 strokeWidth={1.8} />
                          </button>
                        )}
                        <button
                          type="button"
                          className="blog-icon-button blog-icon-button--ghost"
                          aria-label="Select post"
                          onClick={(event) => {
                            event.stopPropagation();
                            handleSelectPost(article.id);
                          }}
                        >
                          <ArrowRight strokeWidth={1.8} />
                        </button>
                      </div>
                    </footer>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="blog-list">
            {filteredPosts.map((article) => (
              <article
                key={article.id}
                className={`blog-list-card ${selectedPostId === article.id ? "is-selected" : ""} ${(article.status || "published") === "hidden" ? "is-hidden-post" : ""}`}
                onClick={() => handleSelectPost(article.id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    handleSelectPost(article.id);
                  }
                }}
                role="button"
                tabIndex={0}
              >
                <div className="blog-list-card__media">
                  <PostImage badge={article.badge} tone={article.imageTone || "blue"} imageUrl={article.imageUrl || ""} compact />
                </div>

                <div className="blog-list-card__content">
                  <div className="blog-list-card__main">
                    <MetaRow
                      author={article.author}
                      authorInitial={article.authorInitial}
                      date={formatDate(article.publishedAt)}
                      readTime={formatReadTime(article.content || article.description)}
                      views={`${Number(article.views || 0).toLocaleString()} views`}
                    />

                    <h3>{article.title}</h3>
                    {isAdmin && (
                      <span className={`blog-status-pill blog-status-pill--compact is-${article.status || "published"}`}>
                        {(article.status || "published") === "hidden" ? "Hidden" : "Published"}
                      </span>
                    )}
                    <p>{article.description || article.content}</p>

                    <div className="blog-tag-row">
                      {(article.tags || []).map((tag) => (
                        <button
                          key={tag}
                          type="button"
                          className={`blog-tag-pill ${activeTag === tag ? "active" : ""}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            handleSelectTag(tag);
                          }}
                        >
                          {tag}
                        </button>
                      ))}
                    </div>
                  </div>

                  <footer className="blog-list-card__footer">
                    <div className="blog-card-actions">
                      {isAdmin && (
                        <button
                          type="button"
                          className="blog-link-button blog-link-button--small"
                          onClick={(event) => {
                            event.stopPropagation();
                            handleEditPost(article);
                          }}
                        >
                          <Edit3 strokeWidth={1.9} />
                          <span>Edit Post</span>
                        </button>
                      )}
                      <button
                        type="button"
                        className="blog-link-button blog-link-button--small"
                        onClick={(event) => {
                          event.stopPropagation();
                          handleSelectPost(article.id);
                        }}
                      >
                        <span>View details</span>
                        <ArrowRight strokeWidth={1.9} />
                      </button>
                    </div>

                    <div className="blog-action-row">
                      {isAdmin && (
                        <>
                          <button
                            type="button"
                            className="blog-icon-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              handleTogglePostStatus(article);
                            }}
                            disabled={busyAction.type === "status" && busyAction.id === article.id}
                            aria-label={(article.status || "published") === "hidden" ? "Publish post" : "Hide post"}
                          >
                            {(article.status || "published") === "hidden" ? <Eye strokeWidth={1.8} /> : <EyeOff strokeWidth={1.8} />}
                          </button>
                          <button
                            type="button"
                            className="blog-icon-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              handleDeletePost(article.id);
                            }}
                            aria-label="Delete post"
                          >
                            <Trash2 strokeWidth={1.8} />
                          </button>
                        </>
                      )}
                      <button
                        type="button"
                        className="blog-icon-button"
                        aria-label="Save article"
                        onClick={(event) => event.stopPropagation()}
                      >
                        <Bookmark strokeWidth={1.8} />
                      </button>
                    </div>
                  </footer>
                </div>
              </article>
            ))}

            {!filteredPosts.length && <div className="blog-empty-state">No articles match this filter.</div>}
          </section>
        </main>
      </div>

      {isPostModalOpen && currentPost && (
        <div className="blog-post-modal" role="presentation" onClick={closePostModal}>
          <section
            className="blog-post-modal__dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="blog-post-modal-title"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="blog-post-modal__header">
              <div>
                <p className="blog-post-modal__eyebrow">Post Details</p>
                <h2 id="blog-post-modal-title">{currentPost.title}</h2>
              </div>

              <div className="blog-post-modal__header-actions">
                {isAdmin && (
                  <button
                    type="button"
                    className="blog-mini-toggle active"
                    onClick={() => handleEditPost(currentPost)}
                  >
                    Edit Post
                  </button>
                )}
                <button type="button" className="blog-post-modal__close" onClick={closePostModal} aria-label="Close post details">
                  <X strokeWidth={2} />
                </button>
              </div>
            </header>

            <div className="blog-post-modal__body">
              <article className="blog-detail-card blog-detail-card--modal">
                <PostImage badge={currentPost.badge} tone={currentPost.imageTone || "blue"} imageUrl={currentPost.imageUrl || ""} />

                <div className="blog-detail-card__content">
                  <MetaRow
                    author={currentPost.author}
                    authorInitial={currentPost.authorInitial}
                    date={formatDate(currentPost.publishedAt)}
                    readTime={formatReadTime(currentPost.content || currentPost.description)}
                    views={`${Number(currentPost.views || 0).toLocaleString()} views`}
                  />

                  {isAdmin && (
                    <span className={`blog-status-pill is-${currentPost.status || "published"}`}>
                      {(currentPost.status || "published") === "hidden" ? "Hidden" : "Published"}
                    </span>
                  )}

                  <p className="blog-post-modal__summary">{currentPost.description || currentPost.content}</p>

                  <div className="blog-tag-row">
                    {(currentPost.tags || []).map((tag) => (
                      <button
                        key={tag}
                        type="button"
                        className={`blog-tag-pill ${activeTag === tag ? "active" : ""}`}
                        onClick={() => handleSelectTag(tag)}
                      >
                        {tag}
                      </button>
                    ))}
                  </div>

                  <div className="blog-detail-stats">
                    <span>{currentPost.likes || 0} likes</span>
                    <span>{currentPost.shares || 0} shares</span>
                    <span>{currentPost.comments_count || selectedComments.length || 0} comments</span>
                  </div>

                  <div className="blog-detail-body">
                    <p>{currentPost.content}</p>
                  </div>

                  <footer className="blog-featured-card__footer">
                    <div className="blog-action-row">
                      <button
                        type="button"
                        className="blog-icon-button"
                        onClick={() => handleLike(currentPost.id)}
                        disabled={busyAction.type === "like" && busyAction.id === currentPost.id}
                        aria-label="Like post"
                      >
                        <ThumbsUp strokeWidth={1.8} />
                      </button>
                      <button
                        type="button"
                        className="blog-icon-button"
                        onClick={() => handleShare(currentPost.id)}
                        disabled={busyAction.type === "share" && busyAction.id === currentPost.id}
                        aria-label="Share post"
                      >
                        <Share2 strokeWidth={1.8} />
                      </button>
                      <button type="button" className="blog-icon-button" onClick={() => handleSelectPost(currentPost.id)} aria-label="Keep this post open">
                        <Bookmark strokeWidth={1.8} />
                      </button>
                      {isAdmin && (
                        <>
                          <button
                            type="button"
                            className="blog-icon-button"
                            onClick={() => handleTogglePostStatus(currentPost)}
                            disabled={busyAction.type === "status" && busyAction.id === currentPost.id}
                            aria-label={(currentPost.status || "published") === "hidden" ? "Publish post" : "Hide post"}
                          >
                            {(currentPost.status || "published") === "hidden" ? <Eye strokeWidth={1.8} /> : <EyeOff strokeWidth={1.8} />}
                          </button>
                          <button type="button" className="blog-icon-button" onClick={openEditMode} aria-label="Edit post">
                            <Edit3 strokeWidth={1.8} />
                          </button>
                          <button
                            type="button"
                            className="blog-icon-button"
                            onClick={() => handleDeletePost(currentPost.id)}
                            aria-label="Delete post"
                          >
                            <Trash2 strokeWidth={1.8} />
                          </button>
                        </>
                      )}
                    </div>
                  </footer>
                </div>
              </article>

              <section className="blog-detail-comments blog-detail-comments--modal">
                <div className="blog-section__label">
                  <MessageSquare strokeWidth={1.85} />
                  <h2>Comments & Replies</h2>
                </div>

                {detailLoading ? (
                  <div className="blog-empty-state">Loading post details...</div>
                ) : (
                  <>
                    <div className="blog-comments__composer">
                      <textarea
                        className="blog-comments__input"
                        rows={4}
                        placeholder={isLoggedIn ? "Write a comment..." : "Sign in to add comments"}
                        disabled={!isLoggedIn || !selectedPostId}
                        value={commentDraft}
                        onChange={(event) => setCommentDraft(event.target.value)}
                      />
                      <button
                        type="button"
                        className="blog-comments__button"
                        onClick={handleCommentSubmit}
                        disabled={!isLoggedIn || !selectedPostId}
                      >
                        Post Comment
                      </button>
                    </div>

                    <div className="blog-comments__list">
                      {selectedComments.map((comment) => {
                        const replyKey = `${selectedPostId}:${comment.id}`;
                        return (
                          <div key={comment.id} className="blog-comment">
                            <div className="blog-comment__head">
                              <strong>{comment.author}</strong>
                              <span>{formatDate(comment.createdAt)}</span>
                            </div>
                            <p>{comment.content}</p>

                            {Array.isArray(comment.replies) && comment.replies.length > 0 && (
                              <div className="blog-comment__replies">
                                {comment.replies.map((reply) => (
                                  <div key={reply.id} className="blog-comment blog-comment--reply">
                                    <div className="blog-comment__head">
                                      <strong>{reply.author}</strong>
                                      <span>{formatDate(reply.createdAt)}</span>
                                    </div>
                                    <p>{reply.content}</p>
                                  </div>
                                ))}
                              </div>
                            )}

                            <div className="blog-comment__reply-box">
                              <input
                                type="text"
                                placeholder={isLoggedIn ? "Write a reply..." : "Sign in to reply"}
                                disabled={!isLoggedIn || !selectedPostId}
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
                                onClick={() => handleReplySubmit(comment.id)}
                                disabled={!isLoggedIn || !selectedPostId}
                              >
                                Reply
                              </button>
                            </div>
                          </div>
                        );
                      })}
                      {!selectedComments.length && <div className="blog-empty-state compact">No comments yet. Be the first to reply.</div>}
                    </div>
                  </>
                )}
              </section>
            </div>
          </section>
        </div>
      )}

      {isComposerModalOpen && isLoggedIn && (
        <div className="blog-editor-backdrop blog-editor-backdrop--modal" role="presentation" onClick={closeComposerModal}>
          <section
            className="blog-editor-panel blog-editor-panel--modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="blog-editor-modal-title"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="blog-editor-panel__head">
              <div>
                <p className="blog-editor-panel__kicker">Post Studio</p>
                <h2 id="blog-editor-modal-title">{composerMode === "edit" ? "Edit this post" : "Create a new post"}</h2>
              </div>

              <button type="button" className="blog-post-modal__close" onClick={closeComposerModal} aria-label="Close post editor">
                <X strokeWidth={2} />
              </button>
            </header>

            <div className="blog-editor-grid">
              <div className="blog-editor-visual">
                <PostImage badge={composer.badge || "Preview"} tone="blue" compact imageUrl={composer.imageUrl} alt="Selected post image preview" />

                <label className="blog-editor-field blog-editor-field--full">
                  <span>Upload Image</span>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleComposerImageChange}
                  />
                </label>

                {composer.imageName ? <p className="blog-editor-hint">Selected: {composer.imageName}</p> : <p className="blog-editor-hint">Upload an image to show it on the post card and inside the modal.</p>}
              </div>

              <div className="blog-editor-form">
                <label className="blog-editor-field">
                  <span>Title</span>
                  <input
                    value={composer.title}
                    onChange={(event) => setComposer((current) => ({ ...current, title: event.target.value }))}
                    placeholder="Write a strong title"
                    maxLength={120}
                    required
                  />
                </label>

                <label className="blog-editor-field">
                  <span>Category</span>
                  <input
                    value={composer.category}
                    onChange={(event) => setComposer((current) => ({ ...current, category: event.target.value }))}
                    placeholder="web-security"
                    maxLength={48}
                    required
                  />
                </label>

                <label className="blog-editor-field blog-editor-field--full">
                  <span>Short Description</span>
                  <textarea
                    rows={3}
                    value={composer.description}
                    onChange={(event) => setComposer((current) => ({ ...current, description: event.target.value }))}
                    placeholder="Write the quick summary shown in cards"
                    maxLength={260}
                    required
                  />
                </label>

                <label className="blog-editor-field blog-editor-field--full">
                  <span>Details</span>
                  <textarea
                    rows={8}
                    value={composer.content}
                    onChange={(event) => setComposer((current) => ({ ...current, content: event.target.value }))}
                    placeholder="Full post body and deeper details"
                    maxLength={6000}
                    required
                  />
                </label>

                <label className="blog-editor-field">
                  <span>Tags</span>
                  <input
                    value={composer.tagsText}
                    onChange={(event) => setComposer((current) => ({ ...current, tagsText: event.target.value }))}
                    placeholder="OWASP, Zero Trust, API Security"
                    maxLength={180}
                  />
                </label>

                <label className="blog-editor-field">
                  <span>Badge</span>
                  <input
                    value={composer.badge}
                    onChange={(event) => setComposer((current) => ({ ...current, badge: event.target.value }))}
                    placeholder="New"
                    maxLength={24}
                  />
                </label>

                <label className="blog-editor-field blog-editor-field--full">
                  <span>Image URL</span>
                  <input
                    value={composer.imageUrl}
                    onChange={(event) => setComposer((current) => ({ ...current, imageUrl: event.target.value, imageName: "" }))}
                    placeholder="Optional direct image link"
                  />
                </label>
              </div>
            </div>

            <div className="blog-creation-panel__footer">
              <button type="button" className="blog-comments__button" onClick={submitComposer}>
                {composerMode === "edit" ? "Save Changes" : "Publish Post"}
              </button>
              {composerMode === "edit" && (
                <button type="button" className="blog-comment__reply-button" onClick={openCreateMode}>
                  Cancel Edit
                </button>
              )}
            </div>

            {composerStatus && <p className="blog-editor-status">{composerStatus}</p>}
          </section>
        </div>
      )}

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(BlogPage);
