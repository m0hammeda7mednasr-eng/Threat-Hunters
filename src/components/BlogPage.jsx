import { memo } from 'react';
import {
  ArrowRight,
  Bookmark,
  Calendar,
  Eye,
  Filter,
  Image as ImageIcon,
  Search,
  Share2,
  TrendingUp,
} from 'lucide-react';
import './BlogPage.css';
import Navbar from './Navbar';
import Footer from './Footer';

const categories = [
  { id: 'all', label: 'All Posts', count: 18, active: true },
  { id: 'web-security', label: 'Web Security', count: 5 },
  { id: 'cloud-security', label: 'Cloud Security', count: 4 },
  { id: 'threat-intelligence', label: 'Threat Intelligence', count: 6 },
  { id: 'compliance', label: 'Compliance', count: 3 },
  { id: 'malware', label: 'Malware', count: 4 },
  { id: 'devsecops', label: 'DevSecOps', count: 3 },
];

const trendingTopics = [
  '#OWASP',
  '#Zero Trust',
  '#API Security',
  '#Ransomware',
  '#Cloud Security',
  '#Kubernetes',
  '#Red Team',
  '#Zero-Day',
  '#AI Security',
  '#Compliance',
];

const featuredArticle = {
  id: 'featured-guide',
  badge: 'Featured',
  author: 'Sarah Johnson',
  authorInitial: 'S',
  date: 'Nov 21, 2025',
  readTime: '12 min read',
  views: '15.2K',
  title: 'The Complete Guide to Web Application Security in 2025: Everything You Need to Know',
  description:
    'A comprehensive deep-dive into modern web application security, covering OWASP Top 10, security testing methodologies, and implementing a robust security posture in your development lifecycle.',
  tags: ['OWASP', 'Security Testing', 'DevSecOps'],
};

const trendingNowArticles = Array.from({ length: 4 }, (_, index) => ({
  id: `trending-${index + 1}`,
  badge: 'Trending',
  date: 'Nov 21, 2025',
  readTime: '12 min read',
  views: '15.2K views',
  title: 'The Complete Guide to Web Application Security in 2025: Everything You Need to Know',
}));

const latestArticles = Array.from({ length: 4 }, (_, index) => ({
  id: `latest-${index + 1}`,
  author: 'Michael Chen',
  authorInitial: 'M',
  date: 'Nov 21, 2025',
  readTime: '8 min read',
  views: '23.8K',
  title: "Google Brings AirDrop Compatibility to Android's Quick Share Using Rust-Hardened Security",
  description:
    "In a surprise move, Google announced that it has updated Quick Share to work with Apple's AirDrop, allowing seamless cross-platform file transfers with enhanced security through Rust implementation.",
  tags: ['Google', 'Android', 'Rust'],
}));

const MetaRow = ({ author, authorInitial, date, readTime, views, compact = false }) => (
  <div className={`blog-meta-row ${compact ? 'blog-meta-row--compact' : ''}`}>
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

const ImagePlaceholder = ({ badge, tone = 'blue', compact = false }) => (
  <div className={`blog-image-placeholder ${compact ? 'blog-image-placeholder--compact' : ''}`}>
    {badge ? <span className={`blog-image-placeholder__badge blog-image-placeholder__badge--${tone}`}>{badge}</span> : null}
    <div className="blog-image-placeholder__canvas">
      <ImageIcon strokeWidth={1.8} />
    </div>
  </div>
);

const BlogPage = ({
  onNavigateToSignUp,
  onNavigateToHome,
  onNavigateToAwareness,
  onNavigateToTools,
  isLoggedIn,
}) => {
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
                  className={`blog-category-pill ${category.active ? 'active' : ''}`}
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

          <section className="blog-sidebar-card blog-sidebar-card--subscribe">
            <h3>Stay Updated</h3>
            <p>Get weekly security insights delivered to your inbox</p>
            <input type="email" placeholder="Your email" className="blog-subscribe-input" />
            <button type="button" className="blog-subscribe-button">
              Subscribe
            </button>
          </section>
        </aside>

        <main className="blog-main">
          <header className="blog-hero">
            <h1>Security Intelligence Hub</h1>
            <p>
              Expert insights, latest threats, and actionable security advice from industry leaders
              and practitioners
            </p>

            <label className="blog-search" aria-label="Search articles, topics, or keywords">
              <Search strokeWidth={2} />
              <input type="text" placeholder="Search articles, topics, or keywords..." />
            </label>
          </header>

          <section className="blog-section">
            <header className="blog-section__label">
              <TrendingUp strokeWidth={1.85} />
              <h2>Featured Article</h2>
            </header>

            <article className="blog-featured-card">
              <ImagePlaceholder badge={featuredArticle.badge} />

              <div className="blog-featured-card__content">
                <MetaRow
                  author={featuredArticle.author}
                  authorInitial={featuredArticle.authorInitial}
                  date={featuredArticle.date}
                  readTime={featuredArticle.readTime}
                  views={featuredArticle.views}
                />

                <h3>{featuredArticle.title}</h3>
                <p>{featuredArticle.description}</p>

                <div className="blog-tag-row">
                  {featuredArticle.tags.map((tag) => (
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
                    <button type="button" className="blog-icon-button" aria-label="Save featured article">
                      <Bookmark strokeWidth={1.8} />
                    </button>
                    <button type="button" className="blog-icon-button" aria-label="Share featured article">
                      <Share2 strokeWidth={1.8} />
                    </button>
                  </div>
                </footer>
              </div>
            </article>
          </section>

          <section className="blog-section">
            <header className="blog-section__label">
              <TrendingUp strokeWidth={1.85} />
              <h2>Trending Now</h2>
            </header>

            <div className="blog-trending-grid">
              {trendingNowArticles.map((article) => (
                <article key={article.id} className="blog-trending-card">
                  <ImagePlaceholder badge={article.badge} tone="pink" compact />

                  <div className="blog-trending-card__content">
                    <MetaRow
                      date={article.date}
                      readTime={article.readTime}
                      views={article.views}
                      compact
                    />
                    <h3>{article.title}</h3>

                    <footer className="blog-trending-card__footer">
                      <span className="blog-trending-card__views">
                        <Eye strokeWidth={1.9} />
                        <span>{article.views}</span>
                      </span>
                      <button type="button" className="blog-icon-button blog-icon-button--ghost" aria-label="Save trending article">
                        <Bookmark strokeWidth={1.8} />
                      </button>
                    </footer>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="blog-list">
            {latestArticles.map((article) => (
              <article key={article.id} className="blog-list-card">
                <div className="blog-list-card__media">
                  <ImagePlaceholder compact />
                </div>

                <div className="blog-list-card__content">
                  <div className="blog-list-card__main">
                    <MetaRow
                      author={article.author}
                      authorInitial={article.authorInitial}
                      date={article.date}
                      readTime={article.readTime}
                      views={article.views}
                    />

                    <h3>{article.title}</h3>
                    <p>{article.description}</p>

                    <div className="blog-tag-row">
                      {article.tags.map((tag) => (
                        <span key={tag} className="blog-tag-pill">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>

                  <footer className="blog-list-card__footer">
                    <button type="button" className="blog-link-button blog-link-button--small">
                      <span>Read more</span>
                      <ArrowRight strokeWidth={1.9} />
                    </button>

                    <div className="blog-action-row">
                      <button type="button" className="blog-icon-button" aria-label="Save article">
                        <Bookmark strokeWidth={1.8} />
                      </button>
                      <button type="button" className="blog-icon-button blog-icon-button--ghost" aria-label="Share article">
                        <Share2 strokeWidth={1.8} />
                      </button>
                    </div>
                  </footer>
                </div>
              </article>
            ))}
          </section>

          <div className="blog-load-more">
            <button type="button" className="blog-load-more__button">
              <span>Load More Articles</span>
              <ArrowRight strokeWidth={1.9} />
            </button>
          </div>
        </main>
      </div>

      {!isLoggedIn && <Footer />}
    </div>
  );
};

export default memo(BlogPage);
