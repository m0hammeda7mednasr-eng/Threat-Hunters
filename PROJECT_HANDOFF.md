# Threat Hunters Project Handoff

This document summarizes the current project structure, technologies, backend/frontend integration, data storage, API coverage, and verification commands.

## 1. Project Overview

Threat Hunters is a cybersecurity web application with:

- Public marketing pages.
- User authentication and user console.
- Website vulnerability scanner.
- Breach intelligence tools.
- Security awareness content.
- Blog publishing and engagement.
- Admin dashboard for platform control.

The app is designed to run locally with a React/Vite frontend and a backend API. In development, `npm run dev` starts the frontend and a local mock backend. The Flask backend remains available for MongoDB-backed operation.

## 2. Frontend Stack

- React 19.2
- Vite via `rolldown-vite`
- JavaScript and JSX
- CSS files per major page/component
- Lucide React icons
- Local hash-based routing in `src/App.jsx`
- Theme context in `src/context/ThemeContext.jsx`
- API client in `src/services/api.js`

Main frontend areas:

- `src/components/HomePage.jsx`
- `src/components/SignInPage.jsx`
- `src/components/SignUpPage.jsx`
- `src/components/DashboardPage.jsx`
- `src/components/MoreToolsPage.jsx`
- `src/components/SecurityAwarenessPage.jsx`
- `src/components/BlogPage.jsx`
- `src/components/AdminDashboardPage.jsx`
- `src/components/AdminUsersPage.jsx`
- `src/components/AdminReportsPage.jsx`
- `src/components/AdminTeamPage.jsx`
- `src/components/AdminPricingPage.jsx`
- `src/components/AdminSettingsPage.jsx`
- `src/components/AdminWebEditPage.jsx`
- `src/components/Footer.jsx`

## 3. Backend Stack

- Python Flask
- Flask-PyMongo
- Flask-CORS
- PyJWT
- Requests
- Feedparser
- Email validator
- MongoDB
- Environment variables loaded with `python-dotenv`

Main backend files:

- `Back-end/app.py`
- `Back-end/config.py`
- `Back-end/database/db.py`
- `Back-end/middleware/auth_middleware.py`
- `Back-end/routes/*.py`
- `Back-end/services/*.py`
- `Back-end/tests/*.py`

## 4. Local Mock Backend

The local development backend is:

- `server/mock-backend.mjs`
- Persistent local data: `server/data/mock-db.json`
- `server/data/` is ignored by git.

It mirrors the important Flask endpoints so the frontend can be tested even when MongoDB is not running.

The mock backend supports:

- Auth and password reset.
- User profile/settings/password/account.
- Blog posts, images, likes, shares, comments, replies.
- Security awareness content.
- HIBP email/password checks.
- Website scanner.
- Dashboard metrics.
- Admin users, reports, team, pricing, settings, and web content.

## 5. Database Design

Production backend uses MongoDB. Important collections:

- `users`
- `blogs`
- `comments`
- `likes`
- `blog_views`
- `password_reset_tokens`
- `web_content`
- `admin_config`
- `admin_reports`

Mock backend stores equivalent development data in JSON:

- `users`
- `sessions`
- `resetTokens`
- `posts`
- `webContent`
- `adminSettings`
- `adminTeam`
- `adminPricing`
- `adminReports`

## 6. Environment Variables

Backend variables:

```env
SECRET_KEY=change-me
MONGO_URI=mongodb://localhost:27017/vuln_scanner
JWT_EXPIRATION_HOURS=24
EMAIL_ADDRESS=your-email@example.com
EMAIL_PASSWORD=your-email-app-password
HIBP_API_KEY=your-haveibeenpwned-api-key
```

Frontend variable when needed:

```env
VITE_API_BASE_URL=https://your-api-domain.example/api
```

Security note:

- Real secrets must stay in `.env`.
- `.env`, `.vercel`, `node_modules`, `dist`, logs, and mock local data are ignored by git.
- The HIBP API key is only used by backend endpoints. The browser does not call HIBP directly.

## 7. Frontend API Client

All frontend API calls are centralized in:

```text
src/services/api.js
```

Exports:

- `authAPI`
- `securityAPI`
- `blogAPI`
- `dashboardAPI`
- `scannerAPI`
- `contentAPI`
- `userAPI`
- `adminAPI`
- `utils`

`apiRequest()` attaches the JWT token from local storage and sends JSON payloads.

## 8. API Coverage

Auth:

- `POST /api/register`
- `POST /api/login`
- `POST /api/password/forgot`
- `POST /api/password/reset`

User console:

- `GET /api/user/profile`
- `PUT /api/user/profile`
- `PUT /api/user/password`
- `GET /api/user/settings`
- `PUT /api/user/settings`
- `DELETE /api/user/account`

Scanner:

- `POST /api/scanner/scan`

Security intelligence:

- `GET /api/security/latest-cves`
- `GET /api/security/critical-cves`
- `GET /api/security/kev`
- `GET /api/security/news`
- `GET /api/security/awareness`
- `POST /api/security/check-email`
- `POST /api/security/check-password`

Blog:

- `GET /api/blogs`
- `POST /api/blogs`
- `GET /api/blogs/:id`
- `PUT /api/blogs/:id`
- `DELETE /api/blogs/:id`
- `PATCH /api/blogs/:id/status`
- `POST /api/blogs/:id/like`
- `POST /api/blogs/:id/share`
- `GET /api/blogs/:id/comments`
- `POST /api/blogs/:id/comments`
- `POST /api/blogs/:id/comments/:commentId/replies`

Dashboard:

- `GET /api/dashboard/stats`
- `GET /api/dashboard/activities`
- `GET /api/dashboard/security-metrics`

Admin:

- `GET /api/admin/users`
- `POST /api/admin/users`
- `GET /api/admin/users/:id`
- `PUT /api/admin/users/:id`
- `DELETE /api/admin/users/:id`
- `GET /api/admin/reports`
- `POST /api/admin/reports`
- `POST /api/admin/reports/:id/download`
- `GET /api/admin/team`
- `POST /api/admin/team`
- `PUT /api/admin/team/:id`
- `DELETE /api/admin/team/:id`
- `GET /api/admin/pricing`
- `PUT /api/admin/pricing`
- `POST /api/admin/pricing/plans`
- `PUT /api/admin/pricing/plans/:id`
- `DELETE /api/admin/pricing/plans/:id`
- `GET /api/admin/settings`
- `PUT /api/admin/settings`
- `GET /api/web-content`
- `PUT /api/web-content/:page`

## 9. Admin Dashboard Coverage

The admin dashboard now controls:

- Dashboard metrics and recent activity.
- Users: list, search, filter, create, edit profile/role/status/plan/activity numbers, email shortcut, disable/activate, delete.
- Reports: list, generate, download, track download count.
- Team: list, add invite, edit identity/role/status/activity/permission badges, remove.
- Pricing: list plans, add plan, edit plan copy/price/subscribers/badge/features, delete plan, view transactions.
- Settings: load and save general, notification, security, and email settings.
- Web content: edit public page content, add/remove feature and statistic rows, validate OWASP links, and moderate blog posts.

## 10. Blog Coverage

Blog currently supports:

- New post modal.
- Post edit flow.
- Image URL and upload support.
- Image fallback handling.
- Categories and tags.
- Likes.
- Shares.
- Comments.
- Replies.
- Admin hide/publish.
- Admin delete.

## 11. Scanner And Reports

Scanner backend checks include:

- URL normalization and validation.
- HTTP/HTTPS response checks.
- Security header review.
- Cookie flag review.
- HTML body checks for forms, CSRF hints, mixed content, and secret-like strings.
- Endpoint probing for common sensitive paths.
- Risk scoring.
- Findings and recommendations.

Reports include:

- Scan metadata.
- Risk score.
- Findings.
- Checks.
- Recommendations.
- Download/export support from the user console and admin reports page.

## 12. Legal And Footer Pages

Static legal pages exist under:

- `public/legal/privacy-policy.html`
- `public/legal/terms-of-service.html`
- `public/legal/responsible-disclosure.html`
- `public/legal/data-protection.html`
- `public/legal/legal.css`

Footer links point to real local pages or appropriate project/support links.

## 13. Validation And Quality Controls

Frontend validation added or verified:

- Website URL validation on scan forms.
- Email validation for newsletter and admin settings.
- Admin user create/edit email and non-negative number validation.
- Admin team email and duplicate validation.
- Image URL validation for blog posts.
- Image upload type/size checks.
- Admin settings email validation.
- Admin pricing price, subscriber, and feature validation.
- Admin web editor publish validation for titles, features, statistics, and OWASP links.
- Confirm prompts before destructive admin delete actions.

Backend validation includes:

- Auth checks.
- Admin-only route guards.
- Admin user create/edit validation.
- Admin team duplicate email protection.
- Admin pricing non-negative subscriber validation.
- Blog author/admin permissions.
- URL validation in scanner.
- Email/password reset requirements.
- HIBP backend-only access.

## 14. Commands Used For Verification

Frontend:

```bash
npm run lint
npm run build
```

Backend:

```bash
python -m py_compile Back-end/routes/admin_routes.py
python -m unittest discover -s Back-end/tests -p "test_*.py"
```

Mock backend:

```bash
node --check server/mock-backend.mjs
```

Local full stack:

```bash
npm run dev
```

Browser smoke verification covered:

- `#admin-team`
- `#admin-pricing`
- `#admin-users`
- `#admin-web-edit`

Final admin smoke verification covered:

- Admin Team UI add/edit/delete.
- Admin Pricing UI add/edit/delete.
- Admin Users UI create/edit/delete.
- Admin Web Edit publish to backend and restore original content.
- Admin API validation for negative user counters, negative pricing subscribers, and duplicate team emails.

No test data was left in the mock database after the final smoke tests.

## 15. Deployment Notes

Vercel frontend config:

```text
vercel.json
```

For a production backend deployment:

- Host Flask separately or configure a platform that supports the Python service.
- Set all backend environment variables.
- Point `VITE_API_BASE_URL` to the deployed backend `/api` base path.
- Use a managed MongoDB connection string.
- Keep HIBP API key server-side only.

## 16. Git Hygiene

Ignored files include:

- Logs.
- `node_modules`.
- `dist`.
- `.vercel`.
- `.codex-run`.
- `server/data`.
- Python cache folders.
- Environment files.

Do not commit:

- Real `.env` values.
- HIBP API keys.
- Email passwords.
- Local mock database data.

## 17. Current Local Demo Accounts

Admin:

```text
admin@threathunters.com / Admin@12345
```

Regular user:

```text
user@threathunters.com / User@12345
```

These are for local development/demo only.
