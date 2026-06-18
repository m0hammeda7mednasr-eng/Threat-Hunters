# Threat Hunters

Threat Hunters is a full-stack cybersecurity platform for website scanning, breach intelligence, security awareness, blog publishing, reports, and admin control.

## What Is Included

- Public landing page with website scan entry point.
- Authentication, profile, settings, password reset, and account controls.
- User console with scan activity, reports, PDF-style exports, and profile management.
- Security tools for email exposure checks and password breach checks through the backend.
- Security awareness page backed by API content, learning resources, and branded PDF downloads.
- Blog system with posts, images, likes, shares, comments, replies, hidden/published moderation, and admin controls.
- Admin dashboard for users, reports, team, pricing, settings, and website content editing.
- Professional footer routes for help, documentation, FAQs, issue reporting, contact support, privacy, terms, responsible disclosure, and data protection.
- Shared branded PDF generator for admin reports and security awareness resources.
- Flask backend with MongoDB support.
- Local mock backend for development when MongoDB is not available.

## Tech Stack

- Frontend: React 19, Vite, JavaScript, CSS modules/files, Lucide React icons.
- Backend: Flask, Flask-PyMongo, Flask-CORS, PyJWT, Requests, Feedparser.
- Database: MongoDB for production/backend mode.
- Local development data: JSON mock database under `server/data/` (ignored by git).
- External security API: Have I Been Pwned through backend-only calls.

## Quick Start

Install frontend dependencies:

```bash
npm install
```

Start the local development stack:

```bash
npm run dev
```

The development script starts:

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:5000`

Build production frontend:

```bash
npm run build
```

Run frontend lint:

```bash
npm run lint
```

Run backend tests:

```bash
python -m unittest discover -s Back-end/tests -p "test_*.py"
```

## Backend Setup

Install Python requirements:

```bash
pip install -r Back-end/requirements.txt
```

Create `Back-end/.env` from `Back-end/.env.example` and set these values:

```env
SECRET_KEY=change-me
MONGO_URI=mongodb://localhost:27017/vuln_scanner
JWT_EXPIRATION_HOURS=24
EMAIL_ADDRESS=your-email@example.com
EMAIL_PASSWORD=your-email-app-password
HIBP_API_KEY=your-haveibeenpwned-api-key
```

Do not commit real secrets. `.env` is ignored by git.

## Important API Areas

- Auth: `/api/register`, `/api/login`, `/api/password/forgot`, `/api/password/reset`
- User console: `/api/user/profile`, `/api/user/settings`, `/api/user/password`, `/api/user/account`
- Scanner: `/api/scanner/scan`
- Security intelligence: `/api/security/latest-cves`, `/api/security/critical-cves`, `/api/security/kev`, `/api/security/news`, `/api/security/awareness`
- Breach checks: `/api/security/check-email`, `/api/security/check-password`
- Blog: `/api/blogs`, `/api/blogs/:id`, `/api/blogs/:id/comments`, `/api/blogs/:id/like`, `/api/blogs/:id/share`
- Dashboard: `/api/dashboard/stats`, `/api/dashboard/activities`, `/api/dashboard/security-metrics`
- Admin users: `/api/admin/users`
- Admin reports: `/api/admin/reports`
- Admin team: `/api/admin/team`
- Admin pricing: `/api/admin/pricing`
- Admin settings: `/api/admin/settings`
- Web content editor: `/api/web-content`

## Admin Login

Local demo admin account:

```text
admin@threathunters.com / Admin@12345
```

## In-App Footer Pages

Footer links open routed React pages instead of dead anchors:

- `#help-center`
- `#documentation`
- `#faqs`
- `#report-issue`
- `#contact-support`
- `#privacy-policy`
- `#terms-of-service`
- `#responsible-disclosure`
- `#data-protection`

## Documentation

See [PROJECT_HANDOFF.md](./PROJECT_HANDOFF.md) for the detailed frontend, backend, database, integration, testing, and deployment handoff.

## Deployment

The frontend is configured for Vercel with `vercel.json`.

For full production deployment, configure:

- Frontend environment variable `VITE_API_BASE_URL` if the API is hosted separately.
- Backend environment variables in the hosting provider.
- MongoDB connection string.
- HIBP API key in backend environment only.

## License

MIT. See [LICENSE](./LICENSE).
