# شرح مشروع Threat Hunters بالتفصيل

## 1. المشروع ده بيعمل إيه؟

`Threat Hunters` هو مشروع تخرج عبارة عن منصة Cybersecurity Full-Stack.

الفكرة الأساسية:

- المستخدم يدخل رابط موقع ويب.
- السيستم يعمل فحص أمني مبدئي أو متقدم.
- يعرض النتيجة بشكل سهل الفهم.
- يوفّر Dashboard و Reports و Tools إضافية.
- فيه Blog و Security Awareness و Admin Panel.

بمعنى أبسط:

المشروع مش مجرد واجهة شكلها حلو، لكنه Workflow كامل:

`Input -> Analysis -> Findings -> Risk Score -> Report -> Follow-up Action`

---

## 2. الـ Tech Stack

### Frontend

- `React 19`
- `Vite`
- `JavaScript / JSX`
- `CSS files` لكل صفحة أو Component
- `lucide-react` للأيقونات

### Backend

- `Flask`
- `Flask-CORS`
- `Flask-PyMongo`
- `PyJWT`
- `Requests`
- `Feedparser`
- `python-dotenv`

### Database

- `MongoDB Atlas`

### ليه التقسيمة دي؟

- `React` مناسب للواجهات التفاعلية والـ state الكتير.
- `Vite` سريع جدًا في التطوير والبناء.
- `Flask` بسيط وواضح وسهل تقسيمه إلى routes و services.
- `MongoDB` مناسب للبيانات المرنة مثل blogs, reports, admin config.

---

## 3. هيكل المشروع

### الجزء الأمامي

- `src/main.jsx`: نقطة البداية.
- `src/App.jsx`: إدارة الصفحات والتنقل العام.
- `src/index.css`: قواعد عامة + الفونتات + سلوك عام للواجهة.
- `src/styles/colors.css`: كل ألوان وثيمات الموقع.
- `src/services/api.js`: كل استدعاءات الـ API.
- `src/context/ThemeContext.jsx`: إدارة الـ theme.
- `src/context/AuthContext.jsx`: إدارة تسجيل الدخول.
- `src/components/`: كل الصفحات والمكونات.

### الجزء الخلفي

- `Back-end/Backend/app.py`: تشغيل Flask وربط الـ blueprints.
- `Back-end/Backend/config.py`: تحميل الإعدادات من البيئة.
- `Back-end/Backend/routes/`: الراوتس.
- `Back-end/Backend/services/`: منطق البزنس.
- `Back-end/Backend/database/db.py`: الاتصال بـ Mongo.
- `Back-end/Backend/middleware/auth_middleware.py`: التحقق من التوكن والصلاحيات.
- `Back-end/Backend/scanner` و `scanner2`: أدوات الفحص الأمني.

---

## 4. بداية تشغيل الفرونت

الملف [src/main.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/main.jsx:1) هو أول ملف يشتغل.

هو بيعمل 3 حاجات مهمين:

1. يحمل الـ CSS العام:
   - `index.css`
   - `colors.css`
2. يلف التطبيق كله داخل `ThemeProvider`
3. يلف التطبيق كله داخل `AuthProvider`

وده معناه إن:

- أي Component يقدر يعرف الثيم الحالي.
- أي Component يقدر يعرف هل المستخدم مسجل دخول ولا لا.

---

## 5. الفونتات بالتفصيل

الملف الأساسي هنا هو [src/index.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/index.css:1).

### الفونتات المستخدمة

- `Manrope`
- `Space Grotesk`

### منين جايين؟

من Google Fonts عن طريق:

```css
@import url('https://fonts.googleapis.com/css2?family=Manrope...&family=Space+Grotesk...');
```

### توزيع الفونتات

- `--font-body: 'Manrope'`
  ده الفونت الأساسي للنصوص العادية.
- `--font-display: 'Space Grotesk'`
  ده مستخدم للعناوين واللوجو والنصوص البارزة.

### ليه التقسيمة دي كويسة؟

- `Manrope` شكله نظيف وسهل القراءة في النصوص الطويلة.
- `Space Grotesk` شكله Tech / Modern ومناسب جدًا لهوية مشروع سايبير سيكيوريتي.

### فين بيتطبق؟

- `body` بياخد `var(--font-body)`
- `h1` إلى `h6` وبعض عناصر البراند بياخدوا `var(--font-display)`

يعني:

- النصوص اليومية = مريحة وواضحة
- العناوين = أقوى وأوضح بصريًا

---

## 6. الألوان والثيم بالتفصيل

أهم ملف هنا هو [src/styles/colors.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/styles/colors.css:1).

الملف ده معمول بفكرة `Design Tokens`.

### يعني إيه Design Tokens؟

يعني بدل ما كل ملف CSS يكتب لون مباشر مثل `#155dfc` أو `#0b0d18`، المشروع بيعرّف متغيرات عامة:

- `--primary-100`
- `--text-primary`
- `--bg-primary`
- `--surface-panel`
- `--accent-red`

وبعدين كل المكونات تستخدم المتغيرات دي.

### فايدة ده

- تغيير الهوية البصرية يبقى من مكان واحد.
- أسهل في الصيانة.
- يدعم Dark / Light mode بسهولة.

### أنظمة الألوان الموجودة

#### Dark mode

في:

- `:root`
- `:root[data-theme="dark"]`

وده معناه إن الوضع الافتراضي في تعريف الألوان متجه للـ dark.

ألوانه الأساسية:

- خلفيات غامقة جدًا
- أزرق وبنفسجي مزرق كألوان رئيسية
- أحمر / أصفر / أخضر للمخاطر

#### Light mode

في:

- `:root[data-theme="light"]`

ألوانه الأساسية:

- خلفيات فاتحة
- نفس الروح اللونية لكن بإصدار أخف
- نفس التوكنز لكن بقيم مختلفة

### أنواع التوكنز

#### 1. Palette Tokens

دي الألوان الخام نفسها:

- `--palette-primary-100`
- `--palette-background-100`
- `--palette-text-primary`

#### 2. Semantic Tokens

دي الأسماء المستخدمة فعليًا في المكونات:

- `--bg-primary`
- `--text-secondary`
- `--card-bg`
- `--button-gradient`

#### 3. State Tokens

دي مسؤولة عن الـ hover / focus / shadows:

- `--state-focus-ring`
- `--state-card-hover-shadow`
- `--state-hover-surface`

### معنى ده في المناقشة

تقدر تقول:

"أنا ماشتغلتش بألوان hard-coded في كل ملف، لكن بنيت نظام design tokens يدعم التوسعة وتبديل الـ theme بسهولة."

---

## 7. الثيم بيتغير إزاي؟

الملف المسؤول هو [src/context/ThemeContext.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/context/ThemeContext.jsx:1).

### اللي بيحصل

1. يقرأ قيمة `theme` من `localStorage`
2. لو مفيش قيمة، يبدأ بـ `light`
3. كل ما الثيم يتغير:
   - يضيف `data-theme` على `document.documentElement`
   - يحفظ القيمة في `localStorage`

### ليه `data-theme` مهمة؟

لأن ملفات CSS شغالة بصيغة:

```css
:root[data-theme="light"] { ... }
```

فبمجرد تغيير الـ attribute، كل الألوان تتبدل.

### مين بيستخدم `toggleTheme`؟

الزر موجود في:

- `Navbar`
- `AuthNavbar`
- `AdminTopNav`
- وبعض صفحات الأدمن

يعني الثيم متاح في الواجهة العامة وواجهة المستخدم وواجهة الأدمن.

---

## 8. الـ Global UI في `index.css`

الملف [src/index.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/index.css:1) مش مجرد فونتات، لكنه بيحدد قواعد تصميم عامة:

- `scroll-behavior: smooth`
- `box-sizing: border-box`
- transitions عامة على العناصر
- scrollbar styling
- تحسين `focus-visible`
- تحسين الـ font smoothing
- احترام `prefers-reduced-motion`

### نقطة مهمة

في Transition عام على أغلب العناصر:

```css
transition:
  background-color ...,
  color ...,
  border-color ...,
  box-shadow ...,
  transform ...;
```

وده بيدي إحساس ناعم عند التنقل أو تبديل الثيم.

---

## 9. التنقل بين الصفحات معمول إزاي؟

المشروع **لا يستخدم React Router**.

بدل كده، الملف [src/App.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/App.jsx:1) عامل Routing يدوي باستخدام `window.location.hash`.

### أمثلة

- `#home`
- `#signin`
- `#signup`
- `#dashboard`
- `#admin-dashboard`
- `#awareness/something/id`

### ليه ده مهم؟

يعني المشروع SPA لكن بتوجيه بسيط بدون مكتبة Routing خارجية.

### دوال مهمة في `App.jsx`

#### `parseRouteFromHash`

تفهم الـ hash الحالي وترجعه على هيئة:

- الصفحة الحالية
- السكشن الحالي
- تفاصيل awareness detail لو موجودة

#### `handleNavigation`

تتحكم في النقل بين الصفحات حسب:

- هل المستخدم مسجل دخول؟
- هل المستخدم `admin`؟
- الصفحة المطلوبة عامة ولا خاصة؟

#### `createHash`

تبني الـ hash المناسب للصفحة أو السكشن.

### ميزة واضحة

في حماية على مستوى التنقل:

- لو حد مش مسجل دخول وراح Dashboard، يتحول لـ Sign In
- لو حد User عادي حاول يدخل صفحة Admin، يتحول للـ Dashboard العادي

---

## 10. إدارة تسجيل الدخول

في مستويين هنا:

### 1. UI state في `App.jsx`

فيه مفاتيح Local Storage مثل:

- `isLoggedIn`
- `threatHuntersUserRole`
- `threatHuntersUserEmail`

وده لتحديد الصفحة الحالية وسلوك التنقل.

### 2. Auth logic في `AuthContext`

الملف [src/context/AuthContext.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/context/AuthContext.jsx:1) مسؤول عن:

- `login`
- `register`
- `logout`
- `getProfile`
- `updateProfile`
- `changePassword`
- `deleteAccount`
- `requestPasswordReset`
- `resetPassword`

### تخزين بيانات المستخدم

- التوكن في `localStorage`
- بيانات المستخدم في `localStorage` كـ JSON

### الميزة هنا

فيه فصل بين:

- حالة الواجهة والتنقل
- الاتصال الحقيقي بالباك

---

## 11. استدعاء الـ API من الفرونت

الملف الأساسي هو [src/services/api.js](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/services/api.js:1).

### فكرة الملف

بدل ما كل صفحة تكتب `fetch` بنفسها، كل النداءات متجمعة في مكان واحد.

### أهم الأجزاء

#### `API_BASE_URL`

- في التطوير: `http://localhost:5000/api`
- في البرودكشن: `/api`
- أو قيمة مخصصة من `VITE_API_BASE_URL`

#### `apiRequest`

دي دالة عامة:

- تضيف `Authorization` لو فيه token
- تحول الـ body إلى JSON
- ترسل الطلب
- تعالج الرد

#### تقسيم الـ APIs

- `authAPI`
- `securityAPI`
- `blogAPI`
- `dashboardAPI`
- `scannerAPI`
- `contentAPI`
- `userAPI`
- `adminAPI`

### فايدة المعمارية دي

- كل endpoint معروف في مكان واضح
- أسهل جدًا التعديل أو الديباج
- المكونات تبقى أنضف لأن منطق الشبكة بعيد عنها

---

## 12. الصفحة الرئيسية `HomePage`

المنطق في [src/components/HomePage.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/components/HomePage.jsx:1)  
والستايل في [src/components/HomePage.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/components/HomePage.css:1)

### الصفحة فيها إيه؟

- Navbar
- Hero Section
- URL input للفحص
- Preview report وهمي لعرض شكل النتيجة
- How it Works
- Marquee متحرك
- Feature cards
- Final CTA
- Footer

### نقطة قوية جدًا في التصميم

الصفحة مش مجرد بلوكات تقليدية، لكن فيها:

- gradients
- glass surfaces
- marquee animation
- floating icons
- hover depth
- preview sweep animation

وده بيدي إحساس إن المنتج Security SaaS احترافي.

### التحقق من الرابط

في دالتين:

- `isValidWebsiteHostname`
- `normalizeWebsiteUrl`

وظيفتهم:

- التأكد إن الرابط صالح
- إضافة `https://` لو المستخدم نسيها
- رفض القيم غير المنطقية

### لما المستخدم يضغط Scan Now

- يتم حفظ الرابط في:
  `threatHuntersPendingScanUrl`
- وبعدها المستخدم يروح Sign Up

وده معناه إن الموقع بيستخدم الـ landing page كمدخل Conversion قبل الفحص الكامل.

---

## 13. شرح تصميم `HomePage.css`

الملف ضخم نسبيًا لأنه بيعمل شغل بصري كثير.

### أهم أفكار التصميم

#### 1. Shell Layout

`home-shell` بيحدد عرض موحد للمحتوى:

- باستخدام `--shell-max-width`
- و `--shell-gutter`

#### 2. Hero Card

`home-hero-card` معمولة على شكل Panel كبيرة فيها:

- border لطيف
- shadow
- gradient/glass feeling

#### 3. Reusable Buttons

- `home-primary-button`
- `home-secondary-button`

وده معناه إن عندك نظام أزرار ثابت بدل تكرار styles.

#### 4. Responsive Design

في Media Queries كثيرة:

- `1200px`
- `900px`
- `768px`
- `640px`
- `480px`

يعني التصميم متظبط Desktop و Tablet و Mobile.

#### 5. Motion

في Animations مثل:

- `home-marquee`
- `home-marquee-reverse`
- `home-float`
- `home-preview-sweep`

ومع ذلك فيه احترام لـ:

`prefers-reduced-motion`

وده شيء ممتاز Accessibility-wise.

---

## 14. الـ Boot Splash والـ Loading

في `App.jsx` فيه `BootSplash` بيظهر أول مرة لفترة قصيرة.

### الفكرة

- يعطي إحساس branding
- يخلي الدخول للتطبيق شكله polished

كمان الـ lazy loading مستخدم مع:

- `Suspense`
- `lazy()`

وده يقلل التحميل الأولي لأن الصفحات الثقيلة لا تتحمل إلا عند الحاجة.

---

## 15. الحركة والـ Scroll Reveal

في `App.jsx` فيه `IntersectionObserver` بيضيف:

- `scroll-reveal`
- `scroll-reveal-in`

على عناصر كثيرة في الصفحات.

### النتيجة

العناصر تدخل بشكل تدريجي أثناء الـ scroll، وده يرفع جودة الإحساس البصري للموقع.

---

## 16. الباك إند بيتشغل إزاي؟

الملف الأساسي هو [Back-end/Backend/app.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/app.py:1).

### اللي بيحصل فيه

1. تحميل `.env`
2. إنشاء Flask app
3. تحميل `Config`
4. تفعيل `CORS`
5. ربط MongoDB
6. إنشاء Indexes
7. تسجيل كل الـ Blueprints

### الـ Blueprints المسجلة

- `auth_bp`
- `user_bp`
- `blog_bp`
- `security_bp`
- `comment_bp`
- `like_bp`
- `dashboard_bp`
- `content_bp`
- `admin_bp`
- `breach_bp`
- `scanner_bp`

### ليه استخدام Blueprints مهم؟

لأن المشروع كبير، فبدل كل الراوتس تكون في ملف واحد، كل Domain له ملفه.

---

## 17. إعدادات الباك

في [Back-end/Backend/config.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/config.py:1).

### أهم المتغيرات

- `MONGO_URI`
- `SECRET_KEY`
- `HIBP_API_KEY`
- `JWT_EXPIRATION_HOURS`

### مهم جدًا في المناقشة

المفاتيح الحساسة ليست في الفرونت، بل في الباك داخل environment variables.

وده اختيار أمني صحيح.

---

## 18. الـ CORS في الباك

في `app.py` مسموح للفرونت المحلي فقط:

- `http://localhost:5173`
- `http://127.0.0.1:5173`

وده معناه إن الاتصال متقفل على Origins محددة في التطوير.

---

## 19. قواعد البيانات والـ Indexes

في `app.py` فيه `ensure_mongo_indexes()`.

بيعمل Indexes على:

- `blogs.slug`
- `scan_reports(user_id, created_at)`
- `scan_reports(report_id, user_id)`

### فايدة ده

- تحسين الأداء
- منع التكرار في بعض الحالات
- تسريع جلب التقارير

---

## 20. الراوتس الأساسية

### Auth Routes

الملف [Back-end/Backend/routes/auth_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/auth_routes.py:1)

أهم المسارات:

- `POST /api/register`
- `POST /api/login`
- `POST /api/verify-email`
- `POST /api/verify-email/resend`
- `POST /api/password/forgot`
- `POST /api/password/reset`

### Security Routes

الملف [Back-end/Backend/routes/security_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/security_routes.py:1)

أهم المسارات:

- `GET /api/security/latest-cves`
- `GET /api/security/critical-cves`
- `GET /api/security/kev`
- `GET /api/security/news`
- `GET /api/security/awareness`

### Scanner Routes

الملف [Back-end/Backend/routes/scanner_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/scanner_routes.py:1)

- `POST /api/scanner/scan`
- `GET /api/scanner/reports`

### Blog Routes

الملف [Back-end/Backend/routes/blog_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/blog_routes.py:1)

- إنشاء بوست
- تعديل
- حذف
- جلب الكل
- جلب بوست واحد
- تغيير حالة النشر
- مشاركة

### Admin Routes

الملف [Back-end/Backend/routes/admin_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/admin_routes.py:1)

ويضم:

- Users
- Settings
- Team
- Pricing
- Reports

---

## 21. الـ Admin Panel معمول بإيه؟

الأدمن هنا ليس مجرد صفحة شكلية، بل عنده Backend حقيقي.

### الأدمن يقدر يعمل إيه؟

- إدارة المستخدمين
- إنشاء وتعديل وحذف مستخدمين
- تغيير status و role
- إدارة فريق الأدمن
- إدارة الباقات والأسعار
- توليد تقارير إدارية
- تعديل إعدادات المنصة

### نقطة مهمة

في `admin_routes.py` فيه `require_admin()`:

- لو المستخدم ليس admin يرجع `403`

يعني الحماية ليست في الواجهة فقط، بل في السيرفر أيضًا.

---

## 22. نظام الـ Blog

الـ Blog مرتبط بالباك، وليس Static content.

### يدعم

- Posts
- Likes
- Shares
- Comments
- Replies
- Hide / Publish

وده يوضح إن المشروع عنده جانب Content / Community بجانب أدوات الأمن.

---

## 23. نظام الـ Scanner

فيه:

- `scanner`
- `scanner2`

وده يشير إن المشروع يحتوي على Core scanning toolkit أكبر من مجرد endpoint بسيط.

### وظيفة `/scanner/scan`

في الراوت:

- يستقبل البيانات
- يحدد المستخدم الحالي لو موجود
- ينادي `start_scan`
- يرجع النتيجة بصيغة JSON

### وظيفة `/scanner/reports`

- تتطلب Token
- ترجع تقارير الفحص الخاصة بالمستخدم

---

## 24. نظام الـ Security Intelligence

في `security_routes.py` الباك بيجمع بيانات من خدمات مثل:

- `nvd_service`
- `cisa_service`
- `news_service`
- `awareness_service`

### يعني إيه ده؟

المشروع لا يعرض مجرد نصوص ثابتة، بل يربط نفسه بمصادر Security Intelligence:

- CVEs
- KEV
- أخبار أمنية
- محتوى توعوي

---

## 25. حفظ الجلسة والبيانات محليًا

المشروع يستخدم:

- `localStorage`
- `sessionStorage`

### استخدامات `localStorage`

- حالة تسجيل الدخول
- role
- email
- token
- user object
- theme
- pending scan URL

### استخدامات `sessionStorage`

- معرفة هل شاشة `BootSplash` ظهرت في نفس الجلسة أم لا

### ميزة تقنية جيدة

في `App.jsx` فيه `safeStorage` و `safeSessionStorage` مع `try/catch`، وده يمنع crash لو المتصفح مانع التخزين.

---

## 26. الـ PDF والتقارير

من README وملفات المشروع واضح إن المشروع يولد تقارير PDF للمستخدم.

وده مهم جدًا في مشروع التخرج لأنك تقدر تقول:

- النتيجة ليست مجرد UI
- يوجد إخراج رسمي قابل للتحميل والمشاركة
- التقرير يساعد في remediation

---

## 27. فكرة الـ Design System في المشروع

المشروع عنده نواة Design System واضحة حتى لو مش متسماة رسميًا.

مظاهر ده:

- `colors.css` للتوكنز
- `index.css` للقواعد العامة
- فونت body و display منفصلين
- متغيرات spacing مثل:
  - `--shell-max-width`
  - `--shell-gutter`
  - `--section-space`
- متغيرات motion:
  - `--motion-fast`
  - `--motion-base`
  - `--motion-slow`
- متغيرات radius:
  - `--radius-panel`
  - `--radius-card`

وده معناه إن التصميم مش عشوائي.

---

## 28. ليه المشروع شكله احترافي؟

لأن فيه مجموعة قرارات تصميم جيدة:

- Font pairing واضح
- Color tokens منظمة
- Dark/Light themes
- Motion محسوبة
- Responsive design
- Lazy loading
- Hash routing بسيط لكنه منظم
- Backend مفصول عن Frontend
- API layer منفصلة
- Admin backend حقيقي

---

## 29. أهم نقاط القوة اللي تقولها في المناقشة

- المشروع Full-Stack وليس Frontend فقط.
- فيه Separation of Concerns واضح.
- الفونتات مختارة لهوية تقنية حديثة.
- نظام الألوان مبني على Tokens وليس ألوان مبعثرة.
- الـ Theme switching حقيقي ومربوط بالـ DOM و Local Storage.
- الـ API layer موحدة.
- فيه Role-based navigation في الفرونت.
- فيه Role-based authorization في الباك.
- فيه أدوات أمنية فعلية: scan, breaches, CVEs, awareness.
- فيه Admin Panel عملية وليست ديكور.

---

## 30. لو اتسألت: "الفونت ده ليه؟"

ممكن تجاوب:

"استخدمنا `Manrope` للنصوص لأنه واضح ومريح في القراءة داخل الـ dashboards والنصوص الطويلة، واستخدمنا `Space Grotesk` للعناوين لأنه بيدي طابع تقني حديث يناسب منتج Cybersecurity. فكان عندنا توازن بين readability والهوية البصرية."

---

## 31. لو اتسألت: "الألوان معمولة إزاي؟"

ممكن تجاوب:

"الألوان متقسمة إلى palette tokens و semantic tokens داخل `colors.css`. ده خلانا نغيّر الـ dark/light theme من مكان واحد، وكل المكونات تعتمد على متغيرات مثل `--bg-primary` و `--text-primary` بدل ألوان مكتوبة مباشرة."

---

## 32. لو اتسألت: "إيه اللي موجود في App.jsx؟"

جاوب باختصار:

- إدارة الصفحات الحالية
- تحليل الـ hash
- حماية الصفحات حسب حالة المستخدم
- إدارة الـ splash screen
- إدارة scroll progress
- تشغيل reveal animations
- تحميل الصفحات بشكل lazy

يعني `App.jsx` هو مركز التحكم العام للواجهة.

---

## 33. لو اتسألت: "إيه الفرق بين الفرونت والباك هنا؟"

### الفرونت

- عرض البيانات
- استقبال مدخلات المستخدم
- إدارة التنقل
- عرض الـ reports والـ dashboards

### الباك

- المصادقة
- حماية البيانات
- تنفيذ المنطق الأمني
- جلب البيانات الخارجية
- إدارة MongoDB
- فرض صلاحيات الأدمن

---

## 34. ملاحظات مهمة لاحظتها وأنا براجع

- فيه ملف عربي قديم `PROJECT_OVERVIEW_AR.md` لكن ترميزه باين إنه بايظ، لذلك الملف الحالي أنضف للشرح.
- المشروع داخل فولدر `threat-hunters-app` وليس جذر المساحة.
- المشروع يستخدم hash routing يدوي بدل React Router.
- الثيم الافتراضي في `ThemeContext` هو `light`.
- ملفات CSS فيها شغل بصري كثير ومقصود، خصوصًا `HomePage.css`.

---

## 35. أوامر تشغيل المشروع

من داخل `threat-hunters-app`:

```bash
npm install
npm run dev
```

### أوامر مفيدة

```bash
npm run build
npm run lint
python -m unittest discover -s Back-end/tests -p "test_*.py"
```

---

## 36. خلاصة سريعة جدًا

لو عايز تلخص المشروع في دقيقة:

"Threat Hunters هو نظام Cybersecurity Full-Stack مبني بـ React و Flask و MongoDB. الواجهة فيها نظام تصميم منظم يعتمد على Manrope للنصوص و Space Grotesk للعناوين، مع dark/light theme مبني على color tokens. التطبيق يقدم Website Scanning و Security Awareness و Blog و Dashboard و Admin Panel. الفرونت مسؤول عن تجربة الاستخدام والتنقل، والباك مسؤول عن المصادقة والمنطق الأمني والصلاحيات والتكامل مع البيانات الخارجية."

---

## 37. ملفات مهمة تذاكرها قبل المناقشة

- [src/App.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/App.jsx:1)
- [src/index.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/index.css:1)
- [src/styles/colors.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/styles/colors.css:1)
- [src/context/ThemeContext.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/context/ThemeContext.jsx:1)
- [src/context/AuthContext.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/context/AuthContext.jsx:1)
- [src/services/api.js](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/services/api.js:1)
- [src/components/HomePage.jsx](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/components/HomePage.jsx:1)
- [src/components/HomePage.css](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/src/components/HomePage.css:1)
- [Back-end/Backend/app.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/app.py:1)
- [Back-end/Backend/config.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/config.py:1)
- [Back-end/Backend/routes/auth_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/auth_routes.py:1)
- [Back-end/Backend/routes/security_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/security_routes.py:1)
- [Back-end/Backend/routes/scanner_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/scanner_routes.py:1)
- [Back-end/Backend/routes/blog_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/blog_routes.py:1)
- [Back-end/Backend/routes/admin_routes.py](/C:/Users/mm56m/OneDrive/Desktop/front_grad/threat-hunters-app/Back-end/Backend/routes/admin_routes.py:1)

---

## 38. لو تحب تكمل بعد ده

أقدر في خطوة تانية أعمل لك واحد من دول:

1. `ملف أسئلة وأجوبة للمناقشة`
2. `ملخص 2-3 صفحات فقط للحفظ السريع`
3. `شرح Page by Page لكل Component`
4. `شرح Backend routes + services بتفصيل أكبر`
