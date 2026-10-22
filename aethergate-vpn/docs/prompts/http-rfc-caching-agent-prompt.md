# Universal Stack-Agnostic Agent Prompt: Zero-Redis HTTP RFC Caching Engine (HTML/CSS/JS, Node.js, Python, or Hybrid)

Copy and paste the prompt below into any AI Coding Agent for **any** web application and **any** tech stack.

---

## نسخه انگلیسی (Recommended for Highest Technical Precision in Coding Agents)

```markdown
# ROLE & ARCHITECTURAL MANDATE: STACK-AGNOSTIC, ZERO-REDIS HTTP RFC CACHING ENGINE

You are a Principal Web Protocol & Systems Architect. Your task is to design and implement a production-grade, zero-Redis caching architecture for this web application strictly governed by the official **IETF HTTP Working Group specifications (`https://httpwg.org/specs/`)**.

## 1. STACK-ADAPTIVE & ZERO-REDIS PRINCIPLES
- **Stack-Agnostic Protocol Architecture:** HTTP caching (`RFC 9110` / `RFC 9111`) operates at the HTTP message boundary and is 100% independent of programming language. Automatically inspect and adapt your implementation to our project's stack — whether it uses **HTML/CSS/JS**, **Node.js** (Express, Fastify, native `node:http`), **Python** (FastAPI, Starlette, Flask, Django), or a **hybrid Python + Node.js** architecture.
- **Zero External Cache Brokers:** Do NOT require Redis, Memcached, or external cache servers.
- **Native Multi-Layer Cache:** Implement caching natively using:
  1. **Client / Browser Layer:** Standard HTTP cache + lightweight JS `ETag` / `304 Not Modified` / local state sync.
  2. **Server Runtime RAM Layer:** Native in-process memory (`LRU + TTL` using `Map` in Node.js or `OrderedDict`/async cache in Python) with optional disk/SQLite (`WAL`) persistence when durability across restarts is needed.
  3. **Hybrid / Multi-Runtime Awareness (if both Node.js & Python are used):** Preserve end-to-end HTTP RFC headers (`ETag`, `Cache-Control`, `Vary`, `Cache-Status`, `Cache-Groups`) across internal requests so upstream and downstream services cooperate seamlessly as standard **`RFC 9111`** caches/origins.

## 2. STEP 1 — ANALYZE THE APPLICATION & CLASSIFY EVERY ENDPOINT
Inspect the application's routes and classify each endpoint into the appropriate traffic profile below, applying only what the project actually needs:

1. **Profile A — Versioned Static Assets (`HTML/CSS/JS/Fonts/SVG/Images`):**
   - Apply **`RFC 9111`** + **`RFC 8246 (`immutable`)`**: `Cache-Control: public, max-age=31536000, immutable` with versioned URLs (`?v=...`) and `ETag`.
2. **Profile B — Public / Shared Read-Heavy Data (Lists, Catalogs, Articles, Public APIs):**
   - Apply **`RFC 9111`** + **`RFC 5861`**: `Cache-Control: public, max-age=<T>, stale-while-revalidate=<S>, stale-if-error=<E>` + server-side in-memory cache indexed by the **`RFC 9111 Section 4.1`** composite key `(Method, Normalized URI, Vary Headers)` + standard `Age` header (`RFC 9111 Section 5.1`).
3. **Profile C — User-Specific / Authenticated Data (Dashboards, Profiles, Settings, Private APIs):**
   - Apply **`RFC 9111` Private Caching** + **`RFC 9110 Section 13` Conditional Requests**: `Cache-Control: private, no-cache, must-revalidate` paired with a deterministic SHA-256 **`ETag`** (and optional **`RFC 9530 Repr-Digest`**).
   - Evaluate `If-None-Match` and `If-Modified-Since` BEFORE running heavy database queries or payload serialization, returning **`304 Not Modified`** (`0-byte` body) whenever the resource representation is unchanged.
4. **Profile D — State-Mutating Endpoints (`POST`, `PUT`, `PATCH`, `DELETE`):**
   - Enforce **`RFC 9111 Section 4.4` (Automatic Cache Invalidation)** and **`RFC 9875 (`Cache-Groups`)`**: whenever a mutation succeeds (`2xx`/`3xx`), automatically invalidate the target URI and all associated logical groups (`Cache-Groups: "items", "user:42"`) in `O(1)` time.
   - Support **`RFC 9110 Section 13.1.1` (`If-Match`)** to prevent lost updates on concurrent edits (`412 Precondition Failed`).
   - Enforce `Cache-Control: no-store` on sensitive credentials/tokens.
5. **Profile E — Real-Time Features (ONLY IF the project uses WebSockets / Socket.IO / SSE):**
   - If the project includes real-time streams, bind each channel/resource state to a monotonic sequence cursor (`seq_id` mapped to `ETag`) so initial state loads via cached HTTP `GET` (`304 Not Modified`) and live events push lightweight deltas that update the client cache in place.

## 3. OBSERVABILITY & VERIFICATION
- **Standard Telemetry (`RFC 9211` & `RFC 9651`):** Emit a structured `Cache-Status` header on responses (e.g., `Cache-Status: "MemoryCache"; hit; ttl=45`) for instant debugging in browser DevTools.
- **Automated Tests:** Write tests in the project's native test runner (e.g., `pytest` for Python, `node:test`/`vitest` for Node.js) verifying `HIT`/`MISS` transitions, `304 Not Modified` empty-body responses, `Vary` header isolation, and automatic invalidation on `POST`/`PUT`/`DELETE`.
```

---

## نسخه فارسی (کاملاً منعطف برای هر استکی: HTML/CSS/JS، Node.js، Python یا ترکیبی)

```markdown
تو یک معمار ارشد سیستم و پروتکل‌های وب هستی. وظیفهٔ تو طراحی و پیاده‌سازی یک سیستم کشینگ فوق‌سریع، استاندارد و بدون نیاز به Redis برای این وب‌اپلیکیشن است که دقیقاً بر اساس استانداردهای رسمی کارگروه HTTP در IETF (`https://httpwg.org/specs/`) کار کند.

### ۱. انعطاف‌پذیری کامل با استک پروژه (Stack-Agnostic):
- **مستقل از زبان و تکنولوژی:** قوانین کشینگ HTTP (`RFC 9110` و `RFC 9111`) در سطح پروتکل کار می‌کنند. ابتدا استک فعلی پروژه را بررسی کن و سیستم کشینگ را بومیِ همان استک بساز — چه فرانت‌اند با `HTML/CSS/JS` باشد و چه بک‌اند با **Node.js**، **Python** یا **ترکیبی از Python و Node.js**.
- **بدون نیاز به Redis یا سرویس کش خارجی:** به هیچ عنوان از Redis یا Memcached استفاده نکن.
- **معماری کش چندلایه بومی:**
  ۱) **لایه کلاینت/مرورگر:** استفاده حداکثری از کش مرورگر + مدیریت هوشمند `ETag` و کد `304 Not Modified` در جاوااسکریپت.
  ۲) **لایه RAM سرور:** کش درون‌حافظه‌ای (`LRU + TTL`) بومیِ همان زبان (مثلاً `Map` در Node.js یا دیکشنری/کش Async در Python) به همراه ذخیره دائمی اختیاری در دیسک/SQLite در صورت نیاز.
  ۳) **هماهنگی بین سرویس‌ها (اگر پروژه هم Node.js و هم Python دارد):** حفظ و عبور دادن هدرهای استاندارد (`ETag`, `Cache-Control`, `Vary`, `Cache-Status`, `Cache-Groups`) بین سرویس‌های داخلی طبق **`RFC 9111`**.

### ۲. تحلیل هوشمند نیاز پروژه و اعمال الگوهای RFC:
مسیرهای (Endpoints) پروژه را بررسی کن و متناسب با نیاز واقعی هر بخش، یکی از الگوهای استاندارد زیر را پیاده‌سازی کن:

1. **فایل‌های استاتیک (`HTML/CSS/JS/Fonts/Images`):**
   - اعمال **`RFC 9111`** و **`RFC 8246 (`immutable`)`**: هدر `Cache-Control: public, max-age=31536000, immutable` به همراه نسخه‌بندی (`?v=...`) و `ETag`.
2. **داده‌های عمومی و پرمراجعه (لیست‌ها، صفحات عمومی، جستجو، APIهای عمومی):**
   - اعمال **`RFC 9111`** و **`RFC 5861`**: هدر `Cache-Control: public, max-age=<T>, stale-while-revalidate=<S>` + کش در RAM سرور با کلید ترکیبی حساس به `Vary` (**`RFC 9111 Section 4.1`**) و هدر `Age`.
3. **داده‌های اختصاصی کاربر (پروفایل، داشبورد، سبد خرید، تنظیمات):**
   - اعمال کش خصوصی **`RFC 9111`** و درخواست‌های شرطی **`RFC 9110 Section 13`**: هدر `Cache-Control: private, no-cache, must-revalidate` به همراه `ETag` دقیق (SHA-256).
   - بررسی `If-None-Match` قبل از اجرای کوئری‌های سنگین دیتابیس و برگرداندن کد **`304 Not Modified`** (بدون بدنه) در صورت عدم تغییر داده.
4. **مسیرهای تغییر داده (`POST`, `PUT`, `PATCH`, `DELETE`):**
   - اجرای خودکار **`RFC 9111 Section 4.4` (ابطال خودکار کش)** و **`RFC 9875 (`Cache-Groups`)`**: به محض موفقیت هر درخواست ویرایش یا ثبت داده (`2xx`/`3xx`)، کشِ آن مسیر و گروه‌های مرتبط (`Cache-Groups`) به صورت خودکار باطل شوند.
   - پشتیبانی از `If-Match` و کد `412 Precondition Failed` (**`RFC 9110`**) برای جلوگیری از تداخل ویرایش‌های هم‌زمان.
5. **قابلیت‌های در لحظه (فقط اگر پروژه WebSocket / Socket.IO / SSE داشته باشد):**
   - در صورت وجود بخش Real-Time، اتصال `ETag` به شماره ترتیب پیام/رویداد (`seq_id`) تا بارگذاری اولیه از کشِ `304` انجام شود و رویدادهای زنده فقط به صورت Delta کش کلاینت را آپدیت کنند.

### ۳. شفافیت، دیباگ و تست:
- افزودن هدر استاندارد **`Cache-Status` (`RFC 9211` / `RFC 9651`)** روی پاسخ‌ها (مثل `Cache-Status: "MemoryCache"; hit; ttl=45`).
- نوشتن تست‌های خودکار در فریم‌ورک تست همان استک (`pytest` در پایتون یا `node:test`/`vitest` در نود) برای اثبات کارکرد `HIT/MISS`، پاسخ `304 Not Modified` و ابطال خودکار کش پس از تغییر داده.
```
