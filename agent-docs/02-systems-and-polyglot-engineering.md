# 🏛️🖥️ معماری ماژول‌های عمیق، کد تمیز (`DRY/SRP`)، طراحی `Linear` و نقشه اسکیل‌ها (`02-systems-and-polyglot-engineering.md`)

## 🏛️ ۴. قدرت سوم: معماری ماژول‌های عمیق، TDD محض و استاندارد طلایی کدنویسی (`Power #3: Deep Modules, Strict TDD & Golden Clean-Code Law`)

تو در نوشتن کد، سخت‌گیرترین و تمیزترین استانداردهای مهندسی نرم‌افزار جهان را اجرا می‌کنی:

1. **قانون تغییرناپذیر کامنت‌های `WHY`، نام‌گذاری گویا، `Clean Code`، `DRY` و `SRP` (`The Standing Law of WHY-Driven Clean Code, DRY & SRP`):**
   - **قانون مطلق «صفر فارسی در سورس‌کد» (`100% English Source Code — Persian Only in Chat Reports`):** فقط و فقط گزارش‌ها و توضیحات گفتگو با کاربر در چت باید به زبان فارسی باشد. در داخل سورس‌کد (`.py`, `.js`, `.css`, `.html`, `.bat`, تست‌ها، متن‌های رابط کاربری، کامنت‌ها و شناسه‌ها) **در هیچ کجا حتی یک کاراکتر فارسی نباید وجود داشته باشد.**
   - **۱۰۰٪ انگلیسی و مبتنی بر چرایی (`WHY, Never Merely WHAT`):** تمام کامنت‌ها و داک‌استرینگ‌ها در تمام فایل‌های سورس‌کد باید به زبان **انگلیسی**، استاندارد و دقیقاً مبتنی بر چرایی (`WHY`) باشند (الزام پروتکلی، رفتار سرور هدف، محدودیت کرنل یا دلیل ریاضی) — هرگز آن چیزی را که خودِ سینتکس کد می‌گوید تکرار نکن و هرگز عبارت `"for ticket X"` را در کدها ننویس.
   - **اولویت مطلق با خوانایی کد (`Readability First & One Statement Per Line`):** هرگز سعی نکن چند خط کد را در یک خط جا بدهی. کد باید خط‌به‌خط، باز، تمیز و بسیار خوانا نوشته شود.
   - **نام‌های گویا و خودتوصیف‌گر (`Meaningful Identifiers`):** همیشه از نام‌های کامل و معنادار برای توابع، متغیرها و کلاس‌ها استفاده کن (`fetch_catalog_page`, `compute_price_diff_report`, `changed_product_records`, `client_reader`) و هرگز متغیرهای یک‌حرفی (`r, w, c`) یا مبهم ننویس.
   - **رعایت سخت‌گیرانه `Best Practice`، `DRY` و `SRP` (`Single Responsibility Principle`):** هر ماژول، کلاس و تابع باید فقط و فقط یک مسئولیت مشخص داشته باشد (`SRP`) و هیچ منطق یا فرمولی در کدبیس تکرار نشود (`DRY`).
2. **استفاده بهینه از آخرین استانداردهای پایتون `3.13–3.15` و کتابخانه‌های مدرن:**
   - استفاده از تایپینگ مدرن `PEP 604` (`X | None` به جای `Optional[X]`) و `PEP 585` (`collections.abc.AsyncIterator`, `Callable`, `Coroutine`).
   - استفاده از `socket.inet_pton(socket.AF_INET, ...)` به جای `inet_aton` منسوخ.
   - استفاده از `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` مستقیم برای کاوشگرهای بدون گواهی (`CERT_NONE`)، بستن تمیز استریم‌ها با `close_stream_writer()` (`close()` + `await wait_closed()`)، استخر اتصال پایدار `httpx.AsyncClient(trust_env=False)`، پیکربندی `Pydantic v2 ConfigDict(str_strip_whitespace=True, extra="forbid")` و `Uvicorn server_header=False`.

---

## 🖥️ ۵. قدرت چهارم: طراحی رابط کاربری به سبک `Linear` (تم روشن `Light Theme`) و مثلث طلایی کیفیت وب (`Power #4: Linear Light-Mode UI/UX & Web Excellence`)

1. **سیستم طراحی `Linear Light-Mode` (`Linear.app Aesthetic in Crisp Light Mode`):**
   - طراحی رابط کاربری وب‌اپلیکیشن‌ها بر اساس زبان طراحی تحسین‌شده‌ی **`Linear` (`linear.app`) در تم روشن (`Light Theme`)** انجام می‌شود: پس‌زمینه روشن و تمیز (`#F7F8F9` و `#FFFFFF`)، خطوط جداکننده ۱ پیکسلی ظریف (`1px solid #EAECEF` / `#DFE2E6`)، تایپوگرافی انگلیسی فوق‌خوانا (`Inter` و `Geist` به همراه `font-variant-numeric: tabular-nums` برای تراز پیکسلی اعداد)، نشانگرهای معنایی تغییر وضعیت و بدون هیچ‌گونه شلوغی بصری.
2. **مثلث طلایی کیفیت وب‌اپلیکیشن (`Best Practices + Best Performance + Best Accessibility`):**
   - هر وب‌اپلیکیشن باید با نهایت دقت مهندسی و تست شود تا در هر سه معیار بالاترین نمره را کسب کند:
     - **`Best Practices`:** صفر `innerHTML`/`eval` در جاوااسکریپت، صفر `!important` در CSS، مدیریت کامل خطاهای شبکه و استیت‌ها.
     - **`Best Performance`:** رندر دسته‌ای با `DocumentFragment` در کمتر از `16ms`، صفر پرش چیدمان (`CLS = 0`)، فونت‌های آفلاین باندل‌شده و جستجوی $O(1)$.
     - **`Best Accessibility`:** تگ‌های معنایی HTML5 (`<header>`, `<main>`, `<table>`, `<th scope="col">`)، کنتراست استاندارد WCAG AA/AAA، ناوبری کامل کیبورد (`:focus-visible`) و اعلان زنده (`aria-live="polite"`).
3. **بنر رنگی ASCII و منوی عمودی کلیدهای میانبر در ترمینال (`Colorized ANSI CLI & Vertical Hotkey Menu`):**
   - چاپ بنر هنری ASCII با رنگ‌بندی استاندارد ANSI و نمایش **عمودی (`Vertical Menu`)** کلیدهای میانبر در ترمینال.

---

## 🔄 ۶. قدرت پنجم: سند زنده `FEATURES.md` و قانون جایگزینی فایل ZIP در هر نسخه جدید (`Power #5: Living Catalog & Single-ZIP Replacement Law`)

1. **به‌روزرسانی خودکار سند زنده (`FEATURES.md` & `docs/FEATURES.md`):**
   - به محض اضافه شدن هر قابلیت جدید، بدون نیاز به یادآوری کاربر، هر دو فایل `/home/user/aethergate-vpn/FEATURES.md` و `/home/user/aethergate-vpn/docs/FEATURES.md` و شماره نسخه در `constants.py`، `start_aethergate.bat` و `run-windows.bat` (با فرمت ویندوزی `CRLF` و `chcp 65001 >nul`) به‌روزرسانی می‌شوند.
2. **قانون تغییرناپذیر جایگزینی فایل ZIP (`Single Active Version ZIP Law`):**
   - **در هر بار انتشار نسخه جدید، فایل ZIP جدید باید جایگزین فایل‌های ZIP قدیمی آن پروژه شود** تا فضای کاری از فایل‌های زیپ نسخه‌های قبلی (`v9.8`, `v10.0`, ... و نسخه‌های قدیمی‌تر) شلوغ نشود. همیشه فقط **یک فایل ZIP آخرین نسخه** (`/home/user/aethergate-vpn-v<LATEST>-windows.zip`) برای پروژه نگه داشته شود و نسخه‌های قبلی حذف گردند.
3. **تک‌نسخه‌ای بودن منشور ایجنت (`Single Canonical AGENT.md Law`):**
   - فقط یک فایل `AGENT.md` واحد وجود دارد (نه دو فایل جداگانه `AGENT.md` و `AGENTS.md`).

---

## 🧭 ۷. نقشه کامل مهارت‌های مهندسی و طراحی در فضای کاری (`Matt Pocock & Impeccable Skill Map — Idea → Ship`)

1. **`/grill-with-docs`** (`skills/engineering/grill-with-docs/SKILL.md` + `skills/productivity/grilling/SKILL.md` + `skills/engineering/domain-modeling/SKILL.md`)
   - مصاحبه مرحله‌ای در مرز تصمیم‌گیری‌های طراحی (`GLOSSARY.md` + `docs/adr/NNNN-slug.md`).
2. **`/prototype`** (`skills/engineering/prototype/SKILL.md`)
   - نمونه‌سازی سریع منطق (`LOGIC.md`) و رابط کاربری (`UI.md`).
3. **`/to-spec` & `/to-tickets`** (`skills/engineering/to-spec/SKILL.md`, `skills/engineering/to-tickets/SKILL.md`)
   - تبدیل طراحی به مشخصات فنی (`.scratch/<feature-slug>/spec.md`) و برش‌های عمودی (`Tracer-Bullet Vertical Slices`).
4. **`/implement`, `/tdd` & `/codebase-design`** (`skills/engineering/implement/SKILL.md`, `skills/engineering/tdd/SKILL.md`, `skills/engineering/codebase-design/SKILL.md`)
   - پیاده‌سازی تیکت‌به‌تیکت با چرخه **Red-Green-Refactor TDD** و طراحی **ماژول‌های عمیق (`Deep Modules`)**.
5. **`/impeccable`** (`skills/design/impeccable/SKILL.md` + `skills/design/impeccable/reference/*.md`)
   - ظرافت تایپوگرافی، کنتراست، حالت‌های تعاملی و قوانین ضد ظاهر هوش مصنوعی (`polish.md`, `critique.md`, `audit.md`, `operate.md`, `craft-floor.md`).
6. **`/code-review`, `/diagnosing-bugs` & `/retro`** (`skills/engineering/code-review/SKILL.md`, `skills/engineering/diagnosing-bugs/SKILL.md`, `skills/engineering/retro/SKILL.md`)
   - بازبینی دوگانه‌ی استاندارد و مشخصات، ریشه‌یابی علمی باگ‌ها، و بهبود مستمر محیط کاری.

### فهرست مسیر مهارت‌ها در `/home/user/skills/` (`Workspace Skill Index`)
- **Router & Map**: `skills/engineering/ask-matt/SKILL.md`
- **Frontend & Linear UI/UX Skills**: `skills/design/linear-light-ui/SKILL.md`, `skills/design/web-excellence-lighthouse/SKILL.md`, `skills/design/impeccable/SKILL.md`
- **Clean Code, DRY & SRP Skill**: `skills/engineering/clean-code-principles/SKILL.md`
- **Grilling & Domain Modeling**: `skills/productivity/grilling/SKILL.md`, `skills/engineering/grill-with-docs/SKILL.md`, `skills/engineering/domain-modeling/SKILL.md`
- **Planning & Specs**: `skills/engineering/wayfinder/SKILL.md`, `skills/engineering/to-spec/SKILL.md`, `skills/engineering/to-tickets/SKILL.md`
- **Prototyping & Architecture**: `skills/engineering/prototype/SKILL.md`, `skills/engineering/codebase-design/SKILL.md`, `skills/engineering/improve-codebase-architecture/SKILL.md`
- **Implementation, Testing & Quality**: `skills/engineering/tdd/SKILL.md`, `skills/engineering/implement/SKILL.md`, `skills/engineering/implement-spec/SKILL.md`, `skills/engineering/code-review/SKILL.md`, `skills/engineering/diagnosing-bugs/SKILL.md`
- **Supporting Skills**: `skills/productivity/wait-what/SKILL.md`, `skills/productivity/handoff/SKILL.md`, `skills/productivity/to-questionnaire/SKILL.md`, `skills/engineering/research/SKILL.md`, `skills/engineering/wizard/SKILL.md`, `skills/engineering/retro/SKILL.md`

---

