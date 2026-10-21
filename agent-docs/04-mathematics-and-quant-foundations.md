# 🧮📈 ستون‌های هفت‌گانه ریاضیات مهندسی، فیلتر کالمن و معیار کِلی (`04-mathematics-and-quant-foundations.md`)

## 🧮 ۱۱. تسلط ریاضیاتی سطح ۰.۰۱٪ برای دانشمند کامپیوتر و مهندس سیستم (`Sovereign Mathematical Mastery for Computer Scientists & Systems Engineers — The 7 Mathematical Pillars`)

یک مهندس و دانشمند کامپیوترِ «شماره یک» (`Number One`) هیچ‌گاه به کد به چشم متن نگاه نمی‌کند؛ بلکه هر الگوریتم، پروتکل و سیستم را به چشم یک **ساختار ریاضی دقیق** می‌بیند. این ۷ ستون ریاضیات مهندسی و علوم کامپیوتر بر پایه معتبرترین منابع دانشگاهی جهان (`MIT`, `Stanford`, `Caltech`, `NIST`) در حافظه دائمی ایجنت حک شده‌اند:

### ۱۱.۱ ریاضیات گسسته، ترکیبیات، نظریه گراف و تحلیل مجانبی (`Discrete Math, Combinatorics, Graph Theory & Asymptotics`)
- **منابع مرجع رسمی:**
  - **MIT `6.042J / 6.1200J` — *Mathematics for Computer Science*** (Eric Lehman, F. Thomson Leighton & Albert R. Meyer) | `https://ocw.mit.edu/courses/6-042j-mathematics-for-computer-science-spring-2015/`
  - ***Concrete Mathematics: A Foundation for Computer Science*** (Ronald L. Graham, Donald E. Knuth & Oren Patashnik)
- **معادلات و قضایای بنیادین در طراحی سیستم:**
  - **توابع مولد (`Generating Functions`):** تبدیل دنباله‌های بازگشتی پیچیده به سری‌های توانی $G(z) = \sum_{n=0}^{\infty} a_n z^n$ برای استخراج فرم بسته (`Closed-Form`) پیچیدگی الگوریتم‌ها.
  - **قضیه اصلی بازگشت‌ها (`Master Theorem`) و تقریب استرلینگ / اویلر-مکلورن:** تحلیل دقیق مرزهای $\Theta(f(n))$، $\mathcal{O}(f(n))$ و $\Omega(f(n))$ و بهینه‌سازی مسیرهای داغ (`Hot Path`) به زمان اجرای $\mathcal{O}(1)$ و $\mathcal{O}(\log n)$.
  - **نظریه گراف و جریان شبکه (`Max-Flow Min-Cut Theorem` — Ford-Fulkerson):** بیشینه‌ی نرخ انتقال داده در یک شبکه دقیقاً برابر با کمینه‌ی ظرفیت برش (`Minimum Cut`) گلوگاه‌های آن است؛ مبنای مسیریابی چندمسیره و توزیع بار در شبکه‌های توزیع‌شده.

### ۱۱.۲ جبر خطی کاربردی، نظریه طیفی و تجزیه ماتریس (`Applied Linear Algebra, Spectral Theory & Matrix Decomposition`)
- **منابع مرجع رسمی:**
  - **MIT `18.06` & `18.065` — *Linear Algebra and Learning from Data*** (Prof. Gilbert Strang) | `https://github.com/mitmath/18065`
  - **Stanford — *Introduction to Applied Linear Algebra: Vectors, Matrices, and Least Squares*** (Stephen Boyd & Lieven Vandenberghe) | `https://web.stanford.edu/~boyd/vmls/`
- **معادلات و قضایای بنیادین در طراحی سیستم:**
  - **تجزیه مقادیر منفرد (`Singular Value Decomposition — SVD`):** هر ماتریس $A \in \mathbb{R}^{m \times n}$ به فرم $A = U \Sigma V^T$ تجزیه می‌شود؛ بر اساس قضیه‌ی `Eckart–Young–Mirsky`، نگه‌داشتن $k$ مقدار منفرد بزرگ‌تر ($\sigma_1 \ge \dots \ge \sigma_k$) بهترین تقریب کم‌رتبه (`Low-Rank Approximation`) ممکن را در نُرم فروبنیوس و طیفی می‌دهد.
  - **نظریه طیفی گراف (`Spectral Graph Theory` & `Laplacian Matrix`):** ماتریس لاپلاسین گراف $L = D - A$ و دومین مقدار ویژه کوچک آن ($\lambda_2$ یا `Algebraic Connectivity / Fiedler Value`) معیار ریاضیِ مقاومت یک شبکه‌ی همتا-به-همتا (`P2P` مثل بیت‌کوین) در برابر تکه‌تکه شدن (`Network Partition / Eclipse Attack`) است.
  - **عدد شرط (`Condition Number`):** $\kappa(A) = \frac{\sigma_{\max}(A)}{\sigma_{\min}(A)}$ میزان حساسیت و پایداری عددی سیستم در برابر خطاهای گرد کردن ممیز شناور (`IEEE 754 Floating-Point Precision`) را تعیین می‌کند.

### ۱۱.۳ نظریه احتمال، فرآیندهای تصادفی، زنجیره مارکوف، حساب ایتو و نظریه صف (`Probability, Stochastic Processes, Itô Calculus & Queueing Theory`)
- **منابع مرجع رسمی:**
  - **MIT `6.042J` Probability Modules** & **Harvard `Math 154` Probability Theory** | `https://people.math.harvard.edu/~knill/teaching/math154/handouts/probability-theory-2025.pdf`
  - ***Applied Stochastic Differential Equations*** (Simo Särkkä & Arno Solin) | `https://users.aalto.fi/~asolin/sde-book/sde-book.pdf`
- **معادلات و قضایای بنیادین در طراحی سیستم:**
  - **نابرابری‌های تمرکز (`Concentration Inequalities — Chernoff & Hoeffding Bounds`):**
    $$\Pr\left[\left|\frac{1}{n}\sum_{i=1}^n X_i - \mu\right| \ge \varepsilon\right] \le 2\exp\left(-2n\varepsilon^2\right)$$
    مبنای ریاضی برای تشخیص سریع سرورهای خراب (`Zombie Eviction`) و تصمیم‌گیری آماری با کمترین نمونه‌برداری ممکن.
  - **قانون لیتل (`Little's Law`) و فرمول پولانچک-خینچین (`Pollaczek–Khinchine Formula`):** در هر سیستم صف پایدار، میانگین تعداد درخواست‌های در حال پردازش برابر است با $L = \lambda W$؛ و زمانی که نرخ ورود $\lambda$ به ظرفیت سرویس $\mu$ نزدیک شود ($\rho = \lambda/\mu \to 1$)، تاخیر صف به صورت غیرخطی و انفجاری با $\frac{\rho}{1-\rho}$ رشد می‌کند (علت ریاضی نیاز به استخر سوکت‌های پیش‌گرم‌شده و `Concurrency Cap`).
  - **حساب تصادفی و لم ایتو (`Itô's Lemma`):** برای فرآیند تصادفی $dX_t = \mu_t dt + \sigma_t dW_t$، دیفرانسیل تابع $f(X_t)$ برابر است با $df(X_t) = f'(X_t)dX_t + \frac{1}{2}\sigma_t^2 f''(X_t)dt$؛ سنگ‌بنای مدل‌سازی نویز، فیلتر کالمن و ریاضیات مالی/الگوریتمی.

### ۱۱.۴ نظریه اطلاعات شانون، آنتروپی و نظریه کدگذاری (`Shannon Information Theory, Entropy & Statistical Indistinguishability`)
- **منابع مرجع رسمی:**
  - **Claude E. Shannon (1948) — *A Mathematical Theory of Communication*** & ***(1949) Communication Theory of Secrecy Systems***
  - **Caltech `EE/CS` Information Theory Curriculum** | `https://www.catalog.caltech.edu/archive/2024-25/2024-25/department/EE/`
- **معادلات و قضایای بنیادین در طراحی سیستم:**
  - **آنتروپی شانون (`Shannon Entropy`):** $H(X) = -\sum_{x} P(x) \log_2 P(x)$ (حداکثر ۸.۰۰ بیت بر بایت برای جریان کاملاً تصادفی/رمزنگاری‌شده).
  - **واگرایی کولبک-لیبلر (`Kullback–Leibler Divergence`):**
    $$D_{\text{KL}}(P \parallel Q) = \sum_{x} P(x) \log_2 \left(\frac{P(x)}{Q(x)}\right)$$
    معیار طلایی در استتار ترافیک ضد فیلترینگ (`Traffic Morphing`): اگر توزیع طول پکت‌ها و فاصله زمانی بین پکت‌های تونل ما ($P$) نسبت به ترافیک عادی وب‌گردی ($Q$) دارای $D_{\text{KL}}(P \parallel Q) \to 0$ باشد، بر اساس قضیه‌ی `Neyman–Pearson` هیچ فایروال هوش مصنوعی در جهان نمی‌تواند ترافیک ما را از ترافیک عادی تشخیص دهد!
  - **ظرفیت کانال شانون-هارتلی (`Shannon–Hartley Theorem`):** $C = B \log_2\left(1 + \frac{S}{N}\right)$.

### ۱۱.۵ جبر مجرد، نظریه اعداد، خم‌های بیضوی و رمزنگاری مشبکه‌ی پسا-کوانتومی (`Abstract Algebra, ECC & Post-Quantum Lattice Cryptography`)
- **منابع مرجع رسمی:**
  - **Stanford — *A Graduate Course in Applied Cryptography*** (Prof. Dan Boneh & Prof. Victor Shoup) | `https://toc.cryptobook.us/`
  - **NIST Post-Quantum Standards (`FIPS 203 ML-KEM`, `FIPS 204 ML-DSA`, `FIPS 205 SLH-DSA`)** | `https://csrc.nist.gov/`
- **معادلات و قضایای بنیادین در طراحی سیستم:**
  - **میدان‌های متناهی (`Finite Fields` $\mathbb{F}_p, \text{GF}(2^n)$) و خم‌های بیضوی مونتگومری (`Curve25519` — `RFC 7748`):** معادله $By^2 = x^3 + Ax^2 + x \pmod{2^{255}-19}$ با نردبان مونتگومری (`Montgomery Ladder`) که در زمان ثابت (`Constant-Time`) اجرا می‌شود تا حملات کانال جانبی زمانی (`Timing Side-Channel Attacks`) از نظر ریاضی ناممکن شوند.
  - **ریاضیات مشبکه پسا-کوانتومی (`Module-Learning-With-Errors — M-LWE` در `X25519MLKEM768` / `FIPS 203`):** محاسبات روی حلقه چندجمله‌ای‌های سیکلوتومیک $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ با اولِ $q = 3329$، که در آن ضرب چندجمله‌ای‌ها با استفاده از **تبدیل نظریه‌ی اعداد (`Number Theoretic Transform — NTT`)** از پیچیدگی $\mathcal{O}(n^2)$ به $\mathcal{O}(n \log n)$ کاهش می‌یابد و در برابر الگوریتم کوانتومی شُور (`Shor's Algorithm`) کاملاً مقاوم است.

### ۱۱.۶ ریاضیات مهندسی، معادلات دیفرانسیل، تبدیل فوریه، تبدیل لاپلاس و پردازش سیگنال (`Engineering Analysis: ODEs/PDEs, Fourier & Laplace Transforms`)
- **منابع مرجع رسمی:**
  - **MIT `6.003` — *Signals and Systems: Fourier & Laplace Transforms*** | `https://ocw.mit.edu/courses/6-003-signals-and-systems-fall-2011/`
  - **Stanford `EE261` — *The Fourier Transform and Its Applications*** (Prof. Brad Osgood)
- **معادلات و قضایای بنیادین در طراحی سیستم (قلب تپنده‌ی مهندسی نیکولا تسلا):**
  - **تبدیل لاپلاس (`Laplace Transform`):**
    $$\mathcal{L}\{f(t)\} = F(s) = \int_{0}^{\infty} f(t)e^{-st}\,dt, \quad s = \sigma + j\omega$$
    معادلات دیفرانسیل خطی تغییرناپذیر با زمان (`LTI Differential Equations`) را از حوزه زمان ($t$) به معادلات جبری در حوزه فرکانس مختلط ($s$) تبدیل می‌کند. یک سیستم کنترل یا حلقه بازخورد زمانی و تنها زمانی **پایدار مجانبی (`BIBO Stable`)** است که تمام قطب‌های تابع تبدیل $H(s) = \frac{Y(s)}{X(s)}$ در نیم‌صفحه‌ی چپِ صفحه مختلط قرار داشته باشند ($\text{Re}(s_p) = \sigma < 0$).
  - **تبدیل فوریه و الگوریتم `FFT` (`Cooley–Tukey Fast Fourier Transform`):**
    $$X(j\omega) = \int_{-\infty}^{\infty} x(t)e^{-j\omega t}\,dt$$
    تجزیه هر سیگنال زمانی به طیف فرکانس‌های هارمونیک آن در زمان $\mathcal{O}(N \log N)$؛ ابزار ریاضی برای کشف الگوهای تناوبی (مثل ضربان‌های قلب قابل شناسایی توسط فایروال DPI) و حذف آن‌ها با طیف گسترده (`Spread-Spectrum Jitter`).
  - **قضیه نمونه‌برداری نایکوئیست-شانون (`Whittaker–Shannon Sampling Theorem`):** بازسازی کامل سیگنال با پهنای باند $B$ نیازمند نرخ نمونه‌برداری $f_s > 2B$ است.

### ۱۱.۷ بهینه‌سازی محدب، نظریه دوگانگی و کنترل بهینه (`Convex Optimization, Lagrangian Duality & Optimal Control`)
- **منابع مرجع رسمی:**
  - **Stanford `EE364a` — *Convex Optimization*** (Prof. Stephen Boyd & Prof. Lieven Vandenberghe) | `https://web.stanford.edu/class/ee364a/`
  - **Stanford `EE263` — *Introduction to Linear Dynamical Systems*** (Prof. Stephen Boyd)
- **معادلات و قضایای بنیادین در طراحی سیستم:**
  - **بهینه‌سازی محدب (`Convex Optimization`):** هر کمینه‌ی محلی در یک تابع محدب ($\nabla^2 f(x) \succeq 0$) روی یک مجموعه‌ی محدب، تضمین‌شده **کمینه‌ی سراسری (`Global Optimum`)** است.
  - **شرایط بهینگی کاروش-کان-تاکر (`KKT Optimality Conditions`) و روش‌های نقطه داخلی (`Interior-Point Barrier Methods`):** حل مسائل تخصیص منابع، مسیریابی با کمترین تاخیر، و تنظیم خودکار پارامترهای سیستم در کسری از میلی‌ثانیه.

### ۱۱.۸ مقالات بنیادین ریاضیات کوانت، فیلترینگ کالمن، نظریه اطلاعات کِلی و میکروساختار بازار (`Primary Quantitative & Filtering Papers — Full-Text Digested`)
- **۱. معیار کِلی و نرخ انتقال اطلاعات (`Kelly Criterion` — J. L. Kelly Jr., *"A New Interpretation of Information Rate"*, *Bell System Technical Journal*, Vol. 35, No. 4, pp. 917–926, July 1956 & E. O. Thorp Continuous Extension):**
  - **منبع کامل:** `https://cpb-us-w2.wpmucdn.com/u.osu.edu/dist/7/36891/files/2017/07/Kelly1956-1uwz47o.pdf`
  - **اثبات و معادلات کلیدی:** بیشینه‌سازی امید ریاضی خطی ثروت $\mathbb{E}[V_N]$ با شرط‌بندی کل سرمایه ($\ell = 1$) طبق قانون اعداد بزرگ با احتمال ۱ به ورشکستگی کامل ($\lim_{N\to\infty} V_N = 0$) می‌انجامد. چون لگاریتم در تکرار شرط‌ها خاصیت جمع‌پذیری دارد ($\log(V_N/V_0) = \sum \log(1 + \ell R_i)$)، بیشینه‌سازی نرخ رشد نمایی $G = \lim_{N\to\infty} \frac{1}{N}\log_2(V_N/V_0)$ منجر به فرمول بهینه کِلی می‌شود:
    $$\ell^* = \frac{q b - p}{b} = q - \frac{1 - q}{b}, \qquad f_{\text{continuous}}^* = \frac{\mu - r}{\sigma^2}, \qquad f_{\text{Half-Kelly}} = \frac{1}{2}f^*$$
    و در حالت چندگزینه‌ای با کارمزد بازار (`Track Take`، معادلات ۲ و ۳ صفحه ۹۲۴–۹۲۶)، تخصیص بهینه روی گزینه‌های مرتب‌شده $p(s)\alpha_s \ge p(s+1)\alpha_{s+1}$ برابر است با $a^*(s) = \max\left(0, p(s) - \frac{b}{\alpha_s}\right)$ که در آن $b = \min_{t} \frac{1 - p_t}{1 - \sigma_t}$ کسری از سرمایه است که باید نقد نگه داشته شود.
- **۲. فیلتر خطی و پیش‌بینی بهینه کالمن (`Kalman Filter` — R. E. Kálmán, *"A New Approach to Linear Filtering and Prediction Problems"*, *Transactions of the ASME — Journal of Basic Engineering*, Vol. 82, Series D, pp. 35–45, March 1960):**
  - **منبع کامل:** `https://www.unitedthc.com/DSP/Kalman1960.pdf`
  - **اثبات و معادلات کلیدی (قضیه ۳، معادلات ۱۸ تا ۳۲):** بر اساس تصویر متعامد (`Orthogonal Projection`) روی زیرفضای خطی تولیدشده توسط بردار نوآوری (`Innovation`) $\tilde{\mathbf{y}}(t|t-1) = \mathbf{y}(t) - \mathbf{M}(t)\mathbf{x}^*(t|t-1)$، بهره بهینه کالمن ($\boldsymbol{\Delta}^*(t)$) و معادله تفاضلی غیرخطی ریکاتی (`Discrete Riccati Equation`) برای ماتریس کوواریانس خطا ($\mathbf{P}^*(t)$) عبارتند از:
    $$\boldsymbol{\Delta}^*(t) = \boldsymbol{\Phi}(t+1;t)\mathbf{P}^*(t)\mathbf{M}'(t)\left[\mathbf{M}(t)\mathbf{P}^*(t)\mathbf{M}'(t) + \mathbf{R}(t)\right]^{-1}$$
    $$\mathbf{P}^*(t+1) = \boldsymbol{\Phi}(t+1;t)\left\{\mathbf{P}^*(t) - \mathbf{P}^*(t)\mathbf{M}'(t)\left[\mathbf{M}(t)\mathbf{P}^*(t)\mathbf{M}'(t) + \mathbf{R}(t)\right]^{-1}\mathbf{M}(t)\mathbf{P}^*(t)\right\}\boldsymbol{\Phi}'(t+1;t) + \mathbf{Q}(t)$$
    و در پیاده‌سازی عددی از فرم پایدار جوزف (`Bucy–Joseph Stabilized PSD Form`) $\mathbf{P}_{k|k} = (\mathbf{I} - \mathbf{K}_k\mathbf{H}_k)\mathbf{P}_{k|k-1}(\mathbf{I} - \mathbf{K}_k\mathbf{H}_k)^T + \mathbf{K}_k\mathbf{R}_k\mathbf{K}_k^T$ استفاده می‌شود تا ماتریس کوواریانس در برابر خطای ممیز شناور همواره متقارن و معین مثبت بماند.
- **۳. فرآیند بازگشت به میانگین اورنشتاین-اولنبک و سمیت جریان سفارشات نهنگ‌ها (`Ornstein–Uhlenbeck SDE, EWMA Order Flow Imbalance & VPIN` — K. Bechler & M. Ludkovski, `arXiv:1409.2618` & Easley, López de Prado, O'Hara, *Review of Financial Studies*, 2012):**
  - **منبع کامل:** `https://arxiv.org/html/1409.2618`
  - **اثبات و معادلات کلیدی (معادلات ۲، ۳۰، ۳۱ و ۳۲):** عدم تعادل جریان سفارشات ($Y_t^0$) از معادله دیفرانسیل تصادفی اورنشتاین-اولنبک $dY_t^0 = -\beta Y_t^0 dt + \sigma dW_t$ با واریانس مانا $\frac{\sigma^2}{2\beta}$ و نیمه‌عمر بازگشت به میانگین $t_{1/2} = \frac{\ln 2}{\beta}$ پیروی می‌کند. در فضای حجمی گسسته، شاخص عدم تعادل نمایی حجم-وزن (`EWMA Flow Imbalance`، معادله ۳۰) و شاخص احتمال معاملات آگاهانه نهنگ‌ها (`VPIN`، معادلات ۳۱ و ۳۲) عبارتند از:
    $$I_{k+1} = e^{-\beta |V_k|} I_k + \left(1 - e^{-\beta |V_k|}\right)\operatorname{sgn}(V_k) \in [-1, 1]$$
    $$\tilde{I}_\ell := \frac{V_\ell^B - V_\ell^S}{V} = \frac{2V_\ell^B}{V} - 1, \qquad \text{VPIN}_\ell = \frac{1}{n}\sum_{k=\ell-n}^{\ell-1} |\tilde{I}_k| \in [0, 1]$$

---

