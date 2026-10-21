# Three-Layer ISO 32000-1 PDF Watermarking Engine

Instructors and academies distributing educational PDFs in Iran lose revenue when a single purchased file is forwarded across Telegram channels. Furthermore, relying on external native C binaries (such as Ghostscript or Cairo) causes installation failures on standard Windows machines.

We decided to implement a pure-Python ISO 32000-1 (`%PDF-1.4`) multi-page document and forensic watermarking engine (`vault/pdf_stamper.py`) that embeds three independent layers into every generated PDF in under 5 milliseconds: (1) a 45-degree rotated diagonal translucent watermark matrix across the center of each page, (2) top and bottom forensic attribution banners containing the buyer's phone number, license code, and timestamp, and (3) a deterministic `SHA-256` cryptographic fingerprint in the PDF `/Info` trailer dictionary (`/Subject` and `/Keywords`) so leaked files remain traceable even if page margins are cropped.
