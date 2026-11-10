Impersonation & Fingerprints
============================

The following browser profiles are currently available as preset. We also offer an
extended list as an API on `impersonate.pro <https://impersonate.pro>`_. See :doc:`pro`.

.. csv-table::
   :header: "Browser", "Version", "OS", "Target name", "Wrapper script", "H3 fingerprints"

   "Chrome", "99", "Windows 10", "``chrome99``", "``curl_chrome99``", ""
   "Chrome", "100", "Windows 10", "``chrome100``", "``curl_chrome100``", ""
   "Chrome", "101", "Windows 10", "``chrome101``", "``curl_chrome101``", ""
   "Chrome", "104", "Windows 10", "``chrome104``", "``curl_chrome104``", ""
   "Chrome", "107", "Windows 10", "``chrome107``", "``curl_chrome107``", ""
   "Chrome", "110", "Windows 10", "``chrome110``", "``curl_chrome110``", ""
   "Chrome", "116", "Windows 10", "``chrome116``", "``curl_chrome116``", ""
   "Chrome", "119", "macOS Sonoma", "``chrome119``", "``curl_chrome119``", ""
   "Chrome", "120", "macOS Sonoma", "``chrome120``", "``curl_chrome120``", ""
   "Chrome", "123", "macOS Sonoma", "``chrome123``", "``curl_chrome123``", ""
   "Chrome", "124", "macOS Sonoma", "``chrome124``", "``curl_chrome124``", ""
   "Chrome", "131", "macOS Sonoma", "``chrome131``", "``curl_chrome131``", ""
   "Chrome", "133", "macOS Sequoia", "``chrome133a``", "``curl_chrome133a``", ""
   "Chrome", "136", "macOS Sequoia", "``chrome136``", "``curl_chrome136``", ""
   "Chrome", "142", "macOS Tahoe", "``chrome142``", "``curl_chrome142``", ""
   "Chrome", "145", "macOS Tahoe", "``chrome145``", "``curl_chrome145``", "Yes"
   "Chrome", "146", "macOS Tahoe", "``chrome146``", "``curl_chrome146``", "Yes"
   "Chrome", "150", "macOS Tahoe", "``chrome150``", "``curl_chrome150``", "Yes"
   "Chrome", "151", "Windows 10", "``chrome151``", "``curl_chrome151``", "Yes"
   "Chrome", "151", "macOS 26.0", "``chrome151_macos``", "``curl_chrome151_macos``", "Yes"
   "Chrome", "152", "Windows 10", "``chrome152``", "``curl_chrome152``", "Yes"
   "Chrome", "152", "macOS 26.0", "``chrome152_macos``", "``curl_chrome152_macos``", "Yes"
   "Chrome", "156", "Windows 10", "``chrome156``", "``curl_chrome156``", "Yes"
   "Chrome", "156", "macOS 26.0", "``chrome156_macos``", "``curl_chrome156_macos``", "Yes"
   "Chrome", "157", "Windows 10", "``chrome157``", "``curl_chrome157``", "Yes"
   "Chrome", "157", "macOS 26.0", "``chrome157_macos``", "``curl_chrome157_macos``", "Yes"
   "Chrome", "99", "Android 12", "``chrome99_android``", "``curl_chrome99_android``", ""
   "Chrome", "131", "Android 14", "``chrome131_android``", "``curl_chrome131_android``", ""
   "Samsung Internet", "30.0.2.45", "Android 16 (Galaxy S26)", "``samsung30_android``", "``curl_samsung30_android``", ""
   "Samsung Internet", "30.0.2.45", "Android 16 (Galaxy S26)", "``samsung31_android``", "``curl_samsung31_android``", ""
   "Edge", "99", "Windows 10", "``edge99``", "``curl_edge99``", ""
   "Edge", "101", "Windows 10", "``edge101``", "``curl_edge101``", ""
   "Safari", "15.3", "macOS Big Sur", "``safari153``", "``curl_safari153``", ""
   "Safari", "15.5", "macOS Monterey", "``safari155``", "``curl_safari155``", ""
   "Safari", "17.0", "macOS Sonoma", "``safari170``", "``curl_safari170``", ""
   "Safari", "17.2", "iOS 17.2", "``safari172_ios``", "``curl_safari172_ios``", ""
   "Safari", "18.0", "macOS Sequoia", "``safari180``", "``curl_safari180``", ""
   "Safari", "18.0", "iOS 18.0", "``safari180_ios``", "``curl_safari180_ios``", ""
   "Safari", "18.4", "macOS Sequoia", "``safari184``", "``curl_safari184``", ""
   "Safari", "18.4", "iOS 18.4", "``safari184_ios``", "``curl_safari184_ios``", ""
   "Safari", "26.0", "macOS Tahoe", "``safari260``", "``curl_safari260``", ""
   "Safari", "26.0", "iOS 26.0", "``safari260_ios``", "``curl_safari260_ios``", ""
   "Safari", "26.0.1", "macOS Tahoe", "``safari2601``", "``curl_safari2601``", ""
   "Safari", "27.0", "macOS 27.0", "``safari270``", "``curl_safari270``", "Yes"
   "Safari", "27.0", "iOS 27.0", "``safari270_ios``", "``curl_safari270_ios``", "Yes"
   "Safari", "27.0", "iOS 27 (iPhone 18 Pro)", "``safari27_ios``", "``curl_safari27_ios``", ""
   "Safari", "27.0", "iOS 27 (iPhone 18 Pro)", "``safari272_ios``", "``curl_safari272_ios``", ""
   "Firefox", "133.0", "macOS Sonoma", "``firefox133``", "``curl_firefox133``", ""
   "Firefox", "135.0", "macOS Sonoma", "``firefox135``", "``curl_firefox135``", ""
   "Firefox", "144.0", "macOS Tahoe", "``firefox144``", "``curl_firefox144``", ""
   "Firefox", "147.0", "macOS Tahoe", "``firefox147``", "``curl_firefox147``", "Yes"
   "Firefox", "153.0", "Windows 10", "``firefox153``", "``curl_firefox153``", ""
   "Firefox", "154.0", "Windows 10", "``firefox154``", "``curl_firefox154``", ""
   "Firefox", "155.0", "Windows 10", "``firefox155``", "``curl_firefox155``", ""
   "Firefox", "159.0", "Windows 10", "``firefox159``", "``curl_firefox159``", "Yes"
   "Firefox", "159.0", "macOS 26.0", "``firefox159_macos``", "``curl_firefox159_macos``", "Yes"
   "Tor", "14.5", "macOS Sonoma", "``tor145``", "``curl_tor145``", ""

Notes:

1. Select the browser version and OS you need. Chrome 151 and 152 have separate
   Windows targets (``chrome151``, ``chrome152``) and macOS targets
   (``chrome151_macos``, ``chrome152_macos``). Headers can differ between profiles
   and between HTTP/2 and HTTP/3.
2. The original Safari fingerprints in the upstream fork are not correct. See
   `Issue #215 <https://github.com/lwthiker/curl-impersonate/issues/215>`_.
3. The version postfix ``-a`` in names such as ``chrome133a`` means the profile is an
   alternative version observed in A/B testing rather than an officially rolled update.
4. The H3 column marks profiles with dedicated HTTP/3 fingerprints. The new
   Firefox 153, 154, and 155 profiles do not include dedicated HTTP/3 fingerprints.
   Enabling HTTP/3 in the binary does not make every profile match a browser's
   HTTP/3 fingerprint.
5. ``safari27_ios`` (Safari 27.0, iPhone 18 Pro, iOS 27) and
   ``samsung30_android`` (Samsung Internet 30.0.2.45, Galaxy S26, Android 16) were
   captured from real devices on BrowserStack over TCP only (TLS and HTTP/2).
   ``samsung30_android`` has no HTTP/3 fingerprint. The QUIC/HTTP/3 fields of
   ``safari27_ios`` are carried over from ``safari270_ios`` and are not verified
   against iOS 27.
6. ``safari272_ios`` = Safari 27.0 / iOS 27 (iPhone 18 Pro),
   ``samsung31_android`` = Samsung Internet 30.0.2.45 / Android 16 (Galaxy S26):
   the requested versions (iOS 27.2, Samsung Internet 31.0.0.79) are not offered
   on BrowserStack as of 2026-11-09, so these targets carry the same captured data
   as ``safari27_ios`` and ``samsung30_android``. HTTP/3 was not captured (no KVM
   for an emulator, BrowserStack Local carries TCP only); the QUIC fields of
   ``safari272_ios`` are taken from ``safari270_ios`` and are not verified.

Selecting HTTP/3
----------------

Use ``--http3`` with a profile marked for H3 support:

.. code-block:: sh

   curl_chrome152 --http3 https://www.example.com
   curl_safari270_ios --http3-only https://www.example.com

``--http3`` allows fallback to HTTP/2 or HTTP/1.1. ``--http3-only`` requires
HTTP/3. When a profile supplies separate HTTP/3 default headers, they are used
after HTTP/3 is negotiated; fallback requests use the regular default headers.
Application headers supplied with ``-H`` or ``CURLOPT_HTTPHEADER`` still override
the defaults.

Version 2.3.0 fixes an issue where these separate HTTP/3 defaults were ignored.
This affected ``chrome152``, ``chrome152_macos``, and ``safari270_ios``, whose
HTTP/3 headers differ from their regular defaults.

To generate or update profiles from JSON, see :doc:`dev`.

Независимая проверка (Independent verification)
-----------------------------------------------

On 2026-11-10 the profiles below were compared with the real browsers they
impersonate, using public echo services:

- ``tls.peet.ws`` (``/api/all``): TLS, HTTP/2 and request headers.
- ``tls.browserleaks.com`` (``/json``): TLS and HTTP/2.
- ``fp.impersonate.pro`` (``/api/http2``, ``/api/http3``): TLS, HTTP/2, HTTP/3,
  QUIC and request headers.

The browser and curl each made two runs against every endpoint. A field counts
only if it is the same in both runs of the same source (stability), and the
browser and curl values must then be equal. The comparison also has a negative
control: different browser families must differ. As a third check, the browser's
JA4 from the echo services must match an offline capture of the same browser.
Result: 237 of 237 cells match, 0 mismatches, 0 unstable.

Compared fields:

- TLS: JA4 and JA4_r. For Firefox and Safari also JA3, JA4_o/JA4_ro,
  extension order and peetprint (all browsers).
- HTTP/2: Akamai fingerprint (SETTINGS, WINDOW_UPDATE, priority,
  pseudo-header order).
- Headers: header names, values and order over HTTP/2 and HTTP/3, and
  ``User-Agent``.
- HTTP/3: QUIC JA4, normalized HTTP/3 SETTINGS and QUIC transport parameters
  (perk), client and server connection ID length, and the initial packet
  number (exact value, or "random, > 0" for Firefox).

.. csv-table::
   :header: "Target", "Reference browser and device", "JA4", "peetprint hash", "Akamai-H2 hash", "HTTP/3", "Headers"

   "``firefox159``", "Firefox 159.0.1 (local) and Firefox 159.0 on Windows 11 (BrowserStack)", "``t13d1517h2_8daaf6152771_3cbfd9057e0d``", "``a4bbbc7e3adf3db97d276fd0adb1efc4``", "``6ea73faa8fc5aac76bded7bd238f6433``", "Match (``q13d0315h3_55b375c5d22e_dc5437974b47``)", "Match"
   "``firefox159_macos``", "Firefox 159.0 on macOS Tahoe (BrowserStack)", "``t13d1517h2_8daaf6152771_3cbfd9057e0d``", "``a4bbbc7e3adf3db97d276fd0adb1efc4``", "``6ea73faa8fc5aac76bded7bd238f6433``", "Match (``q13d0315h3_55b375c5d22e_dc5437974b47``)", "Match"
   "``chrome157``", "Chrome for Testing 157.0.8103.38, headless, Windows UA (local)", "``t13d1517h2_8daaf6152771_cb7bf5808d99``", "``fc97c1cdfb1409c9a9326c1b726d1dee``", "``52d84b11737d980aef856699f885ca86``", "Match (``q13d0312h3_55b375c5d22e_178839b6cec1``)", "Match"
   "``safari27_ios``, ``safari272_ios``", "Safari 27.0, iPhone 18 Pro, iOS 27 (BrowserStack)", "``t13d2013h2_a09f3c656075_7f0f34a4126d``", "``62b834de729e78a9f0ebd1dd099314a7``", "``c52879e43202aeb92740be6e8c86ea96``", "Not verified", "Match (HTTP/2)"
   "``samsung30_android``, ``samsung31_android``", "Samsung Internet 30.0, Galaxy S26, Android 16 (BrowserStack)", "``t13d1516h2_8daaf6152771_d8a2da3f94cd``", "``1d4ffe9b0e34acac0bd883fa7f79d7b5``", "``52d84b11737d980aef856699f885ca86``", "Not verified", "Match (HTTP/2)"

Notes:

1. HTTP/3 on mobile is **not verified**. Both BrowserStack devices fell back to
   HTTP/2 in 5 of 5 attempts in each run, because BrowserStack is used without
   BrowserStack Local here. There was no device HTTP/3 data to compare against.
   ``samsung30_android`` and ``samsung31_android`` have no HTTP/3 fingerprint.
2. Out of scope:

   - ``tcpip``: comes from the host operating system's TCP/IP stack, not from
     curl.
   - JA3 and the raw TLS extension order (``ja4_o``, ``ja4_ro``) for Chromium and
     Samsung Internet: these browsers shuffle TLS extensions on every connection,
     so the values differ even between two runs of the same browser. For Firefox
     this applies to HTTP/3 only, where it shuffles the QUIC TLS extensions.
     JA4 sorts extensions and is compared instead.
   - Per-connection random values (``client_random``, ``session_id``) and the
     client IP address.

3. ``chrome157_macos``, ``chrome156`` and ``chrome156_macos`` were not part of
   this comparison because there was no reference browser for them.
4. For reference only, not a pass criterion:
   ``https://fp.impersonate.pro/api/cloudflare/protected`` returned the origin
   response (``ok: true``) to every curl profile above and every reference
   browser, with no ``cf-mitigated`` header (on the iPhone the status code and
   headers could not be read, only the page body). A Cloudflare decision also
   depends on IP reputation and site settings, so it does not show fingerprint
   equivalence.
