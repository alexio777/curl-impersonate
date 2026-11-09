import os
import re
import sys
import json
import random
import logging
import pathlib
import shutil
import socket
import subprocess
import tempfile
import itertools
import asyncio
import time

import yaml
import pytest
from th1.tls.parser import parse_pcap
from th1.tls.signature import TLSClientHelloSignature
from th1.http2.parser import parse_nghttpd_log
from th1.http2.signature import HTTP2Signature
import dpkt

# Data files live next to this module, whatever the working directory.
TESTS_DIR = pathlib.Path(__file__).resolve().parent


@pytest.fixture
def browser_signatures():
    docs = {}
    for path in (TESTS_DIR / "signatures").glob("**/*.yaml"):
        with open(path, "r") as f:
            # Parse signatures.yaml database.
            for doc in yaml.safe_load_all(f.read()):
                if not doc:
                    continue
                browser = doc["browser"]
                key = f'{browser["name"]}_{browser["version"]}_{browser["os"]}'
                docs[key] = doc
                if browser.get("target"):
                    docs[browser["target"]] = doc
    return docs


"""
Test that the network signature of curl-impersonate is identical to that of
a real browser, by comparing with known signatures
"""

# When running curl use a specific range of local ports.
# This ensures we will capture the correct traffic in tcpdump.
LOCAL_PORTS = (50000, 50100)


# https://docs.github.com/en/actions/learn-github-actions/variables
logging.debug("$CI is: %s", os.getenv("CI"))
TEST_URLS = [
    "https://www.wikimedia.org",
    "https://www.wikipedia.org",
    "https://www.mozilla.org/en-US/",
    "https://www.apache.org",
    # "https://www.kernel.org",
    "https://git-scm.com",
]
# TEST_URLS = [
#     "https://tls.browserleaks.com/json",
#     "https://httpbin.org/ip",
# ]

# List of binaries and their expected signatures
CURL_BINARIES_AND_SIGNATURES = yaml.safe_load((TESTS_DIR / "targets.yaml").read_text())
HTTP3_CLIENTS = []
for path in (TESTS_DIR / "signatures").glob("**/*.yaml"):
    for doc in yaml.safe_load_all(path.read_text()):
        if not doc or not doc.get("signature", {}).get("http3"):
            continue
        profile = doc["browser"].get("target")
        if not profile:
            continue
        HTTP3_CLIENTS.extend(
            [
                pytest.param(
                    f"curl_{profile}", None, None, profile, id=f"{profile}-wrapper"
                ),
                pytest.param(
                    "minicurl",
                    {},
                    "libcurl-impersonate",
                    profile,
                    id=f"{profile}-libcurl",
                ),
            ]
        )


# Canonical Chromium wire header order for the exact dynamic POST tests
# (test_exact_dynamic_header_order_http2/http3 below).
# Source: Chromium net/url_request/url_request_http_job.cc and
# net/spdy/spdy_http_utils.cc header emission order (30 preset tokens
# minus "host,connection", which become :authority / are dropped on
# the H2/H3 wire). This is an independent oracle: it is intentionally
# NOT derived from the preset http_header_order/http3_http_header_order
# strings, so preset drift from Chromium fails instead of passing
# tautologically. Keep this constant verbatim in sync with
# CANONICAL_WIRE_HEADER_ORDER in build/gen/verify_cft.py.
CANONICAL_WIRE_HEADER_ORDER = (
    "content-length",
    "pragma",
    "cache-control",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-full-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-form-factors",
    "upgrade-insecure-requests",
    "content-type",
    "user-agent",
    "origin",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "priority",
)

EXACT_DYNAMIC_PROFILES = [
    "chrome156",
    "chrome156_macos",
    "chrome157",
    "chrome157_macos",
    "firefox159",
    "firefox159_macos",
    "safari27_ios",
]

# HTTP/3 was not captured for the WebKit profile (BrowserStack Local
# carries TCP only): its exact dynamic order is asserted over HTTP/2 only.
EXACT_DYNAMIC_H3_PROFILES = [
    p for p in EXACT_DYNAMIC_PROFILES if not p.startswith("safari")
]

# Gecko request modes exercised per Firefox profile (Chromium: nav only).
GECKO_EXACT_MODES = ("nav", "fetch", "xhr")

# Firefox 159.0.1 non-pseudo wire order per request mode, written from the
# live capture (build/gen/firefox-159/NOTES.md), never from lib/http.c or
# the observed output. HTTP/3: no te, alt-used before referer (nav) or
# before cookie (fetch/XHR). XHR carries no priority header.
GECKO_WIRE_HEADER_ORDER = {
    ("nav", "h2"): (
        "user-agent", "accept", "accept-language", "accept-encoding",
        "content-type", "content-length", "origin", "referer", "cookie",
        "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
        "sec-fetch-site", "sec-fetch-user", "priority", "te",
    ),
    ("nav", "h3"): (
        "user-agent", "accept", "accept-language", "accept-encoding",
        "content-type", "content-length", "origin", "alt-used", "referer",
        "cookie", "upgrade-insecure-requests", "sec-fetch-dest",
        "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "priority",
    ),
    ("fetch", "h2"): (
        "user-agent", "accept", "accept-language", "accept-encoding",
        "referer", "content-type", "content-length", "origin", "cookie",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority",
        "te",
    ),
    ("fetch", "h3"): (
        "user-agent", "accept", "accept-language", "accept-encoding",
        "referer", "content-type", "content-length", "origin", "alt-used",
        "cookie", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
        "priority",
    ),
    ("xhr", "h2"): (
        "user-agent", "accept", "accept-language", "accept-encoding",
        "content-type", "x-requested-with", "content-length", "origin",
        "referer", "cookie", "sec-fetch-dest", "sec-fetch-mode",
        "sec-fetch-site", "te",
    ),
    ("xhr", "h3"): (
        "user-agent", "accept", "accept-language", "accept-encoding",
        "content-type", "x-requested-with", "content-length", "origin",
        "referer", "alt-used", "cookie", "sec-fetch-dest", "sec-fetch-mode",
        "sec-fetch-site",
    ),
}

# Safari 27.0 (iPhone 18 Pro, iOS 27) non-pseudo HTTP/2 wire order per
# request mode, written from the live BrowserStack capture
# (build/gen/safari-272-ios/NOTES.md): nav = cross-site <form> POST,
# fetch = cross-site fetch() POST (sec-fetch-site before origin),
# xhr = same-origin XMLHttpRequest POST with X-Requested-With.
WEBKIT_WIRE_HEADER_ORDER = {
    "nav": (
        "accept", "content-type", "origin", "sec-fetch-site",
        "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest",
        "content-length", "accept-language", "priority", "accept-encoding",
    ),
    "fetch": (
        "accept", "content-type", "sec-fetch-site", "origin",
        "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest",
        "content-length", "accept-language", "priority", "accept-encoding",
    ),
    "xhr": (
        "accept", "content-type", "origin", "sec-fetch-site",
        "content-length", "sec-fetch-mode", "user-agent", "referer",
        "sec-fetch-dest", "x-requested-with", "accept-language", "priority",
        "accept-encoding", "cookie",
    ),
}

# Pseudo-header order per engine and protocol (Firefox: capture NOTES.md).
EXACT_PSEUDO_ORDER = {
    ("chromium", "h2"): (":method", ":authority", ":scheme", ":path"),
    ("chromium", "h3"): (":method", ":authority", ":scheme", ":path"),
    ("gecko", "h2"): (":method", ":path", ":authority", ":scheme"),
    ("gecko", "h3"): (":method", ":scheme", ":authority", ":path"),
    ("webkit", "h2"): (":method", ":scheme", ":authority", ":path"),
}


def _exact_engine(profile):
    if profile.startswith("firefox"):
        return "gecko"
    if profile.startswith("safari"):
        return "webkit"
    return "chromium"


def _exact_dynamic_cases(profiles=EXACT_DYNAMIC_PROFILES):
    for profile in profiles:
        if _exact_engine(profile) in ("gecko", "webkit"):
            for mode in GECKO_EXACT_MODES:
                yield pytest.param(profile, mode, id=f"{profile}-{mode}")
        else:
            yield pytest.param(profile, "nav", id=profile)


EXACT_DYNAMIC_CASES = list(_exact_dynamic_cases())
EXACT_DYNAMIC_H3_CASES = list(_exact_dynamic_cases(EXACT_DYNAMIC_H3_PROFILES))


@pytest.fixture
def socks5_udp_proxy(pytestconfig):
    """Run a local SOCKS5 server with UDP ASSOCIATE support."""
    socks5 = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", "socks5"
    )
    if not os.access(socks5, os.X_OK):
        socks5 = shutil.which("socks5")
    if not socks5:
        pytest.skip("socks5 test server is not installed")

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    with tempfile.TemporaryFile() as log:
        proc = subprocess.Popen(
            [socks5, "-a", f"127.0.0.1:{port}"],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log.seek(0)
                stderr = log.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"socks5 test server exited early: {stderr}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            proc.terminate()
            proc.wait(timeout=5)
            raise RuntimeError("socks5 test server failed to start")

        try:
            yield f"127.0.0.1:{port}"
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)


@pytest.fixture
def test_urls():
    # Shuffle TEST_URLS randomly
    return random.sample(TEST_URLS, k=len(TEST_URLS))


@pytest.fixture
def tcpdump(pytestconfig):
    """Initialize a sniffer to capture curl's traffic."""
    interface = pytestconfig.getoption("capture_interface")

    logging.debug(f"Running tcpdump on interface {interface}")

    p = subprocess.Popen(
        [
            "tcpdump",
            "-n",
            "-i",
            interface,
            "-s",
            "0",
            "-w",
            "-",
            "-U",  # Important, makes tcpdump unbuffered
            (
                f"(tcp src portrange {LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}"
                f" and tcp dst port 443) or"
                f"(tcp dst portrange {LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}"
                f" and tcp src port 443)"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    yield p

    p.terminate()
    p.wait(timeout=10)


async def _read_proc_output(proc, timeout: int = 5):
    """Read an async process' output until timeout is reached"""
    data = bytes()
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    passed = loop.time() - start_time
    while passed < timeout:
        try:
            data += await asyncio.wait_for(
                proc.stdout.readline(), timeout=timeout - passed
            )
        except asyncio.TimeoutError:
            pass
        passed = loop.time() - start_time
    return data


async def _wait_nghttpd(proc):
    """Wait for nghttpd to start listening on its designated port"""
    data = bytes()
    while data is not None:
        data = await proc.stdout.readline()
        if not data:
            # Process terminated
            return False

        line = data.decode("utf-8").rstrip()
        if "listen 0.0.0.0:8443" in line:
            return True

    return False


@pytest.fixture
async def nghttpd():
    """Initialize an HTTP/2 server.
    The returned object is an asyncio.subprocess.Process object,
    so async methods must be used with it.
    """
    logging.debug("Running nghttpd on :8443")

    # Launch nghttpd and wait for it to start listening.

    proc = await asyncio.create_subprocess_exec(
        "nghttpd",
        "-v",
        "8443",
        "ssl/server.key",
        "ssl/server.crt",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        # Wait up to 3 seconds for nghttpd to start.
        # Otherwise fail.
        started = await asyncio.wait_for(_wait_nghttpd(proc), timeout=3)
        if not started:
            raise Exception("nghttpd failed to start")
    except asyncio.TimeoutError:
        raise Exception("nghttpd failed to start on time")

    yield proc

    proc.terminate()
    await proc.wait()


def _set_ld_preload(env_vars, lib):
    if sys.platform.startswith("linux"):
        env_vars["LD_PRELOAD"] = lib + ".so"
    elif sys.platform.startswith("darwin"):
        env_vars["DYLD_INSERT_LIBRARIES"] = lib + ".dylib"


def _run_curl(curl_binary, env_vars, extra_args, urls, output="/dev/null"):
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    logging.debug(f"Launching '{curl_binary}' to {urls}")
    if env_vars:
        logging.debug(
            "Environment variables: {}".format(
                " ".join([f"{k}={v}" for k, v in env_vars.items()])
            )
        )

    args = [
        curl_binary,
        "-o",
        output,
        "-o",
        output,
        "--local-port",
        f"{LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}",
    ]
    if extra_args:
        args += extra_args
    args.extend(urls)
    logging.debug("runing curl with: %s", " ".join(args))

    curl = subprocess.Popen(args, env=env)
    return curl.wait(timeout=60)


def _assert_partial_tls_signature(sig, expected, allow_tls_permutation):
    """Compare supplied th1 fields with profile GREASE/resumption rules."""
    actual = sig.to_dict()
    ciphers = actual["ciphersuites"]
    if "grease" in expected:
        assert ("GREASE" in ciphers) == expected["grease"]
    actual["ciphersuites"] = [value for value in ciphers if value != "GREASE"]
    for key, value in expected.items():
        if key not in ("partial", "grease", "extensions"):
            assert actual[key] == value, f"TLS {key}: {actual[key]!r} != {value!r}"

    # Match th1's treatment of resumption and ECH-dependent padding.
    ignored = {"GREASE", "pre_shared_key"}
    if any(ext["type"] == "encrypted_client_hello" for ext in actual["extensions"]):
        ignored.add("padding")
    actual_extensions = [ext for ext in actual["extensions"] if ext["type"] not in ignored]
    expected_extensions = [ext for ext in expected["extensions"] if ext["type"] not in ignored]
    actual_order = [ext["type"] for ext in actual_extensions]
    expected_order = [ext["type"] for ext in expected_extensions]
    if allow_tls_permutation:
        assert sorted(actual_order) == sorted(expected_order)
    else:
        assert actual_order == expected_order
    by_type = {ext["type"]: ext for ext in actual_extensions}
    for extension in expected_extensions:
        actual_extension = by_type[extension["type"]]
        for field, value in extension.items():
            observed = actual_extension[field]
            if field == "supported_groups":
                observed = [group for group in observed if group != "GREASE"]
            assert observed == value, (
                f"TLS {extension['type']}.{field}: {observed!r} != {value!r}"
            )


def test_tls_client_hello_smoke(pytestconfig, browser_signatures):
    """Check one recent profile over loopback without a packet sniffer."""
    profile = "chrome152"
    binary = "curl-impersonate.exe" if sys.platform == "win32" else "curl-impersonate"
    curl_binary = pathlib.Path(pytestconfig.getoption("install_dir")) / "bin" / binary
    expected = browser_signatures[profile]["signature"]

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        port = server.getsockname()[1]
        # Keep a hostname in the URL so the ClientHello includes SNI.
        args = [
            str(curl_binary.resolve()),
            "--disable",
            "--impersonate", profile,
            "--noproxy", "*",
            "--resolve", f"fingerprint.test:{port}:127.0.0.1",
            "--connect-timeout", "5",
            "--max-time", "10",
            f"https://fingerprint.test:{port}/",
        ]
        with subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        ) as curl:
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(5)
                    with conn.makefile("rb") as stream:
                        header = stream.read(5)
                        assert len(header) == 5, "Missing TLS record header"
                        length = int.from_bytes(header[3:5], "big")
                        body = stream.read(length)
                        assert len(body) == length, "Incomplete TLS ClientHello"
            finally:
                if curl.poll() is None:
                    curl.kill()
                _, stderr = curl.communicate(timeout=5)
                logging.debug("Loopback curl stderr: %s", stderr.decode(errors="replace"))

    # The server intentionally closes after ClientHello; no TLS handshake or
    # HTTP request completes, so curl's exit code isn't a success criterion.
    sig = TLSClientHelloSignature.from_bytes(header + body)
    _assert_partial_tls_signature(
        sig,
        expected["tls_client_hello"],
        expected.get("options", {}).get("tls_permute_extensions", False),
    )


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, expected_signature",
    CURL_BINARIES_AND_SIGNATURES,
)
def test_tls_client_hello(
    pytestconfig,
    tcpdump,
    curl_binary,
    env_vars,
    ld_preload,
    browser_signatures,
    expected_signature,
    test_urls,
):
    """
    Check that curl's TLS signature is identical to that of a
    real browser.

    Launches curl while sniffing its TLS traffic with tcpdump. Then
    extracts the Client Hello packet from the capture and compares its
    signature with the expected one defined in the YAML database.
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )
    if ld_preload:
        # Injecting libcurl-impersonate with LD_PRELOAD is supported on
        # Linux only. On Mac there is DYLD_INSERT_LIBRARIES but it
        # requires more work to be functional.
        if not sys.platform.startswith("linux"):
            pytest.skip()

        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )

    test_urls = test_urls[0:2]
    ret = _run_curl(curl_binary, env_vars=env_vars, extra_args=None, urls=test_urls)
    assert ret == 0

    try:
        pcap, stderr = tcpdump.communicate(timeout=5)

        # If tcpdump finished running before timeout, it's likely it failed
        # with an error.
        assert tcpdump.returncode == 0, (
            f"tcpdump failed with error code {tcpdump.returncode}, " f"stderr: {stderr}"
        )
    except subprocess.TimeoutExpired:
        tcpdump.kill()
        pcap, stderr = tcpdump.communicate(timeout=3)

    assert len(pcap) > 0
    logging.debug(f"Captured pcap of length {len(pcap)} bytes")

    try:
        client_hellos = parse_pcap(pcap)
    except dpkt.NeedData:
        logging.error("DPKT does not support Chrome 124 yet.")
        return

    # A client hello message for each URL
    assert len(client_hellos) == len(test_urls)

    logging.debug(
        f"Found {len(client_hellos)} Client Hello messages, "
        f"comparing to signature '{expected_signature}'"
    )

    for client_hello in client_hellos:
        # sig = TLSClientHelloSignature.from_bytes(client_hello)
        sig = client_hello["signature"]
        expected = browser_signatures[expected_signature]["signature"]["tls_client_hello"]

        allow_tls_permutation = (
            browser_signatures[expected_signature]["signature"]
            .get("options", {})
            .get("tls_permute_extensions", False)
        )

        if expected.get("partial"):
            _assert_partial_tls_signature(sig, expected, allow_tls_permutation)
        else:
            expected_sig = TLSClientHelloSignature.from_dict(expected)
            equals, reason = expected_sig.equals(sig, allow_tls_permutation)
            assert equals, reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, expected_signature",
    CURL_BINARIES_AND_SIGNATURES,
)
async def test_http2_headers(
    pytestconfig,
    nghttpd,
    curl_binary,
    env_vars,
    ld_preload,
    browser_signatures,
    expected_signature,
):
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )
    if ld_preload:
        # Injecting libcurl-impersonate with LD_PRELOAD is supported on
        # Linux only. On Mac there is DYLD_INSERT_LIBRARIES but it
        # requires more work to be functional.
        if not sys.platform.startswith("linux"):
            pytest.skip()

        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k"],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=2)

    assert len(output) > 0
    sig = parse_nghttpd_log(output)

    logging.debug(f"Received {len(sig.frames)} HTTP/2 frames")

    expected_sig = HTTP2Signature.from_dict(
        browser_signatures[expected_signature]["signature"]["http2"]
    )

    equals, msg = sig.equals(expected_sig)
    assert equals, msg


def _quic_grease_id(key):
    """RFC 9000 reserved transport parameter ids: 31 * N + 27."""
    return key.isdigit() and int(key) >= 27 and (int(key) - 27) % 31 == 0


def _quic_version_information(value):
    """The endpoint lists available versions sorted by value, so a random
    GREASE version lands anywhere; compare them as a multiset."""
    chosen, separator, available = value.partition("@")
    if not separator:
        return value
    versions = [item if item == "GREASE" else int(item, 0)
                for item in available.split(",") if item]
    numbers = sorted(item for item in versions if item != "GREASE")
    grease = ["GREASE"] * versions.count("GREASE")
    return f"{chosen}@" + ",".join(str(item) for item in numbers + grease)


def _http3_transport_parameters(text, auto_ids=()):
    """Normalize option syntax and the endpoint rendering to one form.

    The endpoint shows any id of the reserved form as a bare "GREASE"
    (also 0xff02de1a min_ack_delay) and a zero-length value as "id:0x";
    the option syntax writes the id and value, and "id" for empty.
    """
    result = {}
    for item in text.split(";"):
        key, separator, value = item.partition(":")
        if key == "GREASE" or _quic_grease_id(key):
            result["GREASE"] = result.get("GREASE", 0) + 1
            continue
        if value.startswith("0x"):
            value = value[2:]
        if key in auto_ids and value:
            value = "AUTO"
        if key == "17":
            value = _quic_version_information(value)
        result[key] = value if separator or key.isdigit() else None
    return result


def _assert_http3_signature(response, expected):
    actual = response["http3"]
    if "perk_text_normalized" in expected:
        assert actual["perk_text_normalized"] == expected["perk_text_normalized"]
    else:
        # The endpoint may append fields absent from option-derived expectations.
        parts = actual["perk_text_normalized"].split("|", 3)
        assert len(parts) >= 3, "HTTP/3 fingerprint must contain settings, order and transport parameters"
        settings, order, transport = parts[:3]
        assert settings == expected["settings"]
        assert order.replace(",", "") == expected["pseudo_headers_order"]
        parameters = _http3_transport_parameters(expected["quic_transport_parameters"])
        auto_ids = {key for key, value in parameters.items() if value == "AUTO"}
        assert _http3_transport_parameters(transport, auto_ids) == parameters

    # Current API responses use name/value records; older captures use a map.
    actual_headers = actual["headers"]
    if isinstance(actual_headers, list):
        actual_headers = {header["name"]: header["value"] for header in actual_headers}
    for name, value in expected["headers"].items():
        observed = actual_headers.get(name)
        assert observed == value, f"HTTP/3 header {name}: {observed!r} != {value!r}"

    # Option-only profiles do not contain a complete QUIC TLS capture.
    if "ja3_text" in expected:
        assert response["tls"]["ja3"]["text"] == expected["ja3_text"]
    if "signature_algorithms" in expected:
        signature_algorithms = next(
            extension
            for extension in response["tls"]["extensions"]
            if extension["name"] == "signature_algorithms"
        )
        assert signature_algorithms["data"]["algorithms"] == expected[
            "signature_algorithms"
        ]


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, profile", HTTP3_CLIENTS
)
def test_http3_fingerprint(
    pytestconfig, browser_signatures, curl_binary, env_vars, ld_preload, profile
):
    """Compare stable HTTP/3, QUIC, and QUIC TLS fingerprint fields."""
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )
    expected = browser_signatures[profile]["signature"]["http3"]
    env_vars = dict(env_vars or {})
    if ld_preload:
        if not sys.platform.startswith("linux"):
            pytest.skip()
        env_vars["CURL_IMPERSONATE"] = profile
        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "fingerprint.json")
        for attempt in range(2):
            ret = _run_curl(
                curl_binary,
                env_vars=env_vars,
                extra_args=["--http3-only"],
                urls=["https://fp.impersonate.pro/api/http3"],
                output=output,
            )
            if ret == 0:
                break
            logging.warning("HTTP/3 fingerprint attempt %d failed", attempt + 1)
        assert ret == 0

        with open(output, "r") as f:
            response = json.load(f)

    assert "http3" in response, response.get("info", response)
    _assert_http3_signature(response, expected)


@pytest.mark.parametrize("proxy_scheme", ["socks5", "socks5h"])
@pytest.mark.parametrize("http3_option", ["--http3", "--http3-only"])
def test_http3_through_socks_udp_proxy(
    pytestconfig, socks5_udp_proxy, proxy_scheme, http3_option
):
    """HTTP/3 must use SOCKS5 UDP ASSOCIATE for proxied QUIC traffic."""
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", "curl-impersonate"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "fingerprint.json")
        proxy_used = os.path.join(tmpdir, "proxy-used.txt")
        for attempt in range(2):
            ret = _run_curl(
                curl_binary,
                env_vars=None,
                extra_args=[
                    "--impersonate",
                    "chrome146",
                    http3_option,
                    "--proxy",
                    f"{proxy_scheme}://{socks5_udp_proxy}",
                    "--noproxy",
                    "",
                    "--write-out",
                    f"%output{{{proxy_used}}}%{{proxy_used}}",
                ],
                urls=["https://fp.impersonate.pro/api/http3"],
                output=output,
            )
            if ret == 0:
                break
            logging.warning(
                "HTTP/3 (%s) through %s proxy attempt %d failed",
                http3_option,
                proxy_scheme,
                attempt + 1,
            )
        assert ret == 0

        with open(output, "r") as f:
            response = json.load(f)
        with open(proxy_used, "r") as f:
            assert f.read() == "1"

    assert "http3" in response, response.get("info", response)


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, profile", HTTP3_CLIENTS
)
async def test_http3_fallback_to_http2(
    pytestconfig,
    nghttpd,
    browser_signatures,
    curl_binary,
    env_vars,
    ld_preload,
    profile,
):
    """HTTP/3 preferred mode must retain the profile when falling back to H2."""
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )
    env_vars = dict(env_vars or {})
    if ld_preload:
        if not sys.platform.startswith("linux"):
            pytest.skip()
        env_vars["CURL_IMPERSONATE"] = profile
        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )
    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["--http3", "-k"],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=2)
    assert len(output) > 0

    actual = parse_nghttpd_log(output)
    expected = HTTP2Signature.from_dict(
        browser_signatures[profile]["signature"]["http2"]
    )
    equals, msg = actual.equals(expected)
    assert equals, msg



@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload",
    [
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate",
        ),
    ],
)
async def test_no_builtin_headers(
    pytestconfig, nghttpd, curl_binary, env_vars, ld_preload
):
    """
    Ensure the built-in headers of libcurl-impersonate are not added when
    the CURL_IMPERSONATE_HEADERS environment variable is set to "no".
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )

    if not sys.platform.startswith("linux"):
        pytest.skip()

    _set_ld_preload(
        env_vars,
        os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
    )

    # Use some custom headers with a specific order.
    # We will test that the headers are sent in the exact given order, as
    # it is important for users to be able to control the exact headers
    # content and order.
    headers = [
        "X-Hello: World",
        "Accept: application/json",
        "X-Goodbye: World",
        "Accept-Encoding: deflate, gzip, br" "X-Foo: Bar",
        "User-Agent: curl-impersonate",
    ]
    header_args = list(itertools.chain(*[["-H", header] for header in headers]))

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k"] + header_args,
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)

    assert len(output) > 0
    sig = parse_nghttpd_log(output)
    for frame in sig.frames:
        if frame.frame_type == "HEADERS":
            headers_frame = frame
    for i, header in enumerate(headers_frame.headers):
        assert header.lower() == headers[i].lower()


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload",
    [
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101"},
            "libcurl-impersonate",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate",
        ),
    ],
)
async def test_user_agent(pytestconfig, nghttpd, curl_binary, env_vars, ld_preload):
    """
    Ensure that any user-agent set with CURLOPT_HTTPHEADER will override
    the one set by libcurl-impersonate.
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )

    if not sys.platform.startswith("linux"):
        pytest.skip()

    _set_ld_preload(
        env_vars,
        os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
    )

    user_agent = "My-User-Agent"

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k", "-H", f"User-Agent: {user_agent}"],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)

    assert len(output) > 0

    sig = parse_nghttpd_log(output)
    for frame in sig.frames:
        if frame.frame_type == "HEADERS":
            headers_frame = frame
    assert any(
        [header.lower().startswith("user-agent:") for header in headers_frame.headers]
    )

    for header in headers_frame.headers:
        if header.lower().startswith("user-agent:"):
            assert header[len("user-agent:") :].strip() == user_agent


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload",
    [
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101"},
            "libcurl-impersonate",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate",
        ),
    ],
)
async def test_user_agent_curlopt_useragent(
    pytestconfig, nghttpd, curl_binary, env_vars, ld_preload
):
    """
    Ensure that any user-agent set with CURLOPT_USERAGENT will override
    the one set by libcurl-impersonate. See:
    https://github.com/lwthiker/curl-impersonate/issues/51
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )

    if not sys.platform.startswith("linux"):
        pytest.skip()

    _set_ld_preload(
        env_vars,
        os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
    )

    user_agent = "My-User-Agent"

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k", "-A", user_agent],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)

    assert len(output) > 0

    sig = parse_nghttpd_log(output)
    for frame in sig.frames:
        if frame.frame_type == "HEADERS":
            headers_frame = frame
    headers = headers_frame.headers
    assert any([header.lower().startswith("user-agent:") for header in headers])

    for header in headers:
        if header.lower().startswith("user-agent:"):
            assert header[len("user-agent:") :].strip() == user_agent


def _exact_dynamic_inputs(profile, base_headers):
    """Explicit per-test dynamic header values (not from the preset)."""
    version = re.search(r"chrome(\d+)", profile).group(1)
    return {
        # From "-d a=1".
        "content-length": "3",
        "content-type": "application/x-www-form-urlencoded",
        # Passed via -H.
        "pragma": "no-cache",
        "cache-control": "no-cache",
        "sec-ch-ua-full-version": f'"{version}.0.0.0"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-platform": base_headers["sec-ch-ua-platform"],
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-ch-ua-model": '""',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-wow64": "?0",
        "sec-ch-ua-full-version-list": (
            f'"Chromium";v="{version}.0.0.0", '
            f'"Google Chrome";v="{version}.0.0.0"'
        ),
        "sec-ch-ua-form-factors": '"Desktop"',
        "origin": "https://example.com",
        # Auto-computed from cross-site "-e https://example.com/".
        "sec-fetch-site": "cross-site",
        # From "-e https://example.com/" and "-b sid=1".
        "referer": "https://example.com/",
        "cookie": "sid=1",
    }


def _gecko_exact_inputs(mode):
    """Explicit per-test dynamic values of a Gecko cross-site POST."""
    dynamic = {
        # From "-d a=1".
        "content-length": "3",
        "content-type": "application/x-www-form-urlencoded",
        # Derived by the engine from the cross-site "-e" on a POST.
        "origin": "https://example.com",
        "sec-fetch-site": "cross-site",
        # From "-e https://example.com/" and "-b sid=1".
        "referer": "https://example.com/",
        "cookie": "sid=1",
    }
    if mode in ("fetch", "xhr"):
        # Firefox fetch()/XHR: cors/empty, Accept */*.
        dynamic.update(
            {"accept": "*/*", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors"}
        )
    if mode == "fetch":
        dynamic["priority"] = "u=4"
    if mode == "xhr":
        dynamic["x-requested-with"] = "XMLHttpRequest"
    return dynamic


def _webkit_exact_inputs(mode):
    """Explicit per-test dynamic values of a WebKit POST (see
    WEBKIT_WIRE_HEADER_ORDER for the context of each mode)."""
    dynamic = {
        # From "-d a=1".
        "content-length": "3",
        "content-type": "application/x-www-form-urlencoded",
    }
    if mode == "xhr":
        # Same-origin XHR: Safari sends the cookie and the full referer.
        dynamic.update({
            "origin": "https://localhost:8443",
            "sec-fetch-site": "same-origin",
            "referer": "https://localhost:8443/page",
            "cookie": "sid=1",
            "accept": "*/*",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "priority": "u=3, i",
            "x-requested-with": "XMLHttpRequest",
        })
        return dynamic
    # Cross-site: no cookie in the capture (SameSite), so none is given.
    dynamic.update({
        "origin": "https://example.com",
        "sec-fetch-site": "cross-site",
        "referer": "https://example.com/",
    })
    if mode == "fetch":
        dynamic.update({"accept": "*/*", "sec-fetch-dest": "empty",
                        "sec-fetch-mode": "cors", "priority": "u=3, i"})
    return dynamic


def _webkit_exact_curl_args(mode, dynamic):
    """WebKit POST arguments in an order unlike the wire order."""
    args = []
    if "cookie" in dynamic:
        args += ["-b", dynamic["cookie"]]
    args += ["-d", "a=1", "-e", dynamic["referer"]]
    if mode == "fetch":
        args += ["-H", "Sec-Fetch-Mode: cors"]
    if mode == "xhr":
        args += ["-H", f"X-Requested-With: {dynamic['x-requested-with']}"]
    return args


def _expected_exact_dynamic_headers(
    browser_signatures, profile, mode="nav", h3_authority=None
):
    """Expected [(name, value)] wire sequence for the exact POST tests.

    Base header values come from the profile's H2 signature HEADERS
    frame; dynamic values come from _exact_dynamic_inputs (Chromium) or
    _gecko_exact_inputs (Gecko). The order is CANONICAL_WIRE_HEADER_ORDER
    (Chromium) or GECKO_WIRE_HEADER_ORDER (Gecko) only -- never the
    preset string and never the observed output. h3_authority selects
    the HTTP/3 order and is the expected Gecko alt-used value.
    """
    frames = browser_signatures[profile]["signature"]["http2"]["frames"]
    headers_frame = next(f for f in frames if f["frame_type"] == "HEADERS")
    base_headers = {}
    for header in headers_frame["headers"]:
        if isinstance(header, (list, tuple)):
            name, value = header[0], header[1]
        else:
            name, _, value = header.partition(": ")
        base_headers[name.lower()] = value
    if _exact_engine(profile) == "gecko":
        dynamic = _gecko_exact_inputs(mode)
        values = {**base_headers, **dynamic}
        if h3_authority:
            values["alt-used"] = h3_authority
        order = GECKO_WIRE_HEADER_ORDER[(mode, "h3" if h3_authority else "h2")]
    elif _exact_engine(profile) == "webkit":
        assert not h3_authority, "WebKit H3 order was not captured"
        dynamic = _webkit_exact_inputs(mode)
        values = {**base_headers, **dynamic}
        order = WEBKIT_WIRE_HEADER_ORDER[mode]
    else:
        dynamic = _exact_dynamic_inputs(profile, base_headers)
        values = {**base_headers, **dynamic}
        order = CANONICAL_WIRE_HEADER_ORDER
    expected = [(name, values[name]) for name in order]
    return expected, dynamic


def _gecko_exact_curl_args(mode, dynamic):
    """Gecko POST arguments in an order unlike the wire order.

    Cookie (late on the wire) first; the body before the referer that
    fetch() puts ahead of content-type; the mode selector last.
    """
    args = ["-b", dynamic["cookie"], "-d", "a=1", "-e", dynamic["referer"]]
    if mode == "fetch":
        args += ["-H", "Sec-Fetch-Mode: cors"]
    if mode == "xhr":
        args += ["-H", f"X-Requested-With: {dynamic['x-requested-with']}"]
    return args


def _exact_dynamic_curl_args(dynamic, profile, mode):
    """POST arguments in deliberately scrambled (non-canonical) order."""
    if _exact_engine(profile) == "gecko":
        return _gecko_exact_curl_args(mode, dynamic)
    if _exact_engine(profile) == "webkit":
        return _webkit_exact_curl_args(mode, dynamic)

    def header(name):
        return ["-H", f"{name}: {dynamic[name]}"]

    args = []
    # Origin first: canonically it must end up after every Sec-CH-UA-*.
    args += header("origin")
    args += ["-b", dynamic["cookie"]]
    # High-entropy Sec-CH-UA-* in reverse canonical order.
    for name in (
        "sec-ch-ua-form-factors",
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-wow64",
        "sec-ch-ua-bitness",
        "sec-ch-ua-model",
        "sec-ch-ua-platform-version",
        "sec-ch-ua-arch",
        "sec-ch-ua-full-version",
        "sec-ch-ua-platform",
    ):
        args += header(name)
    args += ["-e", dynamic["referer"], "-d", "a=1"]
    # Canonically second/third, supplied last.
    args += header("cache-control")
    args += header("pragma")
    return args


def _run_curl_capture_stderr(curl_binary, extra_args, url):
    """Run curl capturing stderr (for the HTTP/3 verbose nva dump).

    Separate helper: the contract of _run_curl is unchanged.
    """
    args = [
        curl_binary,
        "-o",
        "/dev/null",
        "--local-port",
        f"{LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}",
    ]
    if extra_args:
        args += extra_args
    args.append(url)
    logging.debug("running curl with: %s", " ".join(args))
    proc = subprocess.run(
        args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60
    )
    return proc.returncode, proc.stderr.decode("utf-8", errors="replace")


_HTTP3_VERBOSE_HEADER_RE = re.compile(r"\[HTTP/3\] \[(\d+)\] \[([^\]]+)\]")


def _parse_http3_verbose_headers(stderr):
    """Parse "[HTTP/3] [sid] [name: value]" lines of the first stream.

    Splits on the first ": " (pseudo-headers like ":method: POST"
    survive: their leading colon is not followed by a space).
    Returns (pseudo_pairs, regular_pairs).
    """
    streams = {}
    for match in _HTTP3_VERBOSE_HEADER_RE.finditer(stderr):
        stream_id, field = match.group(1), match.group(2)
        if ": " not in field:
            continue
        name, value = field.split(": ", 1)
        streams.setdefault(stream_id, []).append((name, value))
    assert streams, (
        "no [HTTP/3] verbose header dump found in curl stderr; "
        f"stderr tail: {stderr[-2000:]!r}"
    )
    first_stream = next(iter(streams.values()))
    pseudo = [pair for pair in first_stream if pair[0].startswith(":")]
    regular = [
        (name.lower(), value)
        for name, value in first_stream
        if not name.startswith(":")
    ]
    return pseudo, regular


_NGHTTPD_HEADER_LINE_RE = re.compile(
    r"recv \(stream_id=\d+(?:, [^)]*)?\) (.+)$"
)


def _parse_nghttpd_headers_frame(output):
    """Extract (pseudo_names, [(name, value)]) of the first HEADERS frame.

    Deliberately not th1's parse_nghttpd_log: its header-line regex
    requires "(stream_id=N)" exactly, so nghttpd's
    "(stream_id=1, sensitive) cookie: ..." line is silently dropped
    and the cookie would be missing from the observed sequence.
    """
    pseudo = []
    regular = []
    for line in output.decode("utf-8", errors="replace").splitlines():
        if "recv HEADERS frame" in line:
            break
        match = _NGHTTPD_HEADER_LINE_RE.search(line)
        if not match:
            continue
        header = match.group(1)
        if header.startswith(":"):
            pseudo.append(re.match(r"(:\w+):", header).group(1))
        else:
            name, _, value = header.partition(": ")
            regular.append((name.lower(), value))
    assert regular, "no HEADERS frame headers found in nghttpd log"
    return pseudo, regular


@pytest.mark.asyncio
@pytest.mark.parametrize("profile,mode", EXACT_DYNAMIC_CASES)
async def test_exact_dynamic_header_order_http2(
    pytestconfig, nghttpd, browser_signatures, profile, mode
):
    """Exact dynamic POST header (name, value) sequence over HTTP/2."""
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", f"curl_{profile}"
    )
    expected, dynamic = _expected_exact_dynamic_headers(
        browser_signatures, profile, mode
    )

    ret = _run_curl(
        curl_binary,
        env_vars=None,
        extra_args=["-k"] + _exact_dynamic_curl_args(dynamic, profile, mode),
        urls=["https://localhost:8443/"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)
    assert len(output) > 0, "nghttpd produced no log output"

    pseudo, actual = _parse_nghttpd_headers_frame(output)
    assert pseudo == list(EXACT_PSEUDO_ORDER[(_exact_engine(profile), "h2")])
    assert actual == expected


@pytest.mark.parametrize("profile,mode", EXACT_DYNAMIC_H3_CASES)
def test_exact_dynamic_header_order_http3(
    pytestconfig, browser_signatures, profile, mode
):
    """Exact dynamic POST header (name, value) sequence over HTTP/3.

    Captured from curl's verbose "[HTTP/3] [sid] [name: value]" dump
    of the nva array handed to nghttp3_conn_submit_request; the fp
    endpoint only provides the QUIC handshake (its HTTP status for
    POST is irrelevant, hence no -f).
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", f"curl_{profile}"
    )
    authority = "fp.impersonate.pro"
    expected, dynamic = _expected_exact_dynamic_headers(
        browser_signatures, profile, mode, h3_authority=authority
    )

    ret, stderr = None, ""
    for attempt in range(2):
        ret, stderr = _run_curl_capture_stderr(
            curl_binary,
            extra_args=["-v", "--http3-only"]
            + _exact_dynamic_curl_args(dynamic, profile, mode),
            url=f"https://{authority}/api/http3",
        )
        if ret == 0:
            break
        logging.warning("HTTP/3 exact header attempt %d failed", attempt + 1)
    assert ret == 0, (
        f"curl exited with {ret} (network error?); stderr tail: {stderr[-2000:]!r}"
    )

    pseudo, actual = _parse_http3_verbose_headers(stderr)
    pseudo_values = {
        ":method": "POST",
        ":authority": authority,
        ":scheme": "https",
        ":path": "/api/http3",
    }
    assert pseudo == [
        (name, pseudo_values[name])
        for name in EXACT_PSEUDO_ORDER[(_exact_engine(profile), "h3")]
    ]
    assert actual == expected
