# Predefined Python helpers inserted by fix templates (only the helpers a fix needs are copied).
# Each helper starts with a "# --- secreview:<name>" marker line and ends before the next marker.

# --- secreview:safe_url
def _secreview_safe_url(url):
    """Allow only http(s) URLs whose host does not resolve to a private/loopback/link-local address."""
    import ipaddress
    import os
    import socket
    from urllib.parse import urlparse
    parsed = urlparse(str(url))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("secreview: URL scheme or host not allowed")
    allowed = {h.strip().lower() for h in os.environ.get("SECREVIEW_ALLOWED_HOSTS", "").split(",") if h.strip()}
    if allowed and parsed.hostname.lower() not in allowed:
        raise ValueError("secreview: host not in allowlist")
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise ValueError("secreview: host does not resolve") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("secreview: internal address blocked")
    return url

# --- secreview:safe_redirect
def _secreview_safe_redirect(target, default="/"):
    """Only allow same-site relative redirects."""
    target = str(target or "")
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return default

# --- secreview:end
