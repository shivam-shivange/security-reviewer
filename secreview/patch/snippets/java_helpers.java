// Predefined Java helpers inserted (as private static methods) by fix templates.
// Each helper starts with a "// --- secreview:<name>" marker line.

// --- secreview:safe_file
    private static java.io.File secreviewSafeFile(String base, String name) {
        try {
            java.io.File root = new java.io.File(base).getCanonicalFile();
            java.io.File target = new java.io.File(root, name).getCanonicalFile();
            if (!target.toPath().startsWith(root.toPath())) {
                throw new SecurityException("Path traversal blocked");
            }
            return target;
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

// --- secreview:safe_url
    private static String secreviewSafeUrl(String value) {
        try {
            java.net.URI uri = new java.net.URI(value);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
            if (!scheme.equals("http") && !scheme.equals("https") || uri.getHost() == null) {
                throw new SecurityException("URL scheme or host not allowed");
            }
            String allowed = System.getenv().getOrDefault("SECREVIEW_ALLOWED_HOSTS", "");
            if (!allowed.isBlank() && !java.util.Arrays.asList(allowed.toLowerCase().split("\\s*,\\s*")).contains(uri.getHost().toLowerCase())) {
                throw new SecurityException("Host not in allowlist");
            }
            for (java.net.InetAddress a : java.net.InetAddress.getAllByName(uri.getHost())) {
                if (a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress() || a.isAnyLocalAddress() || a.isMulticastAddress()) {
                    throw new SecurityException("Internal address blocked");
                }
            }
            return value;
        } catch (java.net.URISyntaxException | java.net.UnknownHostException e) {
            throw new SecurityException("Invalid URL", e);
        }
    }

// --- secreview:safe_redirect
    private static String secreviewSafeRedirect(String target) {
        String t = target == null ? "" : target;
        return t.startsWith("/") && !t.startsWith("//") && !t.contains("\\") ? t : "/";
    }

// --- secreview:escape_html
    private static String secreviewEscapeHtml(Object value) {
        String s = String.valueOf(value);
        StringBuilder out = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<': out.append("&lt;"); break;
                case '>': out.append("&gt;"); break;
                case '&': out.append("&amp;"); break;
                case '"': out.append("&quot;"); break;
                case '\'': out.append("&#39;"); break;
                default: out.append(c);
            }
        }
        return out.toString();
    }

// --- secreview:end
