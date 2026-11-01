package com.admin.common.engine;

import com.alibaba.fastjson.JSONObject;

import java.net.IDN;
import java.net.InetAddress;
import java.util.Locale;

/** Pure parsing: resolving a hostname is exclusively an Agent capability. */
public final class Endpoint {
    private final String kind, host, family;
    private final int port;

    private Endpoint(String kind, String host, int port, String family) {
        this.kind = kind;
        this.host = host;
        this.port = port;
        this.family = family;
    }

    public String getKind() {
        return kind;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getFamily() {
        return family;
    }

    public static Endpoint parse(String text) {
        if (text == null || !text.equals(text.trim()))
            throw new IllegalArgumentException("invalid endpoint");
        String host, port;
        if (text.startsWith("[")) {
            int end = text.indexOf(']');
            if (end < 1 || end + 1 >= text.length() || text.charAt(end + 1) != ':')
                throw new IllegalArgumentException("invalid bracketed endpoint");
            host = text.substring(1, end);
            port = text.substring(end + 2);
        } else {
            int colon = text.indexOf(':');
            if (colon < 1 || colon != text.lastIndexOf(':'))
                throw new IllegalArgumentException("endpoint must be host:port; bracket IPv6");
            host = text.substring(0, colon);
            port = text.substring(colon + 1);
        }
        if (!port.matches("[0-9]{1,5}")) throw new IllegalArgumentException("invalid port");
        int n = Integer.parseInt(port);
        if (n < 1 || n > 65535) throw new IllegalArgumentException("invalid port");
        if (host.contains(":")) {
            if (!host.matches("[0-9A-Fa-f:.]+"))
                throw new IllegalArgumentException("invalid or scoped IPv6");
            try {
                byte[] bytes = InetAddress.getByName(host).getAddress();
                if (bytes.length == 4)
                    return new Endpoint(
                            "ip", InetAddress.getByAddress(bytes).getHostAddress(), n, "ipv4");
                return new Endpoint("ip", compress(bytes), n, "ipv6");
            } catch (Exception e) {
                throw new IllegalArgumentException("invalid IPv6");
            }
        }
        if (host.matches("[0-9.]+")) {
            if (!KernelForwardingEngine.ipv4(host))
                throw new IllegalArgumentException("ambiguous or invalid IPv4");
            return new Endpoint("ip", host, n, "ipv4");
        }
        if (host.indexOf('%') >= 0
                || host.indexOf('@') >= 0
                || host.indexOf('/') >= 0
                || host.indexOf('\\') >= 0
                || host.indexOf('?') >= 0
                || host.indexOf('#') >= 0) throw new IllegalArgumentException("invalid hostname");
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        try {
            host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid IDNA hostname");
        }
        if (host.isEmpty() || host.length() > 253)
            throw new IllegalArgumentException("invalid hostname length");
        for (String label : host.split("\\.", -1))
            if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))
                throw new IllegalArgumentException("invalid DNS label");
        return new Endpoint("hostname", host, n, "auto");
    }

    private static String compress(byte[] b) {
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) g[i] = ((b[i * 2] & 255) << 8) | (b[i * 2 + 1] & 255);
        int best = -1, length = 1;
        for (int i = 0; i < 8; ) {
            if (g[i] != 0) {
                i++;
                continue;
            }
            int j = i;
            while (j < 8 && g[j] == 0) j++;
            if (j - i > length) {
                best = i;
                length = j - i;
            }
            i = j;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; ) {
            if (i == best) {
                out.append("::");
                i += length;
                continue;
            }
            if (out.length() > 0 && out.charAt(out.length() - 1) != ':') out.append(':');
            out.append(Integer.toHexString(g[i++]));
        }
        return out.toString();
    }

    public JSONObject json() {
        JSONObject j = new JSONObject();
        j.put("kind", kind);
        j.put("host", host);
        j.put("port", port);
        j.put("family", family);
        return j;
    }
}
