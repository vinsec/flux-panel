package com.admin.common.engine;

import com.admin.common.lang.R;
import com.admin.entity.Node;
import com.alibaba.fastjson.JSONObject;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;

/**
 * Install instructions require publisher-pinned artifacts, never a floating upstream GOST asset
 * whose WSS/reporting implementation may differ.
 */
@Service
public class NodeReleaseService {
    @Value("${node.release.base-url:}")
    private String base;

    @Value("${node.release.manifest-sha256:}")
    private String manifest;

    @Value("${node.release.installer-sha256:}")
    private String installer;

    static String quoted(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    static String secureBase(String text) {
        URI uri = URI.create(text);
        if (!"https".equals(uri.getScheme())
                || uri.getHost() == null
                || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null)
            throw new IllegalArgumentException("release URL must be a pinned HTTPS base");
        return text.replaceAll("/+$", "");
    }

    public R command(Node node, String panel) {
        try {
            if (!manifest.matches("[a-fA-F0-9]{64}") || !installer.matches("[a-fA-F0-9]{64}"))
                return R.err(
                        "请先发布经过验证的节点安装包，并配置固定 release URL、manifest SHA256 和 installer"
                            + " SHA256；也可使用已校验的离线包。未回退到未经验证的上游 GOST 下载。");
            String release = secureBase(base);
            String addr = panel.matches("^[a-z]+://.*") ? panel : "wss://" + panel;
            URI endpoint = URI.create(addr);
            if (endpoint.getHost() == null
                    || !java.util.Set.of("wss", "https").contains(endpoint.getScheme())
                    || endpoint.getRawUserInfo() != null
                    || endpoint.getRawQuery() != null
                    || endpoint.getRawFragment() != null)
                throw new IllegalArgumentException("节点安装需要有效的 WSS/HTTPS 面板地址");
            String engine = EngineRegistry.normalize(node.getEngine());
            JSONObject config = new JSONObject();
            config.put("addr", addr);
            config.put("secret", node.getSecret());
            if ("iptables".equals(engine)) {
                config.put("apply", true);
                config.put("statePath", "/var/lib/flux-agent/state.json");
                config.put("intervalSeconds", 5);
            }
            String command =
                    "umask 077\nFLUX_SETUP=$(mktemp -d)\ntrap 'rm -rf -- \"$FLUX_SETUP\"' EXIT\n"
                            + "curl --fail --location --proto '=https' --proto-redir '=https' "
                            + quoted(release + "/install.sh")
                            + " -o \"$FLUX_SETUP/install.sh\"\n"
                            + "printf '%s  %s\\n' "
                            + quoted(installer.toLowerCase())
                            + " \"$FLUX_SETUP/install.sh\" | sha256sum --strict -c -\n"
                            + "cat > \"$FLUX_SETUP/config.json\" <<'FLUX_NODE_CONFIG'\n"
                            + config.toJSONString()
                            + "\nFLUX_NODE_CONFIG\n"
                            + "bash \"$FLUX_SETUP/install.sh\" --engine "
                            + engine
                            + " --release-url "
                            + quoted(release)
                            + " --manifest-sha256 "
                            + quoted(manifest.toLowerCase())
                            + " --config \"$FLUX_SETUP/config.json\"";
            return R.ok(command);
        } catch (IllegalArgumentException e) {
            return R.err(e.getMessage());
        }
    }
}
