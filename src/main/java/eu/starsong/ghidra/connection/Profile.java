package eu.starsong.ghidra.connection;

import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.Set;

/** Approved connection policy. Credentials are deliberately not part of this value. */
public record Profile(String id, String kind, String backend, String endpoint, String auth,
        String credentialRef, Set<String> permissions) {
    public Profile {
        permissions = Set.copyOf(permissions);
    }

    public URL nativeURL() {
        try {
            return new URI(endpoint).toURL();
        } catch (Exception invalid) {
            throw new ConnectionException("CONNECTION_PROFILE_INVALID", 400,
                "The configured endpoint is not supported by this Ghidra installation.");
        }
    }

    public Map<String, Object> publicView() {
        return Map.of("id", id, "kind", kind, "backend", backend,
            "permissions", permissions.stream().sorted().toList());
    }

    @Override
    public String toString() { return "Profile[" + id + ", " + kind + ", " + backend + "]"; }
}
