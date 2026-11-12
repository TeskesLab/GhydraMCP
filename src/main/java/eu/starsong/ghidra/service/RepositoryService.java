package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.ConnectionProfiles;
import eu.starsong.ghidra.connection.Profile;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.ManagedProgramGuard;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.base.project.GhidraProject;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** Native Ghidra Server client. Never converts or changes the user's active project. */
public final class RepositoryService implements AutoCloseable {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final Set<java.nio.file.attribute.PosixFilePermission> PRIVATE =
        PosixFilePermissions.fromString("rwx------");
    private static final java.lang.reflect.Method FILE_LINK_PREDICATE = fileLinkPredicate();

    interface Access {
        <T> T call(String id, String grant, Function<Profile, T> operation);
        Path directory();
    }

    interface Connector {
        Workspace connect(Profile profile, Path directory) throws Exception;
    }

    interface Workspace extends AutoCloseable {
        Project project();
        boolean readOnly() throws Exception;
        void refresh() throws Exception;
        @Override void close() throws Exception;
    }

    private final Map<String, Profile> bindings = new HashMap<>();
    private final Access access;
    private final Connector connector;
    private final String instance;
    private final Map<String, Workspace> workspaces = new HashMap<>();
    private final Map<Program, String> programs = new IdentityHashMap<>();
    private boolean closed;

    public RepositoryService() {
        this("process-" + ProcessHandle.current().pid());
    }

    public RepositoryService(int port) {
        this("instance-" + port);
    }

    private RepositoryService(String instance) {
        this(new Access() {
            public <T> T call(String id, String grant, Function<Profile, T> operation) {
                return ConnectionProfiles.withProfile(id, "ghidra", grant, operation);
            }
            public Path directory() { return ConnectionProfiles.directory(); }
        }, RepositoryService::connectNative, instance);
    }

    RepositoryService(Access access, Connector connector, String instance) {
        this.access = access;
        this.connector = connector;
        this.instance = instance;
    }

    public synchronized Map<String, Object> status(String profile) {
        return execute(profile, "read", p -> {
            Workspace ws = workspace(p);
            ws.refresh();
            return Map.of("profile", p.id(), "connected", true,
                "read_only", ws.readOnly()
                    || (!p.permissions().contains("checkout") && !p.permissions().contains("checkin")),
                "permissions", p.permissions());
        });
    }

    /** One folder, not a recursive walk. Truncation counts folders and files accurately. */
    public synchronized Map<String, Object> files(String profile, String path, int offset, int limit) {
        String safePath = validatePath(path, true);
        if (offset < 0 || limit < 1 || limit > 1000) {
            throw invalid("Listing offset must be nonnegative and limit must be between 1 and 1000");
        }
        return execute(profile, "read", p -> {
            Workspace ws = workspace(p);
            ws.refresh();
            DomainFolder folder = folder(ws.project().getProjectData(), safePath);
            DomainFolder[] folders = folder.getFolders();
            DomainFile[] files = folder.getFiles();
            long total = (long) folders.length + files.length;
            List<Map<String, Object>> entries = new ArrayList<>((int) Math.min(limit, Math.max(0, total - offset)));
            int skip = offset;
            for (DomainFolder child : folders) {
                if (entries.size() == limit) break;
                if (skip > 0) { skip--; continue; }
                entries.add(Map.of("path", child.getPathname(), "name", child.getName(), "type", "folder"));
            }
            for (DomainFile child : files) {
                if (entries.size() == limit) break;
                if (skip > 0) { skip--; continue; }
                Map<String, Object> entry = describe(child);
                entry.put("type", "file");
                entries.add(entry);
            }
            return Map.of("profile", p.id(), "path", safePath, "entries", entries,
                "count", entries.size(), "total", total, "offset", offset, "limit", limit,
                "truncated", offset > 0 || total > entries.size(),
                "has_more", (long) offset + entries.size() < total);
        });
    }

    public synchronized Map<String, Object> open(GhidraContext ctx, String profile, String path, int version) {
        String safePath = validatePath(path, false);
        if (version != -1 && version < 1) throw invalid("Version must be -1 or a positive integer");
        // Inspect the active database on EDT; native network and disk operations below stay off EDT.
        GhidraSwing.runRead(() -> {
            Program current = ctx.program();
            if (current != null && current.isChanged()) {
                throw conflict("Save or close the current program before opening a repository program");
            }
        });
        return execute(profile, "read", p -> {
            Workspace ws = workspace(p);
            ws.refresh();
            DomainFile file = file(ws.project().getProjectData(), safePath);
            boolean writable = version == -1 && p.permissions().contains("checkout") && !ws.readOnly()
                && file.isCheckedOut() && !file.isReadOnly();
            if (writable && (!file.isCheckedOutExclusive() || !file.isLatestVersion()
                    || file.getVersion() != file.getLatestVersion())) {
                throw conflict("Editing requires a current exclusive repository checkout");
            }
            if (writable && file.canRecover()) {
                throw conflict("Recover the repository program outside this API before opening it for editing");
            }
            int requestedVersion = version == -1 ? file.getLatestVersion() : version;
            Program retained = GhidraSwing.runRead(() -> {
                for (var entry : programs.entrySet()) {
                    Program candidate = entry.getKey();
                    if (entry.getValue().equals(p.id()) && !candidate.isClosed()
                            && candidate.getDomainFile().getPathname().equals(safePath)
                            && candidate.getDomainFile().getVersion() == requestedVersion
                            && candidate.getDomainFile().isReadOnly() == !writable) return candidate;
                }
                return null;
            });
            boolean alreadyOwned = retained != null;
            Program program = retained;
            if (program == null) {
                // READ_ONLY permits local compatibility adjustments without altering the stored version.
                DomainObject object = writable
                    ? file.getDomainObject(this, false, false, MONITOR)
                    : file.getReadOnlyDomainObject(this, requestedVersion, MONITOR);
                if (!(object instanceof Program nativeProgram)) {
                    object.release(this);
                    throw invalid("Repository file is not a program");
                }
                program = nativeProgram;
            }
            try {
                if (!writable) ManagedProgramGuard.registerReadOnly(program);
                ctx.activateProgram(program, ws.project());
                programs.put(program, p.id());
            } catch (RuntimeException e) {
                if (!alreadyOwned) program.release(this);
                throw e;
            }
            releaseInactivePrograms(program);
            Program activated = program;
            int openedVersion = GhidraSwing.runRead(() -> activated.getDomainFile().getVersion());
            return Map.of("profile", p.id(), "path", safePath, "version", openedVersion,
                "opened", true, "read_only", !writable);
        });
    }

    private void releaseInactivePrograms(Program active) {
        GhidraSwing.runRead(() -> {
            var iterator = programs.keySet().iterator();
            while (iterator.hasNext()) {
                Program program = iterator.next();
                if (program == active || program.isChanged()) continue;
                List<Object> consumers = program.getConsumerList();
                if (consumers.size() == 1 && consumers.get(0) == this) {
                    program.release(this);
                    iterator.remove();
                }
            }
        });
    }


    /**
     * Inspect one selected BSim identity through an approved repository binding.
     * The temporary consumer never enters the selection/program cache or checks out a file.
     */
    public synchronized Map<String, Object> inspectMatch(String profile, Map<?, ?> match,
            int version, int maxCodeLines) {
        return referenceMatch(profile, match, version, maxCodeLines, false);
    }

    public synchronized Map<String, Object> exportMatch(String profile, Map<?, ?> match, int version) {
        return referenceMatch(profile, match, version, 1000, true);
    }

    private Map<String, Object> referenceMatch(String profile, Map<?, ?> match,
            int version, int maxCodeLines, boolean exporting) {
        if (profile == null || profile.isBlank()) throw invalid("An explicit reference profile is required");
        Set<String> fields = Set.of("match_id", "function", "address", "executable", "path",
            "similarity", "significance", "executable_md5", "repository_url", "architecture",
            "compiler", "reference_available", "reference_reason");
        if (match == null || !fields.containsAll(match.keySet())) throw invalid("Unsupported match field");
        String matchId = matchText(match, "match_id");
        if (!matchId.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            throw invalid("Invalid selected match identifier");
        }
        String md5 = matchText(match, "executable_md5");
        if (!md5.matches("[0-9a-fA-F]{32}")) throw invalid("Invalid selected executable MD5");
        String address = matchText(match, "address");
        if (!address.matches("(?:[A-Za-z_][A-Za-z0-9_.-]*::)?(?:0[xX])?[0-9a-fA-F]{1,16}")) {
            throw invalid("Invalid selected function address");
        }
        String repositoryUrl = matchText(match, "repository_url");
        URI selected = repositoryURI(repositoryUrl);
        if (version != -1 && version < 1) throw invalid("Version must be -1 or a positive integer");
        if (maxCodeLines < 1 || maxCodeLines > 10000) {
            throw invalid("max_code_lines must be between 1 and 10000");
        }
        String indexedName = match.get("function") instanceof String name ? name : null;
        return execute(profile, "read", p -> {
            String path = matchPath(p, selected);
            Workspace ws = workspace(p);
            ws.refresh();
            DomainFile file = file(ws.project().getProjectData(), path);
            if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
                throw invalid("Repository file is not a native program");
            }
            if (!file.isVersioned()) throw conflict("Reference file has no stored repository version");
            int concreteVersion = version == -1 ? file.getLatestVersion() : version;
            if (concreteVersion < 1) throw conflict("Reference file has no stored repository version");
            Object consumer = new Object();
            DomainObject object = file.getReadOnlyDomainObject(consumer, concreteVersion, MONITOR);
            if (object == null) throw notFound();
            try {
                if (!(object instanceof Program program)) throw invalid("Repository file is not a native program");
                ghidra.program.model.listing.Function function = GhidraSwing.runUninterruptibly(() -> GhidraSwing.runRead(() -> {
                    ManagedProgramGuard.registerReadOnly(program);
                    if (program.isClosed() || program.getExecutableMD5() == null
                            || !md5.equalsIgnoreCase(program.getExecutableMD5())) {
                        throw new ConnectionException("BSIM_REFERENCE_IDENTITY_MISMATCH", 409,
                            "Reference executable MD5 does not match the selected match");
                    }
                    return resolveMatchFunction(program, address, indexedName);
                }));
                long modification = GhidraSwing.runRead(program::getModificationNumber);
                Map<String, Object> snapshot = exporting
                    ? BSimSignatureTransfer.export(program, function)
                    : BSimFunctionSnapshot.capture(program, function, maxCodeLines);
                GhidraSwing.runUninterruptibly(() -> GhidraSwing.runRead(() -> {
                    if (program.isClosed() || !md5.equalsIgnoreCase(program.getExecutableMD5())
                            || program.getModificationNumber() != modification) {
                        throw conflict("Reference changed during evidence capture");
                    }
                    return null;
                }));
                Map<String, Object> result = new java.util.LinkedHashMap<>();
                result.put("match_id", matchId);
                result.put("identity_verified", true);
                result.put("profile", p.id());
                result.put("path", path);
                result.put("version", concreteVersion);
                if (exporting) {
                    result.putAll(snapshot);
                    result.put("identity", Map.of("repository_url", repositoryUrl,
                        "executable_md5", md5.toLowerCase(java.util.Locale.ROOT),
                        "selected_address", address,
                        "address", GhidraSwing.runRead(() -> BSimMatchService.qualifiedAddress(function)),
                        "indexed_function", indexedName == null ? "" : indexedName));
                } else {
                    result.put("snapshot", snapshot);
                    if (indexedName != null) {
                        Map<?, ?> capturedFunction = (Map<?, ?>) snapshot.get("function");
                        result.put("indexed_name", indexedName);
                        result.put("name_changed", !indexedName.equals(capturedFunction.get("name")));
                    }
                }
                if (exporting) BSimSignatureTransfer.requireBoundedJson(result);
                return result;
            } finally {
                // Native release/close performs disk I/O and must stay off the EDT.
                object.release(consumer);
            }
        });
    }

    private static String matchText(Map<?, ?> match, String key) {
        if (!(match.get(key) instanceof String value) || value.isBlank() || value.length() > 8192) {
            throw invalid("Selected match identity is incomplete");
        }
        return value;
    }

    private static URI repositoryURI(String value) {
        try {
            URI uri = new URI(value);
            if (!"ghidra".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                    || uri.getPort() == 0 || uri.getPort() > 65535 || uri.getPort() < -1
                    || uri.getRawPath() == null || uri.getRawPath().matches("(?i).*%(?:2f|5c).*")) {
                throw invalid("Invalid selected repository URL");
            }
            validatePath(uri.getPath(), false);
            return uri;
        } catch (java.net.URISyntaxException e) {
            throw invalid("Invalid selected repository URL");
        }
    }

    private static String matchPath(Profile profile, URI selected) {
        String endpoint = profile.endpoint();
        URI approved = repositoryURI(endpoint.endsWith("/") ? endpoint.substring(0, endpoint.length() - 1) : endpoint);
        String repository = approved.getPath();
        if (!repository.matches("/[^/]+") || !approved.getHost().equalsIgnoreCase(selected.getHost())
                || nativePort(approved) != nativePort(selected) || !selected.getPath().startsWith(repository + "/")) {
            throw new ConnectionException("BSIM_REFERENCE_SCOPE_MISMATCH", 403,
                "Selected repository URL is outside the approved profile");
        }
        return validatePath(selected.getPath().substring(repository.length()), false);
    }

    private static int nativePort(URI uri) { return uri.getPort() == -1 ? 13100 : uri.getPort(); }

    /** Exact entry point, never a containing function or a name-only substitute. Called on EDT. */
    static ghidra.program.model.listing.Function resolveMatchFunction(Program program,
            String coordinate, String indexedName) {
        int separator = coordinate.indexOf("::");
        String offsetText = separator < 0 ? coordinate : coordinate.substring(separator + 2);
        if (offsetText.startsWith("0x") || offsetText.startsWith("0X")) offsetText = offsetText.substring(2);
        long offset;
        try { offset = Long.parseUnsignedLong(offsetText, 16); }
        catch (NumberFormatException e) { throw invalid("Invalid selected function address"); }
        var factory = program.getAddressFactory();
        if (separator >= 0) {
            var space = factory.getAddressSpace(coordinate.substring(0, separator));
            var exact = functionAt(program, space, offset);
            if (exact != null) return exact;
            throw new ConnectionException("BSIM_REFERENCE_FUNCTION_NOT_FOUND", 404,
                "Selected reference function was not found at its exact address");
        }
        ghidra.program.model.listing.Function sole = null;
        ghidra.program.model.listing.Function named = null;
        int candidates = 0, namedCandidates = 0;
        for (var space : factory.getAddressSpaces()) {
            var candidate = functionAt(program, space, offset);
            if (candidate == null) continue;
            sole = candidate;
            candidates++;
            if (indexedName != null && indexedName.equals(candidate.getName(true))) {
                named = candidate;
                namedCandidates++;
            }
        }
        if (candidates == 1) return sole;
        if (namedCandidates == 1) return named;
        if (candidates == 0) {
            throw new ConnectionException("BSIM_REFERENCE_FUNCTION_NOT_FOUND", 404,
                "Selected reference function was not found at its exact address");
        }
        throw new ConnectionException("BSIM_REFERENCE_ADDRESS_AMBIGUOUS", 409,
            "Selected reference function address is ambiguous");
    }

    private static ghidra.program.model.listing.Function functionAt(Program program,
            ghidra.program.model.address.AddressSpace space, long offset) {
        if (space == null || !space.isMemorySpace()) return null;
        try { return program.getFunctionManager().getFunctionAt(space.getAddress(offset)); }
        catch (ghidra.program.model.address.AddressOutOfBoundsException e) { return null; }
    }

    public synchronized Map<String, Object> checkout(String profile, String path, boolean exclusive) {
        String safePath = validatePath(path, false);
        return execute(profile, "checkout", p -> {
            Workspace ws = workspace(p);
            requireWritable(ws);
            ws.refresh();
            DomainFile file = file(ws.project().getProjectData(), safePath);
            checkoutFile(file, exclusive);
            Map<String, Object> result = describe(file);
            result.put("profile", p.id());
            return result;
        });
    }

    public synchronized Map<String, Object> checkin(String profile, String path, String comment,
            boolean keepCheckedOut) {
        String safePath = validatePath(path, false);
        if (comment == null || comment.isBlank() || comment.length() > 4096) {
            throw invalid("An explicit nonblank check-in comment of at most 4096 characters is required");
        }
        return execute(profile, "checkin", p -> {
            Workspace ws = workspace(p);
            requireWritable(ws);
            ws.refresh();
            DomainFile file = file(ws.project().getProjectData(), safePath);
            // Ghidra otherwise silently keeps an open program checked out. Only release our
            // sole consumer, never close a GUI/headless-owned program or discard changes.
            if (!keepCheckedOut) releaseUnusedPrograms(p.id(), safePath);
            checkinFile(file, comment, keepCheckedOut);
            Map<String, Object> result = describe(file);
            result.put("profile", p.id());
            result.put("checked_in", true);
            return result;
        });
    }

    static void checkoutFile(DomainFile file, boolean exclusive) throws Exception {
        if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
            throw invalid("Only native program files support repository checkout through this API");
        }
        if (!file.isVersioned() || file.isHijacked() || file.isCheckedOut() || file.isChanged()
                || file.isOpen() || file.isBusy() || file.canRecover()) {
            throw conflict("File must be versioned, closed, unchanged and not already checked out");
        }
        if (!file.canCheckout()) throw readOnly();
        if (!file.checkout(exclusive, MONITOR) || !file.isCheckedOut()
                || (exclusive && !file.isCheckedOutExclusive())) {
            throw conflict("Checkout was not granted; no checkout was forced");
        }
    }

    static void checkinFile(DomainFile file, String comment, boolean keepCheckedOut) throws Exception {
        if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
            throw invalid("Only native program files support no-merge check-in through this API");
        }
        if (!file.isCheckedOut() || file.isHijacked() || file.isBusy() || file.canRecover()) {
            throw conflict("File must have a valid local checkout with no recovery or busy state");
        }
        if (!file.isCheckedOutExclusive() || System.getProperty("ForceMerge") != null) {
            throw conflict("Check-in requires an exclusive checkout to guarantee no automatic merge");
        }
        if (!file.isLatestVersion() || file.getVersion() != file.getLatestVersion()) {
            throw conflict("Repository version changed; resolve the conflict outside this API");
        }
        if (file.isChanged()) throw conflict("Save the program locally before check-in; save is not check-in");
        if (!keepCheckedOut && file.isOpen()) {
            throw conflict("Close the program before releasing checkout, or use keep_checked_out=true");
        }
        if (!file.modifiedSinceCheckout()) throw conflict("No saved changes exist since checkout");
        if (!file.canCheckin()) throw readOnly();
        int previous = file.getLatestVersion();
        file.checkin(new CheckinHandler() {
            public String getComment() { return comment; }
            public boolean keepCheckedOut() { return keepCheckedOut; }
            public boolean createKeepFile() { return false; }
        }, MONITOR);
        if (file.getLatestVersion() <= previous || file.isCheckedOut() != keepCheckedOut) {
            throw conflict("Native check-in did not complete the requested state transition; inspect repository state");
        }
    }

    private void releaseUnusedPrograms(String profile, String path) {
        GhidraSwing.runRead(() -> {
            var iterator = programs.entrySet().iterator();
            while (iterator.hasNext()) {
                var entry = iterator.next();
                Program program = entry.getKey();
                if (!entry.getValue().equals(profile) || !program.getDomainFile().getPathname().equals(path)) continue;
                if (program.isChanged()) throw conflict("Save the program locally before check-in");
                List<Object> consumers = program.getConsumerList();
                if (consumers.size() == 1 && consumers.get(0) == this) {
                    program.release(this);
                    iterator.remove();
                }
            }
        });
    }

    private Workspace workspace(Profile profile) throws Exception {
        Workspace existing = workspaces.get(profile.id());
        if (existing != null) {
            if (!profile.equals(bindings.get(profile.id()))) {
                throw conflict("Profile changed while its workspace is active; restart the worker or select a new profile");
            }
            return existing;
        }
        Path root = access.directory();
        if (root == null) throw invalid("Repository worker directory is not configured");
        Path directory = privateDirectory(privateDirectory(privateDirectory(root, "repositories"), instance), profile.id());
        Workspace created = connector.connect(profile, directory);
        workspaces.put(profile.id(), created);
        bindings.put(profile.id(), profile);
        return created;
    }

    private static Path privateDirectory(Path parent, String name) throws Exception {
        Path directory = parent.resolve(name);
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PRIVATE));
        }
        if (Files.isSymbolicLink(directory) || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS).equals(PRIVATE)
                || !Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS))) {
            throw new ConnectionException("CONNECTION_STORE_UNSAFE", 403, "Repository workspace protection is unsafe");
        }
        return directory;
    }

    private <T> T execute(String id, String permission, NativeOperation<T> operation) {
        if (SwingUtilities.isEventDispatchThread()) {
            throw conflict("Native repository operations must run off the Swing thread");
        }
        if (closed) throw new RepositoryException("REPOSITORY_CLOSED", 409, "Repository service is closed");
        return access.call(id, permission, profile -> {
            try {
                return operation.run(profile);
            } catch (ConnectionException | RepositoryException e) {
                throw e;
            } catch (LinkageError | ClassNotFoundException | NoSuchMethodException e) {
                throw new RepositoryException("REPOSITORY_UNSUPPORTED", 501, "Required native Ghidra repository APIs are unavailable");
            } catch (Exception e) {
                // Never propagate native exception messages/causes: they can contain identities or endpoints.
                Throwable nativeError = e;
                while (nativeError instanceof InvocationTargetException target && target.getCause() != null) {
                    nativeError = target.getCause();
                }
                String type = nativeError.getClass().getName();
                if (Set.of("ghidra.framework.store.LockException", "ghidra.util.exception.FileInUseException",
                        "ghidra.util.exception.VersionException", "ghidra.util.NotOwnerException").contains(type)) {
                    throw conflict("Native project or program is locked or incompatible; resolve it outside this API");
                }
                if (Set.of("ghidra.util.ReadOnlyException", "ghidra.util.exception.UserAccessException").contains(type)) {
                    throw readOnly();
                }
                throw new ConnectionException("CONNECTION_FAILED", 502, "Native repository operation failed");
            }
        });
    }

    @FunctionalInterface private interface NativeOperation<T> { T run(Profile profile) throws Exception; }

    private static void requireWritable(Workspace ws) throws Exception {
        if (ws.readOnly()) throw readOnly();
    }

    static String validatePath(String path, boolean rootAllowed) {
        if (path == null || !path.startsWith("/") || path.length() > 4096
                || path.indexOf('\\') >= 0 || path.indexOf('%') >= 0
                || path.chars().anyMatch(c -> c < 32 || c == 127)) throw invalid("Invalid repository path");
        if (path.equals("/") && rootAllowed) return path;
        for (String component : path.substring(1).split("/", -1)) {
            if (component.isEmpty() || component.equals(".") || component.equals("..")) throw invalid("Invalid repository path");
        }
        return path;
    }

    private static DomainFolder folder(ProjectData data, String path) {
        DomainFolder current = data.getRootFolder();
        if (path.equals("/")) return current;
        for (String component : path.substring(1).split("/")) {
            current = current.getFolder(component);
            if (current == null || current.isLinked()) throw notFound();
        }
        return current;
    }

    private static DomainFile file(ProjectData data, String path) throws ReflectiveOperationException {
        int split = path.lastIndexOf('/');
        DomainFolder parent = folder(data, split == 0 ? "/" : path.substring(0, split));
        DomainFile file = parent.getFile(path.substring(split + 1));
        if (file == null || !file.exists()) throw notFound();
        if (FILE_LINK_PREDICATE == null) throw new NoSuchMethodException("Native repository link predicate is unavailable");
        if ((Boolean) FILE_LINK_PREDICATE.invoke(file, (Object[]) null)) throw notFound();
        return file;
    }

    /** Ghidra 12 renamed the Ghidra 11 link predicate; resolve it once, fail closed if absent. */
    private static java.lang.reflect.Method fileLinkPredicate() {
        try { return DomainFile.class.getMethod("isLink"); }
        catch (NoSuchMethodException renamed) {
            try { return DomainFile.class.getMethod("isLinkFile"); }
            catch (NoSuchMethodException unavailable) { return null; }
        }
    }

    private static Map<String, Object> describe(DomainFile file) {
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("path", file.getPathname());
        result.put("name", file.getName());
        result.put("version", file.getVersion());
        result.put("latest_version", file.getLatestVersion());
        result.put("checked_out", file.isCheckedOut());
        result.put("exclusive", file.isCheckedOutExclusive());
        result.put("modified_since_checkout", file.modifiedSinceCheckout());
        return result;
    }

    /** Optional FileSystem.jar types are reflected so the committed baseline can compile. */
    private static Workspace connectNative(Profile profile, Path directory) throws Exception {
        URL endpoint = profile.nativeURL();
        String repository = endpoint.getPath();
        if (!"ghidra".equals(endpoint.getProtocol()) || repository == null
                || !repository.matches("/[^/]+/?")) throw invalid("Profile must select exactly one native repository");
        repository = repository.substring(1).replaceAll("/$", "");
        Class<?> clients = Class.forName("ghidra.framework.client.ClientUtil");
        Object server = clients.getMethod("getRepositoryServer", String.class, int.class, boolean.class)
            .invoke(null, endpoint.getHost(), endpoint.getPort() > 0 ? endpoint.getPort() : 13100, true);
        if (server == null || !Boolean.TRUE.equals(invoke(server, "connect"))) {
            throw new ConnectionException("CONNECTION_AUTH_FAILED", 401, "Native repository authentication failed");
        }
        eu.starsong.ghidra.connection.WorkerAuthentication.verifyRepositoryIdentity(
            profile, (String) invoke(server, "getUser"));
        Object adapter = server.getClass().getMethod("getRepository", String.class).invoke(server, repository);
        if (adapter == null) throw notFound();
        GhidraProject local = null;
        try {
            invoke(adapter, "connect");
            verifyRepositoryIdentity(profile, adapter);
            Path marker = directory.resolve("checkout.gpr");
            if (Files.isSymbolicLink(marker) || Files.isSymbolicLink(directory.resolve("checkout.rep"))) {
                throw new ConnectionException("CONNECTION_STORE_UNSAFE", 403, "Repository workspace protection is unsafe");
            }
            boolean existing = Files.exists(marker, LinkOption.NOFOLLOW_LINKS);
            if (!existing) {
                // createProject may delete matching remnants: a missing marker is not
                // permission to replace an existing checkout or broken local workspace.
                try (var contents = Files.newDirectoryStream(directory)) {
                    if (contents.iterator().hasNext()) {
                        throw conflict("Incomplete local workspace requires manual repair; no files were replaced");
                    }
                }
            }
            local = (GhidraProject) GhidraProject.class.getMethod(
                existing ? "openProject" : "createProject", String.class, String.class, boolean.class)
                .invoke(null, directory.toString(), "checkout", false);
            ProjectData data = local.getProject().getProjectData();
            Class<?> repositoryType = Class.forName("ghidra.framework.client.RepositoryAdapter");
            if (!existing) {
                ProjectData.class.getMethod("convertProjectToShared", repositoryType, TaskMonitor.class)
                    .invoke(data, adapter, MONITOR);
                // Conversion replaces the filesystem, but existing folder/file caches still
                // reference the disposed private filesystem. Reopen before exposing the workspace.
                local.close();
                local = null;
                local = (GhidraProject) GhidraProject.class.getMethod(
                    "openProject", String.class, String.class, boolean.class)
                    .invoke(null, directory.toString(), "checkout", false);
                data = local.getProject().getProjectData();
            }
            Object liveAdapter = ProjectData.class.getMethod("getRepository").invoke(data);
            if (liveAdapter == null || !repository.equals(invoke(liveAdapter, "getName"))
                    || !invoke(adapter, "getServerInfo").equals(invoke(liveAdapter, "getServerInfo"))) {
                throw conflict("Local workspace belongs to a different repository; use a new profile");
            }
            invoke(liveAdapter, "connect");
            verifyRepositoryIdentity(profile, liveAdapter);
            GhidraProject project = local;
            return new Workspace() {
                public Project project() { return project.getProject(); }
                public boolean readOnly() throws Exception {
                    Object user = invoke(liveAdapter, "getUser");
                    return Boolean.TRUE.equals(invoke(server, "isReadOnly")) || user == null
                        || !Boolean.TRUE.equals(invoke(user, "hasWritePermission"));
                }
                public void refresh() throws Exception {
                    if (!Boolean.TRUE.equals(invoke(server, "connect"))) {
                        throw new ConnectionException("CONNECTION_AUTH_FAILED", 401, "Native repository authentication failed");
                    }
                    invoke(liveAdapter, "connect");
                    verifyRepositoryIdentity(profile, liveAdapter);
                    project.getProject().getProjectData().refresh(false);
                }
                public void close() throws Exception {
                    try { project.close(); } finally { invoke(liveAdapter, "disconnect"); }
                }
            };
        } catch (Exception | LinkageError e) {
            if (local != null) local.close();
            invoke(adapter, "disconnect");
            throw e;
        }
    }

    private static void verifyRepositoryIdentity(Profile profile, Object adapter) throws Exception {
        Object user = invoke(adapter, "getUser");
        eu.starsong.ghidra.connection.WorkerAuthentication.verifyRepositoryIdentity(
            profile, user == null ? null : (String) invoke(user, "getName"));
    }

    private static Object invoke(Object object, String method) throws Exception {
        try { return object.getClass().getMethod(method).invoke(object); }
        catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception cause) throw cause;
            throw e;
        }
    }

    /** Refuse before disabling HTTP or releasing the headless selection's consumer. */
    public synchronized void prepareClose(boolean headless) {
        if (!headless) return; // ProgramManager owns GUI save/discard decisions.
        GhidraSwing.runRead(() -> {
            for (Program program : programs.keySet()) {
                if (!program.isClosed() && program.isChanged()
                        && (headless || program.getConsumerList().size() == 1)) {
                    throw conflict("Unsaved repository program prevents shutdown; save it before stopping");
                }
            }
        });
    }

    @Override public void close() { close(true); }

    /** Called only after draining GUI requests; ProgramManager owns their save/discard choices. */
    public void closeAfterGuiDisposal() { close(false); }

    private synchronized void close(boolean protectUnsaved) {
        if (closed) return;
        if (protectUnsaved) GhidraSwing.runRead(() -> {
            for (Program program : programs.keySet()) {
                if (!program.isClosed() && program.isChanged()
                        && program.getConsumerList().size() == 1) {
                    throw conflict("Unsaved repository program prevents shutdown; save it before stopping");
                }
            }
        });
        closed = true;
        // A GUI may outlive this HTTP server. Keep its workspace/lock until its last
        // program closes instead of invalidating live databases or discarding edits.
        for (var entry : workspaces.entrySet()) {
            Workspace ws = entry.getValue();
            List<Program> retained = programs.entrySet().stream()
                .filter(p -> p.getValue().equals(entry.getKey()))
                .map(Map.Entry::getKey).toList();
            java.util.concurrent.atomic.AtomicBoolean closing = new java.util.concurrent.atomic.AtomicBoolean();
            Runnable finish = () -> {
                for (Program program : retained) if (!program.isClosed()) return;
                if (!closing.compareAndSet(false, true)) return;
                Runnable diskClose = () -> {
                    try { ws.close(); }
                    catch (Exception | LinkageError e) {
                        ghidra.util.Msg.warn(RepositoryService.class, "Native repository workspace could not close cleanly");
                    }
                };
                if (SwingUtilities.isEventDispatchThread()) {
                    java.util.concurrent.CompletableFuture.runAsync(diskClose);
                } else {
                    diskClose.run();
                }
            };
            for (Program program : retained) {
                if (!program.isClosed()) program.addCloseListener(
                    ignored -> java.util.concurrent.CompletableFuture.runAsync(finish));
            }
            for (Program program : retained) {
                if (!program.isClosed()) program.release(this);
            }
            finish.run();
        }
        programs.clear();
        workspaces.clear();
        bindings.clear();
    }

    private static RepositoryException invalid(String message) { return new RepositoryException("REPOSITORY_PATH_INVALID", 400, message); }
    private static RepositoryException conflict(String message) { return new RepositoryException("REPOSITORY_CONFLICT", 409, message); }
    private static RepositoryException readOnly() { return new RepositoryException("REPOSITORY_READ_ONLY", 403, "Native repository does not permit this write"); }
    private static RepositoryException notFound() { return new RepositoryException("REPOSITORY_NOT_FOUND", 404, "Repository file or folder was not found"); }

    public static final class RepositoryException extends RuntimeException {
        private final String code;
        private final int status;
        public RepositoryException(String code, int status, String message) {
            super(message);
            this.code = code;
            this.status = status;
        }
        public String code() { return code; }
        public int status() { return status; }
    }
}
