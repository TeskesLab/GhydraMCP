package eu.starsong.ghidra.service;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.connection.Profile;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.junit.Assert.*;

/** Deterministic native state fixtures: no server, credentials, or remote connections. */
public class RepositoryServiceTest {
    private static Profile profile(Set<String> grants) {
        return new Profile("test", "ghidra", "ghidra", "ghidra://example.invalid/repository",
            "none", null, grants);
    }

    private static final class Access implements RepositoryService.Access {
        Profile profile;
        final Path root;
        int calls;
        Access(Set<String> grants) throws Exception {
            profile = profile(grants);
            root = Files.createTempDirectory("ghydra-repository-test-");
        }
        public Path directory() { return root; }
        public <T> T call(String id, String grant, Function<Profile, T> operation) {
            calls++;
            if (!profile.id().equals(id)) throw new ConnectionException("CONNECTION_PROFILE_NOT_FOUND", 404, "Unknown profile");
            if (!profile.permissions().contains(grant)) throw new ConnectionException("CONNECTION_PERMISSION_DENIED", 403, "Permission denied");
            return operation.apply(profile);
        }
    }

    private static final class NativeFile implements InvocationHandler {
        boolean checkedOut;
        boolean exclusive;
        boolean changed;
        boolean saved;
        boolean open;
        boolean hijacked;
        boolean recover;
        boolean busy;
        boolean link;
        boolean writable = true;
        boolean grantCheckout = true;
        int version = 1;
        int latest = 1;
        int checkoutCalls;
        int checkinCalls;
        int openCalls;
        String comment;
        String name = "program";
        final DomainFile file = proxy(DomainFile.class, this);
        NativeProgram program = new NativeProgram(this, false, -1);
        boolean writableOpen;
        int requestedVersion;

        @Override public Object invoke(Object proxy, Method method, Object[] args) throws Exception {
            return switch (method.getName()) {
                case "getName" -> name;
                case "getDomainObjectClass" -> ghidra.program.model.listing.Program.class;
                case "getPathname" -> "/" + name;
                case "exists", "isVersioned" -> true;
                case "isLink", "isLinkFile" -> link;
                case "isCheckedOut" -> checkedOut;
                case "isCheckedOutExclusive" -> exclusive;
                case "isLatestVersion" -> version == latest;
                case "getVersion" -> version;
                case "getLatestVersion" -> latest;
                case "isChanged" -> changed;
                case "isOpen" -> open;
                case "isBusy" -> busy;
                case "isHijacked" -> hijacked;
                case "canRecover" -> recover;
                case "isReadOnly" -> !writable;
                case "canCheckout", "canCheckin", "canSave" -> writable;
                case "modifiedSinceCheckout" -> saved;
                case "checkout" -> {
                    checkoutCalls++;
                    if (grantCheckout) {
                        checkedOut = true;
                        exclusive = (boolean) args[0];
                    }
                    yield grantCheckout;
                }
                case "getDomainObject", "getReadOnlyDomainObject" -> {
                    openCalls++;
                    writableOpen = method.getName().equals("getDomainObject");
                    requestedVersion = writableOpen ? -1 : ((Number) args[1]).intValue();
                    if (!writableOpen) {
                        assertTrue("Readonly opens must pin a concrete repository version", requestedVersion > 0);
                        program = new NativeProgram(this, true, requestedVersion);
                    } else if (program.readOnly) {
                        program = new NativeProgram(this, false, -1);
                    }
                    program.consumers.add(args[0]);
                    open = true;
                    yield program.program;
                }
                case "save" -> {
                    changed = false;
                    saved = true;
                    yield null;
                }
                case "checkin" -> {
                    checkinCalls++;
                    CheckinHandler handler = (CheckinHandler) args[0];
                    comment = handler.getComment();
                    checkedOut = handler.keepCheckedOut();
                    assertFalse(handler.createKeepFile());
                    version = ++latest;
                    saved = false;
                    yield null;
                }
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                case "toString" -> "SyntheticDomainFile";
                default -> defaultValue(method.getReturnType());
            };
        }
    }

    private static final class NativeProgram implements InvocationHandler {
        final NativeFile file;
        final boolean readOnly;
        final DomainFile readOnlyFile;
        final Set<Object> consumers = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        final List<ghidra.framework.model.DomainObjectClosedListener> listeners = new ArrayList<>();
        final ghidra.program.model.listing.Program program = proxy(ghidra.program.model.listing.Program.class, this);
        boolean closed;
        int locks;
        NativeProgram(NativeFile file, boolean readOnly, int version) {
            this.file = file;
            this.readOnly = readOnly;
            readOnlyFile = proxy(DomainFile.class, (p, method, args) -> switch (method.getName()) {
                case "isReadOnly" -> true;
                case "getVersion" -> version;
                default -> file.invoke(p, method, args);
            });
        }
        public Object invoke(Object proxy, Method method, Object[] args) {
            return switch (method.getName()) {
                case "getDomainFile" -> readOnly ? readOnlyFile : file.file;
                case "isChanged" -> file.changed;
                case "isClosed" -> closed;
                case "getConsumerList" -> new ArrayList<>(consumers);
                case "isChangeable" -> true; // Native compatibility views may still accept DB transactions.
                case "isLocked" -> locks != 0;
                case "lock" -> { locks++; yield true; }
                case "unlock" -> { assertTrue(locks > 0); locks--; yield null; }
                case "addConsumer" -> consumers.add(args[0]);
                case "addCloseListener" -> {
                    listeners.add((ghidra.framework.model.DomainObjectClosedListener) args[0]);
                    yield null;
                }
                case "release" -> {
                    consumers.remove(args[0]);
                    if (consumers.isEmpty()) {
                        closed = true;
                        if (file.program == this) file.open = false;
                        for (var listener : List.copyOf(listeners)) listener.domainObjectClosed(program);
                    }
                    yield null;
                }
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            };
        }
    }

    private static final class ActiveContext extends eu.starsong.ghidra.server.GhidraContext {
        ghidra.program.model.listing.Program selected;
        Project project;
        ActiveContext() { super(null, null, 1234, Map.of()); }
        @Override public ghidra.program.model.listing.Program program() { return selected; }
        @Override public void activateProgram(ghidra.program.model.listing.Program program, Project project) {
            if (selected != null && selected != program) selected.release(this);
            program.addConsumer(this);
            selected = program;
            this.project = project;
        }
        void closeProgram() {
            selected.release(this);
            selected = null;
        }
    }

    private static final class NativeWorkspace implements RepositoryService.Workspace {
        final NativeFile state;
        boolean readOnly;
        boolean closed;
        final java.util.concurrent.CountDownLatch closeLatch = new java.util.concurrent.CountDownLatch(1);
        int refreshes;
        final Project project;
        NativeWorkspace(NativeFile state, int entries) {
            this.state = state;
            DomainFile[] files = new DomainFile[entries];
            for (int index = 0; index < entries; index++) {
                NativeFile entry = index == 0 ? state : new NativeFile();
                entry.name = index == 0 ? "program" : "program-" + index;
                files[index] = entry.file;
            }
            DomainFolder folder = proxy(DomainFolder.class, (p, m, a) -> switch (m.getName()) {
                case "getFiles" -> files;
                case "getFolders" -> new DomainFolder[0];
                case "getFile" -> "program".equals(a[0]) ? state.file : null;
                case "getPathname" -> "/";
                default -> defaultValue(m.getReturnType());
            });
            ProjectData data = proxy(ProjectData.class, (p, m, a) -> switch (m.getName()) {
                case "getRootFolder" -> folder;
                default -> defaultValue(m.getReturnType());
            });
            project = proxy(Project.class, (p, m, a) -> switch (m.getName()) {
                case "getProjectData" -> data;
                default -> defaultValue(m.getReturnType());
            });
        }
        public Project project() { return project; }
        public boolean readOnly() { return readOnly; }
        public void refresh() { refreshes++; }
        public void close() { closed = true; closeLatch.countDown(); }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        return null;
    }

    private static void conflict(ThrowingCall call) throws Exception {
        try { call.run(); fail("Expected conflict"); }
        catch (RepositoryService.RepositoryException e) {
            assertEquals("REPOSITORY_CONFLICT", e.code());
            assertEquals(409, e.status());
        }
    }
    private interface ThrowingCall { void run() throws Exception; }

    @Test public void checkoutSaveAndCheckinAreDifferentNativeTransitions() throws Exception {
        NativeFile state = new NativeFile();
        RepositoryService.checkoutFile(state.file, true);
        assertTrue(state.checkedOut);
        assertTrue(state.exclusive);
        state.changed = true;
        conflict(() -> RepositoryService.checkinFile(state.file, "publish", true));
        assertEquals(0, state.checkinCalls);
        state.file.save(TaskMonitor.DUMMY);
        assertEquals(1, state.latest); // A local save did not publish a repository version.
        assertEquals(0, state.checkinCalls);
        RepositoryService.checkinFile(state.file, "publish", true);
        assertEquals(2, state.latest);
        assertEquals("publish", state.comment);
        assertTrue(state.checkedOut);
    }

    @Test public void checkinCanExplicitlyReleaseClosedExclusiveCheckout() throws Exception {
        NativeFile state = checkedOut();
        RepositoryService.checkinFile(state.file, "release checkout", false);
        assertFalse(state.checkedOut);
        assertEquals(2, state.latest);
    }

    @Test public void checkoutNeverForcesExistingOrDeniedCheckout() throws Exception {
        NativeFile state = checkedOut();
        conflict(() -> RepositoryService.checkoutFile(state.file, true));
        assertEquals(0, state.checkoutCalls);
        state.checkedOut = false;
        state.grantCheckout = false;
        conflict(() -> RepositoryService.checkoutFile(state.file, true));
        assertFalse(state.checkedOut);
    }

    @Test public void nativeConflictsNeverReachCheckinOrAutoMerge() throws Exception {
        List<NativeFile> cases = new ArrayList<>();
        NativeFile stale = checkedOut(); stale.latest = 2; cases.add(stale);
        NativeFile nonexclusive = checkedOut(); nonexclusive.exclusive = false; cases.add(nonexclusive);
        NativeFile changed = checkedOut(); changed.changed = true; cases.add(changed);
        NativeFile hijacked = checkedOut(); hijacked.hijacked = true; cases.add(hijacked);
        NativeFile recover = checkedOut(); recover.recover = true; cases.add(recover);
        NativeFile busy = checkedOut(); busy.busy = true; cases.add(busy);
        NativeFile unchanged = checkedOut(); unchanged.saved = false; cases.add(unchanged);
        for (NativeFile state : cases) {
            conflict(() -> RepositoryService.checkinFile(state.file, "not published", true));
            assertEquals(0, state.checkinCalls);
        }
    }

    @Test public void openProgramCannotSilentlyOverrideKeepCheckedOutFalse() throws Exception {
        NativeFile state = checkedOut();
        state.open = true;
        conflict(() -> RepositoryService.checkinFile(state.file, "must close", false));
        assertEquals(0, state.checkinCalls);
        RepositoryService.checkinFile(state.file, "keep open", true);
        assertTrue(state.checkedOut);
    }

    @Test public void profileAndServerGrantsAreCheckedBeforeWrites() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeFile state = new NativeFile();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            try { service.checkout("test", "/program", true); fail(); }
            catch (ConnectionException e) { assertEquals("CONNECTION_PERMISSION_DENIED", e.code()); }
            assertEquals(0, state.checkoutCalls);
            access.profile = profile(Set.of("read", "checkout", "checkin"));
            ws.readOnly = true;
            try { service.checkout("test", "/program", true); fail(); }
            catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_READ_ONLY", e.code()); }
            try { service.checkin("test", "/program", "blocked", false); fail(); }
            catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_READ_ONLY", e.code()); }
            assertEquals(0, state.checkoutCalls);
            assertEquals(0, state.checkinCalls);
        }
        assertTrue(ws.closed);
    }

    @Test public void boundedListingReportsExactTruncationAndMissingPaths() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeWorkspace ws = new NativeWorkspace(new NativeFile(), 3);
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            Map<String, Object> page = service.files("test", "/", 0, 2);
            assertEquals(2, page.get("count"));
            assertEquals(3L, page.get("total"));
            assertEquals(true, page.get("truncated"));
            assertEquals(false, service.files("test", "/", 0, 3).get("truncated"));
            Map<String, Object> last = service.files("test", "/", 2, 2);
            var firstEntries = (List<?>) page.get("entries");
            assertEquals(List.of("/program", "/program-1"), firstEntries.stream()
                .map(entry -> ((Map<?, ?>) entry).get("path")).toList());
            assertEquals("/program-2", ((Map<?, ?>) ((List<?>) last.get("entries")).get(0)).get("path"));
            assertEquals(false, last.get("has_more"));
            assertEquals(true, page.get("has_more"));
            assertEquals(0, service.files("test", "/", 3, 2).get("count"));
            try { service.files("test", "/", -1, 2); fail(); }
            catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_PATH_INVALID", e.code()); }
            try { service.files("test", "/missing", 0, 2); fail(); }
            catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_NOT_FOUND", e.code()); }
        }
    }

    @Test public void wrongProfileAndChangedBindingNeverReuseWorkspace() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeWorkspace ws = new NativeWorkspace(new NativeFile(), 1);
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            try { service.status("another-profile"); fail(); }
            catch (ConnectionException e) { assertEquals("CONNECTION_PROFILE_NOT_FOUND", e.code()); }
            service.status("test");
            access.profile = new Profile("test", "ghidra", "ghidra", "ghidra://example.invalid/other",
                "none", null, Set.of("read"));
            conflict(() -> service.status("test"));
        }
    }

    @Test public void unsafePathsFailBeforeNativeAccess() throws Exception {
        Access access = new Access(Set.of("read", "checkout"));
        try (RepositoryService service = new RepositoryService(access, (p, d) -> { throw new AssertionError(); }, "instance-test")) {
            for (String path : List.of("program", "/../program", "/a/./program", "/a//program", "/a/", "/%2e%2e/program", "/a\\b")) {
                try { service.checkout("test", path, true); fail(path); }
                catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_PATH_INVALID", e.code()); }
            }
            assertEquals(0, access.calls);
        }
    }

    @Test public void nativeErrorDetailsAreNeverReturnedAsMessagesOrCauses() throws Exception {
        Access access = new Access(Set.of("read"));
        try (RepositoryService service = new RepositoryService(access,
                (p, d) -> { throw new IOException("synthetic-user:synthetic-password@example.invalid"); }, "instance-test")) {
            try { service.status("test"); fail(); }
            catch (ConnectionException e) {
                assertEquals("CONNECTION_FAILED", e.code());
                assertEquals("Native repository operation failed", e.getMessage());
                assertNull(e.getCause());
            }
        }
    }

    @Test public void profileReadOnlyOpenKeepsReadonlyProxyEvenWithExistingCheckout() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeFile state = checkedOut();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        ActiveContext ctx = new ActiveContext();
        RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test");
        Map<String, Object> result = service.open(ctx, "test", "/program", 1);
        assertEquals(true, result.get("read_only"));
        assertFalse(state.writableOpen);
        assertEquals(1, state.requestedVersion);
        assertTrue(ctx.program().getDomainFile().isReadOnly());
        assertTrue("Exercise a native compatibility view, not immutable implementation details",
            ctx.program().isChangeable());
        assertEquals(2, ctx.program().getConsumerList().size());
        service.open(ctx, "test", "/program", 1);
        assertEquals(1, state.openCalls); // Reopening does not acquire the same consumer twice.
        assertSame(state.program.program, ctx.selected);
        assertSame(ws.project, ctx.project);
        assertEquals(2, ctx.program().getConsumerList().size());
        assertEquals(0, state.checkoutCalls);
        assertEquals(0, state.checkinCalls);
        service.close();
        assertFalse(ws.closed); // Active GUI/headless consumer must keep its project alive.
        ctx.closeProgram();
        assertTrue(ws.closeLatch.await(5, java.util.concurrent.TimeUnit.SECONDS));
    }

    @Test public void repositoryLinksCannotOpenCheckoutOrPublish() throws Exception {
        Access access = new Access(Set.of("read", "checkout", "checkin"));
        NativeFile state = new NativeFile();
        state.link = true;
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        ActiveContext ctx = new ActiveContext();
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            for (ThrowingCall call : new ThrowingCall[] {
                    () -> service.open(ctx, "test", "/program", 1),
                    () -> service.checkout("test", "/program", true),
                    () -> service.checkin("test", "/program", "reviewed", true) }) {
                try { call.run(); fail("Repository link was followed"); }
                catch (RepositoryService.RepositoryException refused) {
                    assertEquals("REPOSITORY_NOT_FOUND", refused.code());
                    assertEquals(404, refused.status());
                }
            }
            assertNull(ctx.selected);
            assertEquals(0, state.openCalls);
            assertEquals(0, state.checkoutCalls);
            assertEquals(0, state.checkinCalls);
        }
    }

    @Test public void openRefusesUnsavedActiveProgramWithoutNativeWork() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeFile active = new NativeFile();
        active.changed = true;
        ActiveContext ctx = new ActiveContext();
        ctx.selected = active.program.program;
        try (RepositoryService service = new RepositoryService(access,
                (p, d) -> { throw new AssertionError("Must not contact native server"); }, "instance-test")) {
            conflict(() -> service.open(ctx, "test", "/program", -1));
            assertEquals(0, access.calls);
            assertSame(active.program.program, ctx.selected);
            assertTrue(active.changed);
        }
    }

    @Test public void servicePublishesOnlyAfterExplicitLocalSave() throws Exception {
        Access access = new Access(Set.of("read", "checkout", "checkin"));
        NativeFile state = new NativeFile();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        ActiveContext ctx = new ActiveContext();
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            assertEquals(true, service.checkout("test", "/program", true).get("checked_out"));
            assertEquals(false, service.open(ctx, "test", "/program", -1).get("read_only"));
            assertTrue(state.writableOpen);
            state.changed = true;
            conflict(() -> service.checkin("test", "/program", "needs saving", true));
            state.file.save(TaskMonitor.DUMMY);
            Map<String, Object> published = service.checkin("test", "/program", "saved analysis", true);
            assertEquals(true, published.get("checked_in"));
            assertEquals(2, published.get("latest_version"));
            assertEquals(true, published.get("checked_out"));
            assertEquals(1, state.checkinCalls);
            ctx.closeProgram();
        }
        assertTrue(ws.closed);
    }

    @Test public void missingNativeApiIsExplicitAndClosedServiceCannotReconnect() throws Exception {
        Access access = new Access(Set.of("read"));
        RepositoryService service = new RepositoryService(access,
            (p, d) -> { throw new ClassNotFoundException("synthetic unavailable native API"); }, "instance-test");
        try {
            try { service.status("test"); fail(); }
            catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_UNSUPPORTED", e.code()); }
        } finally { service.close(); }
        int calls = access.calls;
        try { service.status("test"); fail(); }
        catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_CLOSED", e.code()); }
        assertEquals(calls, access.calls);
    }

    @Test public void checkinRequiresExplicitNonblankCommentBeforeNativeAccess() throws Exception {
        Access access = new Access(Set.of("checkin"));
        try (RepositoryService service = new RepositoryService(access,
                (p, d) -> { throw new AssertionError("Must not connect for invalid comment"); }, "instance-test")) {
            for (String comment : new String[] { null, "", " ", "a".repeat(4097) }) {
                try { service.checkin("test", "/program", comment, true); fail(); }
                catch (RepositoryService.RepositoryException e) { assertEquals("REPOSITORY_PATH_INVALID", e.code()); }
            }
            assertEquals(0, access.calls);
        }
    }

    @Test public void writableOpenLeavesNativeRecoveryDataUntouched() throws Exception {
        Access access = new Access(Set.of("read", "checkout"));
        NativeFile state = checkedOut();
        state.recover = true;
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            conflict(() -> service.open(new ActiveContext(), "test", "/program", -1));
            assertEquals(0, state.openCalls);
            assertTrue(state.recover);
        }
    }

    @Test public void writableOpenRejectsStaleAndNonexclusiveCheckoutsBeforeOpening() throws Exception {
        for (boolean stale : new boolean[] { true, false }) {
            Access access = new Access(Set.of("read", "checkout"));
            NativeFile state = checkedOut();
            if (stale) state.latest++;
            else state.exclusive = false;
            NativeWorkspace ws = new NativeWorkspace(state, 1);
            try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
                conflict(() -> service.open(new ActiveContext(), "test", "/program", -1));
                assertEquals(0, state.openCalls);
            }
        }
    }


    @Test public void repeatedLatestReadonlyOpenRetainsTheSameNativeProgramAndConsumers() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeFile state = new NativeFile();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        ActiveContext ctx = new ActiveContext();
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            service.open(ctx, "test", "/program", -1);
            var first = ctx.program();
            assertEquals(1, first.getDomainFile().getVersion());
            assertTrue(first.getDomainFile().isReadOnly());
            assertTrue(first.isChangeable());
            assertEquals(2, first.getConsumerList().size());
            service.open(ctx, "test", "/program", -1);
            assertSame(first, ctx.program());
            assertEquals(1, state.openCalls);
            assertEquals(2, first.getConsumerList().size());
            assertEquals(1, state.requestedVersion);
            ctx.closeProgram();
        }
        assertTrue(state.program.closed);
    }

    @Test public void browsingVersionsReleasesCleanInactivePrograms() throws Exception {
        Access access = new Access(Set.of("read"));
        NativeFile state = new NativeFile();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        ActiveContext ctx = new ActiveContext();
        ghidra.program.model.listing.Program previous = null;
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            for (int version = 1; version <= 8; version++) {
                state.latest = version;
                assertEquals(version, service.open(ctx, "test", "/program", -1).get("version"));
                if (previous != null) assertTrue(previous.isClosed());
                previous = ctx.program();
                assertFalse(previous.isClosed());
                assertTrue(previous.getDomainFile().isReadOnly());
            }
            ctx.closeProgram();
        }
        assertTrue(previous.isClosed());
        assertFalse(state.checkedOut);
        assertEquals(0, state.checkinCalls);
    }
    @Test public void readonlyVersionCacheNeverAuthorizesWritableCheckoutSelection() throws Exception {
        Access access = new Access(Set.of("read", "checkout"));
        NativeFile state = checkedOut();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        ActiveContext ctx = new ActiveContext();
        ghidra.program.model.listing.Program readOnly;
        ghidra.program.model.listing.Program writable;
        try (RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test")) {
            assertEquals(true, service.open(ctx, "test", "/program", 1).get("read_only"));
            readOnly = ctx.program();
            Object gui = new Object();
            readOnly.addConsumer(gui);
            assertEquals(false, service.open(ctx, "test", "/program", -1).get("read_only"));
            writable = ctx.program();
            assertNotSame(readOnly, writable);
            assertTrue(readOnly.getDomainFile().isReadOnly());
            assertFalse(writable.getDomainFile().isReadOnly());
            assertEquals(true, service.open(ctx, "test", "/program", 1).get("read_only"));
            assertSame(readOnly, ctx.program());
            assertFalse(readOnly.isClosed());
            assertTrue(writable.isClosed());
            readOnly.release(gui);
            ctx.closeProgram();
        }
        assertTrue(readOnly.isClosed());
        assertTrue(writable.isClosed());
    }


    @Test public void dirtyHeadlessSelectionRefusesShutdownWhileHttpCanStillSaveIt() throws Exception {
        Access access = new Access(Set.of("read", "checkout"));
        NativeFile state = checkedOut();
        NativeWorkspace ws = new NativeWorkspace(state, 1);
        RepositoryService service = new RepositoryService(access, (p, d) -> ws, "instance-test");
        var server = new eu.starsong.ghidra.server.GhydraServer(null, 0, new java.util.HashMap<>(), false);
        server.register(new eu.starsong.ghidra.resource.RepositoryResource(service));
        server.register(new eu.starsong.ghidra.resource.ProgramResource());
        server.start();
        var handle = new eu.starsong.ghidra.server.GhydraServerFactory.Handle(server, null, service);
        var client = java.net.http.HttpClient.newHttpClient();
        java.net.URI base = java.net.URI.create("http://127.0.0.1:" + server.app().port());
        try {
            var untouched = client.send(java.net.http.HttpRequest.newBuilder(base.resolve("/program/save?workspace_only=true"))
                .POST(java.net.http.HttpRequest.BodyPublishers.noBody()).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(200, untouched.statusCode());
            assertTrue(untouched.body().contains("\"analyzer_owned\":true"));
            var opened = client.send(java.net.http.HttpRequest.newBuilder(base.resolve("/repositories/open"))
                .header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                    "{\"profile\":\"test\",\"path\":\"/program\"}")).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(opened.body(), 200, opened.statusCode());
            state.changed = true;
            conflict(handle::stop);
            assertTrue(state.changed);
            assertFalse(state.program.closed);
            assertFalse(ws.closed);
            var saved = client.send(java.net.http.HttpRequest.newBuilder(base.resolve("/program/save?workspace_only=true"))
                .POST(java.net.http.HttpRequest.BodyPublishers.noBody()).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(saved.body(), 200, saved.statusCode());
            assertFalse(state.changed);
        } finally {
            state.changed = false;
            handle.stop();
        }
        assertTrue(state.program.closed);
        assertTrue(ws.closed);
    }

    private static NativeFile checkedOut() {
        NativeFile state = new NativeFile();
        state.checkedOut = true;
        state.exclusive = true;
        state.saved = true;
        return state;
    }
}
