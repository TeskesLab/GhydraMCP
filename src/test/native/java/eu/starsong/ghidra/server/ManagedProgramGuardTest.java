package eu.starsong.ghidra.server;

import eu.starsong.ghidra.connection.ConnectionException;
import eu.starsong.ghidra.service.RepositoryService;
import eu.starsong.ghidra.service.SaveService;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.AbortedTransactionListener;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.UnableToSwingException;
import ghidra.util.task.TaskMonitor;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.swing.SwingUtilities;
import java.awt.AWTEvent;
import java.awt.EventQueue;
import java.awt.Toolkit;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;

/** Real helper/native database regressions; no repositories, credentials, or windows are created. */
public class ManagedProgramGuardTest {
    private static Language fixtureLanguage;

    @BeforeClass public static void loadNativeLanguage() throws Exception {
        fixtureLanguage = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    }

    private static final class CountingProgram extends ProgramDB {
        int starts;
        boolean readOnlyFile;
        final DomainFile permissionProxy;
        CountingProgram(Language language, Object consumer) throws IOException {
            super("managed-guard", language, language.getDefaultCompilerSpec(), consumer);
            permissionProxy = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
                new Class<?>[]{DomainFile.class}, (proxy, method, args) ->
                    method.getName().equals("isReadOnly") ? readOnlyFile
                        : method.invoke(super.getDomainFile(), args));
            starts = 0;
        }
        @Override public DomainFile getDomainFile() {
            return permissionProxy == null ? super.getDomainFile() : permissionProxy;
        }
        @Override public int startTransaction(String name, AbortedTransactionListener listener) {
            starts++;
            return super.startTransaction(name, listener);
        }
    }

    private static final class NativeProgram implements AutoCloseable {
        final Object root = new Object();
        final RepositoryService repository = new RepositoryService();
        final ActiveProgram active = new ActiveProgram(null, null);
        final CountingProgram program;
        NativeProgram(boolean managed) throws Exception {
            program = new CountingProgram(fixtureLanguage, root);
            if (managed) {
                program.addConsumer(repository);
                active.activate(program, null);
            }
        }
        @Override public void close() {
            active.close();
            if (program.isUsedBy(repository)) program.release(repository);
            program.release(root);
            repository.close();
        }
    }

    private static void conflict(Runnable operation) {
        try {
            operation.run();
            fail("Expected managed ownership conflict");
        } catch (ConnectionException e) {
            assertEquals("REPOSITORY_CONFLICT", e.code());
            assertEquals(409, e.status());
        }
    }

    @Test public void legitimateHeadlessSelectionMutatesNativeDatabase() throws Exception {
        try (NativeProgram fixture = new NativeProgram(true)) {
            assertEquals("committed", TransactionHelper.executeInTransaction(fixture.program, "edit", () -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                fixture.program.getOptions(Program.PROGRAM_INFO).setString("guard-test", "committed");
                return "committed";
            }));
            assertEquals(1, fixture.program.starts);
            assertEquals("committed", fixture.program.getOptions(Program.PROGRAM_INFO)
                .getString("guard-test", "missing"));
        }
    }

    @Test(timeout = 5000) public void lockedManagedProgramNeverEntersNativeTransactionRetry() throws Exception {
        try (NativeProgram fixture = new NativeProgram(true)) {
            assertTrue(fixture.program.lock("native save"));
            int startsBeforeRequest = fixture.program.starts;
            try {
                AtomicBoolean ran = new AtomicBoolean();
                conflict(() -> TransactionHelper.executeInTransaction(fixture.program, "locked", () -> {
                    ran.set(true);
                    return null;
                }));
                assertFalse(ran.get());
                assertEquals(startsBeforeRequest, fixture.program.starts);
                assertTrue(fixture.program.isLocked());
            } finally {
                fixture.program.unlock();
            }
        }
    }

    @Test public void changeableManagedReadonlyProxyRejectsMutationBeforeNativeTransaction() throws Exception {
        try (NativeProgram fixture = new NativeProgram(true)) {
            fixture.program.readOnlyFile = true;
            assertTrue("Compatibility copies remain natively changeable", fixture.program.isChangeable());
            assertTrue(fixture.program.getDomainFile().isReadOnly());
            boolean changedBefore = fixture.program.isChanged();
            AtomicBoolean ran = new AtomicBoolean();
            try {
                TransactionHelper.executeInTransaction(fixture.program, "readonly compatibility copy", () -> {
                    ran.set(true);
                    fixture.program.setName("must-not-change");
                    fixture.program.getOptions(Program.PROGRAM_INFO).setString("guard-test", "forbidden");
                    return null;
                });
                fail("A readonly repository file must refuse writes even through a changeable view");
            } catch (ConnectionException denied) {
                assertEquals("REPOSITORY_READ_ONLY", denied.code());
                assertEquals(403, denied.status());
            }
            assertFalse(ran.get());
            assertEquals("Guard must reject before entering native transaction machinery", 0,
                fixture.program.starts);
            assertEquals("managed-guard", fixture.program.getName());
            assertEquals("missing", fixture.program.getOptions(Program.PROGRAM_INFO)
                .getString("guard-test", "missing"));
            assertEquals(changedBefore, fixture.program.isChanged());
        }
    }
    @Test public void readonlyProtectionSurvivesServiceReleaseUntilNativeProgramCloses() throws Exception {
        Path directory = Files.createTempDirectory("ghydra-readonly-lifecycle-");
        Program closedProgram;
        Object owner = new Object();
        try {
            GhidraProject project = GhidraProject.createProject(directory.toString(), "lifecycle", false);
            try {
                // Native content handlers require ProgramDB itself, not the counting subclass.
                ProgramDB seed = new ProgramDB("managed-guard", fixtureLanguage,
                    fixtureLanguage.getDefaultCompilerSpec(), owner);
                DomainFile file;
                try {
                    file = project.getProjectData().getRootFolder().createFile("managed-guard", seed,
                        TaskMonitor.DUMMY);
                } finally { seed.release(owner); }
                Program program = (Program) file.getReadOnlyDomainObject(owner, -1, TaskMonitor.DUMMY);
                closedProgram = program;
                try (RepositoryService repository = new RepositoryService();
                     ActiveProgram active = new ActiveProgram(null, null)) {
                    program.addConsumer(repository);
                    try {
                        SwingUtilities.invokeAndWait(() -> {
                            active.activate(program, project.getProject());
                            ManagedProgramGuard.registerReadOnly(program);
                            program.release(repository);
                        });
                        repository.close();
                        assertFalse(program.isUsedBy(repository));
                        assertTrue(program.isUsedBy(active));
                        assertTrue(ManagedProgramGuard.isManaged(program));
                        assertTrue(program.isChangeable());
                        assertFalse("Use a genuinely saved native database", program.isChanged());
                        try {
                            TransactionHelper.executeInTransaction(program, "after service release", () -> {
                                program.setName("forbidden-after-release");
                                return null;
                            });
                            fail("A surviving selection must retain repository readonly permissions");
                        } catch (ConnectionException denied) {
                            assertEquals("REPOSITORY_READ_ONLY", denied.code());
                            assertEquals(403, denied.status());
                        }
                        assertEquals("managed-guard", program.getName());
                        assertFalse(program.isChanged());
                        assertFalse(new SaveService().save(program).saved());
                        assertFalse(program.isChanged());
                        assertTrue(program.isUsedBy(active));
                    } finally {
                        if (program.isUsedBy(repository)) program.release(repository);
                    }
                } finally { program.release(owner); }
                assertTrue(closedProgram.isClosed());
                assertFalse("Native close must release readonly lifetime tracking",
                    ManagedProgramGuard.isManaged(closedProgram));
            } finally { project.close(); }
        } finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }


    @Test public void ordinaryProgramStillMutatesWithoutManagedOwnership() throws Exception {
        try (NativeProgram fixture = new NativeProgram(false)) {
            assertEquals(42, (int) TransactionHelper.executeInTransaction(fixture.program, "ordinary", () -> 42));
            assertEquals(1, fixture.program.starts);
        }
    }

    @Test public void staleSelectionAndCacheConsumerDoNotAuthorizeMutation() throws Exception {
        try (NativeProgram fixture = new NativeProgram(true)) {
            fixture.active.close();
            fixture.program.addConsumer(fixture.active); // A stale consumer is not a selected program.
            Object cache = new Object();
            fixture.program.addConsumer(cache);
            try {
                conflict(() -> TransactionHelper.executeInTransaction(fixture.program, "stale", () -> null));
                assertEquals(0, fixture.program.starts);
                assertTrue(fixture.program.isUsedBy(fixture.repository));
            } finally {
                fixture.program.release(cache);
                fixture.program.release(fixture.active);
            }
        }
    }

    private static final class ObservedQueue extends EventQueue {
        final CountDownLatch posted = new CountDownLatch(1);
        volatile Thread request;
        @Override public void postEvent(AWTEvent event) {
            super.postEvent(event);
            if (Thread.currentThread() == request) posted.countDown();
        }
        void uninstall() { pop(); }
    }

    @Test(timeout = 10000) public void queuedMutationRechecksOwnershipAtActualSwingExecution() throws Exception {
        assertTrue("Exercise production headless dispatch", SystemUtilities.isInHeadlessMode());
        NativeProgram fixture = new NativeProgram(true);
        ObservedQueue queue = new ObservedQueue();
        Toolkit.getDefaultToolkit().getSystemEventQueue().push(queue);
        try (fixture) {
            CountDownLatch entered = new CountDownLatch(1);
            FutureTask<Void> closeBeforeDispatch = new FutureTask<>(() -> {
                entered.countDown();
                assertTrue(queue.posted.await(5, TimeUnit.SECONDS));
                fixture.active.close();
                return null;
            });
            SwingUtilities.invokeLater(closeBeforeDispatch);
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            AtomicBoolean ran = new AtomicBoolean();
            FutureTask<Void> mutation = new FutureTask<>(() -> {
                queue.request = Thread.currentThread();
                conflict(() -> TransactionHelper.executeInTransaction(fixture.program, "queued", () -> {
                    ran.set(true);
                    return null;
                }));
                return null;
            });
            new Thread(mutation, "queued-managed-mutation-test").start();
            closeBeforeDispatch.get(5, TimeUnit.SECONDS);
            mutation.get(5, TimeUnit.SECONDS);
            assertFalse(ran.get());
            assertEquals(0, fixture.program.starts);
            assertTrue(fixture.program.isUsedBy(fixture.repository));
        } finally {
            SwingUtilities.invokeAndWait(queue::uninstall);
        }
    }

    @Test public void typedConnectionAndRepositoryErrorsSurviveTransactionHelper() throws Exception {
        try (NativeProgram fixture = new NativeProgram(false)) {
            ConnectionException connection = new ConnectionException("REPOSITORY_CONFLICT", 409, "conflict");
            try {
                TransactionHelper.executeInTransaction(fixture.program, "typed connection", () -> { throw connection; });
                fail("Expected typed connection error");
            } catch (ConnectionException e) { assertSame(connection, e); }
            RepositoryService.RepositoryException repository =
                new RepositoryService.RepositoryException("REPOSITORY_CONFLICT", 409, "conflict");
            try {
                TransactionHelper.executeInTransaction(fixture.program, "typed repository", () -> { throw repository; });
                fail("Expected typed repository error");
            } catch (RepositoryService.RepositoryException e) { assertSame(repository, e); }
        }
    }

    /** Native interface fixture exercises real SaveService coordination, including ref-counted locks. */
    private static final class SaveFixture implements AutoCloseable {
        final RepositoryService repository = new RepositoryService();
        final ActiveProgram active = new ActiveProgram(null, null);
        final Set<Object> consumers = Collections.newSetFromMap(new IdentityHashMap<>());
        final CountDownLatch saving = new CountDownLatch(1);
        final CountDownLatch finish = new CountDownLatch(1);
        volatile int locks;
        volatile boolean changed = true;
        volatile boolean closed;
        boolean readOnly;
        volatile boolean failSave;
        volatile boolean enforceEdt;
        int saves;
        final DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[]{DomainFile.class}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "isReadOnly": return readOnly;
                    case "save":
                        assertFalse("Disk save must not run on EDT", SwingUtilities.isEventDispatchThread());
                        assertTrue(locks > 0);
                        saves++;
                        saving.countDown();
                        assertTrue(finish.await(5, TimeUnit.SECONDS));
                        assertFalse("Request pin must keep database alive", closed);
                        if (failSave) throw new IOException("fixture disk failure");
                        changed = false;
                        return null;
                    default: return defaultValue(method.getReturnType());
                }
            });
        final Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[]{Program.class}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getName": return "save-fixture";
                    case "getDomainFile": return file;
                    case "isChanged": return changed;
                    case "isClosed": return closed;
                    case "isChangeable": return true;
                    case "getConsumerList": return new ArrayList<>(consumers);
                    case "isLocked": return locks > 0;
                    case "addConsumer":
                        if (enforceEdt) assertTrue(SwingUtilities.isEventDispatchThread());
                        return consumers.add(args[0]);
                    case "release":
                        if (enforceEdt) assertTrue(SwingUtilities.isEventDispatchThread());
                        consumers.remove(args[0]);
                        closed = consumers.isEmpty();
                        return null;
                    case "lock":
                        assertTrue(SwingUtilities.isEventDispatchThread());
                        locks++;
                        return true;
                    case "unlock":
                        assertTrue(SwingUtilities.isEventDispatchThread());
                        assertTrue(locks > 0);
                        locks--;
                        return null;
                    default: return defaultValue(method.getReturnType());
                }
            });
        SaveFixture(boolean managed) {
            if (managed) {
                consumers.add(repository);
                active.activate(program, null);
            }
            enforceEdt = true;
        }
        @Override public void close() throws Exception {
            finish.countDown();
            SwingUtilities.invokeAndWait(() -> {
                active.close();
                if (consumers.contains(repository)) program.release(repository);
            });
            repository.close();
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        return null;
    }

    @Test(timeout = 10000) public void managedSavePinsDatabaseAndRetainsItsLockThroughOffEdtIo() throws Exception {
        try (SaveFixture fixture = new SaveFixture(true)) {
            FutureTask<SaveService.SaveResult> save = new FutureTask<>(() -> new SaveService().save(fixture.program));
            new Thread(save, "managed-save-test").start();
            assertTrue(fixture.saving.await(5, TimeUnit.SECONDS));
            conflict(() -> new SaveService().save(fixture.program));
            conflict(() -> TransactionHelper.executeInTransaction(fixture.program, "during save", () -> null));
            SwingUtilities.invokeAndWait(() -> {
                fixture.active.close();
                fixture.program.release(fixture.repository);
                assertFalse(fixture.closed);
                assertEquals(1, fixture.consumers.size());
                // A native GUI save/close may nest a lock. Releasing it must not release ours.
                assertTrue(fixture.program.lock("GUI close"));
                fixture.program.unlock();
                assertEquals(1, fixture.locks);
            });
            fixture.finish.countDown();
            assertTrue(save.get(5, TimeUnit.SECONDS).saved());
            assertTrue(fixture.closed);
            assertEquals(0, fixture.locks);
            assertEquals(1, fixture.saves);
        }
    }

    @Test public void failedManagedSaveReleasesRequestConsumerAndLock() throws Exception {
        try (SaveFixture fixture = new SaveFixture(true)) {
            fixture.failSave = true;
            fixture.finish.countDown();
            try {
                new SaveService().save(fixture.program);
                fail("Expected disk save failure");
            } catch (RuntimeException e) { assertTrue(e.getCause() instanceof IOException); }
            assertEquals(0, fixture.locks);
            assertEquals(2, fixture.consumers.size());
            assertFalse(fixture.closed);
        }
    }

    @Test public void managedSaveRejectsClosedOrOwnerlessProgramsWithoutIo() throws Exception {
        try (SaveFixture fixture = new SaveFixture(true)) {
            SwingUtilities.invokeAndWait(fixture.active::close);
            conflict(() -> new SaveService().save(fixture.program));
            fixture.closed = true;
            conflict(() -> new SaveService().save(fixture.program));
            conflict(() -> TransactionHelper.executeInTransaction(fixture.program, "closed", () -> {
                fail("Closed managed operation must not execute");
                return null;
            }));
            assertEquals(0, fixture.saves);
            assertEquals(0, fixture.locks);
        }
    }

    @Test public void ordinaryUnchangedSaveRemainsNoOpWithoutPinOrLock() throws Exception {
        try (SaveFixture fixture = new SaveFixture(false)) {
            fixture.changed = false;
            assertFalse(new SaveService().save(fixture.program).saved());
            assertEquals(0, fixture.saves);
            assertEquals(0, fixture.locks);
            assertTrue(fixture.consumers.isEmpty());
        }
    }
    @Test public void managedUnchangedReadonlyCompatibilitySaveRemainsNoOp() throws Exception {
        try (SaveFixture fixture = new SaveFixture(true)) {
            fixture.readOnly = true;
            fixture.changed = false;
            assertTrue(fixture.program.isChangeable());
            assertFalse(new SaveService().save(fixture.program).saved());
            assertEquals(0, fixture.saves);
            assertEquals(0, fixture.locks);
            assertEquals(2, fixture.consumers.size());
        }
    }

    @Test public void managedDirtyReadonlyCompatibilitySaveIsDeniedWithoutIo() throws Exception {
        try (SaveFixture fixture = new SaveFixture(true)) {
            fixture.readOnly = true;
            assertTrue(fixture.program.isChangeable());
            try {
                new SaveService().save(fixture.program);
                fail("A readonly compatibility copy must never be saved");
            } catch (ConnectionException denied) {
                assertEquals("REPOSITORY_READ_ONLY", denied.code());
                assertEquals(403, denied.status());
            }
            assertTrue(fixture.changed);
            assertEquals(0, fixture.saves);
            assertEquals(0, fixture.locks);
            assertEquals(2, fixture.consumers.size());
        }
    }


    private static final class EdtBlock implements AutoCloseable {
        final CountDownLatch release = new CountDownLatch(1);
        final FutureTask<Void> blocker;
        EdtBlock() throws Exception {
            CountDownLatch entered = new CountDownLatch(1);
            blocker = new FutureTask<>(() -> {
                entered.countDown();
                assertTrue(release.await(5, TimeUnit.SECONDS));
                return null;
            });
            SwingUtilities.invokeLater(blocker);
            assertTrue(entered.await(5, TimeUnit.SECONDS));
        }
        @Override public void close() throws Exception {
            release.countDown();
            blocker.get(5, TimeUnit.SECONDS);
            SwingUtilities.invokeAndWait(() -> {});
        }
    }

    @Test(timeout = 10000) public void timedOutQueuedDispatchNeverExecutesLater() throws Exception {
        AtomicBoolean ran = new AtomicBoolean();
        try (EdtBlock ignored = new EdtBlock()) {
            try {
                GhidraSwing.runNow(() -> ran.set(true), 20, TimeUnit.MILLISECONDS);
                fail("Expected dispatch start timeout");
            } catch (UnableToSwingException expected) {}
        }
        assertFalse(ran.get());
    }

    @Test(timeout = 10000) public void interruptedQueuedDispatchCancelsAndPreservesInterruption() throws Exception {
        AtomicBoolean ran = new AtomicBoolean();
        try (EdtBlock ignored = new EdtBlock()) {
            FutureTask<Void> request = new FutureTask<>(() -> {
                Thread.currentThread().interrupt();
                try {
                    GhidraSwing.runNow(() -> ran.set(true), 5, TimeUnit.SECONDS);
                    fail("Expected interrupted dispatch");
                } catch (UnableToSwingException expected) {
                    assertTrue(Thread.currentThread().isInterrupted());
                }
                return null;
            });
            new Thread(request, "interrupted-dispatch-test").start();
            request.get(5, TimeUnit.SECONDS);
        }
        assertFalse(ran.get());
    }

    @Test(timeout = 10000) public void startedDispatchCannotBeAbandonedByInterruptingRequester() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        CountDownLatch returned = new CountDownLatch(1);
        AtomicBoolean completed = new AtomicBoolean();
        FutureTask<Void> request = new FutureTask<>(() -> {
            GhidraSwing.runNow(() -> {
                entered.countDown();
                try {
                    assertTrue(finish.await(5, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    throw new AssertionError(e);
                }
                completed.set(true);
            }, 5, TimeUnit.SECONDS);
            assertTrue(completed.get());
            returned.countDown();
            return null;
        });
        Thread thread = new Thread(request, "started-dispatch-test");
        thread.start();
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            thread.interrupt();
            assertFalse(returned.await(20, TimeUnit.MILLISECONDS));
        } finally {
            finish.countDown();
        }
        request.get(5, TimeUnit.SECONDS);
        assertTrue(completed.get());
    }
}
