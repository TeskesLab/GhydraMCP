// A/B of the real plugin code inside Ghidra.
//
// The baseline is the plugin installed in this Ghidra (the old build, whose
// listing materialises the whole program). The "after" side is the jar built
// from the current sources, loaded with a child-first class loader so it wins
// over the installed extension on the script classpath.
//
// Build the jar from the compiled classes first:
//   mvn -B compile
//   jar cf src/test/ghidra/GhydraClasses.jar -C target/classes .
//
//   analyzeHeadless <proj> Perf -process <binary> -noanalysis \
//       -scriptPath src/test/ghidra -postScript VerifyCache \
//       src/test/ghidra/GhydraClasses.jar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

public class VerifyCache extends GhidraScript {

    /** Loads the plugin classes from the jar before the installed extension. */
    static class ChildFirstLoader extends URLClassLoader {
        ChildFirstLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    if (name.startsWith("eu.starsong.ghidra.")) {
                        try {
                            loaded = findClass(name);
                        } catch (ClassNotFoundException e) {
                            loaded = super.loadClass(name, false);
                        }
                    } else {
                        loaded = super.loadClass(name, false);
                    }
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("RESULT usage: pass the path to the built plugin jar");
            return;
        }
        File jar = new File(args[0]);
        if (!jar.isFile()) {
            println("RESULT jar-not-found: " + jar);
            return;
        }

        Function biggest = null;
        long most = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getBody().getNumAddresses() > most) {
                most = f.getBody().getNumAddresses();
                biggest = f;
            }
        }
        if (biggest == null) {
            println("RESULT no-functions");
            return;
        }

        // ---- before: the plugin installed in this Ghidra ----
        eu.starsong.ghidra.service.FunctionService oldService =
            new eu.starsong.ghidra.service.FunctionService();

        long t0 = System.nanoTime();
        Object oldList = oldService.list(currentProgram, null);
        long oldListMs = (System.nanoTime() - t0) / 1_000_000;

        long t1 = System.nanoTime();
        var oldCfg = oldService.getCfg(currentProgram, biggest);
        long oldCfgMs = (System.nanoTime() - t1) / 1_000_000;

        // ---- after: the current sources ----
        // The parent is the loader of the installed plugin: it already
        // resolves the framework classes the plugin needs.
        ClassLoader appLoader = oldService.getClass().getClassLoader();
        ChildFirstLoader loader = new ChildFirstLoader(new URL[] { jar.toURI().toURL() }, appLoader);
        Class<?> newServiceClass = loader.loadClass("eu.starsong.ghidra.service.FunctionService");
        Object newService = newServiceClass.getDeclaredConstructor().newInstance();

        Class<?> filterClass = null;
        for (Class<?> nested : newServiceClass.getDeclaredClasses()) {
            if (nested.getSimpleName().equals("FunctionFilter")) {
                filterClass = nested;
            }
        }
        Method newList = newServiceClass.getMethod(
            "list", Program.class, filterClass, int.class, int.class);
        Method newCfg = newServiceClass.getMethod("getCfg", Program.class, Function.class);

        long t2 = System.nanoTime();
        Object newPage1 = newList.invoke(newService, currentProgram, null, 0, 100);
        long newListFirstMs = (System.nanoTime() - t2) / 1_000_000;

        long t3 = System.nanoTime();
        Object newPage2 = newList.invoke(newService, currentProgram, null, 0, 100);
        long newListCachedMs = (System.nanoTime() - t3) / 1_000_000;

        long t4 = System.nanoTime();
        var newCfg1 = (java.util.Map<String, Object>) newCfg.invoke(newService, currentProgram, biggest);
        long newCfgFirstMs = (System.nanoTime() - t4) / 1_000_000;

        long t5 = System.nanoTime();
        var newCfg2 = (java.util.Map<String, Object>) newCfg.invoke(newService, currentProgram, biggest);
        long newCfgCachedMs = (System.nanoTime() - t5) / 1_000_000;

        int oldTotal = ((java.util.List<?>) oldList).size();
        int newTotal = (Integer) newPage1.getClass().getMethod("total").invoke(newPage1);

        println("RESULT ab-listing"
                + " beforeMaterialiseAllMs=" + oldListMs
                + " afterFirstPageMs=" + newListFirstMs
                + " afterCachedMs=" + newListCachedMs
                + " beforeItems=" + oldTotal
                + " afterTotal=" + newTotal);

        println("RESULT ab-cfg"
                + " beforeMs=" + oldCfgMs
                + " afterFirstMs=" + newCfgFirstMs
                + " afterCachedMs=" + newCfgCachedMs
                + " blocks=" + newCfg1.get("blockCount")
                + " sameBlocks=" + oldCfg.get("blockCount").equals(newCfg1.get("blockCount")));

        loader.close();
    }
}
