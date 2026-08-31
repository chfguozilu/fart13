package android.app;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.net.Uri;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.provider.MediaStore;
import android.util.Log;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexFile;

import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** @hide */
final class RuntimeProfileController {
    private static final String TAG = "RuntimeProfile";
    private static final String PROP_PACKAGE = "debug.runtime.profile.package";
    private static final String PROP_DELAY_MS = "debug.runtime.profile.delay_ms";
    private static final int DEFAULT_DELAY_MS = 10_000;
    private static final AtomicBoolean sScheduled = new AtomicBoolean(false);

    private RuntimeProfileController() {}

    /**
     * Schedules one probe pass after Application.onCreate(). An empty package
     * property disables the pass, so an ordinary build boot remains unaffected.
     */
    static void schedule(Application application) {
        if (application == null) {
            return;
        }

        final String requestedPackage = SystemProperties.get(PROP_PACKAGE, "");
        final String packageName = application.getPackageName();
        if (requestedPackage.isEmpty() || !requestedPackage.equals(packageName)) {
            return;
        }

        // System properties are process-global, while sScheduled is only
        // process-local. Without this check every :remote/:tools/:push process
        // of the requested package starts an independent profiling pass. Raw-object
        // probing is intentionally restricted to the Application's configured
        // main process unless a future revision adds an explicit process selector.
        final String currentProcessName = Application.getProcessName();
        final String mainProcessName = application.getApplicationInfo().processName;
        if (currentProcessName == null || mainProcessName == null
                || !mainProcessName.equals(currentProcessName)) {
            Log.i(TAG, "skip non-main process: current=" + currentProcessName
                    + ", main=" + mainProcessName + ", pid=" + Process.myPid());
            return;
        }
        if (!sScheduled.compareAndSet(false, true)) {
            return;
        }

        final int delayMs = Math.max(0,
                SystemProperties.getInt(PROP_DELAY_MS, DEFAULT_DELAY_MS));
        Log.i(TAG, "schedule main process=" + currentProcessName + ", pid=" + Process.myPid()
                + ", delayMs=" + delayMs);
        final Thread worker = new Thread(
                () -> run(application, currentProcessName, delayMs), "RuntimeProfileWorker");
        worker.setDaemon(true);
        worker.start();
    }

    private static void run(Application application, String processName, int delayMs) {
        Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
        SystemClock.sleep(delayMs);

        final ClassLoader applicationLoader = application.getClassLoader();
        if (applicationLoader == null) {
            Log.e(TAG, "Application ClassLoader is null");
            return;
        }

        final ContentResolver resolver = application.getContentResolver();
        final RuntimeApi runtimeApi;
        try {
            runtimeApi = RuntimeApi.create();
        } catch (Throwable error) {
            Log.e(TAG, "Cannot resolve runtime bridge methods", error);
            return;
        }

        final String outputName = application.getPackageName()
                + "-" + processName.replace(':', '_')
                + "-pid" + Process.myPid()
                + "-" + System.currentTimeMillis()
                + ".rpr";
        final ContentValues values = new ContentValues();
        // A process killed during capture can leave a pending MediaStore row,
        // but it must not leave a file whose name looks like a committed RPR.
        values.put(MediaStore.MediaColumns.DISPLAY_NAME, outputName + ".pending");
        values.put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream");
        values.put(MediaStore.MediaColumns.RELATIVE_PATH,
                Environment.DIRECTORY_DOWNLOADS + "/RuntimeProfiles/"
                        + application.getPackageName());
        // Keep an unfinished stream hidden. It is published only after ART has
        // written the commit footer and fsync() has succeeded.
        values.put(MediaStore.MediaColumns.IS_PENDING, 1);

        final Uri collection = MediaStore.Downloads.getContentUri(
                MediaStore.VOLUME_EXTERNAL_PRIMARY);
        final Uri output;
        try {
            output = resolver.insert(collection, values);
        } catch (Throwable error) {
            // Isolated/sandboxed processes cannot acquire MediaStore providers.
            // The main-process filter above should normally exclude them, but
            // this boundary must still never kill the hosting process.
            Log.e(TAG, "MediaStore insert failed for process=" + processName
                    + ", pid=" + Process.myPid(), error);
            return;
        }
        if (output == null) {
            Log.e(TAG, "MediaStore insert failed");
            return;
        }

        boolean writerStarted = false;
        boolean outputComplete = false;
        Throwable passFailure = null;
        try (ParcelFileDescriptor descriptor = resolver.openFileDescriptor(output, "w")) {
            if (descriptor == null) {
                throw new IOException("openFileDescriptor returned null");
            }
            // ART dup()s this fd. The ParcelFileDescriptor remains Java-owned.
            writerStarted = runtimeApi.startWriter(descriptor.getFd());
            if (!writerStarted) {
                throw new IOException("ART writer did not start");
            }

            try {
                probeLoaderChain(applicationLoader, runtimeApi);
            } finally {
                // This must run before try-with-resources closes descriptor.
                // Although ART owns a dup(), keeping the MediaStore descriptor
                // alive until the queue is drained avoids publishing/revoking a
                // FUSE-backed file while native writes are still in progress.
                outputComplete = runtimeApi.stopWriter();
                writerStarted = false;
            }
            if (!outputComplete) {
                throw new IOException("ART writer did not commit a complete output");
            }
        } catch (Throwable error) {
            passFailure = error;
            Log.e(TAG, "runtime profile pass failed", error);
        } finally {
            // Defensive fallback for an unexpected reflection failure before
            // the normal in-resource stop path could finish.
            if (writerStarted) {
                try {
                    outputComplete = runtimeApi.stopWriter();
                } catch (Throwable stopError) {
                    outputComplete = false;
                    Log.e(TAG, "Cannot stop runtime writer", stopError);
                } finally {
                    writerStarted = false;
                }
            }
        }

        if (passFailure == null && outputComplete) {
            try {
                final ContentValues publish = new ContentValues();
                publish.put(MediaStore.MediaColumns.DISPLAY_NAME, outputName);
                publish.put(MediaStore.MediaColumns.IS_PENDING, 0);
                if (resolver.update(output, publish, null, null) != 1) {
                    throw new IOException("MediaStore did not publish completed output");
                }
                Log.i(TAG, "runtime output committed: " + output);
                return;
            } catch (Throwable publishError) {
                Log.e(TAG, "Cannot publish completed runtime output " + output, publishError);
            }
        }

        // An incomplete stream has no commit footer and must never look like a
        // successful result to the user. Delete its pending MediaStore row;
        // the offline parser can still salvage old v1 files captured by older
        // builds, but new builds publish only committed v2 files.
        try {
            resolver.delete(output, null, null);
        } catch (Throwable deleteError) {
            Log.w(TAG, "Cannot delete failed runtime output " + output, deleteError);
        }
    }

    private static void probeLoaderChain(ClassLoader firstLoader, RuntimeApi runtimeApi)
            throws ReflectiveOperationException {
        final List<LoaderDexFile> sources = new ArrayList<>();
        final IdentityHashMap<DexFile, Boolean> seenDexFiles = new IdentityHashMap<>();

        // A shell may install a custom subclass of BaseDexClassLoader. Always
        // use the actual loader object and its loadClass(), never Class.forName().
        for (ClassLoader loader = firstLoader; loader != null; loader = loader.getParent()) {
            if (!(loader instanceof BaseDexClassLoader)) {
                continue;
            }
            for (DexFile dexFile : runtimeApi.getDexFiles((BaseDexClassLoader) loader)) {
                if (dexFile != null && seenDexFiles.put(dexFile, Boolean.TRUE) == null) {
                    sources.add(new LoaderDexFile(loader, dexFile));
                }
            }
        }

        int classCount = 0;
        for (LoaderDexFile source : sources) {
            final String[] classNames = runtimeApi.getClassNames(source.dexFile);
            for (String className : classNames) {
                try {
                    final Class<?> target = source.loader.loadClass(className);
                    // Parent delegation can return a same-named class from a
                    // different loader. Do not probe it under the wrong DexFile.
                    if (target.getClassLoader() != source.loader) {
                        continue;
                    }
                    runtimeApi.invokeClass(target);
                    classCount++;
                    if ((classCount % 100) == 0) {
                        Log.i(TAG, "probed classes=" + classCount);
                    }
                } catch (ClassNotFoundException | LinkageError error) {
                    Log.v(TAG, "skip class " + className + ": " + error);
                } catch (Throwable error) {
                    // One malformed/protected class must not abort the complete
                    // pass. Native code independently clears Java exceptions
                    // raised by each probe invocation.
                    Log.w(TAG, "probe class failed: " + className, error);
                }
            }
        }
        Log.i(TAG, "probe pass complete, classes=" + classCount);
    }

    /**
     * framework-minus-apex is compiled against core-library API stubs. The
     * runtime bridge methods added to libcore are deliberately @hide, so direct Java
     * calls would not be visible on framework's compile classpath. Resolve the
     * real boot-class methods at runtime instead of expanding core platform
     * API/stub signature files solely for this development feature.
     */
    private static final class RuntimeApi {
        private final Method startWriter;
        private final Method stopWriter;
        private final Method invokeClass;
        private final Field pathList;
        private final Field dexElements;
        private final Field elementDexFile;

        private RuntimeApi(Method startWriter, Method stopWriter, Method invokeClass,
                Field pathList, Field dexElements, Field elementDexFile) {
            this.startWriter = startWriter;
            this.stopWriter = stopWriter;
            this.invokeClass = invokeClass;
            this.pathList = pathList;
            this.dexElements = dexElements;
            this.elementDexFile = elementDexFile;
        }

        static RuntimeApi create() throws ReflectiveOperationException {
            final Field pathList = BaseDexClassLoader.class.getDeclaredField("pathList");
            final Class<?> pathListClass = Class.forName("dalvik.system.DexPathList");
            final Field dexElements = pathListClass.getDeclaredField("dexElements");
            final Class<?> elementClass = Class.forName("dalvik.system.DexPathList$Element");
            final Field elementDexFile = elementClass.getDeclaredField("dexFile");
            pathList.setAccessible(true);
            dexElements.setAccessible(true);
            elementDexFile.setAccessible(true);
            final Method startWriter =
                    DexFile.class.getDeclaredMethod("beginRuntimeProfile", int.class);
            final Method stopWriter = DexFile.class.getDeclaredMethod("endRuntimeProfile");
            final Method invokeClass =
                    DexFile.class.getDeclaredMethod("visitRuntimeMethods", Class.class);
            startWriter.setAccessible(true);
            stopWriter.setAccessible(true);
            invokeClass.setAccessible(true);
            return new RuntimeApi(
                    startWriter,
                    stopWriter,
                    invokeClass,
                    pathList,
                    dexElements,
                    elementDexFile);
        }

        boolean startWriter(int fd) throws ReflectiveOperationException {
            return (Boolean) startWriter.invoke(null, fd);
        }

        boolean stopWriter() throws ReflectiveOperationException {
            return (Boolean) stopWriter.invoke(null);
        }

        DexFile[] getDexFiles(BaseDexClassLoader loader) throws ReflectiveOperationException {
            final Object pathListObject = pathList.get(loader);
            final Object elements = dexElements.get(pathListObject);
            final int count = Array.getLength(elements);
            final ArrayList<DexFile> result = new ArrayList<>(count);
            for (int index = 0; index < count; ++index) {
                final DexFile dexFile = (DexFile) elementDexFile.get(Array.get(elements, index));
                if (dexFile != null) {
                    result.add(dexFile);
                }
            }
            return result.toArray(new DexFile[result.size()]);
        }

        String[] getClassNames(DexFile dexFile) {
            final ArrayList<String> result = new ArrayList<>();
            final Enumeration<String> entries = dexFile.entries();
            while (entries.hasMoreElements()) {
                result.add(entries.nextElement());
            }
            return result.toArray(new String[result.size()]);
        }

        void invokeClass(Class<?> target) throws ReflectiveOperationException {
            invokeClass.invoke(null, target);
        }
    }

    private static final class LoaderDexFile {
        final ClassLoader loader;
        final DexFile dexFile;

        LoaderDexFile(ClassLoader loader, DexFile dexFile) {
            this.loader = loader;
            this.dexFile = dexFile;
        }
    }
}
