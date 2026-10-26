import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import soot.*;
import soot.options.Options;

/** Development-only consumer: inventories come from original DEX, never Garlic text. */
public final class StrictConsumer {
    private static String signature(String owner, String name, String result, List<String> params) {
        return "<" + owner + ": " + result + " " + name + "(" + String.join(",", params) + ")>";
    }

    private static Map<String, Boolean> inventory(Path source, String name) throws Exception {
        var result = new TreeMap<String, Boolean>();
        var container = DexFileFactory.loadDexContainer(source.toFile(), Opcodes.getDefault());
        int matches = 0;
        for (String entry : container.getDexEntryNames()) {
            for (var cls : container.getEntry(entry).getDexFile().getClasses()) {
                if (!Type.getType(cls.getType()).getClassName().equals(name)) continue;
                matches++;
                for (var method : cls.getMethods()) {
                    var params = method.getParameterTypes().stream()
                        .map(t -> Type.getType(t.toString()).getClassName()).toList();
                    String key = signature(name, method.getName(),
                        Type.getType(method.getReturnType()).getClassName(), params);
                    if (result.put(key, method.getImplementation() != null) != null)
                        throw new AssertionError("Duplicate DEX method: " + key);
                }
            }
        }
        if (matches != 1 || result.isEmpty())
            throw new AssertionError("Expected one nonempty original class " + name + ", got " + matches);
        return result;
    }

    public static void main(String[] args) throws Exception {
        String mode = args[0], name = args[2];
        var expected = inventory(Path.of(args[1]), name);
        for (var entry : expected.entrySet())
            System.out.println("SOURCE " + (entry.getValue() ? "BODY " : "DECL ") + entry.getKey());
        G.reset();
        Options options = Options.v();
        options.set_src_prec(mode.equals("dex") ? Options.src_prec_apk : Options.src_prec_jimple);
        options.set_force_android_jar(args[5]);
        options.set_prepend_classpath(true);
        // Dependencies may be Android/application classes; the requested class is checked below.
        options.set_allow_phantom_refs(true);
        options.set_validate(true);
        options.set_output_format(Options.output_format_class);
        options.set_output_dir(args[4]);
        options.set_soot_classpath(args[3] + File.pathSeparator + args[5]);
        if (mode.equals("dex")) options.set_process_dir(List.of(args[1]));
        SootClass cls = Scene.v().forceResolve(name, SootClass.BODIES);
        cls.setApplicationClass();
        Scene.v().loadNecessaryClasses();
        if (cls.isPhantom()) throw new AssertionError("Requested class is phantom: " + name);
        var actual = new TreeMap<String, Boolean>();
        var failures = new ArrayList<Throwable>();
        for (SootMethod method : cls.getMethods()) {
            actual.put(method.getSignature(), method.isConcrete());
            if (!method.isConcrete()) continue;
            System.err.println("validate=" + method.getSignature());
            try {
                method.retrieveActiveBody().validate();
                System.out.println("VALIDATED " + method.getSignature());
            } catch (RuntimeException | AssertionError failure) {
                System.out.println("INVALID " + method.getSignature());
                failures.add(failure);
                failure.printStackTrace(System.err);
            }
        }
        if (!actual.equals(expected))
            throw new AssertionError("Method inventory mismatch: " + actual + " != " + expected);
        if (!failures.isEmpty()) {
            var failure = new AssertionError("Invalid bodies in " + name + ": " + failures.size());
            failures.forEach(failure::addSuppressed);
            throw failure;
        }
        PackManager.v().runPacks();
        for (SootMethod method : cls.getMethods())
            if (method.isConcrete()) method.getActiveBody().validate();
        PackManager.v().writeOutput();
        Path output = Path.of(args[4], name.replace('.', '/') + ".class");
        var bytecode = new TreeMap<String, Boolean>();
        new ClassReader(Files.readAllBytes(output)).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override public MethodVisitor visitMethod(int access, String method, String desc,
                                                       String generic, String[] exceptions) {
                var params = java.util.Arrays.stream(Type.getArgumentTypes(desc))
                    .map(Type::getClassName).toList();
                bytecode.put(signature(name, method, Type.getReturnType(desc).getClassName(), params),
                    (access & (org.objectweb.asm.Opcodes.ACC_ABSTRACT | org.objectweb.asm.Opcodes.ACC_NATIVE)) == 0);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        if (!bytecode.equals(expected))
            throw new AssertionError("Emitted class inventory mismatch: " + bytecode + " != " + expected);
        System.out.println("ACCEPTED " + name);
        for (var entry : expected.entrySet())
            System.out.println((entry.getValue() ? "BODY " : "DECL ") + entry.getKey());
    }
}
