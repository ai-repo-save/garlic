import java.io.File;
import java.nio.file.*;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.*;
import org.objectweb.asm.*;
import soot.*;
import soot.options.Options;

/** Compares original DEX metadata, strict bodies, and emitted JVM class metadata. */
public final class StrictCorpusConsumer {
    static String methodKey(String name, List<? extends CharSequence> params, String result) {
        return name + "(" + String.join("", params) + ")" + result;
    }
    static String descriptor(soot.Type type) {
        if (type instanceof ArrayType a) return "[".repeat(a.numDimensions) + descriptor(a.baseType);
        if (type instanceof RefType r) return "L" + r.getClassName().replace('.', '/') + ";";
        return switch (type.toString()) {
            case "void" -> "V"; case "boolean" -> "Z"; case "byte" -> "B"; case "char" -> "C";
            case "short" -> "S"; case "int" -> "I"; case "long" -> "J"; case "float" -> "F"; case "double" -> "D";
            default -> throw new AssertionError(type);
        };
    }
    static String name(String descriptor) { return org.objectweb.asm.Type.getType(descriptor).getClassName(); }
    static Map<String, Integer> expectedMethods(ClassDef cls) {
        var result = new TreeMap<String, Integer>();
        for (var m : cls.getMethods()) result.put(methodKey(m.getName(), m.getParameterTypes(), m.getReturnType()), m.getAccessFlags() & 0x53f);
        return result;
    }
    static Map<String, Integer> expectedFields(ClassDef cls) {
        var result = new TreeMap<String, Integer>();
        for (var f : cls.getFields()) result.put(f.getName() + ":" + f.getType(), f.getAccessFlags() & 0xdf);
        return result;
    }
    static void equal(Object actual, Object expected, String context) {
        if (!actual.equals(expected)) throw new AssertionError(context + ": " + actual + " != " + expected);
    }
    static void bytecode(Path path, ClassDef expected) throws Exception {
        var methods = new TreeMap<String, Integer>();
        var fields = new TreeMap<String, Integer>();
        new ClassReader(Files.readAllBytes(path)).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override public void visit(int version, int access, String className, String generic, String parent, String[] interfaces) {
                equal(access & 0x611, expected.getAccessFlags() & 0x611, "JVM class flags");
                equal(new TreeSet<>(Arrays.asList(interfaces)), new TreeSet<>(expected.getInterfaces().stream().map(t -> t.substring(1, t.length() - 1)).toList()), "JVM interfaces");
            }
            @Override public MethodVisitor visitMethod(int access, String method, String desc, String generic, String[] exceptions) {
                methods.put(method + desc, access & 0x53f); return null;
            }
            @Override public FieldVisitor visitField(int access, String field, String desc, String generic, Object value) {
                fields.put(field + ":" + desc, access & 0xdf); return null;
            }
        }, ClassReader.SKIP_CODE);
        equal(methods, expectedMethods(expected), "JVM methods");
        equal(fields, expectedFields(expected), "JVM fields");
    }
    public static void main(String[] args) throws Exception {
        var dex = DexFileFactory.loadDexFile(new File(args[1]), org.jf.dexlib2.Opcodes.forDexVersion(39));
        G.reset();
        var options = Options.v();
        options.set_src_prec(args[0].equals("dex") ? Options.src_prec_apk : Options.src_prec_jimple);
        options.set_force_android_jar(args[4]);
        options.set_prepend_classpath(true);
        options.set_allow_phantom_refs(true);
        options.set_validate(true);
        options.set_output_format(Options.output_format_class);
        options.set_output_dir(args[3]);
        options.set_soot_classpath(args[2] + File.pathSeparator + args[4]);
        if (args[0].equals("dex")) options.set_process_dir(List.of(args[1]));
        var classes = new TreeMap<String, SootClass>();
        for (var original : dex.getClasses()) {
            String name = name(original.getType());
            var cls = Scene.v().forceResolve(name, SootClass.BODIES);
            cls.setApplicationClass(); classes.put(name, cls);
        }
        Scene.v().loadNecessaryClasses();
        var failures = new ArrayList<Throwable>();
        for (var original : dex.getClasses()) {
            var cls = classes.get(name(original.getType()));
            try {
                equal(cls.isPhantom(), false, "Requested class phantom");
                equal(cls.getModifiers() & 0x611, original.getAccessFlags() & 0x611, "Soot class flags " + cls);
                equal(new TreeSet<>(cls.getInterfaces().stream().map(SootClass::getName).toList()),
                    new TreeSet<>(original.getInterfaces().stream().map(StrictCorpusConsumer::name).toList()), "Soot interfaces " + cls);
                var actual = new TreeMap<String, Integer>();
                for (var m : cls.getMethods()) actual.put(methodKey(m.getName(), m.getParameterTypes().stream().map(StrictCorpusConsumer::descriptor).toList(), descriptor(m.getReturnType())), m.getModifiers() & 0x53f);
                equal(actual, expectedMethods(original), "Soot method inventory " + cls);
                var fields = new TreeMap<String, Integer>();
                for (var f : cls.getFields()) fields.put(f.getName() + ":" + descriptor(f.getType()), f.getModifiers() & 0xdf);
                equal(fields, expectedFields(original), "Soot field inventory " + cls);
            } catch (RuntimeException | AssertionError e) { failures.add(e); e.printStackTrace(System.err); }
            for (var m : cls.getMethods()) if (m.isConcrete()) {
                try { m.retrieveActiveBody().validate(); System.out.println("BODY " + m.getSignature()); }
                catch (RuntimeException | AssertionError e) { failures.add(e); e.printStackTrace(System.err); }
            }
        }
        if (!failures.isEmpty()) throw new AssertionError("Strict validation failures: " + failures.size());
        PackManager.v().runPacks();
        for (var cls : classes.values()) for (var m : cls.getMethods()) if (m.isConcrete()) m.getActiveBody().validate();
        PackManager.v().writeOutput();
        for (var original : dex.getClasses()) bytecode(Path.of(args[3], name(original.getType()).replace('.', '/') + ".class"), original);
        System.out.println("ACCEPTED " + dex.getClasses().size());
    }
}
