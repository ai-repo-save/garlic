import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;

/** Development-only dexlib2 construction; operands follow the AOSP DEX instruction tables. */
final class FixtureSupport {
    static ImmutableMethod method(String owner, String name, String result, List<String> params,
                                  int flags, MethodImplementationBuilder b) {
        return new ImmutableMethod("L" + owner + ";", name,
            params.stream().map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(),
            result, flags, Set.of(), Set.of(), b == null ? null : b.getMethodImplementation());
    }
    static ImmutableClassDef cls(String name, int flags, String parent, List<String> interfaces,
                                 List<ImmutableField> fields, List<ImmutableMethod> methods) {
        return new ImmutableClassDef("L" + name + ";", flags, parent, interfaces,
            "BuildCorpus.java", Set.of(), fields, methods);
    }
    static ImmutableMethodReference ref(String owner, String name, String result, String... params) {
        return new ImmutableMethodReference("L" + owner + ";", name, List.of(params), result);
    }
    static void invoke(MethodImplementationBuilder b, Opcode op, Reference ref, int... regs) {
        if (op.format == Format.Format3rc) {
            b.addInstruction(new BuilderInstruction3rc(op, regs.length == 0 ? 0 : regs[0], regs.length, ref));
        } else {
            int[] r = Arrays.copyOf(regs, 5);
            b.addInstruction(new BuilderInstruction35c(op, regs.length, r[0], r[1], r[2], r[3], r[4], ref));
        }
    }
    static ImmutableMethod constructor(String name, String parent) {
        var b = new MethodImplementationBuilder(1);
        invoke(b, Opcode.INVOKE_DIRECT, ref(parent, "<init>", "V"), 0);
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        return method(name, "<init>", "V", List.of(), 0x10001, b);
    }
    static void constant(MethodImplementationBuilder b, String type, int reg, long bits) {
        if (type.equals("J") || type.equals("D"))
            b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, reg, bits));
        else b.addInstruction(new BuilderInstruction31i(Opcode.CONST, reg, (int) bits));
    }
    static Opcode ret(String type) {
        return type.equals("J") || type.equals("D") ? Opcode.RETURN_WIDE
            : type.startsWith("L") || type.startsWith("[") ? Opcode.RETURN_OBJECT : Opcode.RETURN;
    }
    static void write(Path path, List<ImmutableClassDef> classes) throws Exception {
        DexFileFactory.writeDexFile(path.toString(), new ImmutableDexFile(Opcodes.forDexVersion(39), classes));
    }
}
