import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.immutable.*;

/** Literal arithmetic is absent from the existing arithmetic runner's operand matrix. */
final class BuildArithmetic {
    static void write(Path output, List<String> cases) throws Exception {
        var opcodes = Opcodes.forDexVersion(39);
        var methods = new ArrayList<ImmutableMethod>();
        for (int value = 0xd0; value <= 0xe2; value++) {
            Opcode op = opcodes.getOpcodeByValue(value);
            for (boolean min : new boolean[]{true, false}) {
                int literal = op.format == Format.Format22s ? (min ? -32768 : 32767) : (min ? -128 : 127);
                var b = new MethodImplementationBuilder(2);
                FixtureSupport.constant(b, "I", 1, -1234567);
                if (op.format == Format.Format22s) b.addInstruction(new BuilderInstruction22s(op, 0, 1, literal));
                else b.addInstruction(new BuilderInstruction22b(op, 0, 1, literal));
                b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
                String name = op + (min ? "_MIN" : "_MAX");
                methods.add(FixtureSupport.method("LiteralArithmetic", name, "I", List.of(), 9, b));
                cases.add("LiteralArithmetic\t" + name + "\t-");
            }
        }
        FixtureSupport.write(output.resolve("LiteralArithmetic.dex"), List.of(FixtureSupport.cls(
            "LiteralArithmetic", 1, "Ljava/lang/Object;", List.of(), List.of(), methods)));
    }
}
