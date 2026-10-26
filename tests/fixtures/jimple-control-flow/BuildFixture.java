import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;

/** DEX operands follow https://source.android.com/docs/core/runtime/dalvik-bytecode. */
public final class BuildFixture {
    private static final List<ImmutableMethod> METHODS = new ArrayList<>();

    private static void method(String name, String result, List<String> parameters,
                               MethodImplementationBuilder body) {
        var params = parameters.stream()
            .map(type -> new ImmutableMethodParameter(type, Set.of(), null)).toList();
        METHODS.add(new ImmutableMethod("LControlFlow;", name, params, result, 0x9,
            Set.of(), Set.of(), body.getMethodImplementation()));
    }

    public static void main(String[] args) throws Exception {
        var b = new MethodImplementationBuilder(2); // p0 = v1
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 1, b.getLabel("left")));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 11));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("left");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 23));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        method("branch", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(3); // p0 = v2
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        b.addLabel("head");
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_GE, 1, 2, b.getLabel("done")));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 1));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 1, 1, 1));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("head")));
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        method("loop", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(5); // p0 = v3, p1 = v4
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 7));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 84));
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 1, 1, 3));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 19));
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 1, 1, 4));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 1));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"),
            b.getLabel("end"), b.getLabel("handler"));
        method("handler", "I", List.of("I", "I"), b);

        b = new MethodImplementationBuilder(3); // p0 = v2
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 2, b.getLabel("object")));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 7));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("object");
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("null")));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, -1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("null");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 31));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        method("nullZero", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(3); // p0 = v2
        b.addInstruction(new BuilderInstruction21ih(Opcode.CONST_HIGH16, 0, 0x3fc00000));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_NEZ, 2, b.getLabel("merge")));
        b.addInstruction(new BuilderInstruction21ih(Opcode.CONST_HIGH16, 0, 0xc0100000));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        method("floatHigh", "F", List.of("I"), b);

        b = new MethodImplementationBuilder(3); // p0 = v2
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 0, b.getLabel("negative")));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 1));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("negative");
        b.addInstruction(new BuilderInstruction12x(Opcode.NEG_INT, 1, 0));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        method("alias", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(7); // p0 = v4, p1 = v5/v6
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 0, 5));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("negative")));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_WIDE_16, 2, 9));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_LONG, 0, 0, 2));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("negative");
        b.addInstruction(new BuilderInstruction12x(Opcode.NEG_LONG, 0, 0));
        b.addLabel("merge");
        // DEX explicitly permits overlapping move-wide source/destination pairs.
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 1, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 1));
        method("wide", "J", List.of("I", "J"), b);

        b = new MethodImplementationBuilder(3); // p0 = v2
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 37));
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LTZ, 2, b.getLabel("throwNull")));
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 2));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("end")));
        b.addLabel("throwNull");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("arithmetic");
        // A DEX handler may ignore the exception without move-exception.
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 41));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("nullPointer");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 43));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"),
            b.getLabel("end"), b.getLabel("arithmetic"));
        b.addCatch("Ljava/lang/NullPointerException;", b.getLabel("start"),
            b.getLabel("end"), b.getLabel("nullPointer"));
        method("catches", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(4); // p0 = v2, p1 = v3
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 2));
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 3));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"),
            b.getLabel("end"), b.getLabel("handler"));
        method("exceptionState", "I", List.of("I", "I"), b);

        b = new MethodImplementationBuilder(4); // p0 = v2, p1 = v3
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 5));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 84));
        b.addLabel("innerStart");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 1, 2));
        b.addLabel("innerEnd");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("second")));
        b.addLabel("innerHandler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 13));
        b.addLabel("second");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 3));
        b.addLabel("secondEnd");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("merge")));
        b.addLabel("outerHandler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 29));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("innerStart"),
            b.getLabel("innerEnd"), b.getLabel("innerHandler"));
        b.addCatch(b.getLabel("innerStart"), b.getLabel("innerEnd"), b.getLabel("outerHandler"));
        b.addCatch(b.getLabel("second"), b.getLabel("secondEnd"), b.getLabel("outerHandler"));
        method("nested", "I", List.of("I", "I"), b);

        b = new MethodImplementationBuilder(2); // p0 = v1
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("merge")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0,
            new ImmutableStringReference("present")));
        b.addLabel("merge");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("null")));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 47));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("null");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 29));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        method("nullJoin", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(5); // p0 = v4
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        b.addLabel("head");
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_GE, 1, 4, b.getLabel("done")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 2,
            new ImmutableStringReference("iteration")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 3, 2));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 2));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 1, 1, 1));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("head")));
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        method("typeLoop", "I", List.of("I"), b);

        b = new MethodImplementationBuilder(10); // selector=v6, divisor=v7, value=v8/v9
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 3,
            new ImmutableStringReference("high-word")));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 3, b.getLabel("integer")));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LTZ, 6, b.getLabel("overwrite")));
        b.addLabel("integer");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 3, 257));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 3));
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 6, 7));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("overwrite")));
        b.addLabel("handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 3, 511));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 3));
        b.addLabel("overwrite");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 3, 8, 9, 6, 0, 0,
            new ImmutableMethodReference("Ljava/lang/Long;", "rotateLeft", List.of("J", "I"), "J")));
        // The incoming v3 may be a reference or integer; move-result-wide replaces both words.
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 2));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 3, 0, 0, 0,
            new ImmutableMethodReference("Ljava/lang/Long;", "reverseBytes", List.of("J"), "J")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 4));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 0, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_LONG, 4, 4, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 4));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"),
            b.getLabel("end"), b.getLabel("handler"));
        method("wideHighClobber", "J", List.of("I", "I", "J"), b);

        var cls = new ImmutableClassDef("LControlFlow;", 0x1, "Ljava/lang/Object;",
            List.of(), "BuildFixture.java", Set.of(), List.of(), METHODS);
        DexFileFactory.writeDexFile(args[0], new ImmutableDexFile(Opcodes.forDexVersion(35), List.of(cls)));
    }
}
