import java.nio.file.*;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;

/** Bounded, legal DEX corpus, independent of Garlic's opcode tables and emitter. */
public final class BuildCorpus {
    static Path output;
    static final List<String> cases = new ArrayList<>();
    static final List<ImmutableMethod> methods = new ArrayList<>();
    static String owner;

    static void begin(String name) { owner = name; methods.clear(); }
    static void add(String name, String type, MethodImplementationBuilder b) {
        methods.add(FixtureSupport.method(owner, name, type, List.of(), 9, b));
        cases.add(owner + "\t" + name + "\t-");
    }
    static void finish() throws Exception {
        save(List.of(FixtureSupport.cls(owner, 1, "Ljava/lang/Object;", List.of(), List.of(), methods)));
    }
    static void save(List<ImmutableClassDef> classes) throws Exception {
        FixtureSupport.write(output.resolve(owner + ".dex"), classes);
    }
    static void literal(String name, String type, org.jf.dexlib2.builder.BuilderInstruction insn) {
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(insn);
        b.addInstruction(new BuilderInstruction11x(FixtureSupport.ret(type), 0));
        add(name, type, b);
    }
    static void literals() throws Exception {
        begin("IntLiterals");
        literal("smallMin", "I", new BuilderInstruction11n(Opcode.CONST_4, 0, -8));
        literal("smallMax", "I", new BuilderInstruction11n(Opcode.CONST_4, 0, 7));
        literal("shortMin", "I", new BuilderInstruction21s(Opcode.CONST_16, 0, -32768));
        literal("shortMax", "I", new BuilderInstruction21s(Opcode.CONST_16, 0, 32767));
        literal("intMin", "I", new BuilderInstruction31i(Opcode.CONST, 0, Integer.MIN_VALUE));
        literal("intMax", "I", new BuilderInstruction31i(Opcode.CONST, 0, Integer.MAX_VALUE));
        literal("highMin", "I", new BuilderInstruction21ih(Opcode.CONST_HIGH16, 0, 0x80000000));
        literal("highMax", "I", new BuilderInstruction21ih(Opcode.CONST_HIGH16, 0, 0x7fff0000));
        finish();
        begin("LongLiterals");
        literal("wideShortMin", "J", new BuilderInstruction21s(Opcode.CONST_WIDE_16, 0, -32768));
        literal("wideShortMax", "J", new BuilderInstruction21s(Opcode.CONST_WIDE_16, 0, 32767));
        literal("wideIntMin", "J", new BuilderInstruction31i(Opcode.CONST_WIDE_32, 0, Integer.MIN_VALUE));
        literal("wideIntMax", "J", new BuilderInstruction31i(Opcode.CONST_WIDE_32, 0, Integer.MAX_VALUE));
        literal("wideHighMin", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, Long.MIN_VALUE));
        literal("wideHighMax", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, 0x7fff000000000000L));
        literal("longMin", "J", new BuilderInstruction51l(Opcode.CONST_WIDE, 0, Long.MIN_VALUE));
        literal("longMax", "J", new BuilderInstruction51l(Opcode.CONST_WIDE, 0, Long.MAX_VALUE));
        literal("longPattern", "J", new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 0x123456789abcdef0L));
        finish();
        begin("FloatLiterals");
        String[] names = {"floatLarge", "floatSmall", "floatNegativeZero", "floatSubnormal", "floatNan", "floatInfinity", "floatNegativeInfinity"};
        int[] bits = {0x501502f9, 0x2edbe6ff, 0x80000000, 1, 0x7fc00000, 0x7f800000, 0xff800000};
        for (int i = 0; i < names.length; i++)
            literal(names[i], "F", new BuilderInstruction31i(Opcode.CONST, 0, bits[i]));
        literal("floatHigh", "F", new BuilderInstruction21ih(Opcode.CONST_HIGH16, 0, 0x50150000));
        finish();
        begin("DoubleLiterals");
        String[] dn = {"doubleLarge", "doubleSmall", "doubleNegativeZero", "doubleSubnormal", "doubleNan", "doubleInfinity", "doubleNegativeInfinity"};
        long[] db = {0x4415af1d78b58c40L, 0x3ddb7cdfd9d7bdbbL, Long.MIN_VALUE, 1, 0x7ff8000000000000L, 0x7ff0000000000000L, 0xfff0000000000000L};
        for (int i = 0; i < dn.length; i++)
            literal(dn[i], "D", new BuilderInstruction51l(Opcode.CONST_WIDE, 0, db[i]));
        finish();
        begin("FloatNanBits");
        literal("floatNanBits", "F", new BuilderInstruction31i(Opcode.CONST, 0, 0x7fc12345));
        finish();
        begin("DoubleNanBits");
        literal("doubleNanBits", "D", new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 0x7ff8123456789abcL));
        finish();
        begin("StringAscii");
        literal("emptyString", "Ljava/lang/String;", new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("")));
        literal("escapedString", "Ljava/lang/String;", new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("q\"\\\n\t\r\b\f")));
        literal("jumboString", "Ljava/lang/String;", new BuilderInstruction31c(Opcode.CONST_STRING_JUMBO, 0, new ImmutableStringReference("jumbo")));
        finish();
        begin("StringUtf16");
        literal("utf16String", "Ljava/lang/String;", new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("中文\ud83d\ude00")));
        finish();
        begin("StringNul");
        literal("nulString", "Ljava/lang/String;", new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("a\u0000b")));
        finish();
        begin("Classes");
        literal("objectClass", "Ljava/lang/Class;", new BuilderInstruction21c(Opcode.CONST_CLASS, 0, new ImmutableTypeReference("Ljava/lang/String;")));
        literal("arrayClass", "Ljava/lang/Class;", new BuilderInstruction21c(Opcode.CONST_CLASS, 0, new ImmutableTypeReference("[I")));
        finish();
        begin("PrimitiveClass");
        literal("primitiveClass", "Ljava/lang/Class;", new BuilderInstruction21c(Opcode.CONST_CLASS, 0, new ImmutableTypeReference("I")));
        finish();
    }

    static void switches(boolean sparse, boolean empty, boolean middle) throws Exception {
        begin((sparse ? "Sparse" : "Packed") + (empty ? "Empty" : middle ? "Middle" : "Tail"));
        for (int key : new int[]{-1, 0, 1, 2}) {
            var b = new MethodImplementationBuilder(2);
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, key));
            b.addInstruction(new BuilderInstruction31t(sparse ? Opcode.SPARSE_SWITCH : Opcode.PACKED_SWITCH, 0, b.getLabel("payload")));
            b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("default")));
            if (!middle) {
                switchResults(b);
                b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
            }
            b.addLabel("payload");
            if (sparse) {
                var elements = empty ? List.<SwitchLabelElement>of() : List.of(new SwitchLabelElement(-1, b.getLabel("one")), new SwitchLabelElement(1, b.getLabel("two")));
                b.addInstruction(new BuilderSparseSwitchPayload(elements));
            } else b.addInstruction(new BuilderPackedSwitchPayload(0, empty ? List.of() : List.of(b.getLabel("one"), b.getLabel("two"))));
            if (middle) switchResults(b);
            add((sparse ? "sparse" : "packed") + (empty ? "Empty" : "Value") + (key < 0 ? "Neg" : key), "I", b);
        }
        finish();
    }
    static void switchResults(MethodImplementationBuilder b) {
        b.addLabel("default");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 31));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        b.addLabel("one");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 41));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        b.addLabel("two");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 59));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
    }
    static void sharedArray() throws Exception {
        begin("SharedArray");
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, new ImmutableTypeReference("[I")));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 2, 0, new ImmutableTypeReference("[I")));
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 1, b.getLabel("data")));
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 2, b.getLabel("data")));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("read")));
        b.addLabel("data");
        b.addInstruction(new BuilderArrayPayload(4, List.of(17, -29)));
        b.addLabel("read");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET, 1, 1, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET, 2, 2, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 1, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
        add("sharedArray", "I", b);
        finish();
    }
    static void arrayData() throws Exception {
        for (int width : new int[]{1, 2, 4, 8}) {
            for (boolean empty : new boolean[]{false, true}) for (boolean middle : new boolean[]{true, false}) {
                begin("Data" + width + (empty ? "Empty" : "Middle") + (middle ? "" : "Tail"));
                String type = switch (width) { case 1 -> "[B"; case 2 -> "[S"; case 4 -> "[I"; default -> "[J"; };
                var b = new MethodImplementationBuilder(2);
                b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, empty ? 0 : 2));
                b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, new ImmutableTypeReference(type)));
                b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 1, b.getLabel("data")));
                if (middle) b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("done")));
                else b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
                b.addLabel("data");
                List<Number> values = empty ? List.of() : List.of(-1L, width == 8 ? 0x123456789abcdef0L : 37L);
                b.addInstruction(new BuilderArrayPayload(width, values));
                if (middle) {
                    b.addLabel("done");
                    b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
                }
                add("data" + width + (empty ? "Empty" : "Values"), type, b);
                finish();
            }
        }
        sharedArray();
    }

    static final String[] TYPES = {"I", "J", "F", "D", "Z", "B", "C", "S", "Ljava/lang/String;"};
    static final long[] VALUES = {1234567, 0x123456789abcdef0L, 0x3fc00000, 0x4004000000000000L, 1, -113, 0xffee, -31000, 0};
    static String suffix(String type) {
        return switch (type) { case "J", "D" -> "_WIDE"; case "Z" -> "_BOOLEAN"; case "B" -> "_BYTE"; case "C" -> "_CHAR"; case "S" -> "_SHORT"; case "Ljava/lang/String;" -> "_OBJECT"; default -> ""; };
    }
    static void value(MethodImplementationBuilder b, String type, int reg, long bits) {
        if (type.startsWith("L")) b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, reg, new ImmutableStringReference("state-value")));
        else FixtureSupport.constant(b, type, reg, bits);
    }
    static void arraysAndFields() throws Exception {
        for (int i = 0; i < TYPES.length; i++) {
            String type = TYPES[i], id = type.startsWith("L") ? "Object" : type;
            begin("Array" + id);
            var b = new MethodImplementationBuilder(5);
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
            b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, new ImmutableTypeReference("[" + type)));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
            value(b, type, 2, VALUES[i]);
            b.addInstruction(new BuilderInstruction23x(Opcode.valueOf("APUT" + suffix(type)), 2, 1, 0));
            b.addInstruction(new BuilderInstruction23x(Opcode.valueOf("AGET" + suffix(type)), 2, 1, 0));
            b.addInstruction(new BuilderInstruction11x(FixtureSupport.ret(type), 2));
            add("array" + id, type, b);
            b = new MethodImplementationBuilder(2);
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 3));
            b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, new ImmutableTypeReference("[" + type)));
            b.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, 0, 1));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            add("arrayLength", "I", b);
            finish();

            begin("Field" + id);
            String fieldName = "state" + id;
            var field = new ImmutableFieldReference("L" + owner + ";", fieldName, type);
            var instance = new ImmutableFieldReference("L" + owner + ";", "instance", type);
            b = new MethodImplementationBuilder(5);
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("L" + owner + ";")));
            FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref(owner, "<init>", "V"), 0);
            value(b, type, 1, VALUES[i]);
            b.addInstruction(new BuilderInstruction22c(Opcode.valueOf("IPUT" + suffix(type)), 1, 0, instance));
            b.addInstruction(new BuilderInstruction22c(Opcode.valueOf("IGET" + suffix(type)), 3, 0, instance));
            b.addInstruction(new BuilderInstruction21c(Opcode.valueOf("SPUT" + suffix(type)), 3, field));
            b.addInstruction(new BuilderInstruction21c(Opcode.valueOf("SGET" + suffix(type)), 1, field));
            b.addInstruction(new BuilderInstruction11x(FixtureSupport.ret(type), 1));
            add("field" + id, type, b);
            cases.set(cases.size() - 1, owner + "\tfield" + id + "\t" + fieldName);
            methods.add(FixtureSupport.constructor(owner, "java/lang/Object"));
            save(List.of(FixtureSupport.cls(owner, 1, "Ljava/lang/Object;", List.of(), List.of(
                new ImmutableField("L" + owner + ";", fieldName, type, 9, null, Set.of(), Set.of()),
                new ImmutableField("L" + owner + ";", "instance", type, 1, null, Set.of(), Set.of())), methods)));
        }
    }

    static void invokeCases() throws Exception {
        for (boolean range : new boolean[]{false, true}) {
            for (String kind : new String[]{"STATIC", "VIRTUAL", "DIRECT", "SUPER", "INTERFACE"}) {
                begin("Call" + kind + (range ? "Range" : "List"));
                String self = owner, base = owner + "Base", iface = owner + "Face";
                String target = kind.equals("STATIC") ? self : kind.equals("INTERFACE") ? iface : base;
                var b = new MethodImplementationBuilder(8);
                if (!kind.equals("STATIC")) {
                    b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("L" + self + ";")));
                    FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref(self, "<init>", "V"), 0);
                }
                // receiver + long + double = exactly five register words for 35c.
                FixtureSupport.constant(b, "J", 1, 0x123456789abcdef0L);
                FixtureSupport.constant(b, "D", 3, 0x4004000000000000L);
                if (kind.equals("SUPER")) {
                    FixtureSupport.invoke(b, range ? Opcode.INVOKE_VIRTUAL_RANGE : Opcode.INVOKE_VIRTUAL,
                        FixtureSupport.ref(self, "dispatch", "J", "J", "D"), 0, 1, 2, 3, 4);
                } else if (kind.equals("DIRECT")) {
                    target = self;
                    FixtureSupport.invoke(b, Opcode.valueOf("INVOKE_DIRECT" + (range ? "_RANGE" : "")),
                        FixtureSupport.ref(target, "calculate", "J", "J", "D"), 0, 1, 2, 3, 4);
                } else {
                    int[] regs = kind.equals("STATIC") ? new int[]{1,2,3,4} : new int[]{0,1,2,3,4};
                    FixtureSupport.invoke(b, Opcode.valueOf("INVOKE_" + kind + (range ? "_RANGE" : "")),
                        FixtureSupport.ref(target, "calculate", "J", "J", "D"), regs);
                }
                b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 5));
                b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 5));
                add("invokeWide", "J", b);
                methods.add(FixtureSupport.constructor(self, base));
                var calc = calculation(kind.equals("STATIC"));
                if (kind.equals("STATIC") || kind.equals("DIRECT"))
                    methods.add(FixtureSupport.method(self, "calculate", "J", List.of("J", "D"), kind.equals("DIRECT") ? 2 : 9, calc));
                if (kind.equals("SUPER")) {
                    var dispatch = new MethodImplementationBuilder(5);
                    FixtureSupport.invoke(dispatch, range ? Opcode.INVOKE_SUPER_RANGE : Opcode.INVOKE_SUPER,
                        FixtureSupport.ref(base, "calculate", "J", "J", "D"), 0,1,2,3,4);
                    dispatch.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 1));
                    dispatch.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 1));
                    methods.add(FixtureSupport.method(self, "dispatch", "J", List.of("J", "D"), 1, dispatch));
                }
                var baseMethods = new ArrayList<ImmutableMethod>();
                baseMethods.add(FixtureSupport.constructor(base, "java/lang/Object"));
                if (!kind.equals("STATIC") && !kind.equals("DIRECT"))
                    baseMethods.add(FixtureSupport.method(base, "calculate", "J", List.of("J", "D"), 1, calculation(false)));
                var classes = new ArrayList<ImmutableClassDef>();
                classes.add(FixtureSupport.cls(base, 1, "Ljava/lang/Object;", kind.equals("INTERFACE") ? List.of("L" + iface + ";") : List.of(), List.of(), baseMethods));
                if (kind.equals("INTERFACE")) classes.add(FixtureSupport.cls(iface, 0x601, "Ljava/lang/Object;", List.of(), List.of(), List.of(
                    FixtureSupport.method(iface, "calculate", "J", List.of("J", "D"), 0x401, null))));
                classes.add(FixtureSupport.cls(self, 1, "L" + base + ";", List.of(), List.of(), methods));
                save(classes);
            }
        }
        for (boolean range : new boolean[]{false, true}) {
            begin("CallResults" + (range ? "Range" : "List"));
            var b = new MethodImplementationBuilder(2);
            b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("invoke-result")));
            FixtureSupport.invoke(b, range ? Opcode.INVOKE_STATIC_RANGE : Opcode.INVOKE_STATIC,
                FixtureSupport.ref("java/util/Objects", "requireNonNull", "Ljava/lang/Object;", "Ljava/lang/Object;"), 0);
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
            FixtureSupport.invoke(b, range ? Opcode.INVOKE_STATIC_RANGE : Opcode.INVOKE_STATIC,
                FixtureSupport.ref(owner, "store", "V"));
            FixtureSupport.invoke(b, range ? Opcode.INVOKE_VIRTUAL_RANGE : Opcode.INVOKE_VIRTUAL,
                FixtureSupport.ref("java/lang/String", "length", "I"), 1);
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            add("invokeResults", "I", b);
            cases.set(cases.size() - 1, owner + "\tinvokeResults\tcallState");
            var state = new ImmutableFieldReference("L" + owner + ";", "callState", "I");
            var store = new MethodImplementationBuilder(1);
            store.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 101));
            store.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, state));
            store.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            methods.add(FixtureSupport.method(owner, "store", "V", List.of(), 9, store));
            save(List.of(FixtureSupport.cls(owner, 1, "Ljava/lang/Object;", List.of(), List.of(
                new ImmutableField("L" + owner + ";", "callState", "I", 9, null, Set.of(), Set.of())), methods)));
        }
    }

    static void objects() throws Exception {
        begin("Objects");
        var b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("cast")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction22c(Opcode.INSTANCE_OF, 2, 1, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_ENTER, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_EXIT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        add("monitorCast", "I", b);
        b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("monitor-state")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_ENTER, 0));
        FixtureSupport.invoke(b, Opcode.INVOKE_STATIC, FixtureSupport.ref("java/lang/Thread", "holdsLock", "Z", "Ljava/lang/Object;"), 0);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_EXIT, 0));
        FixtureSupport.invoke(b, Opcode.INVOKE_STATIC, FixtureSupport.ref("java/lang/Thread", "holdsLock", "Z", "Ljava/lang/Object;"), 0);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 1, 1, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        add("monitorState", "I", b);
        b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("bad-cast")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Integer;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        add("castFailure", "Ljava/lang/Object;", b);
        finish();
        begin("NestedArray");
        b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, new ImmutableTypeReference("[[I")));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 2, 0, new ImmutableTypeReference("[I")));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 3, -4095));
        b.addInstruction(new BuilderInstruction23x(Opcode.APUT, 3, 2, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.APUT_OBJECT, 2, 1, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_OBJECT, 2, 1, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("[I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 2));
        add("nestedArray", "[I", b);
        finish();
        begin("Structure");
        b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 73));
        var field = new ImmutableFieldReference("LStructure;", "initialized", "I");
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, field));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        methods.add(FixtureSupport.method(owner, "<clinit>", "V", List.of(), 0x10008, b));
        b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, field));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        add("classInitialization", "I", b);
        methods.add(FixtureSupport.method(owner, "abstractMethod", "I", List.of(), 0x401, null));
        methods.add(FixtureSupport.method(owner, "nativeMethod", "I", List.of(), 0x109, null));
        save(List.of(FixtureSupport.cls(owner, 0x401, "Ljava/lang/Object;", List.of(), List.of(
            new ImmutableField("LStructure;", "initialized", "I", 9, null, Set.of(), Set.of())), methods)));
        begin("FilledList");
        filled(false);
        begin("FilledRange");
        filled(true);
    }
    static void filled(boolean range) throws Exception {
        var b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, -1));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 7));
        FixtureSupport.invoke(b, range ? Opcode.FILLED_NEW_ARRAY_RANGE : Opcode.FILLED_NEW_ARRAY, new ImmutableTypeReference("[I"), 0,1);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 2));
        add("filledArray", "[I", b);
        finish();
    }
    static final int[][] INT_PAIRS = {{0, 0}, {-7, -7}, {4, 4}, {-3, 0}, {0, 5}, {9, -2}, {-8, -1}, {1, 2}};
    static final int[] ZERO_VALUES = {-7, 0, 4, -1, 1};

    static void takeBit(MethodImplementationBuilder b, int index) {
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("next" + index)));
        b.addLabel("taken" + index);
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 3, 1 << index));
        b.addInstruction(new BuilderInstruction23x(Opcode.OR_INT, 2, 2, 3));
        b.addLabel("next" + index);
    }
    static void intCompare(String name, Opcode op) {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 0));
        for (int i = 0; i < INT_PAIRS.length; i++) {
            FixtureSupport.constant(b, "I", 0, INT_PAIRS[i][0]);
            FixtureSupport.constant(b, "I", 1, INT_PAIRS[i][1]);
            b.addInstruction(new BuilderInstruction22t(op, 0, 1, b.getLabel("taken" + i)));
            takeBit(b, i);
        }
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        add(name, "I", b);
    }
    static void zeroCompare(String name, Opcode op) {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 0));
        for (int i = 0; i < ZERO_VALUES.length; i++) {
            FixtureSupport.constant(b, "I", 0, ZERO_VALUES[i]);
            b.addInstruction(new BuilderInstruction21t(op, 0, b.getLabel("taken" + i)));
            takeBit(b, i);
        }
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        add(name, "I", b);
    }
    static void refCase(MethodImplementationBuilder b, int index, Opcode op) {
        b.addInstruction(new BuilderInstruction22t(op, 0, 1, b.getLabel("taken" + index)));
        takeBit(b, index);
    }
    static void refCompare(String name, Opcode op) {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("left")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
        refCase(b, 0, op);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("left")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1, new ImmutableStringReference("right")));
        refCase(b, 1, op);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        refCase(b, 2, op);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new ImmutableFieldReference("LRefIf;", "absent", "Ljava/lang/Object;")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1, new ImmutableStringReference("left")));
        refCase(b, 3, op);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("same")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1, new ImmutableStringReference("same")));
        refCase(b, 4, op);
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("Ljava/lang/Object;")));
        FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref("java/lang/Object", "<init>", "V"), 0);
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 1, new ImmutableTypeReference("Ljava/lang/Object;")));
        FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref("java/lang/Object", "<init>", "V"), 1);
        refCase(b, 5, op);
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("Ljava/lang/Object;")));
        FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref("java/lang/Object", "<init>", "V"), 0);
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
        refCase(b, 6, op);
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        add(name, "I", b);
    }
    static void comparisons() throws Exception {
        begin("IntIf");
        intCompare("ifEq", Opcode.IF_EQ);
        intCompare("ifNe", Opcode.IF_NE);
        intCompare("ifLt", Opcode.IF_LT);
        intCompare("ifGt", Opcode.IF_GT);
        intCompare("ifLe", Opcode.IF_LE);
        zeroCompare("ifGez", Opcode.IF_GEZ);
        zeroCompare("ifGtz", Opcode.IF_GTZ);
        finish();
        begin("RefIf");
        refCompare("refEq", Opcode.IF_EQ);
        refCompare("refNe", Opcode.IF_NE);
        save(List.of(FixtureSupport.cls(owner, 1, "Ljava/lang/Object;", List.of(), List.of(
            new ImmutableField("LRefIf;", "absent", "Ljava/lang/Object;", 9, null, Set.of(), Set.of())), methods)));
    }
    static void high16() throws Exception {
        begin("High16");
        literal("high16Zero", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, 0L));
        literal("high16Neg", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, Long.MIN_VALUE));
        literal("high16NegOne", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, -1L << 48));
        literal("high16Pos", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, 1L << 48));
        literal("high16PosMax", "J", new BuilderInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, 0x7fffL << 48));
        finish();
    }
    static void typedPayload(String name, String type, int width, Number... values) {
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, values.length));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, new ImmutableTypeReference(type)));
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 1, b.getLabel("data")));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("done")));
        b.addLabel("data");
        b.addInstruction(new BuilderArrayPayload(width, List.of(values)));
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        add(name, type, b);
    }
    static void typedArrayData() throws Exception {
        begin("TypedArrayData");
        typedPayload("dataBoolean", "[Z", 1, 0, 1);
        // dexlib2 stores width 2 as a signed short; U+FFEE is the same 16 bits as -18.
        typedPayload("dataChar", "[C", 2, 0, (short) 0xffee);
        typedPayload("dataFloat", "[F", 4, 0x80000000, 0x3fc00000);
        typedPayload("dataDouble", "[D", 8, Long.MIN_VALUE, 0x4004000000000000L);
        finish();
    }
    static void polymorphic(boolean range) throws Exception {
        begin(range ? "PolymorphicRange" : "PolymorphicList");
        var b = new MethodImplementationBuilder(6);
        FixtureSupport.invoke(b, Opcode.INVOKE_STATIC, FixtureSupport.ref("java/lang/invoke/MethodHandles", "lookup", "Ljava/lang/invoke/MethodHandles$Lookup;"));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 1, new ImmutableFieldReference("Ljava/lang/Integer;", "TYPE", "Ljava/lang/Class;")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_CLASS, 2, new ImmutableTypeReference("Ljava/lang/String;")));
        FixtureSupport.invoke(b, Opcode.INVOKE_STATIC, FixtureSupport.ref("java/lang/invoke/MethodType", "methodType", "Ljava/lang/invoke/MethodType;", "Ljava/lang/Class;", "Ljava/lang/Class;"), 1, 2);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_CLASS, 2, new ImmutableTypeReference("Ljava/lang/Integer;")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 3, new ImmutableStringReference("parseInt")));
        FixtureSupport.invoke(b, Opcode.INVOKE_VIRTUAL, FixtureSupport.ref("java/lang/invoke/MethodHandles$Lookup", "findStatic", "Ljava/lang/invoke/MethodHandle;", "Ljava/lang/Class;", "Ljava/lang/String;", "Ljava/lang/invoke/MethodType;"), 0, 2, 3, 1);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1, new ImmutableStringReference("41")));
        var method = FixtureSupport.ref("java/lang/invoke/MethodHandle", "invoke", "Ljava/lang/Object;", "[Ljava/lang/Object;");
        var proto = new ImmutableMethodProtoReference(List.of("Ljava/lang/String;"), "I");
        if (range) b.addInstruction(new BuilderInstruction4rcc(Opcode.INVOKE_POLYMORPHIC_RANGE, 0, 2, method, proto));
        else b.addInstruction(new BuilderInstruction45cc(Opcode.INVOKE_POLYMORPHIC, 2, 0, 1, 0, 0, 0, method, proto));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        add("parseInt", "I", b);
        // Bundled dexlib2 interns method protos only through method_ids, not 45cc/4rcc reference2.
        var prototype = new MethodImplementationBuilder(2);
        prototype.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        prototype.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        methods.add(FixtureSupport.method(owner, "prototype", "I", List.of("Ljava/lang/String;"), 9, prototype));
        finish();
    }
    static MethodImplementationBuilder bootstrap() {
        var b = new MethodImplementationBuilder(5);
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("Ljava/lang/invoke/ConstantCallSite;")));
        FixtureSupport.invoke(b, Opcode.INVOKE_VIRTUAL, FixtureSupport.ref("java/lang/invoke/MethodHandles$Lookup", "lookupClass", "Ljava/lang/Class;"), 2);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        FixtureSupport.invoke(b, Opcode.INVOKE_VIRTUAL, FixtureSupport.ref("java/lang/invoke/MethodHandles$Lookup", "findStatic", "Ljava/lang/invoke/MethodHandle;", "Ljava/lang/Class;", "Ljava/lang/String;", "Ljava/lang/invoke/MethodType;"), 2, 1, 3, 4);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref("java/lang/invoke/ConstantCallSite", "<init>", "V", "Ljava/lang/invoke/MethodHandle;"), 0, 1);
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 1, new ImmutableTypeReference("Ljava/lang/RuntimeException;")));
        FixtureSupport.invoke(b, Opcode.INVOKE_DIRECT, FixtureSupport.ref("java/lang/RuntimeException", "<init>", "V", "Ljava/lang/Throwable;"), 1, 0);
        b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        b.addCatch("Ljava/lang/NoSuchMethodException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        b.addCatch("Ljava/lang/IllegalAccessException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        return b;
    }
    static void custom(boolean range) throws Exception {
        begin(range ? "CustomRange" : "CustomList");
        var site = new ImmutableCallSiteReference("call_site_0",
            new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC, FixtureSupport.ref(owner, "link", "Ljava/lang/invoke/CallSite;", "Ljava/lang/invoke/MethodHandles$Lookup;", "Ljava/lang/String;", "Ljava/lang/invoke/MethodType;")),
            "add", new ImmutableMethodProtoReference(List.of("I", "I"), "I"), List.<org.jf.dexlib2.immutable.value.ImmutableEncodedValue>of());
        var b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 20));
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 21));
        if (range) b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_CUSTOM_RANGE, 0, 2, site));
        else FixtureSupport.invoke(b, Opcode.INVOKE_CUSTOM, site, 0, 1);
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        add("invokeAdd", "I", b);
        var add = new MethodImplementationBuilder(2);
        add.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 1));
        add.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        methods.add(FixtureSupport.method(owner, "add", "I", List.of("I", "I"), 9, add));
        methods.add(FixtureSupport.method(owner, "link", "Ljava/lang/invoke/CallSite;", List.of("Ljava/lang/invoke/MethodHandles$Lookup;", "Ljava/lang/String;", "Ljava/lang/invoke/MethodType;"), 9, bootstrap()));
        finish();
    }
    static void modern() throws Exception {
        polymorphic(false);
        polymorphic(true);
        custom(false);
        custom(true);
    }

    static MethodImplementationBuilder calculation(boolean isStatic) {
        var b = new MethodImplementationBuilder(isStatic ? 6 : 7);
        b.addInstruction(new BuilderInstruction12x(Opcode.DOUBLE_TO_LONG, 0, isStatic ? 4 : 5));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_LONG, 0, isStatic ? 2 : 3, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        return b;
    }
    static void formats() throws Exception {
        begin("Registers");
        var b = new MethodImplementationBuilder(304);
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 15, -123));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 15));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_16, 300, 0));
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_FROM16, 1, 300));
        b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel("goto16")));
        b.addLabel("goto16");
        b.addInstruction(new BuilderInstruction20t(Opcode.GOTO_16, b.getLabel("goto8")));
        b.addLabel("goto8");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("done")));
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        add("registerMoves", "I", b);
        b = new MethodImplementationBuilder(304);
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_WIDE_16, 2, -32768));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_WIDE_16, 302, 2));
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_WIDE_FROM16, 4, 302));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 6, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 6));
        add("registerWide", "J", b);
        b = new MethodImplementationBuilder(302);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 8, new ImmutableStringReference("registers")));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 301, 8));
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 9, 301));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 10, 9));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 10));
        add("registerObject", "Ljava/lang/String;", b);
        finish();
    }
    public static void main(String[] args) throws Exception {
        output = Path.of(args[0]); Files.createDirectories(output);
        literals();
        comparisons();
        high16();
        typedArrayData();
        modern();
        for (boolean sparse : new boolean[]{false, true}) {
            switches(sparse, false, false); switches(sparse, false, true); switches(sparse, true, true);
        }
        arrayData(); arraysAndFields(); invokeCases(); objects(); formats();
        BuildArithmetic.write(output, cases);
        Files.write(output.resolve("cases.tsv"), cases);
    }
}
