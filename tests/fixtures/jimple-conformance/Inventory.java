import java.io.File;
import java.nio.file.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.dexbacked.instruction.DexBackedInstruction;

/** Opcode inventory comes from independent dexlib2, not Garlic's decoder table. */
public final class Inventory {
    public static void main(String[] args) throws Exception {
        var opcodes = Opcodes.forDexVersion(39);
        for (int value = 0; value <= 255; value++) {
            Opcode op = opcodes.getOpcodeByValue(value);
            if (op != null && !op.odexOnly())
                System.out.println("OP\t" + value + "\t" + op.name + "\t" + op.format);
            else System.out.println("RESERVED\t" + value);
        }
        for (Opcode payload : new Opcode[]{Opcode.PACKED_SWITCH_PAYLOAD, Opcode.SPARSE_SWITCH_PAYLOAD, Opcode.ARRAY_PAYLOAD})
            System.out.println("PAYLOAD\t" + payload.name + "\t" + payload.format);
        try (var paths = Files.list(Path.of(args[0]))) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".dex")).sorted().toList()) {
                String group = path.getFileName().toString().replace(".dex", "");
                var dex = DexFileFactory.loadDexFile(path.toFile(), opcodes);
                for (var cls : dex.getClasses()) {
                    System.out.println("CLASS\t" + group + "\t" + cls.getType());
                    for (var method : cls.getMethods()) {
                        if (method.getImplementation() == null) continue;
                        int pc = 0;
                        for (var insn : method.getImplementation().getInstructions()) {
                            int offset = ((DexBackedInstruction) insn).instructionStart;
                            System.out.println("HIT\t" + group + "\t" + cls.getType() + "\t" + method.getName() + "\t" + insn.getOpcode().name + "\t" + pc + "\t" + offset);
                            pc += insn.getCodeUnits();
                        }
                    }
                }
            }
        }
    }
}
