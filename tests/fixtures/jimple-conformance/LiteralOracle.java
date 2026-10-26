/** Java int semantics independently evaluate the literal instruction boundary matrix. */
final class LiteralOracle {
    static int evaluate(String name) {
        int value = -1234567;
        int literal = name.contains("LIT16") || name.startsWith("RSUB_INT_") && !name.contains("LIT8")
            ? name.endsWith("_MIN") ? Short.MIN_VALUE : Short.MAX_VALUE
            : name.endsWith("_MIN") ? Byte.MIN_VALUE : Byte.MAX_VALUE;
        return switch (name.substring(0, name.indexOf('_'))) {
            case "ADD" -> value + literal;
            case "RSUB" -> literal - value;
            case "MUL" -> value * literal;
            case "DIV" -> value / literal;
            case "REM" -> value % literal;
            case "AND" -> value & literal;
            case "OR" -> value | literal;
            case "XOR" -> value ^ literal;
            case "SHL" -> value << literal;
            case "SHR" -> value >> literal;
            case "USHR" -> value >>> literal;
            default -> throw new AssertionError("Unspecified Java operation: " + name);
        };
    }
}
