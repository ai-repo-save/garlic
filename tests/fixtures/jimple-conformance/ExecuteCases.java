import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/** Separate JVM process; observes return values and independently reads persisted public fields. */
public final class ExecuteCases {
    static String value(Object v) {
        if (v == null) return "null";
        if (v instanceof Float f) return "F:" + Integer.toUnsignedString(Float.floatToRawIntBits(f), 16);
        if (v instanceof Double d) return "D:" + Long.toUnsignedString(Double.doubleToRawLongBits(d), 16);
        if (v instanceof String s) {
            var result = new StringBuilder("S:");
            for (int i = 0; i < s.length(); i++) result.append(String.format("%04x", (int) s.charAt(i)));
            return result.toString();
        }
        if (v instanceof Class<?> c) return "C:" + c.getName();
        if (v instanceof Character c) return "C16:" + (int) c;
        if (v.getClass().isArray()) {
            var result = new ArrayList<String>();
            for (int i = 0; i < Array.getLength(v); i++) result.add(value(Array.get(v, i)));
            return v.getClass().getName() + result;
        }
        if (v instanceof Number || v instanceof Boolean) return v.getClass().getSimpleName() + ":" + v;
        throw new AssertionError("Unspecified observable value: " + v.getClass());
    }
    public static void main(String[] args) throws Exception {
        boolean failed = false;
        try (var input = new BufferedReader(new InputStreamReader(System.in))) {
            String line;
            while ((line = input.readLine()) != null) {
                var p = line.split("\t", -1);
                try {
                    Class<?> target = Class.forName(args[0].equals("oracle") ? "SourceOracle" : p[0]);
                    Object result;
                    try {
                        result = args[0].equals("oracle") && p[0].equals("LiteralArithmetic")
                            ? LiteralOracle.evaluate(p[1]) : target.getMethod(p[1]).invoke(null);
                    } catch (InvocationTargetException programException) {
                        programException.getCause().printStackTrace(System.err);
                        System.out.println(p[0] + "." + p[1] + "\tTHROW:" + programException.getCause().getClass().getName());
                        continue;
                    }
                    String state = p[2].equals("-") ? "" : "|" + p[2] + "=" + value(target.getField(p[2]).get(null));
                    System.out.println(p[0] + "." + p[1] + "\t" + value(result) + state);
                } catch (ReflectiveOperationException | LinkageError failure) {
                    failed = true;
                    failure.printStackTrace(System.err);
                    System.out.println(p[0] + "." + p[1] + "\tERROR:" + failure);
                }
            }
        }
        if (failed) throw new AssertionError("Execution failures; see per-case stack traces");
    }
}
