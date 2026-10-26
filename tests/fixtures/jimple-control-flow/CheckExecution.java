import java.io.BufferedReader;
import java.io.InputStreamReader;

/** Executes the same explicit cases in separate JVMs for oracle and generated classes. */
public final class CheckExecution {
    public static void main(String[] args) throws Exception {
        Class<?> target = Class.forName(args[0]);
        try (var reader = new BufferedReader(new InputStreamReader(System.in))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split("\t", -1);
                String[] descriptors = fields[2].split(",");
                String[] values = fields[3].split(",");
                Class<?>[] types = new Class<?>[descriptors.length];
                Object[] arguments = new Object[descriptors.length];
                for (int i = 0; i < descriptors.length; i++) {
                    if (descriptors[i].equals("I")) {
                        types[i] = int.class;
                        arguments[i] = Integer.valueOf(values[i]);
                    } else if (descriptors[i].equals("J")) {
                        types[i] = long.class;
                        arguments[i] = Long.valueOf(values[i]);
                    } else throw new AssertionError("Unknown input type: " + descriptors[i]);
                }
                Object result = target.getMethod(fields[1], types).invoke(null, arguments);
                String actual;
                if (result instanceof Float value)
                    actual = "F:" + Integer.toUnsignedString(Float.floatToRawIntBits(value), 16);
                else if (result instanceof Long value) actual = "J:" + value;
                else if (result instanceof Integer value) actual = "I:" + value;
                else throw new AssertionError("Unexpected result: " + result);
                System.out.println(fields[0] + "\t" + actual);
            }
        }
    }
}
