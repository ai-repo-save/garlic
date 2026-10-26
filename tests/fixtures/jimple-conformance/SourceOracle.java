/** Java/JVM oracle: no dependency on dexlib2, Soot, Garlic, or the fixture generator. */
public final class SourceOracle {
    public static int smallMin() { return -8; }
    public static int smallMax() { return 7; }
    public static int shortMin() { return Short.MIN_VALUE; }
    public static int shortMax() { return Short.MAX_VALUE; }
    public static int intMin() { return Integer.MIN_VALUE; }
    public static int intMax() { return Integer.MAX_VALUE; }
    public static int highMin() { return Integer.MIN_VALUE; }
    public static int highMax() { return 2147418112; }
    public static long wideShortMin() { return Short.MIN_VALUE; }
    public static long wideShortMax() { return Short.MAX_VALUE; }
    public static long wideIntMin() { return Integer.MIN_VALUE; }
    public static long wideIntMax() { return Integer.MAX_VALUE; }
    public static long wideHighMin() { return Long.MIN_VALUE; }
    public static long wideHighMax() { return 9223090561878065152L; }
    public static long longMin() { return Long.MIN_VALUE; }
    public static long longMax() { return Long.MAX_VALUE; }
    public static long longPattern() { return 1311768467463790320L; }
    public static float floatLarge() { return 1.0e10f; }
    public static float floatSmall() { return 1.0e-10f; }
    public static float floatNegativeZero() { return -0.0f; }
    public static float floatSubnormal() { return Float.MIN_VALUE; }
    public static float floatNan() { return Float.NaN; }
    public static float floatNanBits() { return Float.intBitsToFloat(0x7fc12345); }
    public static double doubleNanBits() { return Double.longBitsToDouble(0x7ff8123456789abcL); }
    public static float floatInfinity() { return Float.POSITIVE_INFINITY; }
    public static float floatNegativeInfinity() { return Float.NEGATIVE_INFINITY; }
    public static float floatHigh() { return 9999220736.0f; }
    public static double doubleLarge() { return 1.0e20; }
    public static double doubleSmall() { return 1.0e-10; }
    public static double doubleNegativeZero() { return -0.0; }
    public static double doubleSubnormal() { return Double.MIN_VALUE; }
    public static double doubleNan() { return Double.NaN; }
    public static double doubleInfinity() { return Double.POSITIVE_INFINITY; }
    public static double doubleNegativeInfinity() { return Double.NEGATIVE_INFINITY; }
    public static String emptyString() { return ""; }
    public static String escapedString() { return "q\"\\\n\t\r\b\f"; }
    public static String utf16String() { return "中文\ud83d\ude00"; }
    public static String nulString() { return "a\u0000b"; }
    public static String jumboString() { return "jumbo"; }
    public static Class<?> objectClass() { return String.class; }
    public static Class<?> arrayClass() { return int[].class; }
    public static Class<?> primitiveClass() { return int.class; }
    private static int packed(int key) {
        return switch (key) { case 0 -> 41; case 1 -> 59; default -> 31; };
    }
    private static int sparse(int key) {
        return switch (key) { case -1 -> 41; case 1 -> 59; default -> 31; };
    }
    public static int packedValueNeg() { return packed(-1); }
    public static int packedValue0() { return packed(0); }
    public static int packedValue1() { return packed(1); }
    public static int packedValue2() { return packed(2); }
    public static int sparseValueNeg() { return sparse(-1); }
    public static int sparseValue0() { return sparse(0); }
    public static int sparseValue1() { return sparse(1); }
    public static int sparseValue2() { return sparse(2); }
    public static int packedEmptyNeg() { return 31; }
    public static int packedEmpty0() { return 31; }
    public static int packedEmpty1() { return 31; }
    public static int packedEmpty2() { return 31; }
    public static int sparseEmptyNeg() { return 31; }
    public static int sparseEmpty0() { return 31; }
    public static int sparseEmpty1() { return 31; }
    public static int sparseEmpty2() { return 31; }
    public static byte[] data1Values() { return new byte[]{-1, 37}; }
    public static short[] data2Values() { return new short[]{-1, 37}; }
    public static int[] data4Values() { return new int[]{-1, 37}; }
    public static long[] data8Values() { return new long[]{-1, 1311768467463790320L}; }
    public static byte[] data1Empty() { return new byte[0]; }
    public static short[] data2Empty() { return new short[0]; }
    public static int[] data4Empty() { return new int[0]; }
    public static long[] data8Empty() { return new long[0]; }
    public static int sharedArray() { int[] a = {17, -29}, b = {17, -29}; return a[1] + b[1]; }
    public static int arrayI() { int[] a = new int[1]; a[0] = 1234567; return a[0]; }
    public static long arrayJ() { long[] a = new long[1]; a[0] = 1311768467463790320L; return a[0]; }
    public static float arrayF() { float[] a = new float[1]; a[0] = 1.5f; return a[0]; }
    public static double arrayD() { double[] a = new double[1]; a[0] = 2.5; return a[0]; }
    public static boolean arrayZ() { boolean[] a = new boolean[1]; a[0] = true; return a[0]; }
    public static byte arrayB() { byte[] a = new byte[1]; a[0] = -113; return a[0]; }
    public static char arrayC() { char[] a = new char[1]; a[0] = '\uffee'; return a[0]; }
    public static short arrayS() { short[] a = new short[1]; a[0] = -31000; return a[0]; }
    public static String arrayObject() { String[] a = new String[1]; a[0] = "state-value"; return a[0]; }
    public static int arrayLength() { return new int[3].length; }
    public static int stateI;
    public static long stateJ;
    public static float stateF;
    public static double stateD;
    public static boolean stateZ;
    public static byte stateB;
    public static char stateC;
    public static short stateS;
    public static String stateObject;
    private static final class Holder {
        int i; long j; float f; double d; boolean z; byte b; char c; short s; String object;
    }
    public static int fieldI() { var h = new Holder(); h.i = 1234567; stateI = h.i; return stateI; }
    public static long fieldJ() { var h = new Holder(); h.j = 1311768467463790320L; stateJ = h.j; return stateJ; }
    public static float fieldF() { var h = new Holder(); h.f = 1.5f; stateF = h.f; return stateF; }
    public static double fieldD() { var h = new Holder(); h.d = 2.5; stateD = h.d; return stateD; }
    public static boolean fieldZ() { var h = new Holder(); h.z = true; stateZ = h.z; return stateZ; }
    public static byte fieldB() { var h = new Holder(); h.b = -113; stateB = h.b; return stateB; }
    public static char fieldC() { var h = new Holder(); h.c = '\uffee'; stateC = h.c; return stateC; }
    public static short fieldS() { var h = new Holder(); h.s = -31000; stateS = h.s; return stateS; }
    public static String fieldObject() { var h = new Holder(); h.object = "state-value"; stateObject = h.object; return stateObject; }
    public static long invokeWide() { long a = 1311768467463790320L; double b = 2.5; return a + (long) b; }
    public static int callState;
    public static int invokeResults() { Object value = java.util.Objects.requireNonNull("invoke-result"); callState = 101; return ((String) value).length(); }
    public static int monitorCast() { Object value = "cast"; String cast = (String) value; synchronized (value) { return cast instanceof String ? 1 : 0; } }
    public static int monitorState() { Object value = "monitor-state"; boolean inside; synchronized (value) { inside = Thread.holdsLock(value); } return (inside ? 1 : 0) - (Thread.holdsLock(value) ? 1 : 0); }
    public static Object castFailure() { Object value = "bad-cast"; return (Integer) value; }
    public static int[] nestedArray() { int[][] a = new int[1][]; a[0] = new int[1]; a[0][0] = -4095; Object result = a[0]; return (int[]) result; }
    public static int classInitialization() { return Initialized.value; }
    private static class Initialized { static int value; static { value = 73; } }
    public static int[] filledArray() { return new int[]{-1, 7}; }
    public static int registerMoves() { return -123; }
    public static long registerWide() { return -32768L; }
    public static String registerObject() { return "registers"; }
}
