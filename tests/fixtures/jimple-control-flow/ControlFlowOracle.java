public final class ControlFlowOracle {
    public static int branch(int value) {
        int result;
        if (value > 0) result = 11;
        else result = 23;
        return result;
    }

    public static int loop(int limit) {
        int sum = 0;
        for (int i = 0; i < limit; i++) sum += i;
        return sum;
    }

    public static int handler(int first, int second) {
        int state = 7;
        try {
            int quotient = 84 / first;
            state = 19;
            state = quotient / second;
        } catch (ArithmeticException exception) {
            // Each throw point observes the preceding completed assignment.
        }
        return state;
    }

    public static int nullZero(int selector) {
        if (selector == 0) {
            Object value = null;
            return value == null ? 31 : -1;
        }
        int value = 0;
        return value + 7;
    }

    public static float floatHigh(int selector) {
        float value = 1.5f;
        if (selector == 0) value = -2.25f;
        return value;
    }

    public static int alias(int value) {
        int first = value;
        int second = first;
        if (first > 0) first += second;
        else second = -first;
        return first + second;
    }

    public static long wide(int selector, long value) {
        return selector == 0 ? -value : value + 9L;
    }

    public static int catches(int divisor) {
        int state = 37;
        try {
            if (divisor < 0) throw (RuntimeException) null;
            state /= divisor;
        } catch (ArithmeticException ignored) {
            state = 41;
        } catch (NullPointerException exception) {
            state = 43;
        }
        return state;
    }

    public static int exceptionState(int value, int divisor) {
        int state = value;
        try {
            state /= divisor;
        } catch (ArithmeticException exception) {
        }
        return state;
    }

    public static int nested(int first, int second) {
        int state = 5;
        try {
            try {
                state = 84 / first;
            } catch (ArithmeticException exception) {
                state = 13;
            }
            state /= second;
        } catch (Throwable exception) {
            state += 29;
        }
        return state;
    }

    public static int nullJoin(int selector) {
        Object value = null;
        if (selector != 0) value = "present";
        return value == null ? 29 : 47;
    }

    public static int typeLoop(int limit) {
        int sum = 0;
        for (int i = 0; i < limit; i++) {
            Object value = "iteration";
            Object alias = value;
            int increment = 1;
            sum += increment;
        }
        return sum;
    }
}
