package regression;

public class Guard<T> {
    public Guard() {}

    public static class Child extends Guard<String> {
        public Child(boolean first, boolean second, boolean third) {
            if (first || second || third) {
                throw new IllegalArgumentException("rejected");
            }
        }
    }

    public static void any(boolean first, boolean second, boolean third) {
        if (first || second || third) {
            throw new IllegalArgumentException("rejected");
        }
    }

    public static void all(boolean first, boolean second, boolean third) {
        if (first && second && third) {
            throw new IllegalArgumentException("rejected");
        }
    }

    public static void mixed(boolean first, boolean second, boolean third) {
        if (first || !second || third) {
            throw new IllegalArgumentException("rejected");
        }
    }

    public static void calls(String value, String license) {
        if (value.isEmpty() || "0".equals(value) || license.isEmpty()) {
            throw new IllegalArgumentException("rejected");
        }
    }
}
