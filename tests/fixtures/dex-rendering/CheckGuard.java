package regression;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;

public class CheckGuard {
    private static void check(Method method, boolean reject, Object... args) throws Exception {
        boolean rejected = false;
        try {
            method.invoke(null, args);
        } catch (InvocationTargetException error) {
            if (!(error.getCause() instanceof IllegalArgumentException)) throw error;
            rejected = true;
        }
        if (rejected != reject) throw new AssertionError(method.getName() + " wrong gate");
    }

    public static void main(String[] args) throws Exception {
        Method any = Guard.class.getMethod("any", boolean.class, boolean.class, boolean.class);
        Method all = Guard.class.getMethod("all", boolean.class, boolean.class, boolean.class);
        Method mixed = Guard.class.getMethod("mixed", boolean.class, boolean.class, boolean.class);
        for (int bits = 0; bits < 8; bits++) {
            boolean a = (bits & 1) != 0, b = (bits & 2) != 0, c = (bits & 4) != 0;
            check(any, a || b || c, a, b, c);
            check(all, a && b && c, a, b, c);
            check(mixed, a || !b || c, a, b, c);
        }
        Method calls = Guard.class.getMethod("calls", String.class, String.class);
        for (String value : new String[] {"", "0", "123"}) {
            for (String license : new String[] {"", "license"}) {
                check(calls, value.isEmpty() || "0".equals(value) || license.isEmpty(), value, license);
            }
        }
        Class<?> child = Guard.class.getDeclaredClasses()[0];
        if (child.getSuperclass() != Guard.class) throw new AssertionError("lost superclass");
        ParameterizedType parent = (ParameterizedType) child.getGenericSuperclass();
        if (parent.getActualTypeArguments()[0] != String.class) {
            throw new AssertionError("lost superclass type argument");
        }
        System.out.println("24 boolean gates, 6 call gates, generic superclass: passed");
    }
}
