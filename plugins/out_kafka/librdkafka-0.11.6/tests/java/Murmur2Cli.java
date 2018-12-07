import org.apache.kafka.common.utils.Utils;

public class Murmur2Cli {
    public static int toPositive(int number) {
        return number & 0x7fffffff;
    }
    public static void main (String[] args) throws Exception {
        for (String key : args) {
            System.out.println(String.format("%s\t0x%08x", key,
                                             toPositive(Utils.murmur2(key.getBytes()))));
        }
        /* If no args, print hash for empty string */
        if (args.length == 0)
            System.out.println(String.format("%s\t0x%08x", "",
                                             toPositive(Utils.murmur2("".getBytes()))));
    }
}
