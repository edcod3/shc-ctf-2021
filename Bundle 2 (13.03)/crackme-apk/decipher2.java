



public class Main {

    public static int[] x0 = { 
            121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 
            170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 
            218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 
            178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 
            228, 38, 37, 142, 242, 142, 133, 159, 142, 33 };

    public static int[] plsbeflagiwanttokms = {
        49, 198, 173, 239, 28, 94, 163, 63, 245, 74, 199, 32, 207, 179, 162, 215, 133, 0, 152, 143, 154, 194, 57, 202, 106, 84, 234
    };

    //public static String str = getStringFromCode(x0);

    public static void main (String[] args) {
        System.out.println("Flag: " + getStringFromCode(plsbeflagiwanttokms));
    }

    public static String getStringFromCode(int[] paramArrayOfInt) {
            byte[] arrayOfByte = new byte[paramArrayOfInt.length];
            for (byte b = 0; b < paramArrayOfInt.length; b++)
            arrayOfByte[b] = (byte)(paramArrayOfInt[b] ^ x0[b]); 
            return new String(arrayOfByte);
    }



}