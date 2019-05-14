package ghidra.pal.util;

public final class JavaUtil {
	// What the hell is this? Java was returning true for "cval.y!=res.x"
	// when the values were identical. StackExchange suggested it was an
	// int/long issue. I don't like that very much.
	static public boolean CompareLongs(long l1, long l2)
	{
		return new Long(l1).equals(new Long(l2));
	}
	public static byte[] hexStringToByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int index = i * 2;
			int v = Integer.parseInt(s.substring(index, index + 2), 16);
			b[i] = (byte) v;
		}
		return b;
	}
}	
