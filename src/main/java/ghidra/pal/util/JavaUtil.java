package ghidra.pal.util;

public final class JavaUtil {
	// What the hell is this? Java was returning true for "cval.y!=res.x"
	// when the values were identical. StackExchange suggested it was an
	// int/long issue. I don't like that very much.
	static public boolean CompareLongs(long l1, long l2)
	{
		return new Long(l1).equals(new Long(l2));
	}
}	
