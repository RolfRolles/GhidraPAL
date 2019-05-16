package ghidra.pal.wbc.aes;

import ghidra.pal.wbc.PABundle;
import ghidra.pal.wbc.PowerAnalysis;

abstract public class AESPowerAnalysis<B extends PABundle> extends PowerAnalysis<B,Byte[]> {
	public AESPowerAnalysis(int b) {
		super(256,b);
	}
	// So far, the worst parts about Java have involved the interactions 
	// between generics, primitive types, and arrays. Guess I have to unbox
	// these things...
	protected byte[] unboxBytes(Byte[] text) {
		byte[] t = new byte[text.length];
		int j = 0;
		for(Byte b: text)
			t[j++] = b.byteValue();
		return t;
	}
}