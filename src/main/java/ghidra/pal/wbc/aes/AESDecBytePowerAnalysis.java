package ghidra.pal.wbc.aes;

import ghidra.pal.util.Pair;
import ghidra.pal.util.IntegerBitEnumerator;
import ghidra.pal.wbc.PABundle;

public class AESDecBytePowerAnalysis<B extends PABundle> extends AESPowerAnalysis<B> {
	public final int nByte;
	public final int Alg; // e.g. AES.AES128
	AESGuess ag = new AESGuess();
	public AESDecBytePowerAnalysis(int b, int alg) {
		super(8);
		nByte = b;
		Alg = alg;
	}
	protected Iterable<Pair<Integer,Integer>> createGuess(Byte[] text, int sK) {
		return new IntegerBitEnumerator(ag.DecryptionGenerateGuessForByte(unboxBytes(text), nByte, sK, Alg),8);
	}
}
