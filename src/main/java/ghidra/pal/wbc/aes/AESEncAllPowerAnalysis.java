package ghidra.pal.wbc.aes;

import ghidra.pal.util.ByteArrayBitEnumerator;
import ghidra.pal.util.Pair;
import ghidra.pal.wbc.PABundle;

public class AESEncAllPowerAnalysis<B extends PABundle> extends AESPowerAnalysis<B>{
	public final int Alg; // e.g. AES.AES128
	AESGuess ag = new AESGuess();
	public AESEncAllPowerAnalysis(int alg) {
		super(128);
		Alg = alg;
	}
	protected Iterable<Pair<Integer,Integer>> createGuess(Byte[] text, int sK) {
		return new ByteArrayBitEnumerator(ag.EncryptionGenerateGuessForAllBytes(unboxBytes(text), sK, Alg));
	}
}
