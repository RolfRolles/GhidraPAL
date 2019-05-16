package ghidra.pal.wbc.aes;

import ghidra.pal.util.ByteArrayBitEnumerator;
import ghidra.pal.util.Pair;
import ghidra.pal.wbc.PABundle;

public class AESDecAllPowerAnalysis<B extends PABundle> extends AESPowerAnalysis<B>{
	public final int Alg; // e.g. AES.AES128
	AESGuess ag = new AESGuess();
	public AESDecAllPowerAnalysis(int alg) {
		super(128);
		Alg = alg;
	}
	protected Iterable<Pair<Integer,Integer>> createGuess(Byte[] text, int sK) {
		return new ByteArrayBitEnumerator(ag.DecryptionGenerateGuessForAllBytes(unboxBytes(text), sK, Alg));
	}
}
