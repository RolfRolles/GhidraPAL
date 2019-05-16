package ghidra.pal.wbc.des;

import ghidra.pal.util.IntegerBitEnumerator;
import ghidra.pal.util.Pair;
import ghidra.pal.wbc.PABundle;

public class DESAllPowerAnalysis<B extends PABundle> extends DESPowerAnalysis<B> {
	DESGuess dg = new DESGuess();
	public DESAllPowerAnalysis() {
		super(32);
	}
	protected Iterable<Pair<Integer,Integer>> createGuess(Long text, int sK) {
		return new IntegerBitEnumerator(dg.GenerateGuessForAllGroups(text,sK),32);
	}
}
