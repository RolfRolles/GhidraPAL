package ghidra.pal.wbc.des;

import ghidra.pal.util.Pair;
import ghidra.pal.wbc.PABundle;
import ghidra.pal.util.IntegerBitEnumerator;

public class DESGroupPowerAnalysis<B extends PABundle> extends DESPowerAnalysis<B> {
	public final int nGroup;
	DESGuess dg = new DESGuess();
	public DESGroupPowerAnalysis(int g) {
		super(4);
		nGroup = g;
	}
	protected Iterable<Pair<Integer,Integer>> createGuess(Long text, int sK) {
		return new IntegerBitEnumerator(dg.GenerateGuessForGroup(text,nGroup,sK),4);
	}
	
}
