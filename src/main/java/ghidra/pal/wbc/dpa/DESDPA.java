package ghidra.pal.wbc.dpa;

import java.util.List;

import ghidra.pal.wbc.CryptoBitVector;
import ghidra.pal.wbc.PABundle;
import ghidra.pal.wbc.PowerAnalysis;

class DPABundle extends PABundle {
	public DPABundle(int nTraces) {
		super(nTraces);
	}
	public DPABundle(CryptoBitVector cbv) {
		super(cbv);
	}	
}

public class DESDPA extends PowerAnalysis<DPABundle> {
	public DESDPA() {}
	
	protected void analyzePoint(DPABundle pointBundle, DPABundle other, int nBit, int sK) {
		int dpSet = pointBundle.bv.dotProduct(other.bv);
		int dpClear = pointBundle.bv.dotProductNotRhs(other.bv);
		recordMax( (double)(dpSet-dpClear)/((double)(pointBundle.bv.getLength())), nBit, sK);
	}

	public void analyze(List<CryptoBitVector> points, List<Long> plaintexts, int group) {
		int nTraces = plaintexts.size();
		analyzeTrace(points, plaintexts, group, (x) -> new DPABundle(x));
	}
}
	