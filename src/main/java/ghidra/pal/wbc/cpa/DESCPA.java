package ghidra.pal.wbc.cpa;

import java.util.List;

import ghidra.pal.wbc.CryptoBitVector;
import ghidra.pal.wbc.PABundle;
import ghidra.pal.wbc.PowerAnalysis;

class CPABundle extends PABundle {
	public long sum;
	public double denominator;
	public CPABundle(int nTraces) {
		super(nTraces);
	}
	public CPABundle(CryptoBitVector cbv) {
		super(cbv);
	}
	public void finalize() {
		sum = bv.hammingWeight();
		denominator = Math.sqrt((bv.getLength() - sum)*sum);		
	}
	public double rho2(CPABundle other) {
		long dotProduct = bv.dotProduct(other.bv);
		double numerator = (bv.getLength()*dotProduct)-(sum*other.sum);
		double denom = denominator*other.denominator;
		if(denom == 0.0)
			return denom;
		return numerator/denom;
	}
}

public class DESCPA extends PowerAnalysis<CPABundle> {
	public DESCPA() {}
	
	protected void analyzePoint(CPABundle pointBundle, CPABundle other, int nBit, int sK) {
		// Compute the Pearson correlation coefficient between the current
		// point and each CryptoBitVector for the current key/bit guess.
		recordMax(pointBundle.rho2(other), nBit, sK);
	}

	public void analyze(List<CryptoBitVector> points, List<Long> plaintexts, int group) {
		analyzeTrace(points, plaintexts, group, (x) -> new CPABundle(x));
	}
}

