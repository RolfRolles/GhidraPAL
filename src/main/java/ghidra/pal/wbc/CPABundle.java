package ghidra.pal.wbc;

public class CPABundle extends PABundle {
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
	@Override
	public double compute(PABundle o) {
		CPABundle other = (CPABundle)o;
		return rho2(other);
	}
}

