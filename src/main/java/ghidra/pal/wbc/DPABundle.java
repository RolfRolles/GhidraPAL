package ghidra.pal.wbc;

public class DPABundle extends PABundle {
	public DPABundle(int nTraces) {
		super(nTraces);
	}
	public DPABundle(CryptoBitVector cbv) {
		super(cbv);
	}
	@Override
	public double compute(PABundle o) {
		DPABundle other = (DPABundle)o;
		int dpSet = this.bv.dotProduct(other.bv);
		int dpClear = this.bv.dotProductNotRhs(other.bv);
		return (double)(dpSet-dpClear)/((double)(this.bv.getLength()));		
	}
}
