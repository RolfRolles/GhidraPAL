package ghidra.pal.wbc;

abstract public class PABundle {
	public final CryptoBitVector bv;
	public PABundle(int nTraces) {
		bv = new CryptoBitVector(nTraces);
	}
	public PABundle(CryptoBitVector cbv) {
		bv = cbv;
		finalize();
	}
	public void finalize() {

	}
	abstract public double compute(PABundle other);
}

