package ghidra.pal.wbc;

public class PABundle {
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
}

