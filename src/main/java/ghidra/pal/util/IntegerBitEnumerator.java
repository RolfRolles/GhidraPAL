package ghidra.pal.util;

import java.util.Iterator;

public class IntegerBitEnumerator implements Iterable<Pair<Integer,Integer>> {
	final long source;
	final int nBits;
	public IntegerBitEnumerator(int s, int b) {
		source = s;
		nBits = b;
	}
	public IntegerBitEnumerator(long s, int b) {
		source = s;
		nBits = b;
	}
	public Iterator<Pair<Integer,Integer>> iterator() {
		return new IntegerBitEnumeratorIterator(source,nBits);
	}
	class IntegerBitEnumeratorIterator implements Iterator<Pair<Integer,Integer>> {
		final long isource;
		final int inBits;
		protected int idx;
		public IntegerBitEnumeratorIterator(int s, int b) {
			isource = s;
			inBits = b;
			idx = 0;
		}
		public IntegerBitEnumeratorIterator(long s, int b) {
			isource = s;
			inBits = b;
			idx = 0;
		}
		public boolean hasNext() {
			return idx != inBits;
		}
		public Pair<Integer, Integer> next() {
			return new Pair<Integer,Integer>(idx,(int)(isource>>idx++)&1);
		}
		public void remove() {
			throw new UnsupportedOperationException();
		}	
	}
}
