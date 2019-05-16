package ghidra.pal.util;

import java.util.Iterator;

public class ByteArrayBitEnumerator implements Iterable<Pair<Integer,Integer>> {
	final byte[] byteArr;
	public ByteArrayBitEnumerator(byte[] arr) {
		byteArr = arr;
	}
	public Iterator<Pair<Integer,Integer>> iterator() {
		return new ByteArrayBitEnumeratorIterator(byteArr);
	}
	class ByteArrayBitEnumeratorIterator implements Iterator<Pair<Integer,Integer>> {
		final byte[] source;
		protected int byteIdx;
		protected int bitIdx;
		public ByteArrayBitEnumeratorIterator(byte[] arr) {
			source = arr;
			byteIdx = 0;
			bitIdx = 0;
		}
		public boolean hasNext() {
			return byteIdx != source.length;
		}
		public Pair<Integer, Integer> next() {
			int bit = (source[byteIdx] >> bitIdx) & 1;
			int pos = byteIdx*8+bitIdx;
			if(++bitIdx == 8) {
				bitIdx = 0;
				byteIdx += 1;
			}
			return new Pair<Integer,Integer>(pos,bit);
		}
		public void remove() {
			throw new UnsupportedOperationException();
		}	
	}
}
