package ghidra.pal.wbc;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import ghidra.pal.util.Pair;

public class TraceAggregator {
	static int allSameLength(List<ArrayList<Byte>> traces) {
		int length = -1;
		for(ArrayList<Byte> trace : traces) {
			if(length == -1)
				length = trace.size();
			else if(length != trace.size())
				return -1;
		}
		return length;
	}
	
	static public List<CryptoBitVector> aggregate(List<ArrayList<Byte>> traces) {
		int traceLen = allSameLength(traces);
		if(traceLen == -1)
			throw new IllegalArgumentException("TraceAggregator::Aggregate(): length mismatch");
		List<Iterator<Byte>> itList = traces.stream().map((x) -> x.iterator()).collect(Collectors.toList());
		Iterator<Byte> firstIt = itList.get(0);		
		List<CryptoBitVector> results = new ArrayList<CryptoBitVector>();
		int nTraces = traces.size();
		while(firstIt.hasNext()) {
			Byte[] curVals = itList.stream().map((i) -> i.next()).toArray(Byte[]::new);
			for(int j = 0; j < 8; j++) {
				CryptoBitVector dbv = new CryptoBitVector(nTraces);
				boolean asgTrue = false, asgFalse = false;
				for(int i = 0; i < curVals.length; i++) {
					int bit = (curVals[i] >> j) & 1;
					boolean wasOne = bit == 1;
					if(wasOne)
						asgTrue = true;
					else
						asgFalse = true;
					dbv.assignBit(i, wasOne);
				}
				if(asgTrue && asgFalse)
					results.add(dbv);
			}
		}
		return results;
	}
}
