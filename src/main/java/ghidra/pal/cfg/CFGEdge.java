package ghidra.pal.cfg;

import ghidra.graph.DefaultGEdge;

// Straightforward implementation of DefaultGEdge.
public class CFGEdge<A,T> extends DefaultGEdge<CFGVertex<A,T>> {
	CFGEdgeType EdgeType;
	public CFGEdge(CFGVertex<A,T> start, CFGVertex<A,T> end, CFGEdgeType t) {
		super(start,end);
		EdgeType = t;
	}
	public CFGEdgeType getEdgeType() {
		return EdgeType;
	}
}

