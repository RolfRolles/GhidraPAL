package ghidra.pal.cfg;

// A class representing an edge that is yet to be added to a CFG.
// Edges are specified by location types and edge types.
public class CFGPendingEdge<A> {
	public A src;
	public A dst;
	public CFGEdgeType t;
	public CFGPendingEdge(A s, A d, CFGEdgeType ty) {
		src = s;
		dst = d;
		t = ty;
	}
}
