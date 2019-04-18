package ghidra.pal.cfg;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

// The state bundle for the CFG worklist algorithm. The CFGVertexDetailProvider
// objects modify this object to add new locations to the worklist, add pending
// edges, and specify that locations mark block heads.
public class CFGBuilderBundle<A> {
	public List<A> LocationWorkList;
	public List<CFGPendingEdge<A>> DeferredEdges;
	public HashSet<A> Heads;
	
	public CFGBuilderBundle() {
		LocationWorkList = new ArrayList<A>();
		DeferredEdges    = new ArrayList<CFGPendingEdge<A>>();
		Heads            = new HashSet<A>();
	}
}

