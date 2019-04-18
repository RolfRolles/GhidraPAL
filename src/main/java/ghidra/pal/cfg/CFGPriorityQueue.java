package ghidra.pal.cfg;

import java.util.Iterator;
import java.util.List;
import java.util.Comparator;
import java.util.HashMap;
import ghidra.graph.algo.DepthFirstSorter;
import ghidra.pal.util.NoDuplicatesPriorityQueue;

// Use for data flow analysis-style worklist algorithms. We order the vertices
// by reverse post-order for forward-style problems, or preorder for backwards
// problems.
public class CFGPriorityQueue<A,T> {
	class CFGVertexForwardComparator implements Comparator<CFGVertex<A,T>> {
		// Reverse post-order mapping for vertices.
		HashMap<A, Integer> VertexReversePostOrder;
		
		// Construct the ordering from the graph.
		public CFGVertexForwardComparator(CFG<A,T> g) {
			VertexReversePostOrder = new HashMap<A, Integer>();
			
			// Get the postorder list from Ghidra.
			List<CFGVertex<A, T>> jvpre = DepthFirstSorter.postOrder(g);
			
			// First vertex has largest number; descends subsequently.
			int i = jvpre.size() - 1;
			
			Iterator<CFGVertex<A,T>> it = jvpre.iterator();
			while(it.hasNext()) {
				CFGVertex<A,T> curr = it.next();
				// Printer.printf("Vertex %s: ordering number %d\n", curr.getLocator().toString(), i);
				VertexReversePostOrder.put(curr.getLocator(), i--);
			}
		}
		@Override
		public int compare(CFGVertex<A,T> lhs, CFGVertex<A,T> rhs) {
			return VertexReversePostOrder.get(lhs.getLocator()) - VertexReversePostOrder.get(rhs.getLocator());
		}
	}

	class CFGVertexBackwardComparator implements Comparator<CFGVertex<A,T>> {
		// Reverse post-order mapping for vertices.
		HashMap<A, Integer> VertexPreOrder;
		
		// Construct the ordering from the graph.
		public CFGVertexBackwardComparator(CFG<A,T> g) {
			VertexPreOrder = new HashMap<A, Integer>();
			
			// Get the preorder list from Ghidra.
			List<CFGVertex<A, T>> jvpre = DepthFirstSorter.preOrder(g);
			
			// First vertex has smallest number; ascends subsequently.
			int i = 0;
			
			Iterator<CFGVertex<A,T>> it = jvpre.iterator();
			while(it.hasNext()) {
				CFGVertex<A,T> curr = it.next();
				// Printer.printf("Vertex %s: ordering number %d\n", curr.getLocator().toString(), i);
				VertexPreOrder.put(curr.getLocator(), i--);
			}
		}
		@Override
		public int compare(CFGVertex<A,T> lhs, CFGVertex<A,T> rhs) {
			return VertexPreOrder.get(lhs.getLocator()) - VertexPreOrder.get(rhs.getLocator());
		}
	}
	// The priority queue itself.
	public NoDuplicatesPriorityQueue<CFGVertex<A,T>> PQ;
	
	// Constructor dictates forward or backward ordering.
	public CFGPriorityQueue(CFG<A,T> g, boolean forward) {
		Comparator<CFGVertex<A,T>> comp;
		if(forward)
			comp = new CFGVertexForwardComparator(g);
		else
			comp = new CFGVertexBackwardComparator(g);
		PQ = new NoDuplicatesPriorityQueue<CFGVertex<A,T>>(g.getVertexCount(), comp);
	}
}
