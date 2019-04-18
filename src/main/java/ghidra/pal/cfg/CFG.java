package ghidra.pal.cfg;

import java.lang.Iterable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import ghidra.graph.GDirectedGraph;
import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;
import ghidra.program.model.listing.Program;

// This class implements the GDirectedGraph interface as defined by Ghidra, 
// using the CFGVertex and CFGEdge classes. By implementing this interface, we
// get access to the existing graph utility methods inside of Ghidra. Also, 
// hopefully in the future, the Ghidra developers will include a graph drawing
// component that works upon GDirectedGraph objects, at which point we will be
// able to freely (or cheaply) make use of that functionality, rather than 
// having to adapt or rewrite this component.
//
// And, anyway, Ghidra's GDirectedGraph interface is pretty good. I see no 
// reason not to use it.
//
// I haven't bothered to comment most of this because the methods are already
// documented in GDirectedGraph.java, and there are no surprises in the 
// implementation. I have marked the methods that are not strictly required
// by the interface.
public class CFG<A,T> implements GDirectedGraph<CFGVertex<A,T>, CFGEdge<A,T>> {
	A BeginAddr;
	HashMap<A, CFGVertex<A,T>> AddressToVertex;
	HashMap<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>> EdgesBySource;
	HashMap<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>> EdgesByDest;
	
	public CFG(A eaBeg) {
		BeginAddr = eaBeg;
		AddressToVertex = new HashMap<A, CFGVertex<A,T>>();
		EdgesBySource = new HashMap<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>>();
		EdgesByDest   = new HashMap<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>>();
	}
	
	// Non-interface method
	public A getBeginAddr() {
		return BeginAddr;
	}
	
	// Non-interface method
	public CFGVertex<A,T> lookupVertex(A ea) {
		if(AddressToVertex.containsKey(ea))
			return AddressToVertex.get(ea);
		return null;
	}
	
	// Non-interface method
	public boolean hasVertex(A ea) {
		return lookupVertex(ea) != null;
	}
	
	// Non-interface method
	private ArrayList<CFGEdge<A,T>> ensureSourceMapEntry(CFGVertex<A,T> v) {
		if(EdgesBySource.containsKey(v))
			return EdgesBySource.get(v);
		ArrayList<CFGEdge<A,T>> srcList = new ArrayList<CFGEdge<A,T>>();
		EdgesBySource.put(v,srcList);
		return srcList;
	}
		
	// Non-interface method
	private ArrayList<CFGEdge<A,T>> ensureDestMapEntry(CFGVertex<A,T> v) {
		if(EdgesByDest.containsKey(v))
			return EdgesByDest.get(v);
		ArrayList<CFGEdge<A,T>> dstList = new ArrayList<CFGEdge<A,T>>();
		EdgesByDest.put(v,dstList);
		return dstList;
	}
	
	// Non-interface method. Get all vertices with no incoming edges.
	public ArrayList<CFGVertex<A,T>> getInitialVertices() {
		ArrayList<CFGVertex<A,T>> initialList = new ArrayList<CFGVertex<A,T>>();
		Collection<CFGVertex<A,T>> allVertices = getVertices();
		Iterator<CFGVertex<A,T>> it = allVertices.iterator();
		while(it.hasNext()) {
			CFGVertex<A,T> v = it.next();
			ArrayList<CFGEdge<A,T>> inEdges = ensureDestMapEntry(v);
			//Printer.printf("getInitialVertices(%s): had %d incoming vertices\n", v.toString(), inEdges.size());
			if(inEdges.isEmpty()) 
				initialList.add(v);
		}
		return initialList;
	}
	
	// Non-interface method. Get all vertices with no outgoing edges.
	public ArrayList<CFGVertex<A,T>> getTerminalVertices() {
		ArrayList<CFGVertex<A,T>> terminalList = new ArrayList<CFGVertex<A,T>>();
		Collection<CFGVertex<A,T>> allVertices = getVertices();
		Iterator<CFGVertex<A,T>> it = allVertices.iterator();
		while(it.hasNext()) {
			CFGVertex<A,T> v = it.next();
			ArrayList<CFGEdge<A,T>> outEdges = ensureSourceMapEntry(v);
			if(outEdges.isEmpty())
				terminalList.add(v);
		}
		return terminalList;
	}

	public boolean addVertex(CFGVertex<A,T> v) {
		if(EdgesBySource.containsKey(v) || EdgesByDest.containsKey(v))
			return false;
		ensureSourceMapEntry(v);
		ensureDestMapEntry(v);
		AddressToVertex.put(v.getLocator(), v);
		return true;
	}

	public boolean removeVertex(CFGVertex<A,T> v) {
		boolean bRet = false;
		if(EdgesBySource.containsKey(v)) {
			EdgesBySource.remove(v);
			bRet = true;
		}
		if(EdgesByDest.containsKey(v)) {
			EdgesByDest.remove(v);
			bRet = true;
		}
		AddressToVertex.remove(v.getLocator());
		return bRet;
	}
	public void removeVertices(Iterable<CFGVertex<A,T>> vertices) {
		Iterator<CFGVertex<A,T>> it = vertices.iterator();
		while(it.hasNext()) {
			CFGVertex<A,T> curr = it.next();
			removeVertex(curr);
		}
	}
	public void addEdge(CFGEdge<A,T> e) {
		ensureSourceMapEntry(e.getStart()).add(e);
		ensureDestMapEntry(e.getEnd()).add(e);
	}
	public boolean removeEdge(CFGEdge<A,T> e) {
		boolean bRet = false;
		bRet |= ensureSourceMapEntry(e.getStart()).remove(e);
		bRet |= ensureDestMapEntry(e.getEnd()).remove(e);
		return bRet;
	}
	public void removeEdges(Iterable<CFGEdge<A,T>> edges) {
		Iterator<CFGEdge<A,T>> it = edges.iterator();
		while(it.hasNext())
			removeEdge(it.next());
	}
	public CFGEdge<A,T> findEdge(CFGVertex<A,T> start, CFGVertex<A,T> end) {
		ArrayList<CFGEdge<A,T>> srcEdges = ensureSourceMapEntry(start);
		Iterator<CFGEdge<A,T>> it = srcEdges.iterator();
		while(it.hasNext()) {
			CFGEdge<A,T> e = it.next();
			if(e.getEnd() == end)
				return e;
		}
		return null;
	}
	public Collection<CFGVertex<A,T>> getVertices() {
		return EdgesBySource.keySet();
	}
	public Collection<CFGEdge<A,T>> getEdges() {
		ArrayList<CFGEdge<A,T>> outList = new ArrayList<CFGEdge<A,T>>();
		for(HashMap.Entry<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>> entry : EdgesBySource.entrySet())
			outList.addAll(entry.getValue());
		return outList;
	}
	public boolean containsVertex(CFGVertex<A,T> v) {
		return EdgesBySource.containsKey(v);
	}
	public boolean containsEdge(CFGEdge<A,T> e) {
		CFGVertex<A,T> src = e.getStart();
		if(!EdgesBySource.containsKey(src))
			return false;
		ArrayList<CFGEdge<A,T>> list = EdgesBySource.get(src);
		return list.contains(e);
	}
	public boolean containsEdge(CFGVertex<A,T> from, CFGVertex<A,T> to) {
		if(!EdgesBySource.containsKey(from))
			return false;
		Iterator<CFGEdge<A,T>> it = EdgesBySource.get(from).iterator();
		while(it.hasNext()) {
			if(it.next().getEnd() == to)
				return true;
		}
		return false;
	}
	public boolean isEmpty() {
		return EdgesBySource.isEmpty();
	}
	public int getVertexCount() {
		return EdgesBySource.size();
	}
	public int getEdgeCount() {
		return getEdges().size();
	}
	@SuppressWarnings("unchecked")
	public Collection<CFGEdge<A,T>> getInEdges(CFGVertex<A,T> v) {
		return (Collection<CFGEdge<A,T>>)ensureDestMapEntry(v).clone();
	}
	@SuppressWarnings("unchecked")
	public Collection<CFGEdge<A,T>> getOutEdges(CFGVertex<A,T> v) {
		return (Collection<CFGEdge<A,T>>)ensureSourceMapEntry(v).clone();
	}
	@SuppressWarnings("unchecked")
	public CFG<A,T> copy() {
		CFG<A,T> n = new CFG<A,T>(BeginAddr);
		n.AddressToVertex = (HashMap<A, CFGVertex<A,T>>)this.AddressToVertex.clone();
		n.EdgesBySource   = (HashMap<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>>)this.EdgesBySource.clone();
		n.EdgesByDest     = (HashMap<CFGVertex<A,T>, ArrayList<CFGEdge<A,T>>>)this.EdgesByDest.clone();
		return n;
	}
	public CFG<A,T> emptyCopy() {
		return new CFG<A,T>(BeginAddr);
	}
	
	// Non-interface method
	public void PrintGraph(Program currentProgram) throws Exception {
		Collection<CFGVertex<A,T>> vertices = getVertices();
		Iterator<CFGVertex<A,T>> it = vertices.iterator();
		while(it.hasNext()) {
			CFGVertex<A,T> v = it.next();
			Printer.printf("%s: block head\n", v.getLocator());
			List<Pair<A,T>> entities = v.getEntities();
			if(entities != null) {
				Iterator<Pair<A,T>> adit = entities.iterator();
				while(adit.hasNext()) {
					Pair<A,T> p = adit.next(); 
					Printer.printf("\t%s %s\n", p.x.toString(), p.y.toString());
				}
			}
		}
		Collection<CFGEdge<A,T>> edges = getEdges();
		Iterator<CFGEdge<A,T>> eit = edges.iterator();
		while(eit.hasNext()) {
			CFGEdge<A,T> edge = eit.next();
			CFGVertex<A,T> start = edge.getStart();
			CFGVertex<A,T> end = edge.getEnd();
			Printer.printf("\t%s->%s (%s)\n", start.getLocator(), end.getLocator(), edge.getEdgeType());
		}
	}
}
