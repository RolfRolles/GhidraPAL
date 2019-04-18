package ghidra.pal.cfg;

import java.util.List;
import ghidra.graph.GVertex;
import ghidra.pal.util.Pair;

// CFGVertex has a straightfoward implementation.
public class CFGVertex<A,T> implements GVertex {
	A Locator;
	List<Pair<A,T>> Entities;
	public CFGVertex(A Location, List<Pair<A,T>> Ents) {
		Locator  = Location;
		Entities = Ents;
	}
	public int hashCode() {
		return Locator.hashCode();
	}
	public A getLocator() {
		return Locator;
	}
	public List<Pair<A,T>> getEntities() {
		return Entities;
	}

	public void setEntities(List<Pair<A,T>> ents) {
		Entities = ents;
	}
}
