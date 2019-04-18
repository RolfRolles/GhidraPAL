package ghidra.pal.cfg;

import java.util.Collection;
import java.util.HashSet;

// For scenarios where you want an ordinary graph built, but want flow to stop
// upon reading one or more specified locations, use this class and pass the
// location(s) to the constructor.
public class CFGPointTerminator<A> implements CFGExplorationTerminator<A> {
	HashSet<A> TermPoints;
	
	public CFGPointTerminator(A singleLoc) {
		TermPoints = new HashSet<A>();
		TermPoints.add(singleLoc);
	}
	
	public CFGPointTerminator(Collection<A> locCollection) {
		TermPoints = new HashSet<A>();
		TermPoints.addAll(locCollection);		
	}
	
	public boolean shouldTerminateAt(A loc) {
		return TermPoints.contains(loc);
	}
}
