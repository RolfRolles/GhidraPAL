package ghidra.pal.cfg;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashSet;
import java.util.Collection;
import java.util.List;

import ghidra.pal.util.Printer;
import ghidra.pal.util.Pair;


public class CFGBuilder<A,T> {
	CFGBuilderBundle<A> State;
	CFGVertexDetailProvider<A,T> VertexDetailProvider;
	CFGExplorationTerminator<A> Terminator;
	
	// detailProvider: analyzes entities of type T (Instruction, 
	//   PseudoInstruction, PcodeOp, PcodeOpRaw) found at location type A
	//   (Address, Pair<Address,Integer> for PcodeOp/PcodeOpRaw).
	// terminator: tells whether to continue following flow at location type A
	public CFGBuilder(CFGVertexDetailProvider<A,T> detailProvider, CFGExplorationTerminator<A> terminator) {
		VertexDetailProvider = detailProvider;
		Terminator = terminator;
		State = new CFGBuilderBundle<A>();
	}
	
	// Invoke the termination checker upon the specified address. For the 
	// ordinary case, there will be no terminator, so this will always return 
	// false.
	boolean shouldTerminateAt(A loc) {
		return Terminator != null && Terminator.shouldTerminateAt(loc);
	}
	
	// We create edges after all vertices have been discovered. This simplifies
	// the bookkeeping.
	void ApplyDeferredEdges(CFG<A,T> graph, List<CFGPendingEdge<A>> DeferredEdges) {
		Iterator<CFGPendingEdge<A>> it = DeferredEdges.iterator();
		
		// Vertices might be missing from the graph due to the search having 
		// been terminated by the function above. Only add edges to present 
		// pairs of vertices.
		while(it.hasNext()) {
			CFGPendingEdge<A> pe = it.next();
			if(shouldTerminateAt(pe.dst))
				continue;
			CFGVertex<A,T> dst = graph.lookupVertex(pe.dst);
			// This should only happen if the shouldTermiateAt() check above 
			// failed, though it would have contiued in that case, thus, be 
			// noisy about it.
			if(dst == null) {
				Printer.printf("%s: graph did not contain destination vertex (source %s)\n", pe.dst.toString(), pe.src.toString());
				continue;
			}
			// This shouldn't happen -- terminated addresses shouldn't be the
			// source of edges, since if they were terminated, their outgoing
			// flows should not have been processed, thus, be noisy.
			if(shouldTerminateAt(pe.src)) {
				Printer.printf("%s: graph did not contain source vertex (dest %s)\n", pe.src.toString(), pe.dst.toString());
				continue;
			}
			CFGVertex<A,T> src = graph.lookupVertex(pe.src);
			// This shouldn't happen, so be noisy about it.
			if(src == null) {
				Printer.printf("%s: graph did not contain source vertex (dest %s)\n", pe.src.toString(), pe.dst.toString());
				continue;
			}
			graph.addEdge(new CFGEdge<A,T>(src, dst, pe.t));
		}
	}
	
	// A "singleton" CFG is one in which each vertex corresponds to one entity
	// (Instruction, PcodeOp, etc.). That's opposed to a "merged" CFG, in which
	// basic blocks contain lists of entities.
	public CFG<A,T> CreateSingletonCFG(A handlerEa) throws Exception
	{
		CFG<A,T> graph = new CFG<A,T>(handlerEa);

		// Algorithm state:
		// * Location worklist
		// * Set of heads
		// * Edges to be applied
		State = new CFGBuilderBundle<A>();
		State.Heads.add(handlerEa);

		// Addresses to skip because disassembly failed 
		HashSet<A> Skip = new HashSet<A>();

		// Bootstrap worklist algorithm
		State.LocationWorkList.add(handlerEa);
		while(!State.LocationWorkList.isEmpty())
		{
			// Get current location
			A curr = State.LocationWorkList.remove(0);
			
			// If we've seen it, or disassembly previously failed, or the 
			// terminator says to stop, skip this location.
			if(graph.hasVertex(curr) || Skip.contains(curr) || shouldTerminateAt(curr))
				continue;
			
			// Call the detail provider to analyze the flows from the entity 
			// and update the State object accordingly.
			T instr = VertexDetailProvider.provide(curr, State); 
			
			// If the detail provider returned NULL, remark and record.
			if(instr == null) {
				Skip.add(curr);
				Printer.printf("%s: instruction was null\n", curr.toString());
				continue;
			}
			
			// Otherwise, allocate a list for the <Location,EntityType> pair 
			// (<A,T>) for the CFGVertex, and add the pair to the list. 
			List<Pair<A,T>> l = new ArrayList<Pair<A,T>>();
			l.add(new Pair<A,T>(curr,instr));
			
			// Create and add the vertex.
			CFGVertex<A,T> currVertex = new CFGVertex<A,T>(curr, l);
			graph.addVertex(currVertex);
		}
		
		// After worklist termination, add the edges.
		ApplyDeferredEdges(graph, State.DeferredEdges);
		
		// Add additional Heads to the state information for any vertex with
		// more than one predecessor.
		Collection<CFGVertex<A,T>> vertices = graph.getVertices();
		Iterator<CFGVertex<A,T>> it = vertices.iterator();
		while(it.hasNext()) {
			CFGVertex<A,T> destVert = it.next();
			Collection<CFGEdge<A,T>> inEdges = graph.getInEdges(destVert);
			if(inEdges.size() > 1)
				State.Heads.add(destVert.getLocator());
		}
		return graph;
	}
	// Create a "merged" CFG, in which there are multiple entities per vertex
	// (as in, basic blocks).
	public CFG<A,T> CreateMergedCFG(A handlerEa) throws Exception
	{
		// Create the singleton graph first. Use it and the resulting state to
		// merge together chains of vertices <x,y>, where:
		// !Heads.contains(y): y is not a designed block head
		// |npred(x)|==|nsucc(y)|==1: x one successor, y one predecessor 
		// pred(y) == x && succ(x) == y: x and y only have edges between them
		CFG<A,T> singletonCFG = CreateSingletonCFG(handlerEa);
		CFG<A,T> mergedCFG = new CFG<A,T>(handlerEa);
		
		// Allocate list for edges in merged graph.
		List<CFGPendingEdge<A>> DeferredEdges = new ArrayList<CFGPendingEdge<A>>();
		
		Iterator<A> it = State.Heads.iterator();
		// Iterate through all of the heads in the singleton CFG.
		while(it.hasNext()) {
			A blockHeadEa = it.next();
			
			// If we can't find the head by its location, this is bad.
			CFGVertex<A,T> blockVertex = singletonCFG.lookupVertex(blockHeadEa);
			if(blockVertex == null) {
				Printer.printf("Block %s: could not find head vertex\n", blockHeadEa.toString());
				continue;
			}
			
			// Iterate through blockVertex and its successors.
			CFGVertex<A,T> currVertex = blockVertex;
			List<Pair<A,T>> blockEnts = new ArrayList<Pair<A,T>>();
			Collection<CFGEdge<A,T>> outEdges;
			while(true) {
				outEdges = singletonCFG.getOutEdges(currVertex);
				
				// If |nsucc(x)| != 1, can't merge.
				int numOutEdges = outEdges.size();
				blockEnts.addAll(currVertex.getEntities());
				if(numOutEdges != 1)
					break;
				
				// If y is a head, don't add an edge. 
				CFGEdge<A,T> e = outEdges.iterator().next();
				CFGVertex<A,T> nextVertex = e.getEnd();
				if(State.Heads.contains(nextVertex.getLocator()))
					break;
				
				// I decided not to forcibly create heads at the targets of 
				// unconditional branches. For unobfuscated code, if there's a
				// jump instruction, the target really ought to have multiple 
				// incoming references. For obfuscated code, we want to ignore
				// unconditional jumps, so we don't mind coalescing them into
				// a single block. So, just ignore unconditional edges.
				// if(e.getEdgeType() == CFGEdgeType.UNCONDITIONAL) {
				// }
				currVertex = nextVertex;
			}
			Iterator<CFGEdge<A,T>> edit = outEdges.iterator();
			
			// Add all outgoing edges to the merged CFG's deferred list.
			while(edit.hasNext()) {
				CFGEdge<A,T> e = edit.next();
				DeferredEdges.add(new CFGPendingEdge<A>(blockHeadEa, e.getEnd().getLocator(), e.getEdgeType()));
			}
			
			// Create a new vertex with the list of all the 
			// <Location,EntityType> (<A,T>) pairs.
			mergedCFG.addVertex(new CFGVertex<A,T>(blockHeadEa, blockEnts));
		}
		
		// Apply the edges to the CFG.
		ApplyDeferredEdges(mergedCFG, DeferredEdges);	
		return mergedCFG;
	}
}

