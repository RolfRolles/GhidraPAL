package ghidra.pal.cfg;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;

// Utility class, common between Instruction and PseudoInstruction vertex 
// entities, to retrieve the flow information from a given Instruction and add
// it to the State object.
public final class InstructionDetailProviderUtil {
	public static void addFlows(Instruction instr, Address curr, CFGBuilderBundle<Address> State) {
		FlowType ft = instr.getFlowType();
		
		// If it's a jump, be more specific about the type...
		if(ft.isJump()) {
			Address[] flows = instr.getFlows();
			
			// For conditional jumps, add both targets as heads.
			if(ft.isConditional()) {
				Address takenEa = flows[0];
				Address notTakenEa = instr.getFallThrough();
				State.DeferredEdges.add(new CFGPendingEdge<Address>(curr, takenEa,    CFGEdgeType.COND_TAKEN));
				State.DeferredEdges.add(new CFGPendingEdge<Address>(curr, notTakenEa, CFGEdgeType.COND_NOTTAKEN));
				State.LocationWorkList.add(takenEa);
				State.LocationWorkList.add(notTakenEa);
				State.Heads.add(takenEa);
				State.Heads.add(notTakenEa);
			}
			
			// For unconditional jumps, don't add them as heads.
			else if (ft.isUnConditional()) {
				Address takenEa = flows[0];
				State.DeferredEdges.add(new CFGPendingEdge<Address>(curr, takenEa, CFGEdgeType.UNCONDITIONAL));
				State.LocationWorkList.add(takenEa);
			}
			
			// For computed jumps like switch statements, use the stored flows 
			// information to add edges.
			else if (ft.isComputed()) {
				for(int i = 0; i < flows.length; i++) {
					State.LocationWorkList.add(flows[i]);
					State.DeferredEdges.add(new CFGPendingEdge<Address>(curr, flows[i], CFGEdgeType.NWAY));
					State.Heads.add(flows[i]);
				}
			}
		}
		
		// If it wasn't a jump, see if it has a fallthrough and add that.
		else if(ft.hasFallthrough()) {
			Address fallThrough = instr.getFallThrough();
			State.LocationWorkList.add(fallThrough);
			State.DeferredEdges.add(new CFGPendingEdge<Address>(curr, fallThrough, CFGEdgeType.FALLTHROUGH));
		}
	}
}
