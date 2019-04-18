// I used this to make sure the abstract transformers were implemented 
// correctly. However, I haven't updated it for the final architecture of the
// code, so I've just commented it out. Also, I have no idea how to make these
// tests run in an automated fashion, given that it has to be running inside
// of Ghidra with a program loaded.
/*
package ghidra.pal.absint.tvl;

import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeTranslator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import java.util.concurrent.ThreadLocalRandom;
import ghidra.app.services.ProgramManager;
import ghidra.pal.absint.tvl.TVLBitVector;
import ghidra.pal.generic.VisitorUnimplementedException;
import ghidra.pal.util.JavaUtil;
import ghidra.pal.util.Pair;
import ghidra.pal.util.Printer;

import static org.junit.Assert.*;
import org.junit.Test;

class TransformerTester {
	Register rAL, rAX, rEAX;
	Register rBL, rBX, rEBX;
	Register rCL, rCX, rECX;
	public Varnode vAL, vAX, vEAX;
	public Varnode vBL, vBX, vEBX;
	public Varnode vCL, vCX, vECX;
	TVLAbstractInterpreter tvlai;
	AddressSpace TestAddressSpace;
	Address TestAddress;
	int seqNo;
	
	public TransformerTester(Program currentProgram)
	{
		SleighLanguage l = (SleighLanguage)currentProgram.getLanguage();
		VarnodeTranslator vt = new VarnodeTranslator(currentProgram);
		tvlai = new TVLAbstractInterpreter(l.isBigEndian());
		TestAddressSpace = new GenericAddressSpace("TEST", 32, AddressSpace.TYPE_OTHER, 0);
		TestAddress = TestAddressSpace.getAddress(0);
		seqNo = 1;
		
		// Initialize Register and corresponding Varnode objects
		rAL  = l.getRegister("AL");  vAL  = vt.getVarnode(rAL);
		rBL  = l.getRegister("BL");  vBL  = vt.getVarnode(rBL);
		rCL  = l.getRegister("CL");  vCL  = vt.getVarnode(rCL);
		rAX  = l.getRegister("AX");  vAX  = vt.getVarnode(rAX);
		rBX  = l.getRegister("BX");  vBX  = vt.getVarnode(rBX);
		rCX  = l.getRegister("CX");  vCX  = vt.getVarnode(rCX);
		rEAX = l.getRegister("EAX"); vEAX = vt.getVarnode(rEAX);
		rEBX = l.getRegister("EBX"); vEBX = vt.getVarnode(rEBX);
		rECX = l.getRegister("ECX"); vECX = vt.getVarnode(rECX);		
	}
	
	PcodeOp CreatePcodeOp(int op, Varnode[] inputs, Varnode output)
	{
		return new PcodeOp(TestAddress, seqNo++, op, inputs, output);
	}
	
	long GetBinaryPcodeResult(PcodeOp pcode, long valLhs, long valRhs)
	{
		PcodeOpRaw raw = new PcodeOpRaw(pcode);
		OpBehavior behave = raw.getBehavior();
		assert(behave != null);
		assert(behave instanceof BinaryOpBehavior);
		BinaryOpBehavior binaryBehave = (BinaryOpBehavior) behave;
		Varnode lhs = pcode.getInput(0);
		// Varnode rhs = pcode.getInput(1); // unused
		Varnode out = pcode.getOutput();
		return binaryBehave.evaluateBinary(out.getSize(), lhs.getSize(), valLhs, valRhs);
	}
	
	Pair<Long,TVLBitVector> TestBinaryPcode(int op, int nBytes, long valLhs, long valRhs, boolean randomize)
	{
		Varnode lhs, rhs, out;
		switch(nBytes)
		{
			case 1: lhs = vAL;  rhs = vBL;  out = vCL;  break;
			case 2: lhs = vAX;  rhs = vBX;  out = vCX;  break;
			case 4: lhs = vEAX; rhs = vEBX; out = vECX; break;
			default: assert(false); return null;
		}
		Varnode inputs[] = new Varnode[] { lhs, rhs };
		PcodeOp p = CreatePcodeOp(op, inputs, out);
		long result = GetBinaryPcodeResult(p, valLhs, valRhs);
		tvlai.AbstractState.clear();
		TVLBitVector bvlhs = new TVLBitVector(new GhidraSizeAdapter(nBytes), valLhs);
		TVLBitVector bvrhs = new TVLBitVector(new GhidraSizeAdapter(nBytes), valRhs);
		if(randomize)
		{
			TVLBitVector bv = ThreadLocalRandom.current().nextBoolean() ? bvlhs : bvrhs;
			bv.Value()[ThreadLocalRandom.current().nextInt(0, bv.Size())] = TVLBitVector.TVL_HALF;
		}
		tvlai.AbstractState.Associate(lhs, bvlhs);
		tvlai.AbstractState.Associate(rhs, bvrhs);
		try {
			tvlai.visit(null, p);
		}
		catch(VisitorUnimplementedException e)
		{
			Printer.println("Caught visitor unimplemented exception: "+e);
			return null;
		}
		TVLBitVector bvres = tvlai.AbstractState.Lookup(out);
		return new Pair<Long,TVLBitVector>(result,bvres);
	}

	long GetUnaryPcodeResult(PcodeOp pcode, long valLhs)
	{
		PcodeOpRaw raw = new PcodeOpRaw(pcode);
		OpBehavior behave = raw.getBehavior();
		assert(behave != null);
		assert(behave instanceof UnaryOpBehavior);
		UnaryOpBehavior unaryBehave = (UnaryOpBehavior) behave;
		Varnode lhs = pcode.getInput(0);
		Varnode out = pcode.getOutput();
		return unaryBehave.evaluateUnary(out.getSize(), lhs.getSize(), valLhs);
	}

	Pair<Long,TVLBitVector> TestUnaryPcode(int op, int nBytes, long valLhs, boolean randomize)
	{
		Varnode lhs, out;
		switch(nBytes)
		{
			case 1: lhs = vAL;  out = vCL;  break;
			case 2: lhs = vAX;  out = vCX;  break;
			case 4: lhs = vEAX; out = vECX; break;
			default: assert(false); return null;
		}
		Varnode inputs[] = new Varnode[] { lhs };
		PcodeOp p = CreatePcodeOp(op, inputs, out);
		long result = GetUnaryPcodeResult(p, valLhs);
		tvlai.AbstractState.clear();
		TVLBitVector bv = new TVLBitVector(new GhidraSizeAdapter(nBytes), valLhs);
		if(randomize)
			bv.Value()[ThreadLocalRandom.current().nextInt(0, bv.Size())] = TVLBitVector.TVL_HALF;
		tvlai.AbstractState.Associate(lhs, bv);
		
		try {
			tvlai.visit(null, p);
		}
		catch(VisitorUnimplementedException e)
		{
			Printer.println("Caught visitor unimplemented exception: "+e);
			return null;
		}
		TVLBitVector bvres = tvlai.AbstractState.Lookup(out);
		return new Pair<Long,TVLBitVector>(result,bvres);
	}
}


public class TVLAbstractInterpreterTest {
	Program currentProgram;
	void PrintIfConcreteTestFailure(int op, long alValue, long blValue, Pair<Long, TVLBitVector> res) {
		Pair<Integer,Long> cval = res.y.GetConstantValue();
		if(cval == null)
			Printer.printf("Op %s: [al = %02x, bl = %02x] => non-constant %s\n", PcodeOp.getMnemonic(op), alValue, blValue, res.y.toString());
		else if(!JavaUtil.CompareLongs(cval.y,res.x))
			Printer.printf("Op %s: [al = %02x, bl = %02x] => %02x real, %02x abstract\n", PcodeOp.getMnemonic(op), alValue, blValue, res.x, cval.y);
	}
	
	void PrintIfRandomTestFailure(int op, long alValue, long blValue, Pair<Long, TVLBitVector> res) {
		byte[] AbsValue = res.y.Value();
		long realRes = res.x;
		for(int i = 0; i < AbsValue.length; i++)
		{
			long bit = (realRes >> i) & 1L;
			if(AbsValue[i] != TVLBitVector.TVL_HALF)
			{
				if( (bit == 0L && AbsValue[i] != TVLBitVector.TVL_0) ||
				    (bit == 1L && AbsValue[i] != TVLBitVector.TVL_1) )
					Printer.printf("Op %s: [al = %02x, bl = %02x] => %02x real, %s abstract, bit %d differs [%d/%s]\n", PcodeOp.getMnemonic(op), alValue, blValue, res.x, res.y.toString(), i, bit, TVLBitVector.Representation[AbsValue[i]]);
			}
		}
	}

	void TestUnimplemented() throws Exception {
		TransformerTester tt = new TransformerTester(currentProgram);
		int binaryOperators[] = new int[] {
			//PcodeOp.PTRADD,
			PcodeOp.PTRSUB,
		};
		long blValue = 0x55;
		for(long alValue = 0; alValue < 0x100; alValue++)
		{
			for(int i = 0; i < binaryOperators.length; i++)
			{
				int op = binaryOperators[i];
				PcodeOp p = tt.CreatePcodeOp(op, new Varnode[] {tt.vAL, tt.vBL}, tt.vCL);
				long res = tt.GetBinaryPcodeResult(p, alValue, blValue);
				Printer.printf("Op %s: [al = %02x, bl = %02x] => %02x\n", PcodeOp.getMnemonic(op), alValue, blValue, res);
			}
		}
	}
	
	public void TestAbstractTransformers() throws Exception {
		TransformerTester tt = new TransformerTester(currentProgram);
		int binaryOperators[] = new int[] {
			PcodeOp.INT_ADD,
			PcodeOp.INT_AND,
			PcodeOp.INT_CARRY,
			PcodeOp.INT_DIV,
			PcodeOp.INT_EQUAL,
			PcodeOp.INT_LEFT,
			PcodeOp.INT_LESS,
			PcodeOp.INT_LESSEQUAL,
			PcodeOp.INT_MULT,
			PcodeOp.INT_NOTEQUAL,
			PcodeOp.INT_OR,
			PcodeOp.INT_REM,
			PcodeOp.INT_RIGHT,
			PcodeOp.INT_SBORROW,
			PcodeOp.INT_SCARRY,
			PcodeOp.INT_SDIV,
			PcodeOp.INT_SLESS,
			PcodeOp.INT_SLESSEQUAL,
			PcodeOp.INT_SREM,
			PcodeOp.INT_SRIGHT,
			PcodeOp.INT_SUB,
			PcodeOp.INT_XOR
		};
		int unaryOperators[] = new int[] {
			PcodeOp.COPY,
			PcodeOp.INT_2COMP,
			PcodeOp.INT_NEGATE,
			PcodeOp.INT_SEXT,
			PcodeOp.INT_ZEXT
		};

		for(long alValue = 0; alValue < 0x100; alValue++)
		{
			for(long blValue = 0; blValue < 0x100; blValue++)
			{
				for(int i = 0; i < binaryOperators.length; i++)
				{
					int op = binaryOperators[i];
					if(op == PcodeOp.INT_DIV || op == PcodeOp.INT_REM || op == PcodeOp.INT_SDIV || op == PcodeOp.INT_SREM)
					{
						if(JavaUtil.CompareLongs(blValue,0))
							continue;
					}
					Pair<Long, TVLBitVector> res = tt.TestBinaryPcode(op, 1, alValue, blValue, false);
					PrintIfConcreteTestFailure(op, alValue, blValue, res);
					res = tt.TestBinaryPcode(op, 1, alValue, blValue, true);
					PrintIfRandomTestFailure(op, alValue, 0, res);
				}
			}
			for(int i = 0; i < unaryOperators.length; i++)
			{
				int op = unaryOperators[i];
				Pair<Long, TVLBitVector> res = tt.TestUnaryPcode(op, 1, alValue, false);
				PrintIfConcreteTestFailure(op, alValue, 0, res);
				res = tt.TestUnaryPcode(op, 1, alValue, true);
				PrintIfRandomTestFailure(op, alValue, 0, res);
			}			
		}
		Printer.println("Testing operators done");
	}
	@Test
	public void testAll()
	{
		currentProgram = ProgramManager().getCurrentProgram();
	}
	
}
	
*/