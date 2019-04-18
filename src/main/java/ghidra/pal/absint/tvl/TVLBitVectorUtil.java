package ghidra.pal.absint.tvl;

import java.util.function.UnaryOperator;

import ghidra.pal.util.Pair;

import java.util.function.BinaryOperator; 

//This is a utility class for implementing the abstract transformers.
public final class TVLBitVectorUtil {
	// All methods are static -- don't construct this type of object.
	private TVLBitVectorUtil() {}
	
	// Throw an exception if the expected sizes of two bit-vectors did not
	// match. I don't think this is strictly necessary. I think type-checking in
	// the Ghidra pcode should prevent these errors. Call it an abundance of 
	// caution.
	static void SizeMismatchException(String op, int s1, int s2)
	{
		throw new RuntimeException("TVLBitVector: "+op+" sizes "+s1+"/"+s2);
	}
	
	// Given a three-valued bitvector, construct a new one of the same size by
	// applying the function f to its three-valued bits.
	static TVLBitVector Map(TVLBitVector lhs, UnaryOperator<Byte> f)
	{
		int s1 = lhs.Size();
		
		byte[] lhsArr = lhs.Value();
		byte[] newArr = new byte[s1];
		for (int i = 0; i < s1; i++)
			newArr[i] = f.apply(lhsArr[i]);
		
		return new TVLBitVector(newArr);
	}

	// Table for ~x ...
	static final byte[] NotTable = { 
		  TVLBitVector.TVL_1,    // x = 0
		  TVLBitVector.TVL_HALF, // x = 1/2
		  TVLBitVector.TVL_0,    // x = 1
	};

	// Abstract three-valued bitwise NOT
	static TVLBitVector Not(TVLBitVector lhs)
	{
		return Map(lhs, (l) -> NotTable[l]);
	}

	// Given two three-valued bitvectors of the same size, construct a new one of
	// the same size by applying the function f to their component bits at 
	// matching indices.
	static TVLBitVector Map2(TVLBitVector lhs, TVLBitVector rhs, BinaryOperator<Byte> f) 
	{
		int s1 = lhs.Size();
		int s2 = rhs.Size();
		if(s1 != s2)
			SizeMismatchException("map2", s1, s2);
		
		byte[] lhsArr = lhs.Value();
		byte[] rhsArr = rhs.Value();
		byte[] newArr = new byte[s1];
		for (int i = 0; i < s1; i++)
			newArr[i] = f.apply(lhsArr[i], rhsArr[i]);

		return new TVLBitVector(newArr);
	}
	
	// Table for x & y ...
	static final byte[][] AndTable = { 
		//     y = 0                   y = 1/2                y = 1
		{TVLBitVector.TVL_0,     TVLBitVector.TVL_0,    TVLBitVector.TVL_0},    // x = 0
		{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
		{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1}     // x = 1
	};
	// Table for x | y ...
	static final byte[][] OrTable = { 
		//     y = 0                   y = 1/2                y = 1
		{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 0
		{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 1/2
		{TVLBitVector.TVL_1,     TVLBitVector.TVL_1,    TVLBitVector.TVL_1},    // x = 1
	};
	// Table for x ^ y ...
	static final byte[][] XorTable = { 
		//     y = 0                   y = 1/2                y = 1
		{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 0
		{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
		{TVLBitVector.TVL_1,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_0},    // x = 1
	};
	
	// Abstract three-valued bitwise AND
	static TVLBitVector And(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return Map2(lhs, rhs, (l,r) -> AndTable[l][r]);
	}

	// Abstract three-valued bitwise OR
	static TVLBitVector Or(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return Map2(lhs, rhs, (l,r) -> OrTable[l][r]);
	}

	// Abstract three-valued bitwise XOR
	static TVLBitVector Xor(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return Map2(lhs, rhs, (l,r) -> XorTable[l][r]);
	}
	
	// Common method used for size and sign extension.
	static TVLBitVector Extend(TVLBitVector lhs, int newSize, byte extensionVal)
	{
		int lhsSize = lhs.Size();
		
		// Extending to a smaller size? Get out.
		if(lhsSize > newSize)
			throw new RuntimeException("Extend "+TVLBitVector.Representation[extensionVal]+": new size "+newSize+" < "+lhsSize);	

		// Extending to the same size? That's easy.
		if(lhsSize == newSize)
			return lhs.clone();

		// Otherwise, copy the low bits into a new array, fill the upper bits with
		// extensionVal, and return a new bitvector from that.
		byte[] newVal = new byte[newSize];
		byte[] lhsVal = lhs.Value();
		int i;
		for (i = 0; i < lhsSize; i++)
			newVal[i] = lhsVal[i];
		for( ; i < newSize; i++)
			newVal[i] = extensionVal;
		return new TVLBitVector(newVal);
	}

	// Abstract three-valued bitwise zero extension, bit size destination.
	static TVLBitVector ZeroExtend(TVLBitVector lhs, int newSize)
	{
		return Extend(lhs, newSize, TVLBitVector.TVL_0);
	}

	// Abstract three-valued bitwise zero extension, byte size destination.
	static TVLBitVector ZeroExtend(TVLBitVector lhs, GhidraSizeAdapter gsa)
	{
		return ZeroExtend(lhs, gsa.sz*8);
	}

	// Abstract three-valued bitwise sign extension, bit size destination.
	static TVLBitVector SignExtend(TVLBitVector lhs, int newSize)
	{
		return Extend(lhs, newSize, lhs.GetSign());
	}

	// Abstract three-valued bitwise sign extension, byte size destination.
	static TVLBitVector SignExtend(TVLBitVector lhs, GhidraSizeAdapter gsa)
	{
		return SignExtend(lhs, gsa.sz*8);
	}

	// Create a byte-sized three-valued bitvector with the specified lowest bit.
	static TVLBitVector CreateSingle(byte what)
	{
		TVLBitVector x = new TVLBitVector(8, 0);
		x.Value()[0] = what;
		return x;
	}

	// Create a byte-sized three-valued bitvector with a constant lowest bit.
	static TVLBitVector CreateHalfBit()
	{
		return CreateSingle(TVLBitVector.TVL_HALF);
	}

	// Create a byte-sized three-valued bitvector with a constant lowest bit.
	static TVLBitVector CreateBit(boolean bit)
	{
		return CreateSingle(bit ? TVLBitVector.TVL_1 : TVLBitVector.TVL_0);
	}
	
	
	// Helper method for three-valued abstract equality comparisons. Basically,
	// if any two bits at the same position are constants, and the constants 
	// mismatch, if we're doing an equality comparison, this signals that the 
	// result is false, and if we're doing an inequality comparison, then the 
	// result is true. Otherwise, if no concrete mismatches, return 1/2.
	static TVLBitVector EqualsInner(TVLBitVector lhs, TVLBitVector rhs, boolean shouldMatch) 
	{
		int s1 = lhs.Size();
		int s2 = rhs.Size();
		if(s1 != s2)
			SizeMismatchException("EqualsInner("+shouldMatch+")", s1, s2);
		
		byte[] lhsVal = lhs.Value();
		byte[] rhsVal = rhs.Value();
		boolean bHadHalves = false;
		for (int i = 0; i < s1; i++) {
			byte lhsBit = lhsVal[i];
			byte rhsBit = rhsVal[i];
			if(lhsBit == TVLBitVector.TVL_HALF || rhsBit == TVLBitVector.TVL_HALF)
				bHadHalves = true;
			else if(lhsBit != rhsBit)
				return CreateBit(!shouldMatch);
		}
		if(bHadHalves)
			return CreateSingle(TVLBitVector.TVL_HALF);
		return CreateBit(shouldMatch);
	}
	
	// Abstract bitwise equality comparison.
	static TVLBitVector Equals(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return EqualsInner(lhs, rhs, true);
	}

	// Abstract bitwise inequality comparison.
	static TVLBitVector NotEquals(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return EqualsInner(lhs, rhs, false);
	}
	
	// Helper method for shifting left by a fixed quantity.
	static TVLBitVector ShiftLeftInt(TVLBitVector lhs, int amt)
	{
		// Don't shift by a negative amount
		if(amt < 0)
			throw new RuntimeException("ShiftLeftInt("+lhs+","+amt+")");	

		// Do nothing for a zero shift
		if(amt == 0)
			return lhs.clone();
		
		int lhsSize = lhs.Size();

		// Return a zero bitvector if the amount is greater than the size
		if(amt >= lhsSize)
			return new TVLBitVector(lhsSize, 0);
	
		// Otherwise, initialize the lower bits to 0.
		byte[] newArr = new byte[lhsSize];
		byte[] lhsVal = lhs.Value();
		for (int i = 0; i < amt; i++)
			newArr[i] = TVLBitVector.TVL_0;
	
		// Move the existing bits up in the bitvector by the amount.
		for(int j = 0; j < lhsSize-amt; j++)
			newArr[amt+j] = lhsVal[j];
	
		return new TVLBitVector(newArr);
	}
	
	// Helper method for shifting right by a fixed quantity.
	static TVLBitVector ShiftRightInt(TVLBitVector lhs, int amt, byte topFill)
	{
		// Don't shift by a negative amount
		if(amt < 0)
			throw new RuntimeException("ShiftLeftInt("+lhs+","+amt+")");	

		// Do nothing for a zero shift
		if(amt == 0)
			return lhs.clone();
		
		int lhsSize = lhs.Size();

		// Return a zero bitvector if the amount is greater than the size
		if(amt >= lhsSize)
			return Map(lhs, (b) -> topFill);
	
		// Otherwise, initialize the upper bits to topFill.
		byte[] newArr = new byte[lhsSize];
		byte[] lhsVal = lhs.Value();
		for (int i = 0; i < amt; i++)
			newArr[(lhsSize-1)-i] = topFill;
	
		// Move the existing bits down in the bitvector by the amount.
		for(int j = 0; j < lhsSize-amt; j++)
			newArr[j] = lhsVal[j+amt];
	
		return new TVLBitVector(newArr);
	}
	
	// Table for lub(x,y) ...
	static final byte[][] JoinTable = { 
		//     y = 0                   y = 1/2                y = 1
		{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 0
		{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
		{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 1
	};
	
	// Pointwise extension of the bitwise join
	// Made this public due to development outside of this package
	static public TVLBitVector Join(TVLBitVector lhs, TVLBitVector rhs)
	{
		return Map2(lhs, rhs, (l,r) -> JoinTable[l][r]);
	}
	
	// Helper function for abstract shift left/right.
	static TVLBitVector ShiftBvHelper(TVLBitVector lhs, TVLBitVector rhs, boolean bLeft, byte topFill) 
	{
		int lhsSize = lhs.Size();
		int rhsSize = rhs.Size();

		// Seems like Ghidra guarantees this (size is non-zero power of two).
		assert(lhsSize != 0 && (lhsSize & (lhsSize-1)) == 0);

		byte[] rhsVal = rhs.Value();
		
		// Compute, stupidly, log2(lhsSize)
		// I'm sure there's a bit-twiddling hack for log2...
		int log2 = 0;
		for(int i = 1; i < lhsSize; i++) {
			if((lhsSize & (1 << i)) != 0) {
				log2 = i;
				break;
			}
		}
		assert(log2 != 0);
		
		// For an 2^n-bit bitvector, only n bits should be used for the shift 
		// amount. However, in case any higher bits were either set or unknown in 
		// the shift amount, we should return a bitvector initialized to the fill
		// value.
		TVLBitVector tooLarge = null;
		for(int j = log2; j < rhsSize; j++) {
			if(rhsVal[j] == TVLBitVector.TVL_1)
				return Map(lhs, (b) -> topFill);
			if(rhsVal[j] == TVLBitVector.TVL_HALF) {
				tooLarge = Map(lhs, (b) -> topFill);
				break;
			}
		}
		
		// Now, do the actual shift. We support shift amounts with unknown bits, 
		// unlike the original OCaml version.
		TVLBitVector shifted = lhs.clone();
		for(int i = 0; i < log2; i++) {
			switch(rhsVal[i])
			{
				// Shift bit of zero => do nothing.
				case TVLBitVector.TVL_0:
				break;
				
				// Shift bit of one => perform shift by that amount.
				case TVLBitVector.TVL_1:
				shifted = bLeft ? ShiftLeftInt(shifted, 1<<i) : ShiftRightInt(shifted, 1<<i, topFill);
				break;
				
				// Shift bit of 1/2 => don't know whether shift should take place or 
				// not, so perform the shift and join the result with the original.
				case TVLBitVector.TVL_HALF:
				TVLBitVector possibleShifted = bLeft ? ShiftLeftInt(shifted, 1<<i) : ShiftRightInt(shifted, 1<<i, topFill);
				shifted = Join(shifted, possibleShifted);
				break;
			}
		}
		if(tooLarge != null)
			return Join(shifted, tooLarge);
		return shifted;
	}
	
	// Abstract three-valued shift left (including by variable amounts).
	static TVLBitVector ShiftLeftBv(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return ShiftBvHelper(lhs, rhs, true, TVLBitVector.TVL_0);
	}

	// Abstract three-valued shift right (including by variable amounts).
	static TVLBitVector ShiftRightBv(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return ShiftBvHelper(lhs, rhs, false, TVLBitVector.TVL_0);
	}

	// Abstract three-valued signed shift right (including by variable amounts).
	static TVLBitVector ShiftRightArithmeticBv(TVLBitVector lhs, TVLBitVector rhs) 
	{
		return ShiftBvHelper(lhs, rhs, false, lhs.GetSign());
	}

	// Table for x + y + c ...
	static final byte[][][] AddOutputTable = { 
		// c = 0
		{
			//     y = 0                   y = 1/2                y = 1
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 0
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
			{TVLBitVector.TVL_1,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_0}     // x = 1
		},
		
		// c = 1/2
		{
			//     y = 0                   y = 1/2                y = 1
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 0
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}  // x = 1
		},

		// c = 1
		{
			//     y = 0                   y = 1/2                y = 1
			{TVLBitVector.TVL_1,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_0},    // x = 0
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1}     // x = 1
		},
	};

	// Table for x + y + c (carry part) ...
	static final byte[][][] AddCarryTable = { 
		// c = 0
		{
			//     y = 0                   y = 1/2                y = 1
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_0,    TVLBitVector.TVL_0},    // x = 0
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1}     // x = 1
		},
		
		// c = 1/2
		{
			//     y = 0                   y = 1/2                y = 1
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 0
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_HALF}, // x = 1/2
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_1}     // x = 1
		},

		// c = 1
		{
			//     y = 0                   y = 1/2                y = 1
			{TVLBitVector.TVL_0,     TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 0
			{TVLBitVector.TVL_HALF,  TVLBitVector.TVL_HALF, TVLBitVector.TVL_1},    // x = 1/2
			{TVLBitVector.TVL_1,     TVLBitVector.TVL_1,    TVLBitVector.TVL_1}     // x = 1
		},
	};
	
	// Helper function for things based on addition.
	static Pair<TVLBitVector,Byte> AddInternal(TVLBitVector lhs, TVLBitVector rhs, boolean isSub) 
	{
		// Ensure that the sizes match.
		int s1 = lhs.Size();
		int s2 = rhs.Size();
		if(s1 != s2)
			SizeMismatchException("AddInternal(_,_,"+isSub+")", s1, s2);
		
		// Create bitvectors for the sum and carry amounts.
		TVLBitVector sum      = Map(lhs, (x) -> TVLBitVector.TVL_0);
		TVLBitVector carryVec = Map(lhs, (x) -> TVLBitVector.TVL_0);
		
		// If we're subtracting, apply abstract bitwise NOT to RHS.
		if(isSub)
			rhs = Not(rhs);
		
		// If we're subtracting, the initial carry is 1; otherwise, 0.
		byte  lastCarry = isSub ? TVLBitVector.TVL_1 : TVLBitVector.TVL_0;
		
		// Prepare array references.
		byte[]   lhsArr = lhs.Value();
		byte[]   rhsArr = rhs.Value();
		byte[]   sumArr = sum.Value();
		byte[] carryArr = carryVec.Value();
		
		// The addition is implemented via tables. It's cleaner than the OCaml
		// (just due to sloppy programming at the time).
		for(int i = 0; i < s1; i++)
		{
			sumArr[i] = AddOutputTable[lhsArr[i]][rhsArr[i]][lastCarry];
			lastCarry = AddCarryTable [lhsArr[i]][rhsArr[i]][lastCarry];
			carryArr[i] = lastCarry;
		}
		// I suppose technically we didn't need the whole vector of carry bits...
		return new Pair<TVLBitVector,Byte>(sum,lastCarry);
	}

	// Abstract three-valued addition.
	static TVLBitVector Add(TVLBitVector lhs, TVLBitVector rhs) 
	{
		Pair<TVLBitVector,Byte> p = AddInternal(lhs, rhs, false);
		return p.x;
	}

	// Abstract three-valued subtraction.
	static TVLBitVector Subtract(TVLBitVector lhs, TVLBitVector rhs) 
	{
		Pair<TVLBitVector,Byte> p = AddInternal(lhs, rhs, true);
		return p.x;
	}
	
	// Abstract three-valued arithmetic negation.
	static TVLBitVector Neg(TVLBitVector lhs) 
	{
		TVLBitVector zero = Map(lhs, (x) -> TVLBitVector.TVL_0);
		Pair<TVLBitVector,Byte> p = AddInternal(zero, lhs, true);
		return p.x;
	}

	// Abstract three-valued unsigned less-than.
	static TVLBitVector ULT(TVLBitVector lhs, TVLBitVector rhs) 
	{
		Pair<TVLBitVector,Byte> p = AddInternal(lhs, rhs, true);
		return CreateSingle(NotTable[p.y]);
	}

	// Abstract three-valued unsigned less-than-or-equals.
	static TVLBitVector ULE(TVLBitVector lhs, TVLBitVector rhs) 
	{
		byte ult = ULT(lhs,rhs).Value()[0];
		byte eq = Equals(lhs,rhs).Value()[0];
		return CreateSingle(OrTable[ult][eq]);
	}

	// Abstract three-valued signed less-than.
	static TVLBitVector SLT(TVLBitVector lhs, TVLBitVector rhs) 
	{
		byte ult = ULT(lhs,rhs).Value()[0];
		byte signDiff = XorTable[lhs.GetSign()][rhs.GetSign()];
		return CreateSingle(XorTable[signDiff][ult]);
	}

	// Abstract three-valued signed less-than-or-equals.
	static TVLBitVector SLE(TVLBitVector lhs, TVLBitVector rhs) 
	{
		byte slt = SLT(lhs,rhs).Value()[0];
		byte eq = Equals(lhs,rhs).Value()[0];
		return CreateSingle(OrTable[slt][eq]);
	}
	
	// Unsigned overflow is last carry-out bit.
	static TVLBitVector AddOverflow(TVLBitVector lhs, TVLBitVector rhs)
	{
		Pair<TVLBitVector,Byte> p = AddInternal(lhs, rhs, false);
		return CreateSingle(p.y);
	}
	
	// Signed overflow is calculated from the signs of addition inputs/output.
	static TVLBitVector AddCarry(TVLBitVector lhsBv, TVLBitVector rhsBv)
	{
		TVLBitVector sumBv   = TVLBitVectorUtil.Add(lhsBv, rhsBv);
		byte sumSign = sumBv.GetSign();
		byte signDiff1 = TVLBitVectorUtil.XorTable[lhsBv.GetSign()][sumSign];
		byte signDiff2 = TVLBitVectorUtil.XorTable[rhsBv.GetSign()][sumSign];
		byte signDiff3 = TVLBitVectorUtil.AndTable[signDiff1][signDiff2];
		return CreateSingle(signDiff3);
	}

	// Signed overflow is calculated from the signs of subtraction inputs/output.
	static TVLBitVector SubCarry(TVLBitVector lhsBv, TVLBitVector rhsBv)
	{
		TVLBitVector sumBv   = TVLBitVectorUtil.Subtract(lhsBv, rhsBv);
		byte lhsSign = lhsBv.GetSign();
		byte signDiff1 = TVLBitVectorUtil.XorTable[lhsSign][sumBv.GetSign()];
		byte signDiff2 = TVLBitVectorUtil.XorTable[lhsSign][rhsBv.GetSign()];
		byte signDiff3 = TVLBitVectorUtil.AndTable[signDiff1][signDiff2];
		return CreateSingle(signDiff3);
	}

	// Abstract three-valued bitwise multiplication.
	static TVLBitVector Multiply(TVLBitVector lhs, TVLBitVector rhs) 
	{
		// Size check.
		int s1 = lhs.Size();
		int s2 = rhs.Size();
		if(s1 != s2)
			SizeMismatchException("Multiply", s1, s2);
		
		// Partial product begins with zero
		TVLBitVector partialProduct = Map(lhs, (b) -> TVLBitVector.TVL_0);

		// For multiplications by unknown bits, create a three-valued bitvector 
		// where all of the 1-bits are replaced by 1/2 bits, signifying that we 
		// don't know whether the multiplication is taking place or not.
		TVLBitVector lhsHalves = Map(lhs, (b) -> b == TVLBitVector.TVL_1 ? TVLBitVector.TVL_HALF : b);

		byte[] rhsArr = rhs.Value();
		
		// Could probably improve performance by terminating early if all bits in
		// the partial product above the current index are 1/2.
		for(int i = 0; i < s1; i++) {
			switch(rhsArr[i])
			{
				case TVLBitVector.TVL_0:
				break;
				case TVLBitVector.TVL_1:
				partialProduct = Add(partialProduct, ShiftLeftInt(lhs, i));
				break;
				case TVLBitVector.TVL_HALF:
				partialProduct = Add(partialProduct, ShiftLeftInt(lhsHalves, i));
				break;
			}
		}
		return partialProduct;
	}
	
	// Abstract three-valued bitwise division, unsigned. The signed division 
	// algorithm calls this as a subroutine. 
	static Pair<TVLBitVector, TVLBitVector> DivideInner(TVLBitVector lhs, TVLBitVector rhs)
	{
		// Size check.
		int s1 = lhs.Size();
		int s2 = rhs.Size();
		if(s1 != s2)
			SizeMismatchException("Multiply", s1, s2);		

		// If we're dividing by zero, return top.
		Pair<Integer,Long> rhsConst = rhs.GetConstantValue();
		if(rhsConst != null && rhsConst.y == 0)
		{
			TVLBitVector top1 = Map(lhs, (b) -> TVLBitVector.TVL_HALF);
			TVLBitVector top2 = Map(lhs, (b) -> TVLBitVector.TVL_HALF);			
			return new Pair<TVLBitVector, TVLBitVector>(top1, top2);
		}
		
		// Quotient, remainder begin as zero
		TVLBitVector quotient  = Map(lhs, (b) -> TVLBitVector.TVL_0);
		TVLBitVector remainder = Map(lhs, (b) -> TVLBitVector.TVL_0);
		
		// Standard implementation of unsigned division in terms of a quotient
		// and remainder vector, shifting and subtraction. Joins the results if
		// any bit was unknown.
		for(int i = s1-1; i >= 0; i--)
		{
			remainder = ShiftLeftInt(remainder, 1);
			remainder.Value()[0] = lhs.Value()[i];
			TVLBitVector isLEQ = ULE(rhs, remainder);
			byte leq = isLEQ.Value()[0];
			quotient = ShiftLeftInt(quotient, 1);
			quotient.Value()[0] = leq;
			switch(leq)
			{
				case TVLBitVector.TVL_0:
				continue;
				case TVLBitVector.TVL_1:
				remainder = Subtract(remainder, rhs);
				break;
				case TVLBitVector.TVL_HALF:
				TVLBitVector remainderPossibly = Subtract(remainder, rhs);
				remainder = Join(remainderPossibly, remainder);
				break;
			}
		}
		return new Pair<TVLBitVector,TVLBitVector>(quotient,remainder);
	}
	
	
	// Get the unsigned quotient and remainder; return just the quotient.
	static TVLBitVector UnsignedDivide(TVLBitVector lhs, TVLBitVector rhs)
	{
		Pair<TVLBitVector,TVLBitVector> res = DivideInner(lhs,rhs);
		return res.x;
	}

	// Get the unsigned quotient and remainder; return just the remainder.
	static TVLBitVector UnsignedRemainder(TVLBitVector lhs, TVLBitVector rhs)
	{
		Pair<TVLBitVector,TVLBitVector> res = DivideInner(lhs,rhs);
		return res.y;
	}

	// Adjust the sign of a bitvector
	static TVLBitVector SignedDivideHelper(TVLBitVector bv, byte sign)
	{
		switch(sign)
		{
			case TVLBitVector.TVL_0:
			return bv;
			case TVLBitVector.TVL_1:
			return Neg(bv);
			case TVLBitVector.TVL_HALF:
			TVLBitVector negatedPossibly = Neg(bv);
			return Join(negatedPossibly, bv);
		}
		assert(false); 
		return null;
	}

	// Wrapper around the above
	static Pair<TVLBitVector, Byte> SignedDivideHelper(TVLBitVector bv)
	{
		byte sign = bv.GetSign();
		return new Pair<TVLBitVector, Byte>(SignedDivideHelper(bv, sign), sign);
	}

	// Make values unsigned, perform unsigned division, then adjust sign of 
	// result
	static TVLBitVector SignedDivideInner(TVLBitVector lhs, TVLBitVector rhs, boolean want_quotient)
	{
		Pair<TVLBitVector,Byte> lhsSignInfo = SignedDivideHelper(lhs);
		Pair<TVLBitVector,Byte> rhsSignInfo = SignedDivideHelper(rhs);
		Pair<TVLBitVector,TVLBitVector> divisionResult = DivideInner(lhsSignInfo.x, rhsSignInfo.x);
		if(want_quotient)
			return SignedDivideHelper(divisionResult.x, XorTable[lhsSignInfo.y][rhsSignInfo.y]);
		return SignedDivideHelper(divisionResult.y, lhsSignInfo.y);
	}

	// Top-level signed division.
	static TVLBitVector SignedDivide(TVLBitVector lhs, TVLBitVector rhs)
	{
		return SignedDivideInner(lhs, rhs, true);
	}

	// Top-level signed remainder.
	static TVLBitVector SignedRemainder(TVLBitVector lhs, TVLBitVector rhs)
	{
		return SignedDivideInner(lhs, rhs, false);
	}
	
	// Raw comparison of two bit-vector objects. Should I move this into 
	// TVLBitVector itself? Hmm... but then I have to do something with this
	// exception. Just leave it for now.
	static public boolean isEqualTo(TVLBitVector lhs, TVLBitVector rhs) {
		// Size check.
		int s1 = lhs.Size();
		int s2 = rhs.Size();
		if(s1 != s2)
			SizeMismatchException("equals", s1, s2);
		
		byte[] lhsArr = lhs.Value();
		byte[] rhsArr = rhs.Value();
		for(int i = 0; i < lhsArr.length; i++)
			if(lhsArr[i] != rhsArr[i])
				return false;
		return true;		
	}
	
}
