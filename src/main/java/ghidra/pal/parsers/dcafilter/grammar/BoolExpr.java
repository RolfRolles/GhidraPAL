package ghidra.pal.parsers.dcafilter.grammar;

import ghidra.pal.wbc.dca.DCAFilterContext;

public abstract class BoolExpr {
	abstract public boolean evaluate(DCAFilterContext c);
}

class BoolConst extends BoolExpr {
	boolean val;
	public BoolConst(boolean v) {
		val = v;
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return val;
	}
}

abstract class BoolExpr2 extends BoolExpr {
	final BoolExpr lhs, rhs;
	public BoolExpr2(BoolExpr l, BoolExpr r) {
		lhs = l;
		rhs = r;
	}
}

class AndExpr extends BoolExpr2 {
	public AndExpr(BoolExpr l, BoolExpr r) {
		super(l,r);
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		if(lhs.evaluate(c))
			return rhs.evaluate(c);
		return false;
	}
}

class OrExpr extends BoolExpr2 {
	public OrExpr(BoolExpr l, BoolExpr r) {
		super(l,r);
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		if(!lhs.evaluate(c))
			return rhs.evaluate(c);
		return true;
	}
}

class NotExpr extends BoolExpr {
	final BoolExpr child;
	public NotExpr(BoolExpr l) {
		child = l;
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return !child.evaluate(c);
	}
}

class IsReadVar extends BoolExpr {
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return c.IsRead;
	}
}

class IsWriteVar extends BoolExpr {
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return c.IsWrite;
	}
}

abstract class LongExpr {
	abstract public long evaluate(DCAFilterContext c); 
}

class AccessSizeVar extends LongExpr {
	@Override
	public long evaluate(DCAFilterContext c) {
		return c.AccessSize;
	}
}

class AccessEaVar extends LongExpr {
	@Override
	public long evaluate(DCAFilterContext c) {
		return c.AccessEa;
	}
}

class InsnEaVar extends LongExpr {
	@Override
	public long evaluate(DCAFilterContext c) {
		return c.InsnEa;
	}
}

class LongConstant extends LongExpr {
	long val;
	public LongConstant(String v, int radix) {
		if(radix == 16)
			val = Long.decode(v);
		else if (radix == 10)
			val = Integer.parseInt(v);
		else
			throw new IllegalArgumentException(String.format("LongConstant(%s,%d)", v, radix));
	}
	
	@Override
	public long evaluate(DCAFilterContext c) {
		return val;
	}
}

abstract class IntCompare extends BoolExpr {
	LongExpr lhs;
	LongExpr rhs;
	public IntCompare(LongExpr l, LongExpr r) {
		lhs = l;
		rhs = r;
	}
}

class IntEQ extends IntCompare {
	public IntEQ(LongExpr l, LongExpr r) {
		super(l,r);
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return Long.compareUnsigned(lhs.evaluate(c), rhs.evaluate(c)) == 0;
	}
}

class IntNE extends IntCompare {
	public IntNE(LongExpr l, LongExpr r) {
		super(l,r);
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return Long.compareUnsigned(lhs.evaluate(c), rhs.evaluate(c)) != 0;
	}
}

class IntGT extends IntCompare {
	public IntGT(LongExpr l, LongExpr r) {
		super(l,r);
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return Long.compareUnsigned(lhs.evaluate(c), rhs.evaluate(c)) > 0;
	}
}

class IntGE extends IntCompare {
	public IntGE(LongExpr l, LongExpr r) {
		super(l,r);
	}
	@Override
	public boolean evaluate(DCAFilterContext c) {
		return Long.compareUnsigned(lhs.evaluate(c), rhs.evaluate(c)) >= 0;
	}
}
