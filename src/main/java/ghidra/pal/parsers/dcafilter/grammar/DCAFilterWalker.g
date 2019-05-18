tree grammar DCAFilterWalker;

options {
  tokenVocab=DCAFilter;
  ASTLabelType=CommonTree;
}

start_rule returns [BoolExpr e]
 : boolExpr {e = $boolExpr.e;}
;

boolExpr returns [BoolExpr e]
 : ^(OR a=boolExpr b=boolExpr)  {e = new OrExpr($a.e,$b.e);}
 | ^(AND a=boolExpr b=boolExpr) {e = new AndExpr($a.e,$b.e);}
 | ^(NOT a=boolExpr)            {e = new NotExpr($a.e);}
 | TRUE                         {e = new BoolConst(true);}
 | FALSE                        {e = new BoolConst(false);}
 | ISREAD                       {e = new IsReadVar();}
 | ISWRITE                      {e = new IsWriteVar();}
 | comparison                   {e = $comparison.e;}
;

intvar returns [LongExpr e]
 : Accsize {e = new AccessSizeVar();}
 | Accea   {e = new AccessEaVar();}
 | Insea   {e = new InsnEaVar();}
;

constant returns [LongExpr e] 
 : HEX {e = new LongConstant($HEX.text,16);}
 | DEC {e = new LongConstant($DEC.text,10);}
;

compop returns [LongExpr e]
 : constant {e = $constant.e;}
 | intvar   {e = $intvar.e;}
;
comparison returns [BoolExpr e]
 : ^(EQ a=compop b=compop) {e = new IntEQ($a.e,$b.e); }
 | ^(NE a=compop b=compop) {e = new IntNE($a.e,$b.e); }
 | ^(GT a=compop b=compop) {e = new IntGT($a.e,$b.e); }
 | ^(GE a=compop b=compop) {e = new IntGE($a.e,$b.e); }
 | ^(LT a=compop b=compop) {e = new IntGE($b.e,$a.e); }
 | ^(LE a=compop b=compop) {e = new IntGT($b.e,$a.e); }
;

