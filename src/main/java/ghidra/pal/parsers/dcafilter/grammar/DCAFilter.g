grammar DCAFilter;
options {output=AST;}

tokens {
  Constant;
  Intvar;
}

start_rule 
 : boolExpr EOF -> boolExpr;

ISWRITE : 'IsWrite';
ISREAD : 'IsRead';

boolExpr : boolExprOr;

boolExprOr
: boolExprAnd (OR^ boolExprAnd)*;

boolExprAnd
: boolExprNot (AND^ boolExprNot)*;

boolExprNot
: NOT^ boolExprTerm
| boolExprTerm;

boolExprTerm
: '(' boolExprOr ')' -> boolExprOr
| TRUE
| FALSE
| ISWRITE
| ISREAD
| comparison
;

constant : HEX | DEC;

EQ : '==';
NE : '!=';
GE : '>=';
GT : '>';
LE : '<=';
LT : '<';

relop : EQ | NE | GE | GT | LE | LT;

Accsize : 'AccessSize';
Insea : 'InsnEa';
Accea : 'AccessEa';

intvar : Accsize | Accea | Insea;

compop 
 : constant 
 | intvar;

comparison: compop relop^ compop;

TRUE : 'true';
FALSE: 'false';
AND: '&&';
OR: '||';
NOT: '!';
WS : (' ' | '\t' | '\r' | '\n' )* {$channel=HIDDEN;};
HEX : '0x' ('a'..'f' | 'A'..'F' | '0'..'9')+;
DEC : ('0'..'9')+;
