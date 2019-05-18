package ghidra.pal.parsers.dcafilter.grammar;
// $ANTLR 3.5.2 DCAFilterWalker.g 2019-05-17 23:26:24

import org.antlr.runtime.*;
import org.antlr.runtime.tree.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class DCAFilterWalker extends TreeParser {
	public static final String[] tokenNames = new String[] {
		"<invalid>", "<EOR>", "<DOWN>", "<UP>", "AND", "Accea", "Accsize", "Constant", 
		"DEC", "EQ", "FALSE", "GE", "GT", "HEX", "ISREAD", "ISWRITE", "Insea", 
		"Intvar", "LE", "LT", "NE", "NOT", "OR", "TRUE", "WS", "'('", "')'"
	};
	public static final int EOF=-1;
	public static final int T__25=25;
	public static final int T__26=26;
	public static final int AND=4;
	public static final int Accea=5;
	public static final int Accsize=6;
	public static final int Constant=7;
	public static final int DEC=8;
	public static final int EQ=9;
	public static final int FALSE=10;
	public static final int GE=11;
	public static final int GT=12;
	public static final int HEX=13;
	public static final int ISREAD=14;
	public static final int ISWRITE=15;
	public static final int Insea=16;
	public static final int Intvar=17;
	public static final int LE=18;
	public static final int LT=19;
	public static final int NE=20;
	public static final int NOT=21;
	public static final int OR=22;
	public static final int TRUE=23;
	public static final int WS=24;

	// delegates
	public TreeParser[] getDelegates() {
		return new TreeParser[] {};
	}

	// delegators


	public DCAFilterWalker(TreeNodeStream input) {
		this(input, new RecognizerSharedState());
	}
	public DCAFilterWalker(TreeNodeStream input, RecognizerSharedState state) {
		super(input, state);
	}

	@Override public String[] getTokenNames() { return DCAFilterWalker.tokenNames; }
	@Override public String getGrammarFileName() { return "DCAFilterWalker.g"; }



	// $ANTLR start "start_rule"
	// DCAFilterWalker.g:8:1: start_rule returns [BoolExpr e] : boolExpr ;
	public final BoolExpr start_rule() throws RecognitionException {
		BoolExpr e = null;


		BoolExpr boolExpr1 =null;

		try {
			// DCAFilterWalker.g:9:2: ( boolExpr )
			// DCAFilterWalker.g:9:4: boolExpr
			{
			pushFollow(FOLLOW_boolExpr_in_start_rule36);
			boolExpr1=boolExpr();
			state._fsp--;

			e = boolExpr1;
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return e;
	}
	// $ANTLR end "start_rule"



	// $ANTLR start "boolExpr"
	// DCAFilterWalker.g:12:1: boolExpr returns [BoolExpr e] : ( ^( OR a= boolExpr b= boolExpr ) | ^( AND a= boolExpr b= boolExpr ) | ^( NOT a= boolExpr ) | TRUE | FALSE | ISREAD | ISWRITE | comparison );
	public final BoolExpr boolExpr() throws RecognitionException {
		BoolExpr e = null;


		BoolExpr a =null;
		BoolExpr b =null;
		BoolExpr comparison2 =null;

		try {
			// DCAFilterWalker.g:13:2: ( ^( OR a= boolExpr b= boolExpr ) | ^( AND a= boolExpr b= boolExpr ) | ^( NOT a= boolExpr ) | TRUE | FALSE | ISREAD | ISWRITE | comparison )
			int alt1=8;
			switch ( input.LA(1) ) {
			case OR:
				{
				alt1=1;
				}
				break;
			case AND:
				{
				alt1=2;
				}
				break;
			case NOT:
				{
				alt1=3;
				}
				break;
			case TRUE:
				{
				alt1=4;
				}
				break;
			case FALSE:
				{
				alt1=5;
				}
				break;
			case ISREAD:
				{
				alt1=6;
				}
				break;
			case ISWRITE:
				{
				alt1=7;
				}
				break;
			case EQ:
			case GE:
			case GT:
			case LE:
			case LT:
			case NE:
				{
				alt1=8;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 1, 0, input);
				throw nvae;
			}
			switch (alt1) {
				case 1 :
					// DCAFilterWalker.g:13:4: ^( OR a= boolExpr b= boolExpr )
					{
					match(input,OR,FOLLOW_OR_in_boolExpr53); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_boolExpr_in_boolExpr57);
					a=boolExpr();
					state._fsp--;

					pushFollow(FOLLOW_boolExpr_in_boolExpr61);
					b=boolExpr();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new OrExpr(a,b);
					}
					break;
				case 2 :
					// DCAFilterWalker.g:14:4: ^( AND a= boolExpr b= boolExpr )
					{
					match(input,AND,FOLLOW_AND_in_boolExpr71); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_boolExpr_in_boolExpr75);
					a=boolExpr();
					state._fsp--;

					pushFollow(FOLLOW_boolExpr_in_boolExpr79);
					b=boolExpr();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new AndExpr(a,b);
					}
					break;
				case 3 :
					// DCAFilterWalker.g:15:4: ^( NOT a= boolExpr )
					{
					match(input,NOT,FOLLOW_NOT_in_boolExpr88); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_boolExpr_in_boolExpr92);
					a=boolExpr();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new NotExpr(a);
					}
					break;
				case 4 :
					// DCAFilterWalker.g:16:4: TRUE
					{
					match(input,TRUE,FOLLOW_TRUE_in_boolExpr111); 
					e = new BoolConst(true);
					}
					break;
				case 5 :
					// DCAFilterWalker.g:17:4: FALSE
					{
					match(input,FALSE,FOLLOW_FALSE_in_boolExpr142); 
					e = new BoolConst(false);
					}
					break;
				case 6 :
					// DCAFilterWalker.g:18:4: ISREAD
					{
					match(input,ISREAD,FOLLOW_ISREAD_in_boolExpr172); 
					e = new IsReadVar();
					}
					break;
				case 7 :
					// DCAFilterWalker.g:19:4: ISWRITE
					{
					match(input,ISWRITE,FOLLOW_ISWRITE_in_boolExpr201); 
					e = new IsWriteVar();
					}
					break;
				case 8 :
					// DCAFilterWalker.g:20:4: comparison
					{
					pushFollow(FOLLOW_comparison_in_boolExpr229);
					comparison2=comparison();
					state._fsp--;

					e = comparison2;
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return e;
	}
	// $ANTLR end "boolExpr"



	// $ANTLR start "intvar"
	// DCAFilterWalker.g:23:1: intvar returns [LongExpr e] : ( Accsize | Accea | Insea );
	public final LongExpr intvar() throws RecognitionException {
		LongExpr e = null;


		try {
			// DCAFilterWalker.g:24:2: ( Accsize | Accea | Insea )
			int alt2=3;
			switch ( input.LA(1) ) {
			case Accsize:
				{
				alt2=1;
				}
				break;
			case Accea:
				{
				alt2=2;
				}
				break;
			case Insea:
				{
				alt2=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}
			switch (alt2) {
				case 1 :
					// DCAFilterWalker.g:24:4: Accsize
					{
					match(input,Accsize,FOLLOW_Accsize_in_intvar263); 
					e = new AccessSizeVar();
					}
					break;
				case 2 :
					// DCAFilterWalker.g:25:4: Accea
					{
					match(input,Accea,FOLLOW_Accea_in_intvar270); 
					e = new AccessEaVar();
					}
					break;
				case 3 :
					// DCAFilterWalker.g:26:4: Insea
					{
					match(input,Insea,FOLLOW_Insea_in_intvar279); 
					e = new InsnEaVar();
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return e;
	}
	// $ANTLR end "intvar"



	// $ANTLR start "constant"
	// DCAFilterWalker.g:29:1: constant returns [LongExpr e] : ( HEX | DEC );
	public final LongExpr constant() throws RecognitionException {
		LongExpr e = null;


		CommonTree HEX3=null;
		CommonTree DEC4=null;

		try {
			// DCAFilterWalker.g:30:2: ( HEX | DEC )
			int alt3=2;
			int LA3_0 = input.LA(1);
			if ( (LA3_0==HEX) ) {
				alt3=1;
			}
			else if ( (LA3_0==DEC) ) {
				alt3=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}

			switch (alt3) {
				case 1 :
					// DCAFilterWalker.g:30:4: HEX
					{
					HEX3=(CommonTree)match(input,HEX,FOLLOW_HEX_in_constant298); 
					e = new LongConstant((HEX3!=null?HEX3.getText():null),16);
					}
					break;
				case 2 :
					// DCAFilterWalker.g:31:4: DEC
					{
					DEC4=(CommonTree)match(input,DEC,FOLLOW_DEC_in_constant305); 
					e = new LongConstant((DEC4!=null?DEC4.getText():null),10);
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return e;
	}
	// $ANTLR end "constant"



	// $ANTLR start "compop"
	// DCAFilterWalker.g:34:1: compop returns [LongExpr e] : ( constant | intvar );
	public final LongExpr compop() throws RecognitionException {
		LongExpr e = null;


		LongExpr constant5 =null;
		LongExpr intvar6 =null;

		try {
			// DCAFilterWalker.g:35:2: ( constant | intvar )
			int alt4=2;
			int LA4_0 = input.LA(1);
			if ( (LA4_0==DEC||LA4_0==HEX) ) {
				alt4=1;
			}
			else if ( ((LA4_0 >= Accea && LA4_0 <= Accsize)||LA4_0==Insea) ) {
				alt4=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}

			switch (alt4) {
				case 1 :
					// DCAFilterWalker.g:35:4: constant
					{
					pushFollow(FOLLOW_constant_in_compop321);
					constant5=constant();
					state._fsp--;

					e = constant5;
					}
					break;
				case 2 :
					// DCAFilterWalker.g:36:4: intvar
					{
					pushFollow(FOLLOW_intvar_in_compop328);
					intvar6=intvar();
					state._fsp--;

					e = intvar6;
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return e;
	}
	// $ANTLR end "compop"



	// $ANTLR start "comparison"
	// DCAFilterWalker.g:38:1: comparison returns [BoolExpr e] : ( ^( EQ a= compop b= compop ) | ^( NE a= compop b= compop ) | ^( GT a= compop b= compop ) | ^( GE a= compop b= compop ) | ^( LT a= compop b= compop ) | ^( LE a= compop b= compop ) );
	public final BoolExpr comparison() throws RecognitionException {
		BoolExpr e = null;


		LongExpr a =null;
		LongExpr b =null;

		try {
			// DCAFilterWalker.g:39:2: ( ^( EQ a= compop b= compop ) | ^( NE a= compop b= compop ) | ^( GT a= compop b= compop ) | ^( GE a= compop b= compop ) | ^( LT a= compop b= compop ) | ^( LE a= compop b= compop ) )
			int alt5=6;
			switch ( input.LA(1) ) {
			case EQ:
				{
				alt5=1;
				}
				break;
			case NE:
				{
				alt5=2;
				}
				break;
			case GT:
				{
				alt5=3;
				}
				break;
			case GE:
				{
				alt5=4;
				}
				break;
			case LT:
				{
				alt5=5;
				}
				break;
			case LE:
				{
				alt5=6;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 5, 0, input);
				throw nvae;
			}
			switch (alt5) {
				case 1 :
					// DCAFilterWalker.g:39:4: ^( EQ a= compop b= compop )
					{
					match(input,EQ,FOLLOW_EQ_in_comparison346); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_compop_in_comparison350);
					a=compop();
					state._fsp--;

					pushFollow(FOLLOW_compop_in_comparison354);
					b=compop();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new IntEQ(a,b); 
					}
					break;
				case 2 :
					// DCAFilterWalker.g:40:4: ^( NE a= compop b= compop )
					{
					match(input,NE,FOLLOW_NE_in_comparison363); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_compop_in_comparison367);
					a=compop();
					state._fsp--;

					pushFollow(FOLLOW_compop_in_comparison371);
					b=compop();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new IntNE(a,b); 
					}
					break;
				case 3 :
					// DCAFilterWalker.g:41:4: ^( GT a= compop b= compop )
					{
					match(input,GT,FOLLOW_GT_in_comparison380); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_compop_in_comparison384);
					a=compop();
					state._fsp--;

					pushFollow(FOLLOW_compop_in_comparison388);
					b=compop();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new IntGT(a,b); 
					}
					break;
				case 4 :
					// DCAFilterWalker.g:42:4: ^( GE a= compop b= compop )
					{
					match(input,GE,FOLLOW_GE_in_comparison397); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_compop_in_comparison401);
					a=compop();
					state._fsp--;

					pushFollow(FOLLOW_compop_in_comparison405);
					b=compop();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new IntGE(a,b); 
					}
					break;
				case 5 :
					// DCAFilterWalker.g:43:4: ^( LT a= compop b= compop )
					{
					match(input,LT,FOLLOW_LT_in_comparison414); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_compop_in_comparison418);
					a=compop();
					state._fsp--;

					pushFollow(FOLLOW_compop_in_comparison422);
					b=compop();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new IntGE(b,a); 
					}
					break;
				case 6 :
					// DCAFilterWalker.g:44:4: ^( LE a= compop b= compop )
					{
					match(input,LE,FOLLOW_LE_in_comparison431); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_compop_in_comparison435);
					a=compop();
					state._fsp--;

					pushFollow(FOLLOW_compop_in_comparison439);
					b=compop();
					state._fsp--;

					match(input, Token.UP, null); 

					e = new IntGT(b,a); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return e;
	}
	// $ANTLR end "comparison"

	// Delegated rules



	public static final BitSet FOLLOW_boolExpr_in_start_rule36 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OR_in_boolExpr53 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_boolExpr_in_boolExpr57 = new BitSet(new long[]{0x0000000000FCDE10L});
	public static final BitSet FOLLOW_boolExpr_in_boolExpr61 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_AND_in_boolExpr71 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_boolExpr_in_boolExpr75 = new BitSet(new long[]{0x0000000000FCDE10L});
	public static final BitSet FOLLOW_boolExpr_in_boolExpr79 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_NOT_in_boolExpr88 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_boolExpr_in_boolExpr92 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_TRUE_in_boolExpr111 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FALSE_in_boolExpr142 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ISREAD_in_boolExpr172 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ISWRITE_in_boolExpr201 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_comparison_in_boolExpr229 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_Accsize_in_intvar263 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_Accea_in_intvar270 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_Insea_in_intvar279 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_HEX_in_constant298 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_DEC_in_constant305 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constant_in_compop321 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_intvar_in_compop328 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_EQ_in_comparison346 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_compop_in_comparison350 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison354 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_NE_in_comparison363 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_compop_in_comparison367 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison371 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_GT_in_comparison380 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_compop_in_comparison384 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison388 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_GE_in_comparison397 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_compop_in_comparison401 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison405 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_LT_in_comparison414 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_compop_in_comparison418 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison422 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_LE_in_comparison431 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_compop_in_comparison435 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison439 = new BitSet(new long[]{0x0000000000000008L});
}
