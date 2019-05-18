package ghidra.pal.parsers.dcafilter.grammar;
// $ANTLR 3.5.2 DCAFilter.g 2019-05-17 23:26:23

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

import org.antlr.runtime.tree.*;


@SuppressWarnings("all")
public class DCAFilterParser extends Parser {
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
	public Parser[] getDelegates() {
		return new Parser[] {};
	}

	// delegators


	public DCAFilterParser(TokenStream input) {
		this(input, new RecognizerSharedState());
	}
	public DCAFilterParser(TokenStream input, RecognizerSharedState state) {
		super(input, state);
	}

	protected TreeAdaptor adaptor = new CommonTreeAdaptor();

	public void setTreeAdaptor(TreeAdaptor adaptor) {
		this.adaptor = adaptor;
	}
	public TreeAdaptor getTreeAdaptor() {
		return adaptor;
	}
	@Override public String[] getTokenNames() { return DCAFilterParser.tokenNames; }
	@Override public String getGrammarFileName() { return "DCAFilter.g"; }


	public static class start_rule_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "start_rule"
	// DCAFilter.g:9:1: start_rule : boolExpr EOF -> boolExpr ;
	public final DCAFilterParser.start_rule_return start_rule() throws RecognitionException {
		DCAFilterParser.start_rule_return retval = new DCAFilterParser.start_rule_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token EOF2=null;
		ParserRuleReturnScope boolExpr1 =null;

		Object EOF2_tree=null;
		RewriteRuleTokenStream stream_EOF=new RewriteRuleTokenStream(adaptor,"token EOF");
		RewriteRuleSubtreeStream stream_boolExpr=new RewriteRuleSubtreeStream(adaptor,"rule boolExpr");

		try {
			// DCAFilter.g:10:2: ( boolExpr EOF -> boolExpr )
			// DCAFilter.g:10:4: boolExpr EOF
			{
			pushFollow(FOLLOW_boolExpr_in_start_rule34);
			boolExpr1=boolExpr();
			state._fsp--;

			stream_boolExpr.add(boolExpr1.getTree());
			EOF2=(Token)match(input,EOF,FOLLOW_EOF_in_start_rule36);  
			stream_EOF.add(EOF2);

			// AST REWRITE
			// elements: boolExpr
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (Object)adaptor.nil();
			// 10:17: -> boolExpr
			{
				adaptor.addChild(root_0, stream_boolExpr.nextTree());
			}


			retval.tree = root_0;

			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "start_rule"


	public static class boolExpr_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "boolExpr"
	// DCAFilter.g:15:1: boolExpr : boolExprOr ;
	public final DCAFilterParser.boolExpr_return boolExpr() throws RecognitionException {
		DCAFilterParser.boolExpr_return retval = new DCAFilterParser.boolExpr_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		ParserRuleReturnScope boolExprOr3 =null;


		try {
			// DCAFilter.g:15:10: ( boolExprOr )
			// DCAFilter.g:15:12: boolExprOr
			{
			root_0 = (Object)adaptor.nil();


			pushFollow(FOLLOW_boolExprOr_in_boolExpr63);
			boolExprOr3=boolExprOr();
			state._fsp--;

			adaptor.addChild(root_0, boolExprOr3.getTree());

			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "boolExpr"


	public static class boolExprOr_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "boolExprOr"
	// DCAFilter.g:17:1: boolExprOr : boolExprAnd ( OR ^ boolExprAnd )* ;
	public final DCAFilterParser.boolExprOr_return boolExprOr() throws RecognitionException {
		DCAFilterParser.boolExprOr_return retval = new DCAFilterParser.boolExprOr_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token OR5=null;
		ParserRuleReturnScope boolExprAnd4 =null;
		ParserRuleReturnScope boolExprAnd6 =null;

		Object OR5_tree=null;

		try {
			// DCAFilter.g:18:3: ( boolExprAnd ( OR ^ boolExprAnd )* )
			// DCAFilter.g:18:3: boolExprAnd ( OR ^ boolExprAnd )*
			{
			root_0 = (Object)adaptor.nil();


			pushFollow(FOLLOW_boolExprAnd_in_boolExprOr71);
			boolExprAnd4=boolExprAnd();
			state._fsp--;

			adaptor.addChild(root_0, boolExprAnd4.getTree());

			// DCAFilter.g:18:15: ( OR ^ boolExprAnd )*
			loop1:
			while (true) {
				int alt1=2;
				int LA1_0 = input.LA(1);
				if ( (LA1_0==OR) ) {
					alt1=1;
				}

				switch (alt1) {
				case 1 :
					// DCAFilter.g:18:16: OR ^ boolExprAnd
					{
					OR5=(Token)match(input,OR,FOLLOW_OR_in_boolExprOr74); 
					OR5_tree = (Object)adaptor.create(OR5);
					root_0 = (Object)adaptor.becomeRoot(OR5_tree, root_0);

					pushFollow(FOLLOW_boolExprAnd_in_boolExprOr77);
					boolExprAnd6=boolExprAnd();
					state._fsp--;

					adaptor.addChild(root_0, boolExprAnd6.getTree());

					}
					break;

				default :
					break loop1;
				}
			}

			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "boolExprOr"


	public static class boolExprAnd_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "boolExprAnd"
	// DCAFilter.g:20:1: boolExprAnd : boolExprNot ( AND ^ boolExprNot )* ;
	public final DCAFilterParser.boolExprAnd_return boolExprAnd() throws RecognitionException {
		DCAFilterParser.boolExprAnd_return retval = new DCAFilterParser.boolExprAnd_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token AND8=null;
		ParserRuleReturnScope boolExprNot7 =null;
		ParserRuleReturnScope boolExprNot9 =null;

		Object AND8_tree=null;

		try {
			// DCAFilter.g:21:3: ( boolExprNot ( AND ^ boolExprNot )* )
			// DCAFilter.g:21:3: boolExprNot ( AND ^ boolExprNot )*
			{
			root_0 = (Object)adaptor.nil();


			pushFollow(FOLLOW_boolExprNot_in_boolExprAnd87);
			boolExprNot7=boolExprNot();
			state._fsp--;

			adaptor.addChild(root_0, boolExprNot7.getTree());

			// DCAFilter.g:21:15: ( AND ^ boolExprNot )*
			loop2:
			while (true) {
				int alt2=2;
				int LA2_0 = input.LA(1);
				if ( (LA2_0==AND) ) {
					alt2=1;
				}

				switch (alt2) {
				case 1 :
					// DCAFilter.g:21:16: AND ^ boolExprNot
					{
					AND8=(Token)match(input,AND,FOLLOW_AND_in_boolExprAnd90); 
					AND8_tree = (Object)adaptor.create(AND8);
					root_0 = (Object)adaptor.becomeRoot(AND8_tree, root_0);

					pushFollow(FOLLOW_boolExprNot_in_boolExprAnd93);
					boolExprNot9=boolExprNot();
					state._fsp--;

					adaptor.addChild(root_0, boolExprNot9.getTree());

					}
					break;

				default :
					break loop2;
				}
			}

			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "boolExprAnd"


	public static class boolExprNot_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "boolExprNot"
	// DCAFilter.g:23:1: boolExprNot : ( NOT ^ boolExprTerm | boolExprTerm );
	public final DCAFilterParser.boolExprNot_return boolExprNot() throws RecognitionException {
		DCAFilterParser.boolExprNot_return retval = new DCAFilterParser.boolExprNot_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token NOT10=null;
		ParserRuleReturnScope boolExprTerm11 =null;
		ParserRuleReturnScope boolExprTerm12 =null;

		Object NOT10_tree=null;

		try {
			// DCAFilter.g:24:3: ( NOT ^ boolExprTerm | boolExprTerm )
			int alt3=2;
			int LA3_0 = input.LA(1);
			if ( (LA3_0==NOT) ) {
				alt3=1;
			}
			else if ( ((LA3_0 >= Accea && LA3_0 <= Accsize)||LA3_0==DEC||LA3_0==FALSE||(LA3_0 >= HEX && LA3_0 <= Insea)||LA3_0==TRUE||LA3_0==25) ) {
				alt3=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}

			switch (alt3) {
				case 1 :
					// DCAFilter.g:24:3: NOT ^ boolExprTerm
					{
					root_0 = (Object)adaptor.nil();


					NOT10=(Token)match(input,NOT,FOLLOW_NOT_in_boolExprNot103); 
					NOT10_tree = (Object)adaptor.create(NOT10);
					root_0 = (Object)adaptor.becomeRoot(NOT10_tree, root_0);

					pushFollow(FOLLOW_boolExprTerm_in_boolExprNot106);
					boolExprTerm11=boolExprTerm();
					state._fsp--;

					adaptor.addChild(root_0, boolExprTerm11.getTree());

					}
					break;
				case 2 :
					// DCAFilter.g:25:3: boolExprTerm
					{
					root_0 = (Object)adaptor.nil();


					pushFollow(FOLLOW_boolExprTerm_in_boolExprNot110);
					boolExprTerm12=boolExprTerm();
					state._fsp--;

					adaptor.addChild(root_0, boolExprTerm12.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "boolExprNot"


	public static class boolExprTerm_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "boolExprTerm"
	// DCAFilter.g:27:1: boolExprTerm : ( '(' boolExprOr ')' -> boolExprOr | TRUE | FALSE | ISWRITE | ISREAD | comparison );
	public final DCAFilterParser.boolExprTerm_return boolExprTerm() throws RecognitionException {
		DCAFilterParser.boolExprTerm_return retval = new DCAFilterParser.boolExprTerm_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token char_literal13=null;
		Token char_literal15=null;
		Token TRUE16=null;
		Token FALSE17=null;
		Token ISWRITE18=null;
		Token ISREAD19=null;
		ParserRuleReturnScope boolExprOr14 =null;
		ParserRuleReturnScope comparison20 =null;

		Object char_literal13_tree=null;
		Object char_literal15_tree=null;
		Object TRUE16_tree=null;
		Object FALSE17_tree=null;
		Object ISWRITE18_tree=null;
		Object ISREAD19_tree=null;
		RewriteRuleTokenStream stream_25=new RewriteRuleTokenStream(adaptor,"token 25");
		RewriteRuleTokenStream stream_26=new RewriteRuleTokenStream(adaptor,"token 26");
		RewriteRuleSubtreeStream stream_boolExprOr=new RewriteRuleSubtreeStream(adaptor,"rule boolExprOr");

		try {
			// DCAFilter.g:28:3: ( '(' boolExprOr ')' -> boolExprOr | TRUE | FALSE | ISWRITE | ISREAD | comparison )
			int alt4=6;
			switch ( input.LA(1) ) {
			case 25:
				{
				alt4=1;
				}
				break;
			case TRUE:
				{
				alt4=2;
				}
				break;
			case FALSE:
				{
				alt4=3;
				}
				break;
			case ISWRITE:
				{
				alt4=4;
				}
				break;
			case ISREAD:
				{
				alt4=5;
				}
				break;
			case Accea:
			case Accsize:
			case DEC:
			case HEX:
			case Insea:
				{
				alt4=6;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}
			switch (alt4) {
				case 1 :
					// DCAFilter.g:28:3: '(' boolExprOr ')'
					{
					char_literal13=(Token)match(input,25,FOLLOW_25_in_boolExprTerm118);  
					stream_25.add(char_literal13);

					pushFollow(FOLLOW_boolExprOr_in_boolExprTerm120);
					boolExprOr14=boolExprOr();
					state._fsp--;

					stream_boolExprOr.add(boolExprOr14.getTree());
					char_literal15=(Token)match(input,26,FOLLOW_26_in_boolExprTerm122);  
					stream_26.add(char_literal15);

					// AST REWRITE
					// elements: boolExprOr
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (Object)adaptor.nil();
					// 28:22: -> boolExprOr
					{
						adaptor.addChild(root_0, stream_boolExprOr.nextTree());
					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// DCAFilter.g:29:3: TRUE
					{
					root_0 = (Object)adaptor.nil();


					TRUE16=(Token)match(input,TRUE,FOLLOW_TRUE_in_boolExprTerm130); 
					TRUE16_tree = (Object)adaptor.create(TRUE16);
					adaptor.addChild(root_0, TRUE16_tree);

					}
					break;
				case 3 :
					// DCAFilter.g:30:3: FALSE
					{
					root_0 = (Object)adaptor.nil();


					FALSE17=(Token)match(input,FALSE,FOLLOW_FALSE_in_boolExprTerm134); 
					FALSE17_tree = (Object)adaptor.create(FALSE17);
					adaptor.addChild(root_0, FALSE17_tree);

					}
					break;
				case 4 :
					// DCAFilter.g:31:3: ISWRITE
					{
					root_0 = (Object)adaptor.nil();


					ISWRITE18=(Token)match(input,ISWRITE,FOLLOW_ISWRITE_in_boolExprTerm138); 
					ISWRITE18_tree = (Object)adaptor.create(ISWRITE18);
					adaptor.addChild(root_0, ISWRITE18_tree);

					}
					break;
				case 5 :
					// DCAFilter.g:32:3: ISREAD
					{
					root_0 = (Object)adaptor.nil();


					ISREAD19=(Token)match(input,ISREAD,FOLLOW_ISREAD_in_boolExprTerm142); 
					ISREAD19_tree = (Object)adaptor.create(ISREAD19);
					adaptor.addChild(root_0, ISREAD19_tree);

					}
					break;
				case 6 :
					// DCAFilter.g:33:3: comparison
					{
					root_0 = (Object)adaptor.nil();


					pushFollow(FOLLOW_comparison_in_boolExprTerm146);
					comparison20=comparison();
					state._fsp--;

					adaptor.addChild(root_0, comparison20.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "boolExprTerm"


	public static class constant_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "constant"
	// DCAFilter.g:36:1: constant : ( HEX | DEC );
	public final DCAFilterParser.constant_return constant() throws RecognitionException {
		DCAFilterParser.constant_return retval = new DCAFilterParser.constant_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token set21=null;

		Object set21_tree=null;

		try {
			// DCAFilter.g:36:10: ( HEX | DEC )
			// DCAFilter.g:
			{
			root_0 = (Object)adaptor.nil();


			set21=input.LT(1);
			if ( input.LA(1)==DEC||input.LA(1)==HEX ) {
				input.consume();
				adaptor.addChild(root_0, (Object)adaptor.create(set21));
				state.errorRecovery=false;
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				throw mse;
			}
			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constant"


	public static class relop_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "relop"
	// DCAFilter.g:45:1: relop : ( EQ | NE | GE | GT | LE | LT );
	public final DCAFilterParser.relop_return relop() throws RecognitionException {
		DCAFilterParser.relop_return retval = new DCAFilterParser.relop_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token set22=null;

		Object set22_tree=null;

		try {
			// DCAFilter.g:45:7: ( EQ | NE | GE | GT | LE | LT )
			// DCAFilter.g:
			{
			root_0 = (Object)adaptor.nil();


			set22=input.LT(1);
			if ( input.LA(1)==EQ||(input.LA(1) >= GE && input.LA(1) <= GT)||(input.LA(1) >= LE && input.LA(1) <= NE) ) {
				input.consume();
				adaptor.addChild(root_0, (Object)adaptor.create(set22));
				state.errorRecovery=false;
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				throw mse;
			}
			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "relop"


	public static class intvar_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "intvar"
	// DCAFilter.g:51:1: intvar : ( Accsize | Accea | Insea );
	public final DCAFilterParser.intvar_return intvar() throws RecognitionException {
		DCAFilterParser.intvar_return retval = new DCAFilterParser.intvar_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		Token set23=null;

		Object set23_tree=null;

		try {
			// DCAFilter.g:51:8: ( Accsize | Accea | Insea )
			// DCAFilter.g:
			{
			root_0 = (Object)adaptor.nil();


			set23=input.LT(1);
			if ( (input.LA(1) >= Accea && input.LA(1) <= Accsize)||input.LA(1)==Insea ) {
				input.consume();
				adaptor.addChild(root_0, (Object)adaptor.create(set23));
				state.errorRecovery=false;
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				throw mse;
			}
			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "intvar"


	public static class compop_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "compop"
	// DCAFilter.g:53:1: compop : ( constant | intvar );
	public final DCAFilterParser.compop_return compop() throws RecognitionException {
		DCAFilterParser.compop_return retval = new DCAFilterParser.compop_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		ParserRuleReturnScope constant24 =null;
		ParserRuleReturnScope intvar25 =null;


		try {
			// DCAFilter.g:54:2: ( constant | intvar )
			int alt5=2;
			int LA5_0 = input.LA(1);
			if ( (LA5_0==DEC||LA5_0==HEX) ) {
				alt5=1;
			}
			else if ( ((LA5_0 >= Accea && LA5_0 <= Accsize)||LA5_0==Insea) ) {
				alt5=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 5, 0, input);
				throw nvae;
			}

			switch (alt5) {
				case 1 :
					// DCAFilter.g:54:4: constant
					{
					root_0 = (Object)adaptor.nil();


					pushFollow(FOLLOW_constant_in_compop278);
					constant24=constant();
					state._fsp--;

					adaptor.addChild(root_0, constant24.getTree());

					}
					break;
				case 2 :
					// DCAFilter.g:55:4: intvar
					{
					root_0 = (Object)adaptor.nil();


					pushFollow(FOLLOW_intvar_in_compop284);
					intvar25=intvar();
					state._fsp--;

					adaptor.addChild(root_0, intvar25.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "compop"


	public static class comparison_return extends ParserRuleReturnScope {
		Object tree;
		@Override
		public Object getTree() { return tree; }
	};


	// $ANTLR start "comparison"
	// DCAFilter.g:57:1: comparison : compop relop ^ compop ;
	public final DCAFilterParser.comparison_return comparison() throws RecognitionException {
		DCAFilterParser.comparison_return retval = new DCAFilterParser.comparison_return();
		retval.start = input.LT(1);

		Object root_0 = null;

		ParserRuleReturnScope compop26 =null;
		ParserRuleReturnScope relop27 =null;
		ParserRuleReturnScope compop28 =null;


		try {
			// DCAFilter.g:57:11: ( compop relop ^ compop )
			// DCAFilter.g:57:13: compop relop ^ compop
			{
			root_0 = (Object)adaptor.nil();


			pushFollow(FOLLOW_compop_in_comparison291);
			compop26=compop();
			state._fsp--;

			adaptor.addChild(root_0, compop26.getTree());

			pushFollow(FOLLOW_relop_in_comparison293);
			relop27=relop();
			state._fsp--;

			root_0 = (Object)adaptor.becomeRoot(relop27.getTree(), root_0);
			pushFollow(FOLLOW_compop_in_comparison296);
			compop28=compop();
			state._fsp--;

			adaptor.addChild(root_0, compop28.getTree());

			}

			retval.stop = input.LT(-1);

			retval.tree = (Object)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (Object)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "comparison"

	// Delegated rules



	public static final BitSet FOLLOW_boolExpr_in_start_rule34 = new BitSet(new long[]{0x0000000000000000L});
	public static final BitSet FOLLOW_EOF_in_start_rule36 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_boolExprOr_in_boolExpr63 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_boolExprAnd_in_boolExprOr71 = new BitSet(new long[]{0x0000000000400002L});
	public static final BitSet FOLLOW_OR_in_boolExprOr74 = new BitSet(new long[]{0x0000000002A1E560L});
	public static final BitSet FOLLOW_boolExprAnd_in_boolExprOr77 = new BitSet(new long[]{0x0000000000400002L});
	public static final BitSet FOLLOW_boolExprNot_in_boolExprAnd87 = new BitSet(new long[]{0x0000000000000012L});
	public static final BitSet FOLLOW_AND_in_boolExprAnd90 = new BitSet(new long[]{0x0000000002A1E560L});
	public static final BitSet FOLLOW_boolExprNot_in_boolExprAnd93 = new BitSet(new long[]{0x0000000000000012L});
	public static final BitSet FOLLOW_NOT_in_boolExprNot103 = new BitSet(new long[]{0x000000000281E560L});
	public static final BitSet FOLLOW_boolExprTerm_in_boolExprNot106 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_boolExprTerm_in_boolExprNot110 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_25_in_boolExprTerm118 = new BitSet(new long[]{0x0000000002A1E560L});
	public static final BitSet FOLLOW_boolExprOr_in_boolExprTerm120 = new BitSet(new long[]{0x0000000004000000L});
	public static final BitSet FOLLOW_26_in_boolExprTerm122 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TRUE_in_boolExprTerm130 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FALSE_in_boolExprTerm134 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ISWRITE_in_boolExprTerm138 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ISREAD_in_boolExprTerm142 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_comparison_in_boolExprTerm146 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constant_in_compop278 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_intvar_in_compop284 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_compop_in_comparison291 = new BitSet(new long[]{0x00000000001C1A00L});
	public static final BitSet FOLLOW_relop_in_comparison293 = new BitSet(new long[]{0x0000000000012160L});
	public static final BitSet FOLLOW_compop_in_comparison296 = new BitSet(new long[]{0x0000000000000002L});
}
