package ghidra.pal.parsers.dcafilter.grammar;
// $ANTLR 3.5.2 DCAFilter.g 2019-05-17 23:26:23

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class DCAFilterLexer extends Lexer {
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
	// delegators
	public Lexer[] getDelegates() {
		return new Lexer[] {};
	}

	public DCAFilterLexer() {} 
	public DCAFilterLexer(CharStream input) {
		this(input, new RecognizerSharedState());
	}
	public DCAFilterLexer(CharStream input, RecognizerSharedState state) {
		super(input,state);
	}
	@Override public String getGrammarFileName() { return "DCAFilter.g"; }

	// $ANTLR start "T__25"
	public final void mT__25() throws RecognitionException {
		try {
			int _type = T__25;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:2:7: ( '(' )
			// DCAFilter.g:2:9: '('
			{
			match('('); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "T__25"

	// $ANTLR start "T__26"
	public final void mT__26() throws RecognitionException {
		try {
			int _type = T__26;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:3:7: ( ')' )
			// DCAFilter.g:3:9: ')'
			{
			match(')'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "T__26"

	// $ANTLR start "ISWRITE"
	public final void mISWRITE() throws RecognitionException {
		try {
			int _type = ISWRITE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:12:9: ( 'IsWrite' )
			// DCAFilter.g:12:11: 'IsWrite'
			{
			match("IsWrite"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ISWRITE"

	// $ANTLR start "ISREAD"
	public final void mISREAD() throws RecognitionException {
		try {
			int _type = ISREAD;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:13:8: ( 'IsRead' )
			// DCAFilter.g:13:10: 'IsRead'
			{
			match("IsRead"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ISREAD"

	// $ANTLR start "EQ"
	public final void mEQ() throws RecognitionException {
		try {
			int _type = EQ;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:38:4: ( '==' )
			// DCAFilter.g:38:6: '=='
			{
			match("=="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "EQ"

	// $ANTLR start "NE"
	public final void mNE() throws RecognitionException {
		try {
			int _type = NE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:39:4: ( '!=' )
			// DCAFilter.g:39:6: '!='
			{
			match("!="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "NE"

	// $ANTLR start "GE"
	public final void mGE() throws RecognitionException {
		try {
			int _type = GE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:40:4: ( '>=' )
			// DCAFilter.g:40:6: '>='
			{
			match(">="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "GE"

	// $ANTLR start "GT"
	public final void mGT() throws RecognitionException {
		try {
			int _type = GT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:41:4: ( '>' )
			// DCAFilter.g:41:6: '>'
			{
			match('>'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "GT"

	// $ANTLR start "LE"
	public final void mLE() throws RecognitionException {
		try {
			int _type = LE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:42:4: ( '<=' )
			// DCAFilter.g:42:6: '<='
			{
			match("<="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LE"

	// $ANTLR start "LT"
	public final void mLT() throws RecognitionException {
		try {
			int _type = LT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:43:4: ( '<' )
			// DCAFilter.g:43:6: '<'
			{
			match('<'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LT"

	// $ANTLR start "Accsize"
	public final void mAccsize() throws RecognitionException {
		try {
			int _type = Accsize;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:47:9: ( 'AccessSize' )
			// DCAFilter.g:47:11: 'AccessSize'
			{
			match("AccessSize"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "Accsize"

	// $ANTLR start "Insea"
	public final void mInsea() throws RecognitionException {
		try {
			int _type = Insea;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:48:7: ( 'InsnEa' )
			// DCAFilter.g:48:9: 'InsnEa'
			{
			match("InsnEa"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "Insea"

	// $ANTLR start "Accea"
	public final void mAccea() throws RecognitionException {
		try {
			int _type = Accea;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:49:7: ( 'AccessEa' )
			// DCAFilter.g:49:9: 'AccessEa'
			{
			match("AccessEa"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "Accea"

	// $ANTLR start "TRUE"
	public final void mTRUE() throws RecognitionException {
		try {
			int _type = TRUE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:59:6: ( 'true' )
			// DCAFilter.g:59:8: 'true'
			{
			match("true"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "TRUE"

	// $ANTLR start "FALSE"
	public final void mFALSE() throws RecognitionException {
		try {
			int _type = FALSE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:60:6: ( 'false' )
			// DCAFilter.g:60:8: 'false'
			{
			match("false"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FALSE"

	// $ANTLR start "AND"
	public final void mAND() throws RecognitionException {
		try {
			int _type = AND;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:61:4: ( '&&' )
			// DCAFilter.g:61:6: '&&'
			{
			match("&&"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "AND"

	// $ANTLR start "OR"
	public final void mOR() throws RecognitionException {
		try {
			int _type = OR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:62:3: ( '||' )
			// DCAFilter.g:62:5: '||'
			{
			match("||"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OR"

	// $ANTLR start "NOT"
	public final void mNOT() throws RecognitionException {
		try {
			int _type = NOT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:63:4: ( '!' )
			// DCAFilter.g:63:6: '!'
			{
			match('!'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "NOT"

	// $ANTLR start "WS"
	public final void mWS() throws RecognitionException {
		try {
			int _type = WS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:64:4: ( ( ' ' | '\\t' | '\\r' | '\\n' )* )
			// DCAFilter.g:64:6: ( ' ' | '\\t' | '\\r' | '\\n' )*
			{
			// DCAFilter.g:64:6: ( ' ' | '\\t' | '\\r' | '\\n' )*
			loop1:
			while (true) {
				int alt1=2;
				int LA1_0 = input.LA(1);
				if ( ((LA1_0 >= '\t' && LA1_0 <= '\n')||LA1_0=='\r'||LA1_0==' ') ) {
					alt1=1;
				}

				switch (alt1) {
				case 1 :
					// DCAFilter.g:
					{
					if ( (input.LA(1) >= '\t' && input.LA(1) <= '\n')||input.LA(1)=='\r'||input.LA(1)==' ' ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					break loop1;
				}
			}

			_channel=HIDDEN;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "WS"

	// $ANTLR start "HEX"
	public final void mHEX() throws RecognitionException {
		try {
			int _type = HEX;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:65:5: ( '0x' ( 'a' .. 'f' | 'A' .. 'F' | '0' .. '9' )+ )
			// DCAFilter.g:65:7: '0x' ( 'a' .. 'f' | 'A' .. 'F' | '0' .. '9' )+
			{
			match("0x"); 

			// DCAFilter.g:65:12: ( 'a' .. 'f' | 'A' .. 'F' | '0' .. '9' )+
			int cnt2=0;
			loop2:
			while (true) {
				int alt2=2;
				int LA2_0 = input.LA(1);
				if ( ((LA2_0 >= '0' && LA2_0 <= '9')||(LA2_0 >= 'A' && LA2_0 <= 'F')||(LA2_0 >= 'a' && LA2_0 <= 'f')) ) {
					alt2=1;
				}

				switch (alt2) {
				case 1 :
					// DCAFilter.g:
					{
					if ( (input.LA(1) >= '0' && input.LA(1) <= '9')||(input.LA(1) >= 'A' && input.LA(1) <= 'F')||(input.LA(1) >= 'a' && input.LA(1) <= 'f') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt2 >= 1 ) break loop2;
					EarlyExitException eee = new EarlyExitException(2, input);
					throw eee;
				}
				cnt2++;
			}

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "HEX"

	// $ANTLR start "DEC"
	public final void mDEC() throws RecognitionException {
		try {
			int _type = DEC;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// DCAFilter.g:66:5: ( ( '0' .. '9' )+ )
			// DCAFilter.g:66:7: ( '0' .. '9' )+
			{
			// DCAFilter.g:66:7: ( '0' .. '9' )+
			int cnt3=0;
			loop3:
			while (true) {
				int alt3=2;
				int LA3_0 = input.LA(1);
				if ( ((LA3_0 >= '0' && LA3_0 <= '9')) ) {
					alt3=1;
				}

				switch (alt3) {
				case 1 :
					// DCAFilter.g:
					{
					if ( (input.LA(1) >= '0' && input.LA(1) <= '9') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt3 >= 1 ) break loop3;
					EarlyExitException eee = new EarlyExitException(3, input);
					throw eee;
				}
				cnt3++;
			}

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "DEC"

	@Override
	public void mTokens() throws RecognitionException {
		// DCAFilter.g:1:8: ( T__25 | T__26 | ISWRITE | ISREAD | EQ | NE | GE | GT | LE | LT | Accsize | Insea | Accea | TRUE | FALSE | AND | OR | NOT | WS | HEX | DEC )
		int alt4=21;
		switch ( input.LA(1) ) {
		case '(':
			{
			alt4=1;
			}
			break;
		case ')':
			{
			alt4=2;
			}
			break;
		case 'I':
			{
			int LA4_3 = input.LA(2);
			if ( (LA4_3=='s') ) {
				int LA4_16 = input.LA(3);
				if ( (LA4_16=='W') ) {
					alt4=3;
				}
				else if ( (LA4_16=='R') ) {
					alt4=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
							input.consume();
						}
						NoViableAltException nvae =
							new NoViableAltException("", 4, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}
			else if ( (LA4_3=='n') ) {
				alt4=12;
			}

			else {
				int nvaeMark = input.mark();
				try {
					input.consume();
					NoViableAltException nvae =
						new NoViableAltException("", 4, 3, input);
					throw nvae;
				} finally {
					input.rewind(nvaeMark);
				}
			}

			}
			break;
		case '=':
			{
			alt4=5;
			}
			break;
		case '!':
			{
			int LA4_5 = input.LA(2);
			if ( (LA4_5=='=') ) {
				alt4=6;
			}

			else {
				alt4=18;
			}

			}
			break;
		case '>':
			{
			int LA4_6 = input.LA(2);
			if ( (LA4_6=='=') ) {
				alt4=7;
			}

			else {
				alt4=8;
			}

			}
			break;
		case '<':
			{
			int LA4_7 = input.LA(2);
			if ( (LA4_7=='=') ) {
				alt4=9;
			}

			else {
				alt4=10;
			}

			}
			break;
		case 'A':
			{
			int LA4_8 = input.LA(2);
			if ( (LA4_8=='c') ) {
				int LA4_24 = input.LA(3);
				if ( (LA4_24=='c') ) {
					int LA4_28 = input.LA(4);
					if ( (LA4_28=='e') ) {
						int LA4_29 = input.LA(5);
						if ( (LA4_29=='s') ) {
							int LA4_30 = input.LA(6);
							if ( (LA4_30=='s') ) {
								int LA4_31 = input.LA(7);
								if ( (LA4_31=='S') ) {
									alt4=11;
								}
								else if ( (LA4_31=='E') ) {
									alt4=13;
								}

								else {
									int nvaeMark = input.mark();
									try {
										for (int nvaeConsume = 0; nvaeConsume < 7 - 1; nvaeConsume++) {
											input.consume();
										}
										NoViableAltException nvae =
											new NoViableAltException("", 4, 31, input);
										throw nvae;
									} finally {
										input.rewind(nvaeMark);
									}
								}

							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 6 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 4, 30, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 4, 29, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 4, 28, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
							input.consume();
						}
						NoViableAltException nvae =
							new NoViableAltException("", 4, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				int nvaeMark = input.mark();
				try {
					input.consume();
					NoViableAltException nvae =
						new NoViableAltException("", 4, 8, input);
					throw nvae;
				} finally {
					input.rewind(nvaeMark);
				}
			}

			}
			break;
		case 't':
			{
			alt4=14;
			}
			break;
		case 'f':
			{
			alt4=15;
			}
			break;
		case '&':
			{
			alt4=16;
			}
			break;
		case '|':
			{
			alt4=17;
			}
			break;
		case '0':
			{
			int LA4_14 = input.LA(2);
			if ( (LA4_14=='x') ) {
				alt4=20;
			}

			else {
				alt4=21;
			}

			}
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			{
			alt4=21;
			}
			break;
		default:
			alt4=19;
		}
		switch (alt4) {
			case 1 :
				// DCAFilter.g:1:10: T__25
				{
				mT__25(); 

				}
				break;
			case 2 :
				// DCAFilter.g:1:16: T__26
				{
				mT__26(); 

				}
				break;
			case 3 :
				// DCAFilter.g:1:22: ISWRITE
				{
				mISWRITE(); 

				}
				break;
			case 4 :
				// DCAFilter.g:1:30: ISREAD
				{
				mISREAD(); 

				}
				break;
			case 5 :
				// DCAFilter.g:1:37: EQ
				{
				mEQ(); 

				}
				break;
			case 6 :
				// DCAFilter.g:1:40: NE
				{
				mNE(); 

				}
				break;
			case 7 :
				// DCAFilter.g:1:43: GE
				{
				mGE(); 

				}
				break;
			case 8 :
				// DCAFilter.g:1:46: GT
				{
				mGT(); 

				}
				break;
			case 9 :
				// DCAFilter.g:1:49: LE
				{
				mLE(); 

				}
				break;
			case 10 :
				// DCAFilter.g:1:52: LT
				{
				mLT(); 

				}
				break;
			case 11 :
				// DCAFilter.g:1:55: Accsize
				{
				mAccsize(); 

				}
				break;
			case 12 :
				// DCAFilter.g:1:63: Insea
				{
				mInsea(); 

				}
				break;
			case 13 :
				// DCAFilter.g:1:69: Accea
				{
				mAccea(); 

				}
				break;
			case 14 :
				// DCAFilter.g:1:75: TRUE
				{
				mTRUE(); 

				}
				break;
			case 15 :
				// DCAFilter.g:1:80: FALSE
				{
				mFALSE(); 

				}
				break;
			case 16 :
				// DCAFilter.g:1:86: AND
				{
				mAND(); 

				}
				break;
			case 17 :
				// DCAFilter.g:1:90: OR
				{
				mOR(); 

				}
				break;
			case 18 :
				// DCAFilter.g:1:93: NOT
				{
				mNOT(); 

				}
				break;
			case 19 :
				// DCAFilter.g:1:97: WS
				{
				mWS(); 

				}
				break;
			case 20 :
				// DCAFilter.g:1:100: HEX
				{
				mHEX(); 

				}
				break;
			case 21 :
				// DCAFilter.g:1:104: DEC
				{
				mDEC(); 

				}
				break;

		}
	}



}
