package ghidra.pal.wbc;

class FirstSubBytesOutput extends RuntimeException {
	byte[] AfterSubBytes;
	public FirstSubBytesOutput(byte[] interim) {
		AfterSubBytes = interim;
	}
}

public class AESGuess extends AES {
	void AfterSubBytes() {
		AfterInvSubBytes();
	}
	void AfterInvSubBytes() {
		byte[] interim = new byte[16];
		System.arraycopy(m_IntermediateState, 0, interim, 0, 16);
		throw new FirstSubBytesOutput(interim);
	}
	byte[] EncryptionGenerateGuessForByte(byte[] Plaintext, int byteNum, byte sK, int Alg) {
		byte[] key = new byte[16];
		key[byteNum] = sK;
		try {
			FirstEncrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes;
		}
		return null;
	}

	byte[] EncryptionGenerateGuessForAllBytes(byte[] Plaintext, byte sK, int Alg) {
		byte[] key = new byte[16];
		for(int i = 0; i < 16; i++)
			key[i] = sK;
		try {
			FirstEncrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes;
		}
		return null;
	}

	byte[] DecryptionGenerateGuessForByte(byte[] Plaintext, int byteNum, byte sK, int Alg) {
		byte[] key = new byte[16];
		key[byteNum] = sK;
		try {
			FirstDecrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes;
		}
		return null;
	}

	byte[] DecryptionGenerateGuessForAllBytes(byte[] Plaintext, byte sK, int Alg) {
		byte[] key = new byte[16];
		for(int i = 0; i < 16; i++)
			key[i] = sK;
		try {
			FirstDecrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes;
		}
		return null;
	}
}
