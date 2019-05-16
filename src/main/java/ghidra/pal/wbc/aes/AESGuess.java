package ghidra.pal.wbc.aes;

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
	byte EncryptionGenerateGuessForByte(byte[] Plaintext, int byteNum, int sK, int Alg) {
		byte[] key = new byte[16];
		key[byteNum] = (byte)sK;
		try {
			FirstEncrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes[byteNum];
		}
		return 0;
	}

	byte[] EncryptionGenerateGuessForAllBytes(byte[] Plaintext, int sK, int Alg) {
		byte[] key = new byte[16];
		for(int i = 0; i < 16; i++)
			key[i] = (byte)sK;
		try {
			FirstEncrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes;
		}
		return null;
	}

	byte DecryptionGenerateGuessForByte(byte[] Plaintext, int byteNum, int sK, int Alg) {
		byte[] key = new byte[16];
		key[byteNum] = (byte)sK;
		try {
			FirstDecrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes[byteNum];
		}
		return 0;
	}

	byte[] DecryptionGenerateGuessForAllBytes(byte[] Plaintext, int sK, int Alg) {
		byte[] key = new byte[16];
		for(int i = 0; i < 16; i++)
			key[i] = (byte)sK;
		try {
			FirstDecrypt(key, Plaintext, Alg);			
		}
		catch (FirstSubBytesOutput e) {
			return e.AfterSubBytes;
		}
		return null;
	}
}
