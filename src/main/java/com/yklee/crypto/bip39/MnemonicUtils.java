package com.yklee.crypto.bip39;

import com.yklee.crypto.bip39.wordlist.English;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 니모닉 유틸리티
 *
 * @see <a href="http://wiki.hash.kr/index.php/BIP39">...</a>
 */
public class MnemonicUtils {

	/**
	 * 니모닉 생성
	 *
	 * 1. 128bit 엔트로피 생성
	 * 2. 엔트로피를 SHA-256 으로 해싱하여 앞에서 4비트를 추출(128 / 32)
	 * 3. 엔트로피(128) + 체크섬비트(4) 결합
	 * 4. 11비트 단위로 분할하여 12개의 결과를 생성
	 * 5. 각 11비트를 2048(2^11)개의 기 정의된 단어로 치환
	 *
	 */
	public List<String> generateMnemonic() {
		return generateMnemonic(128);
	}

	/**
	 * 니모닉 생성
	 */
	public List<String> generateMnemonic(int strength) {
		// 32비트로 구성되어야 함
		if(strength % 32 != 0) {
			throw new RuntimeException("INVALID_ENTROPY");
		}
		// 랜덤생성
		byte[] entropyArr = new byte[strength / 8];
		new Random().nextBytes(entropyArr);

		return entropyToMnemonic(entropyArr);
	}

	/**
	 * 엔트로피 정보를 이용하여 니모닉으로 변환
	 */
	public List<String> entropyToMnemonic(byte[] entropy) {
		// 엔트로피를 비트로 변환
		String entropyBits = bytesToBinary(entropy);
		// 체크섬 생성
		String checksumBits = deriveChecksumBits(entropy);

		// 엔트로피 비트 + 체크섬
		String bits = entropyBits + checksumBits;

		// 11 비트 단위로 분류
		Pattern pattern = Pattern.compile("(.{1,11})");
		Matcher matcher = pattern.matcher(bits);
		List<String> chunks = new ArrayList<>();

		while(matcher.find()) {
			chunks.add(matcher.group());
		}

		// 각각의 11비트를 2048(2^11)개의 정의된 단어로 치환
		List<String> mnemonic = new ArrayList<>();
		for(String chunk : chunks) {
			mnemonic.add(English.WORD_LIST.get(Integer.parseInt(chunk, 2)));
		}

		return mnemonic;
	}

	/**
	 * 니모닉 to 엔트로피
	 *
	 */
	public String mnemonicToEntropy(List<String> mnemonic) {
		if(mnemonic.size() % 3 != 0) {
			throw new RuntimeException("INVALID_MNEMONIC");
		}

		String bits = mnemonic.stream().map(word -> {
			int idx = English.WORD_LIST.indexOf(word);
			if(idx == -1) {
				throw new RuntimeException("INVALID_MNEMONIC");
			}
			return String.format("%11s", Integer.toBinaryString(idx)).replace(" ", "0");
		}).collect(Collectors.joining());

		// split the binary string into ENT/CS
		int dividerIndex = (int)Math.floor((double) bits.length() / 33) * 32;
		String entropyBits = bits.substring(0, dividerIndex);
		String checksumBits = bits.substring(dividerIndex);

		Pattern pattern = Pattern.compile("(.{1,8})");
		Matcher matcher = pattern.matcher(entropyBits);

		List<String> binaryList = new ArrayList<>();
		while(matcher.find()) {
			binaryList.add(matcher.group());
		}

		byte[] entropyBytes = binaryToByte(binaryList);
		if(entropyBytes.length < 16 ||
				entropyBytes.length > 32 ||
				entropyBytes.length % 4 != 0 ) {
			throw new RuntimeException("INVALID_ENTROPY");
		}

		String newChecksumBits = deriveChecksumBits(entropyBytes);
		if(!newChecksumBits.equals(checksumBits)) {
			throw new RuntimeException("INVALID_CHECKSUM");
		}

		// seed 변환
		return new java.math.BigInteger(entropyBytes).toString(16);
	}

	/**
	 * 선택적 암호문
	 *
	 * BIP39는 시드 생성에서 선택적 암호문(passphrase) 사용이 가능하다.
	 * 만약 암호문을 설정하지 않았다면 니모닉은 상수 문자열 'mnemonic'과 함께 솔트를 구성하여 연장되고,
	 * 주어진 니모닉으로부터 특정한 512비트 시드를 생성한다
	 *
	 */
	public String mnemonicToSeed(List<String> mnemonic, String password) {
		String mnemonicStr = Normalizer.normalize(mnemonic.stream().collect(Collectors.joining(" ")), Normalizer.Form.NFKD);
		String salt = "mnemonic" + Normalizer.normalize(password != null ? password : "", Normalizer.Form.NFKD);

		KeySpec keySpec = new PBEKeySpec(mnemonicStr.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 2048, 64);

		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			byte[] hash  = factory.generateSecret(keySpec).getEncoded();

			return bytesToBinary(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	public boolean validateMnemonic(List<String> mnemonic) {
		try {
			mnemonicToEntropy(mnemonic);
		}catch (Exception e) {
			return false;
		}
		return true;
	}

	private byte[] binaryToByte(List<String> binaryList) {
		byte[] bytes = new byte[binaryList.size()];
		int idx = 0;

		for(String bin: binaryList) {
			int decimal = Integer.parseInt(bin, 2);
			String hex = String.format("%2s", Integer.toHexString(decimal)).replace(" ", "0");
			bytes[idx] = hexToByte(hex);
			idx++;
		}

		return bytes;
	}

	private byte hexToByte(String hexString) {
		int firstDigit = toDigit(hexString.charAt(0));
		int secondDigit = toDigit(hexString.charAt(1));
		return (byte) ((firstDigit << 4) + secondDigit);
	}

	private int toDigit(char hexChar) {
		int digit = Character.digit(hexChar, 16);
		if(digit == -1) {
			throw new IllegalArgumentException(
					"Invalid Hexadecimal Character: "+ hexChar);
		}
		return digit;
	}

	/**
	 * 바이트를 2진수 문자열로 변환
	 *
	 * TODO :: 개선 필요
	 * String hexText = new java.math.BigInteger(bytes).toString(16);
	 */
	private String bytesToBinary(byte[] bytes) {
		StringBuilder builder = new StringBuilder();

		for(byte b: bytes) {
			// byte to hex
			String hex = String.format("%02x", b);
			// hex to decimal
			int decimal = Integer.parseInt(hex, 16);
			// decimal to binary
			builder.append(String.format("%8s", Integer.toBinaryString(decimal)).replace(" ", "0"));
		}
		return builder.toString();
	}

	/**
	 * 체크섬 비트 생성
	 *
	 * 1. 엔트로피를 SHA-256 으로 해싱
	 * 2. 해싱데이터에서 (엔트로피 길이 / 32)비트를 추출하여 체크섬 생성
	 */
	private String deriveChecksumBits(byte[] entropy) {
		int ent = entropy.length * 8;
		int cs = ent / 32;

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(entropy);
			byte[] hash = md.digest();

			return bytesToBinary(hash).substring(0, cs);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) {
		MnemonicUtils m = new MnemonicUtils();
		List<String> mnemonic = m.generateMnemonic();
		System.out.println(mnemonic);
	}
}
