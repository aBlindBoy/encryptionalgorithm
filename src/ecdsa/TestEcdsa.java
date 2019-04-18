package ecdsa;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

public class TestEcdsa {

	
	private static final String data = "ten tears";

	public static void main(String[] args) {
		jdkECDSA();
	}

	public static void jdkECDSA() {

		try {
			// 1.初始化密钥
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
			keyPairGenerator.initialize(112);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			// 获取公钥
			ECPublicKey dsaPublicKey = (ECPublicKey) keyPair.getPublic();
			// 获取密钥
			ECPrivateKey dsaPrivateKey = (ECPrivateKey) keyPair.getPrivate();

			// 2.执行签名
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Signature signature = Signature.getInstance("SHA1withECDSA");
			signature.initSign(privateKey);
			signature.update(data.getBytes());

			byte[] result = signature.sign();
			System.out.println("签名长度:" + result.length);
			System.out.println("JDK dsa 签名:" + DatatypeConverter.printHexBinary(result));

			// 验证签名
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dsaPublicKey.getEncoded());
			keyFactory = KeyFactory.getInstance("EC");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			System.out.println(publicKey.getAlgorithm());
			signature = Signature.getInstance("SHA1withECDSA");
			signature.initVerify(publicKey);
			signature.update(data.getBytes());
			boolean boo = signature.verify(result);
			System.out.println("验证签名" + boo);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
