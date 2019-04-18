package rsa;

import java.io.File;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

/**
 * RSA数字签名算法
 * 
 * @author 23853
 *
 */
public class TestRSA {

	private static final String data = "ten tears";

	public static void main(String[] args) {
		jdkRSA();
	}

	public static void jdkRSA() {

		try {
			// 1.初始化密钥
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(512);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			// 获取公钥
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			// 获取密钥
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

			// 2.执行签名
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Signature signature = Signature.getInstance("MD5withRSA");
			signature.initSign(privateKey);
			signature.update(data.getBytes());

			byte[] result = signature.sign();
			System.out.println(result.length);
			System.out.println("JDK rsa 签名:" + DatatypeConverter.printHexBinary(result));

			// 验证签名
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			System.out.println(publicKey.getAlgorithm());
			signature = Signature.getInstance("MD5withRSA");
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
