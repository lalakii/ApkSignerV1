package com.android.signapk;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class SignApk {
	/**
	 * @author lalaki
	 */
	private static void writeSignatureBlock(Signature var0, X509Certificate var1, OutputStream var2)
			throws IOException, GeneralSecurityException {
		List<java.security.cert.Certificate> certList = new ArrayList<java.security.cert.Certificate>();
		certList.add(var1);
		final byte[] data = var0.sign();
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		try {
			generator.setDefiniteLengthEncoding(true);
			generator.addCertificates(new JcaCertStore(certList));
			generator.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
							.setDirectSignature(true).build(new ContentSigner() {

								@Override
								public byte[] getSignature() {
									return data;
								}

								@Override
								public OutputStream getOutputStream() {
									return new ByteArrayOutputStream();
								}

								@Override
								public AlgorithmIdentifier getAlgorithmIdentifier() {
									return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSA");
								}

							}, var1));
			var2.write(generator.generate(new CMSProcessableByteArray(new byte[0]), true).getEncoded());
		} catch (OperatorCreationException | CMSException e) {
			e.printStackTrace();
		}
	}

	private static Pattern stripPattern = Pattern.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");

	private static X509Certificate readPublicKey(File var0) throws IOException, GeneralSecurityException {
		FileInputStream var1 = new FileInputStream(var0);

		X509Certificate var3;
		try {
			CertificateFactory var2 = CertificateFactory.getInstance("X.509");
			var3 = (X509Certificate) var2.generateCertificate(var1);
		} finally {
			var1.close();
		}

		return var3;
	}

	private static String readPassword(File var0) {
		System.out.print("Enter password for " + var0 + " (password will not be hidden): ");
		System.out.flush();
		BufferedReader var1 = new BufferedReader(new InputStreamReader(System.in));

		try {
			return var1.readLine();
		} catch (IOException var3) {
			return null;
		}
	}

	private static KeySpec decryptPrivateKey(byte[] var0, File var1) throws GeneralSecurityException {
		EncryptedPrivateKeyInfo var2;
		try {
			var2 = new EncryptedPrivateKeyInfo(var0);
		} catch (IOException var9) {
			return null;
		}

		char[] var3 = readPassword(var1).toCharArray();
		SecretKeyFactory var4 = SecretKeyFactory.getInstance(var2.getAlgName());
		SecretKey var5 = var4.generateSecret(new PBEKeySpec(var3));
		Cipher var6 = Cipher.getInstance(var2.getAlgName());
		var6.init(2, var5, var2.getAlgParameters());

		try {
			return var2.getKeySpec(var6);
		} catch (InvalidKeySpecException var8) {
			System.err.println("signapk: Password for " + var1 + " may be bad.");
			throw var8;
		}
	}

	private static PrivateKey readPrivateKey(File var0) throws IOException, GeneralSecurityException {
		DataInputStream var1 = new DataInputStream(new FileInputStream(var0));

		PrivateKey var5;
		try {
			byte[] var2 = new byte[(int) var0.length()];
			var1.read(var2);
			Object var3 = decryptPrivateKey(var2, var0);
			if (var3 == null) {
				var3 = new PKCS8EncodedKeySpec(var2);
			}

			try {
				PrivateKey var4 = KeyFactory.getInstance("RSA").generatePrivate((KeySpec) var3);
				return var4;
			} catch (InvalidKeySpecException var9) {
				var5 = KeyFactory.getInstance("DSA").generatePrivate((KeySpec) var3);
			}
		} finally {
			var1.close();
		}

		return var5;
	}

	private static Manifest addDigestsToManifest(JarFile var0) throws IOException, GeneralSecurityException {
		Manifest var1 = var0.getManifest();
		Manifest var2 = new Manifest();
		Attributes var3 = var2.getMainAttributes();
		if (var1 != null) {
			var3.putAll(var1.getMainAttributes());
		} else {
			var3.putValue("Manifest-Version", "1.0");
			var3.putValue("Created-By", "1.0 (Android SignApk)");
		}

		Encoder encoder = Base64.getEncoder();
		MessageDigest var5 = MessageDigest.getInstance("SHA1");
		byte[] var6 = new byte[4096];
		TreeMap<String, JarEntry> var8 = new TreeMap<String, JarEntry>();
		Enumeration<JarEntry> var9 = var0.entries();

		JarEntry var10;
		while (var9.hasMoreElements()) {
			var10 = (JarEntry) var9.nextElement();
			var8.put(var10.getName(), var10);
		}

		Iterator<JarEntry> var14 = var8.values().iterator();

		while (true) {
			String var11;
			do {
				do {
					do {
						do {
							do {
								if (!var14.hasNext()) {
									return var2;
								}

								var10 = (JarEntry) var14.next();
								var11 = var10.getName();
							} while (var10.isDirectory());
						} while (var11.equals("META-INF/MANIFEST.MF"));
					} while (var11.equals("META-INF/CERT.SF"));
				} while (var11.equals("META-INF/CERT.RSA"));
			} while (stripPattern != null && stripPattern.matcher(var11).matches());

			InputStream var12 = var0.getInputStream(var10);

			int var7;
			while ((var7 = var12.read(var6)) > 0) {
				var5.update(var6, 0, var7);
			}

			Attributes var13 = null;
			if (var1 != null) {
				var13 = var1.getAttributes(var11);
			}

			var13 = var13 != null ? new Attributes(var13) : new Attributes();
			var13.putValue("SHA1-Digest", encoder.encodeToString(var5.digest()));
			var2.getEntries().put(var11, var13);
		}
	}

	private static void writeSignatureFile(Manifest var0, SignApk.SignatureOutputStream var1)
			throws IOException, GeneralSecurityException {
		Manifest var2 = new Manifest();
		Attributes var3 = var2.getMainAttributes();
		var3.putValue("Signature-Version", "1.0");
		var3.putValue("Created-By", "1.0 (Android SignApk)");
		Encoder var4 = Base64.getEncoder();
		MessageDigest var5 = MessageDigest.getInstance("SHA1");
		PrintStream var6 = new PrintStream(new DigestOutputStream(new ByteArrayOutputStream(), var5), true, "UTF-8");
		var0.write(var6);
		var6.flush();
		var3.putValue("SHA1-Digest-Manifest", var4.encodeToString(var5.digest()));
		Map<String, Attributes> var7 = var0.getEntries();
		Iterator<Entry<String, Attributes>> var8 = var7.entrySet().iterator();

		while (var8.hasNext()) {
			Entry<String, Attributes> var9 = (Entry<String, Attributes>) var8.next();
			var6.print("Name: " + (String) var9.getKey() + "\r\n");
			Iterator<Entry<Object, Object>> var10 = ((Attributes) var9.getValue()).entrySet().iterator();

			while (var10.hasNext()) {
				Entry<Object, Object> var11 = (Entry<Object, Object>) var10.next();
				var6.print(var11.getKey() + ": " + var11.getValue() + "\r\n");
			}

			var6.print("\r\n");
			var6.flush();
			Attributes var12 = new Attributes();
			var12.putValue("SHA1-Digest", var4.encodeToString(var5.digest()));
			var2.getEntries().put(var9.getKey().toString(), var12);
		}
		var2.write(var1);
		if (var1.size() % 1024 == 0) {
			var1.write(13);
			var1.write(10);
		}

	}

	private static void signWholeOutputFile(byte[] var0, OutputStream var1, X509Certificate var2, PrivateKey var3)
			throws IOException, GeneralSecurityException {
		if (var0[var0.length - 22] == 80 && var0[var0.length - 21] == 75 && var0[var0.length - 20] == 5
				&& var0[var0.length - 19] == 6) {
			Signature var4 = Signature.getInstance("SHA1withRSA");
			var4.initSign(var3);
			var4.update(var0, 0, var0.length - 2);
			ByteArrayOutputStream var5 = new ByteArrayOutputStream();
			byte[] var6 = "signed by SignApk".getBytes("UTF-8");
			var5.write(var6);
			var5.write(0);
			writeSignatureBlock(var4, var2, var5);
			int var7 = var5.size() + 6;
			if (var7 > 65535) {
				throw new IllegalArgumentException("signature is too big for ZIP file comment");
			} else {
				int var8 = var7 - var6.length - 1;
				var5.write(var8 & 255);
				var5.write(var8 >> 8 & 255);
				var5.write(255);
				var5.write(255);
				var5.write(var7 & 255);
				var5.write(var7 >> 8 & 255);
				var5.flush();
				byte[] var9 = var5.toByteArray();

				for (int var10 = 0; var10 < var9.length - 3; ++var10) {
					if (var9[var10] == 80 && var9[var10 + 1] == 75 && var9[var10 + 2] == 5 && var9[var10 + 3] == 6) {
						throw new IllegalArgumentException("found spurious EOCD header at " + var10);
					}
				}

				var1.write(var0, 0, var0.length - 2);
				var1.write(var7 & 255);
				var1.write(var7 >> 8 & 255);
				var5.writeTo(var1);
			}
		} else {
			throw new IllegalArgumentException("zip data already has an archive comment");
		}
	}

	private static void copyFiles(Manifest var0, JarFile var1, JarOutputStream var2, long var3) throws IOException {
		byte[] var5 = new byte[4096];
		Map<String, Attributes> var7 = var0.getEntries();
		ArrayList<String> var8 = new ArrayList<String>(var7.keySet());
		Collections.sort(var8);
		Iterator<String> var9 = var8.iterator();

		while (var9.hasNext()) {
			String var10 = (String) var9.next();
			JarEntry var11 = var1.getJarEntry(var10);
			JarEntry var12 = null;
			if (var11.getMethod() == 0) {
				var12 = new JarEntry(var11);
			} else {
				var12 = new JarEntry(var10);
			}

			var12.setTime(var3);
			var2.putNextEntry(var12);
			InputStream var13 = var1.getInputStream(var11);

			int var6;
			while ((var6 = var13.read(var5)) > 0) {
				var2.write(var5, 0, var6);
			}

			var2.flush();
		}

	}

	public static void main(String[] var0) {
		if (var0.length != 4 && var0.length != 5) {
			System.err.println("Usage: signapk [-w] publickey.x509[.pem] privatekey.pk8 input.jar output.jar");
			System.exit(2);
		}

		boolean var1 = false;
		byte var2 = 0;
		if (var0[0].equals("-w")) {
			var1 = true;
			var2 = 1;
		}

		JarFile var3 = null;
		JarOutputStream var4 = null;
		FileOutputStream var5 = null;

		try {
			X509Certificate var6 = readPublicKey(new File(var0[var2 + 0]));
			long var7 = var6.getNotBefore().getTime() + 3600000L;
			PrivateKey var9 = readPrivateKey(new File(var0[var2 + 1]));
			var3 = new JarFile(new File(var0[var2 + 2]), false);
			Object var10 = null;
			if (var1) {
				var10 = new ByteArrayOutputStream();
			} else {
				var10 = var5 = new FileOutputStream(var0[var2 + 3]);
			}

			var4 = new JarOutputStream((OutputStream) var10);
			var4.setLevel(9);
			Manifest var12 = addDigestsToManifest(var3);
			JarEntry var11 = new JarEntry("META-INF/MANIFEST.MF");
			var11.setTime(var7);
			var4.putNextEntry(var11);
			var12.write(var4);
			Signature var13 = Signature.getInstance("SHA1withRSA");
			var13.initSign(var9);
			var11 = new JarEntry("META-INF/CERT.SF");
			var11.setTime(var7);
			var4.putNextEntry(var11);
			writeSignatureFile(var12, new SignApk.SignatureOutputStream(var4, var13));
			var11 = new JarEntry("META-INF/CERT.RSA");
			var11.setTime(var7);
			var4.putNextEntry(var11);
			writeSignatureBlock(var13, var6, var4);
			copyFiles(var12, var3, var4, var7);
			var4.close();
			var4 = null;
			((OutputStream) var10).flush();
			if (var1) {
				var5 = new FileOutputStream(var0[var2 + 3]);
				signWholeOutputFile(((ByteArrayOutputStream) var10).toByteArray(), var5, var6, var9);
			}
		} catch (Exception var22) {
			var22.printStackTrace();
			System.exit(1);
		} finally {
			try {
				if (var3 != null) {
					var3.close();
				}

				if (var5 != null) {
					var5.close();
				}
			} catch (IOException var21) {
				var21.printStackTrace();
				System.exit(1);
			}

		}

	}

	private static class SignatureOutputStream extends BufferedOutputStream {
		private Signature mSignature;
		private int mCount;

		public SignatureOutputStream(OutputStream var1, Signature var2) {
			super(var1);
			this.mSignature = var2;
			this.mCount = 0;
		}

		public void write(int var1) throws IOException {
			try {
				this.mSignature.update((byte) var1);
			} catch (SignatureException var3) {
				throw new IOException("SignatureException: " + var3);
			}

			super.write(var1);
			++this.mCount;
		}

		public void write(byte[] var1, int var2, int var3) throws IOException {
			try {
				this.mSignature.update(var1, var2, var3);
			} catch (SignatureException var5) {
				throw new IOException("SignatureException: " + var5);
			}

			super.write(var1, var2, var3);
			this.mCount += var3;
		}

		public int size() {
			return this.mCount;
		}
	}
}
