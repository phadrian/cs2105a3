// Author: A0124123Y

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

/************************************************
 * This skeleton program is prepared for weak  *
 * and average students.                       *
 * If you are very strong in programming. DIY! *
 * Feel free to modify this program.           *
 ***********************************************/

// Alice knows Bob's public key
// Alice sends Bob session (AES) key
// Alice receives messages from Bob, decrypts and saves them to file

class Alice {  // Alice is a TCP client

	String bobIP;  // ip address of Bob
	int bobPort;   // port Bob listens to
	Socket connectionSkt;  // socket used to talk to Bob
	private ObjectOutputStream toBob;   // to send session key to Bob
	private ObjectInputStream fromBob;  // to read encrypted messages from Bob
	private Crypto crypto;        // object for encryption and decryption
	// file to store received and decrypted messages
	public static final String MESSAGE_FILE = "msgs.txt";

	public static void main(String[] args) {

		// Check if the number of command line argument is 2
		if (args.length != 2) {
			System.err.println("Usage: java Alice BobIP BobPort");
			System.exit(1);
		}

		new Alice(args[0], args[1]);
	}

	// Constructor
	public Alice(String ipStr, String portStr) {

		this.crypto = new Crypto();
		bobIP = ipStr;
		bobPort = Integer.parseInt(portStr);
		
		try {
			this.connectionSkt = new Socket(bobIP, bobPort);
		} catch (UnknownHostException e) {
			System.out.println("Error: cannot resolve IP address");
			System.exit(1);
		} catch (IOException e) {
			System.out.println("Error: cannot create Socket for connection");
			System.exit(1);
		}
		
		// Send session key to Bob
		sendSessionKey();

		// Receive encrypted messages from Bob,
		// decrypt and save them to file
		receiveMessages();
	}

	// Send session key to Bob
	public void sendSessionKey() {
		try {
			toBob = new ObjectOutputStream(this.connectionSkt.getOutputStream());
			toBob.writeObject(crypto.getSessionKey());
		} catch (IOException e) {
			System.out.println("Error: cannot create output stream");
			System.exit(1);
		}
	}

	// Receive messages one by one from Bob, decrypt and write to file
	public void receiveMessages() {
		try {
			fromBob = new ObjectInputStream(this.connectionSkt.getInputStream());
			PrintWriter pw = new PrintWriter(new File(MESSAGE_FILE));
			for (int i = 0; i < 10; i++) {
				SealedObject encryptedMessageObj = (SealedObject)fromBob.readObject();
				String message = this.crypto.decryptMsg(encryptedMessageObj);
				System.out.println(message);
				pw.println(message);
			}
			pw.close();
		} catch (IOException e) {
			System.out.println("Error: cannot create input stream");
			System.exit(1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error: cannot typecast to String");
			System.exit(1);
		}
	}

	/*****************/
	/** inner class **/
	/*****************/
	class Crypto {

		// Bob's public key, to be read from file
		private PublicKey pubKey;
		// Alice generates a new session key for each communication session
		private SecretKey sessionKey;
		// File that contains Bob' public key
		public static final String PUBLIC_KEY_FILE = "bob.pub";

		// Constructor
		public Crypto() {
			// Read Bob's public key from file
			readPublicKey();
			// Generate session key dynamically
			initSessionKey();
		}

		// Read Bob's public key from file
		public void readPublicKey() {
			// key is stored as an object and need to be read using ObjectInputStream.
			// See how Bob read his private key as an example.
			try {
				ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
				this.pubKey = (PublicKey)ois.readObject();
				ois.close();
			} catch (FileNotFoundException e) {
				System.out.println("Error: " + PUBLIC_KEY_FILE + " could not be found");
				System.exit(1);
			} catch (IOException e) {
				System.out.println("Error: could not read " + PUBLIC_KEY_FILE);
				System.exit(1);
			} catch (ClassNotFoundException e) {
				System.out.println("Error: cannot typecast to class PublicKey");
				System.exit(1);
			}
		}

		// Generate a session key
		public void initSessionKey() {
			// suggested AES key length is 128 bits
			try {
				KeyGenerator keygen = KeyGenerator.getInstance("AES");
				keygen.init(128);
				sessionKey = keygen.generateKey();
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error: AES encryption not supported");
				System.exit(1);
			}
		}

		// Seal session key with RSA public key in a SealedObject and return
		public SealedObject getSessionKey() {
			SealedObject sessionKeyObj = null;
			// Alice must use the same RSA key/transformation as Bob specified
			try {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, this.pubKey);
				byte[] rawKey = this.sessionKey.getEncoded();
				sessionKeyObj = new SealedObject(rawKey, cipher);
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error: RSA encryption not supported");
				System.exit(1);
			} catch (NoSuchPaddingException e) {
				System.out.println("Error: padding option not supported");
				System.exit(1);
			} catch (InvalidKeyException e) {
				System.out.println("Error: invalid public key");
				System.exit(1);
			} catch (IllegalBlockSizeException e) {
				System.out.println("Error: cipher block size is incorrect");
				System.exit(1);
			} catch (IOException e) {
				System.out.println("Error: could not create SealedObject");
				System.exit(1);
			}

			// RSA imposes size restriction on the object being encrypted (117 bytes).
			// Instead of sealing a Key object which is way over the size restriction,
			// we shall encrypt AES key in its byte format (using getEncoded() method).
			return sessionKeyObj;
		}

		// Decrypt and extract a message from SealedObject
		public String decryptMsg(SealedObject encryptedMsgObj) {
			String plainText = null;

			// Alice and Bob use the same AES key/transformation
			try {
				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, this.sessionKey);
				
				String message = (String)encryptedMsgObj.getObject(cipher);
				plainText = message;
			} catch (GeneralSecurityException gse) {
                System.out.println("Error: wrong cipher to decrypt session key");
                System.exit(1);
            } catch (IOException e) {
				System.out.println("Error: could not receive session key");
				System.exit(1);
			} catch (ClassNotFoundException e) {
				System.out.println("Error: cannot typecast to String");
				System.exit(1);
			}
			
			return plainText;
		}
	}
}