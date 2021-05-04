import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Random;
import java.util.Scanner;

class Client {

	// defining all variables
	public static BigInteger p, q, N, phi, e, e1, d1;
	public static BigInteger one = new BigInteger("1");
	public static int length = 20;

	// defining variables to use in the RSA encryption and decryption
	public static boolean encrypt = false;
	public static int[] s_box = new int[]{9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7};
	public static int[] round_constant = new int[]{128,170,48};
	public static int[][] mix_mat = {{1,4},{4,1}};
	public static int ciph, msg, key;
	public static int[] s_key = new int[]{0,0,0};
	public static int[] w = new int[]{0,0,0,0,0,0};
	public static String pre_round="", round1_sn="", round1_sr="", round1_mix="", round1_ark="", round2_sn="", round2_sr="", round2_ark="";


	// shift rows nibbles 16-bit
	public static int shiftRows(int x) {
	    if(encrypt) return ((x & 3840)>>8 | (x & 15)<<8 | (x & 61680));
	    else return ((x & 240)>>4 | (x & 15)<<4);
	}
	
	//function for substitute nibble 
	public static int subNib(int x)
	{
	    if(encrypt)
	    {
	        int x1=(61440 & x)>>12;
	        int x2=(3840 & x)>>8;
	        int x3=(240 & x)>>4;
	        int x4=(15 & x);
	        return ((s_box[x1]<<12) | (s_box[x2]<<8) | (s_box[x3]<<4) | (s_box[x4]));
	    }
	    else
	    {
	        int var1=(x & 240)>>4;
	        int var2=(x & 15);
	        return (s_box[var1]<<4 | s_box[var2]);
	    }
	}
	
	
	// key generation
	// 1 - divide the key into two sub key w0,w1
	// 2 - Find other sub keys using for loop,w0,w1
	public static void keyGeneration()
	{
	    w[0]=(65280 & key)>>8;
	    w[1]=(255 & key);
	    int i;
	    for(i=2;i<=5;i++)
	    {
	        if(i%2==0)
	        w[i]=w[i-2]^round_constant[i-2]^subNib(shiftRows(w[i-1]));
	        else
	        w[i]=w[i-1]^w[i-2];
	    }
	}
	
	//polynomial multiplication
	public static int gmul(int  x,int  y){
	    int val=0,j=0;
	    while(x>0){
	        val=((x&1)*(y<<j))^val;
	        x=x>>1;
	        j=j+1;
	    }
	    return val;
	}
	
	// generating round keys
	public static void roundKey()
	{
	    s_key[0]=(w[0]<<8 | w[1]);
	    s_key[1]=(w[2]<<8 | w[3]);
	    s_key[2]=(w[4]<<8 | w[5]);
	}
	
	//add round key
	public static int addRoundKey(int m,int k){
	    return (m^k);
	}
	
	
	//bitwise polynomial modulo 19 multiplication
	public static int bitMod(int b1,int b2)
	{
	    int mul = gmul(b1,b2);
	    int shift;
	    while(mul>15){
	        shift = (int)(Math.ceil(Math.log(mul+1)/Math.log(2)))-(int)(Math.ceil(Math.log(19)/Math.log(2)));
	        mul = mul^(19<<shift);
	    }
	    return mul;
	}
	
	//mix columns [1,4 ; 4,1] encoding
	public static int columnMixing(int c){
	    int[] s = new int[4];
	    int[] st = new int[4];
	    s[0]=((61440 & c)>>12)&15;
        s[1]=(3840 & c)>>8;
        s[2]=(240 & c)>>4;
        s[3]=(15 & c);

        st[0]=bitMod(mix_mat[0][0],s[0])^bitMod(mix_mat[0][1],s[1]);
        
        st[1]=bitMod(mix_mat[0][1],s[0])^bitMod(mix_mat[0][0],s[1]);
        
        st[2]=bitMod(mix_mat[1][1],s[2])^bitMod(mix_mat[1][0],s[3]);
        
        st[3]=bitMod(mix_mat[1][0],s[2])^bitMod(mix_mat[1][1],s[3]);
        
        
        return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
	}

	// Encryption starts
	//encryptionRound0
	public static void encryptionRound0()
	{
	    encrypt = true;
	    ciph = addRoundKey(msg,s_key[0]);
	    pre_round = pre_round+Integer.toHexString(ciph);
	}
	//Round1
	public static void encryptionRound1()
	{
	    ciph=subNib(ciph);
	    round1_sn += Integer.toHexString(ciph);
	    
	    ciph=shiftRows(ciph);
	    round1_sr += Integer.toHexString(ciph);
	    
	    ciph=columnMixing(ciph);
	    round1_mix += Integer.toHexString(ciph);
	    
	    ciph=addRoundKey(ciph,s_key[1]);
	    round1_ark += Integer.toHexString(ciph);
	}
	// round2 
	public static void encryptionRound2()
	{
	    ciph=subNib(ciph);
	    round2_sn += Integer.toHexString(ciph);
	    
	    ciph=shiftRows(ciph);
	    round2_sr += Integer.toHexString(ciph);
	    
	    ciph=addRoundKey(ciph,s_key[2]);
	    round2_ark += Integer.toHexString(ciph);
	   	
	    encrypt = false;
	}
	
	//function converting string to hexadecimal string 
	public static String stringToHexadecimal(String str)
	{
		StringBuilder result = new StringBuilder();
	    char[] ch;
		ch = str.toCharArray();
		for (char c : ch) {
			String hexString = Integer.toHexString(c);
			result.append(hexString);
		}
	   	return result.toString();
	}

	public static String properString(String str, int len)
	{
		return String.join("", Collections.nCopies(Math.max(len-str.length(),0), "0")) + str;
	}
	
	// function for advance rsa
	public static void rsa()
	{
		Random rand = new Random();
		N=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		e1=BigInteger.probablePrime(length, rand); 
		for(BigInteger i=BigInteger.ZERO; i.compareTo(N)<0 ;i = i.add(BigInteger.ONE)){

			if((e1.gcd(phi).equals(BigInteger.ONE)) && (e1.compareTo(phi)<0) && ((BigInteger.ONE).compareTo(e1)<0))
				break;
			else
				e1=BigInteger.probablePrime(length, rand);
		}
		d1=e1.modInverse(phi);
	}
	
	// function for simple RSA
	public static void simple_RSA()
	{
		N=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	}
	
	public static BigInteger encrypt(BigInteger msg)
	{ 
		return msg.modPow(e, N);
	}

	public static BigInteger decrypt(BigInteger msg)
	{
		return msg.modPow(d1, N);
	}

	public static BigInteger hashing_function(String input)
    {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            return new BigInteger(1, messageDigest);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
    	}
    }


	public static void main(String[] args) throws IOException {
		
		ServerSocket ss = new ServerSocket(7999);
		Socket s = ss.accept();

		System.out.println("Server Connection Established");
		Scanner in = new Scanner(System.in);
		InputStreamReader inp = new InputStreamReader(s.getInputStream());
		BufferedReader bf = new BufferedReader(inp);
		PrintWriter out = new PrintWriter(s.getOutputStream());

		String server_public_key = bf.readLine();
		e = new BigInteger(server_public_key);

        // All the inputs required 
		System.out.println("Enter public key (prime number around 8000): ");
		String t1  = in.nextLine();
		p = new BigInteger(t1);
		System.out.println("Enter private key (prime number around 8000): ");
		String t2 = in.nextLine();
		q = new BigInteger(t2);
		System.out.println("Enter the message: ");
		String message = in.nextLine();
		System.out.println("Enter the 16-bit key: ");
		String secret_key = in.nextLine();
		int zz = Integer.parseInt(secret_key,2);
		simple_RSA();
		
		BigInteger inn = BigInteger.valueOf(zz);
		System.out.println("Secret Key "+inn);
		BigInteger encrypted_secret_key=encrypt(inn);


		key = Integer.parseInt(secret_key,2);

		int len = message.length();
		String ret="";

		keyGeneration();
		roundKey();

		for(int i=0;i+1<len;i+=2)
		{
			msg = Integer.parseInt(stringToHexadecimal(message.substring(i,i+2)),16);
			encryptionRound0();
			encryptionRound1();
			encryptionRound2();
			String res = Integer.toHexString(ciph);
			ret=ret.concat(properString(res,4));
		}

		if(len%2==1)
		{
			msg = Integer.parseInt(stringToHexadecimal(message.substring(len-1,len)),16);
			encryptionRound0();
			encryptionRound1();
			encryptionRound2();
			String res = Integer.toHexString(ciph);
			ret=ret.concat(properString(res,2));
		}

		String ciphertext = ret;
		BigInteger message_digest = hashing_function(message);
		BigInteger temp4 = message_digest.modPow(one, N);
		System.out.println("message_digest: "+ temp4);
		rsa();
		BigInteger client_signature = decrypt(temp4);
		
		// outputs
		System.out.println("Client_Signature is " + client_signature);
		System.out.println("Cipher_Text is "+ ciphertext);
		System.out.println("Encrypted_Secret_Key is "+ encrypted_secret_key);
		String temp = client_signature.toString(10);
		out.println(""+temp);// bigInteger
		out.println(""+ciphertext); // string
		String temp2 = encrypted_secret_key.toString(10);
		out.println(""+temp2);
		String temp3 = e1.toString(10);
		out.println(""+ temp3); // string
		out.flush();
	}
}
