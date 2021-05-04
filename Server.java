import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

class Server {

	// defining all variables
	public static BigInteger p, q, N, e, e1, phi, d1;
	public static BigInteger one = new BigInteger("1");
	public static int length = 20;

	// defining variables to use in the advanced RSA
	public static boolean decrypt_flag = false;
	public static int[] s_box = new int[]{9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7};
	public static int[] si_box = new int[]{10,5,9,11,1,7,8,15,6,0,2,3,12,4,13,14};
	public static int[] round_constant = new int[]{128,170,48};
	public static int[][] in_mix_mat = {{9,2},{2,9}};
	public static int ciph, dmsg, key;
	public static int[] s_key = new int[]{0,0,0};
	public static int[] w = new int[]{0,0,0,0,0,0};
	public static String pre_round="", round1_sn="", round1_sr="", round1_mix="", round1_ark="", round2_sn="", round2_sr="", round2_ark="";
	
	
	// function to shift rows nibbles 16-bit
	public static int shiftRows(int c)
	{
	    if(decrypt_flag) return ((c & 3840)>>8 | (c & 15)<<8 | (c & 61680));
	    else return ((c & 240)>>4 | (c & 15)<<4);
	}
	
	// functions to substitute nibble
	public static int subNib(int c)
	{
	    if(decrypt_flag) {
			int x1 = (61440 & c) >> 12;
			int x2 = (3840 & c) >> 8;
			int x3 = (240 & c) >> 4;
			int x4 = (15 & c);

			return ((si_box[x1] << 12) | (si_box[x2] << 8) | (si_box[x3] << 4) | (si_box[x4]));
		}
		int var1=(c & 240)>>4;
		int var2=(c & 15);

		return (s_box[var1]<<4 | s_box[var2]);
	}
		
	// function to generate the key
	public static void keyGeneration()
	{
	    w[0]=(65280 & key)>>8;
	    w[1]=(255 & key);
	    for(int i=2;i<=5;i++)
	    {
	        if(i%2==0)
	        w[i]=w[i-2]^round_constant[i-2]^subNib(shiftRows(w[i-1]));
	        else
	        w[i]=w[i-1]^w[i-2];
	    }
	}
	
	//generating Round_keys
	public static void roundKey(){
	    s_key[0]=(w[0]<<8 | w[1]);
	    s_key[1]=(w[2]<<8 | w[3]);
	    s_key[2]=(w[4]<<8 | w[5]);
	}
	
	// add round key
	public static int addRoundKey(int m, int k){
	    return (m^k);
	}

	//polynomial multiplication
	public static int gmul(int  m1,int  m2)
	{
	    int res=0x0;
	    int j=0;
	    while(m1>0){
	        res=((m1&1)*(m2<<j))^res;
	        m1=m1>>1;
	        j=j+1;
	    }
	    return res;
	}
	
	//bitwise polynomial modulo 19 multiplication
	public static int bitMod(int b1,int b2)
	{
	    int mul=gmul(b1,b2);
	   
	    int shift;
	    while(mul>15){
	        shift=(int)(Math.ceil(Math.log(mul+1)/Math.log(2)))-(int)(Math.ceil(Math.log(19)/Math.log(2)));
	        mul=mul^(19<<shift);
	        
	    }
	    return mul;
	}
	
	//mix columns [1,4 ; 4,1] encoding
	public static int columnMixing(int c)
	{
	    int[] s = new int[4];
	    int[] st = new int[4];
	    s[0]=((61440 & c)>>12)&15;
	    s[1]=(3840 & c)>>8;
	    s[2]=(240 & c)>>4;
	    s[3]=(15 & c);
	    st[0]=bitMod(in_mix_mat[0][0],s[0])^bitMod(in_mix_mat[0][1],s[1]);
        
        st[1]=bitMod(in_mix_mat[0][1],s[0])^bitMod(in_mix_mat[0][0],s[1]);
        
        st[2]=bitMod(in_mix_mat[1][1],s[2])^bitMod(in_mix_mat[1][0],s[3]);
        
        st[3]=bitMod(in_mix_mat[1][0],s[2])^bitMod(in_mix_mat[1][1],s[3]);
	        
	    return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
	}

	// Decryption starts

	// Decryption Round 0
	public static void decryptionRound0()
	{
	    decrypt_flag = true;
	    dmsg=addRoundKey(ciph,s_key[2]);
	    pre_round=pre_round+Integer.toHexString(dmsg);
	}

	// Decryption Round 1
	public static void decryptionRound1()
	{
	    dmsg=subNib(dmsg);
	    round1_sn=round1_sn+Integer.toHexString(dmsg);

	   	dmsg=shiftRows(dmsg);
	    round1_sr=round1_sr+Integer.toHexString(dmsg);
	    
	    dmsg=addRoundKey(dmsg,s_key[1]);
	    round1_ark=round1_ark+Integer.toHexString(dmsg);
	    
	    dmsg=columnMixing(dmsg);
	    round1_mix=round1_mix+Integer.toHexString(dmsg);
	}

	// Decryption Round 2
	public static void decryptionRound2()
	{
	    dmsg=subNib(dmsg);
	    round2_sn=round2_sn+Integer.toHexString(dmsg);

	    dmsg=shiftRows(dmsg);
	    round2_sr=round2_sr+Integer.toHexString(dmsg);

	    dmsg=addRoundKey(dmsg,s_key[0]);
	    round2_ark=round2_ark+Integer.toHexString(dmsg);
	    decrypt_flag = false;
	}
	
	// function to convert hexadecimal to string
	public static String hexadecimalToString(String str)
	{
		StringBuilder result = new StringBuilder();
      	char[] charArray = str.toCharArray();
      	for(int i = 0; i < charArray.length; i=i+2)
      	{
         	String st = ""+charArray[i]+""+charArray[i+1];
         	char ch = (char)Integer.parseInt(st, 16);
        	result.append(ch);
      	}
      	return result.toString();
	}

	// advanced RSA algorithm
	public static void rsa()
	{
		Random rand = new Random();
		N=p.multiply(q);
		
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		e1=BigInteger.probablePrime(length, rand); 
		
		for(BigInteger i=BigInteger.ZERO; i.compareTo(N)<0; i = i.add(BigInteger.ONE))
		{
			if((e1.gcd(phi).equals(BigInteger.ONE)) && (e1.compareTo(phi)<0) && ((BigInteger.ONE).compareTo(e1)<0))
				break;
			else
				e1=BigInteger.probablePrime(length, rand);
		}
		d1=e1.modInverse(phi);
	}

	public static BigInteger encrypt(BigInteger msg)
	{ 
		return msg.modPow(e, N);
	}

	public static BigInteger decrypt(BigInteger msg)
	{
		return msg.modPow(d1, N);
	}

	// hash function to map key and value
	public static BigInteger hashingFunction(String input)
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
		Socket s = new Socket("localhost",7999);
		Scanner in = new Scanner(System.in);
		PrintWriter out = new PrintWriter(s.getOutputStream());
		InputStreamReader inp = new InputStreamReader(s.getInputStream());
		BufferedReader bf = new BufferedReader(inp);

		System.out.println("Enter public key (prime number around 8000): ");
		String t1  = in.nextLine();
		p = new BigInteger(t1);
		System.out.println("Enter private key (prime number around 8000): ");
		String t2 = in.nextLine();
		q = new BigInteger(t2);
		rsa();

		String t3 = e1.toString(10); 
		out.println(""+t3);
		out.flush();

		// taking input from client side
		String client_signature = bf.readLine();
		String ciphertext = bf.readLine();
		String encrypted_secret_key = bf.readLine();
		String client_public_key = bf.readLine();
		BigInteger cs = new BigInteger(client_signature); //cs => client_signature
		BigInteger  esk = new BigInteger(encrypted_secret_key); // esk  => encrypted_secret_key
		e = new BigInteger(client_public_key);

		BigInteger temp = decrypt(esk);
		String secret_key = temp.toString(2);
		System.out.println("Secret_Key is " + secret_key);

		key = Integer.parseInt(secret_key,2);

		String ret = "";
		int len = ciphertext.length();

		keyGeneration();
		roundKey();

		for(int i=0;i+3<len;i+=4)
		{
			ciph = Integer.parseInt(ciphertext.substring(i,i+4),16);

			decryptionRound0();
	    	decryptionRound1();
	    	decryptionRound2();

	    	String res = Integer.toHexString(dmsg);
	    	ret = ret.concat(hexadecimalToString(res));
		}

		if(len%4!=0)
		{
			ciph = Integer.parseInt(ciphertext.substring(len-2,len),16);

			decryptionRound0();
			decryptionRound1();
			decryptionRound2();

	    	String res = Integer.toHexString(dmsg);
	    	ret = ret.concat(hexadecimalToString(res));
		}

    	System.out.println("Decoded cipher text: "+ret);
		BigInteger message_digest = hashingFunction(ret);
		BigInteger value = message_digest.modPow(one, N);
		System.out.println("Message_digest: "+ value);
		BigInteger signature = encrypt(cs);
		System.out.println("intermediate_verification_code "+signature);
		
		if(message_digest.compareTo(signature) > 0) // verification of signature
			System.out.println("verified");
		else System.out.println("not verified");
	}
}
