package utils;

import org.apache.shiro.crypto.hash.Md5Hash;

public class Encrypt {
	
	public static void main(String[] args) {
		//new Md5Hash(source, salt, hashIterations)
		//source 指的是要加密的密码
		//salt 盐 盐不同，同样的密码生成的密码不同
		//hashIterations 执行hash加密的次数，是个整形，次数越高，加密程度越高，这个次数一般2，3次就可
		Md5Hash md5Hash = new Md5Hash("123456", "背叛者", 2);
		System.out.println(md5Hash.toString());
	}

	public static String md5(String loginPassword, String username) {
		
		Md5Hash md5Hash=new Md5Hash(loginPassword, username, 2);
		
		return md5Hash.toString();
	}

}
