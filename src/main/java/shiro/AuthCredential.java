package shiro;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

import utils.Encrypt;

public class AuthCredential  extends SimpleCredentialsMatcher{
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		
		//1.从token,拿出当前用户输入的用户名和密码
		//2.利用加密算法，把当前用户输入的密码进行加密，得到加密后密码
		//3.把这个加密后的登录密码，再设置回token
		//4.把token info交给super.doCredentialsMatch(token,info)
		//5.剩下的加密认证工作，就交给shiro来处理了
		UsernamePasswordToken loginToken = (UsernamePasswordToken)token;
		
		//获取当前输入密码
		String loginPassword = String.valueOf(loginToken.getPassword());
		
		//获取当前输入用户名，用户名作为加密用的盐
		String username = loginToken.getUsername();
		
		//对输入的用户名进行加密
		String encryptLoginPassword = Encrypt.md5(loginPassword,username);
		
		//把加密后的登录密码设置到loginToken里
		loginToken.setPassword(encryptLoginPassword.toCharArray());
		
		//这一步，很关键。当前loginToken里存的是加密登录密码。info里存的是用户真实密码
		//shiro就是通过这两个密码去比对的
		return super.doCredentialsMatch(loginToken, info);
	}
}
