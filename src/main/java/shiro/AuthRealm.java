package shiro;

import java.util.ArrayList;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

import Service.UserService;
import pojo.User;

public class AuthRealm extends AuthorizingRealm {
	@Autowired
	private UserService userService;
	
	/*
	 *这个方法是实现授权管理的 
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
		Subject subject = SecurityUtils.getSubject();
		String username = (String)subject.getSession().getAttribute("username");
		ArrayList<String> infoList = new ArrayList<String>();
		infoList.add("系统首页");
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addStringPermissions(infoList);
		
		return info;
	}
	
	
	//登录认证模块，相关的认证方法写在这里
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		//1.把token对象 由AuthenticationToken强转成UsernamePasswordToken
		UsernamePasswordToken login = (UsernamePasswordToken)token;
		//2.通过loginToken,得到当前用户输入的用户名
		String username = login.getUsername();
		//3.后台根据用户名，去数据库里查询，得到对应的用户对象 
		User user = userService.findUserByUsername(username);
		//4.以上三步都 做好了，把shiro的登录认证管理员叫出来，把资料交给他，他会自动去做登录认证
		//需要提供的资料：1.当前的用户对象 2.当前用户的真实密码 3.当AuthRealm的名字(全路径名) ，直接调用的this.getName()即可
		AuthenticationInfo info = new SimpleAuthenticationInfo(user, user.getPassWord(), this.getName());
		
		//return info 之后，shiro就可以做登录认证
		//所谓的登录认证，实际上就是匹配用户的真实密码和用户在页面上输入密码
		//用户的输入密码，shiro已经在token进行存储，所以我们只需要把用户的真实密码资料提交给shiro即可
		//shiro会自动去做密码的匹配
		return info;
	}
	
}
