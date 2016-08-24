package controller;

import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.mysql.jdbc.StringUtils;

import Service.UserService;
import pojo.User;

@Controller
public class LoginController {
	@Autowired
	private UserService userService;
	
	@RequestMapping("validate/doLogin")
	public String Login(String username,String password,HttpSession session){
		//输入用户名与密码的  非空和非空格校验
		if(StringUtils.isNullOrEmpty(username) || StringUtils.isNullOrEmpty(password)){
			//因为login.jsp放在webapp下，所以不能直接返回视图逻辑名，所以可以得用重定向的方法	
			//为空时  提示友好信息   使用的是HttpSession
			session.setAttribute("loginFailed", 2);
			return "redirect:/login.jsp";
		}
		
		//通过shiro实现登录认证
		UsernamePasswordToken token = new UsernamePasswordToken(username, password);
		//在安全管理领域，subj
		Subject subject = SecurityUtils.getSubject();
		
		try {
			subject.login(token);
			session.setAttribute("username", username);
			//如果登录验证通过，则转向欢迎界面
			return "forward:/index";
		} catch (AuthenticationException e) {
			//如果抛出异常，证明没有认证通过，在重定向到登录页面，重新从登录
			return "redirect:/login.jsp";
		}
	}
	
	
	/*
	 * 传统方式
	 * @RequestMapping("validate/doLogin")
	public String Login(String username,String password,HttpSession session){
		//输入用户名与密码的  非空和非空格校验
		if(StringUtils.isNullOrEmpty(username) || StringUtils.isNullOrEmpty(password)){
			//因为login.jsp放在webapp下，所以不能直接返回视图逻辑名，所以可以得用重定向的方法	
			//为空时  提示友好信息   使用的是HttpSession
			session.setAttribute("loginFailed", 2);
			return "redirect:/login.jsp";
		}
		
		User user = userService.findUserByUsername(username);
		//判断用户是否为空  用户对应密码是否为空   用记密码与输入密码是否一致
		if(user!=null && !StringUtils.isNullOrEmpty(user.getPassWord()) && password.equals(user.getPassWord())){
			return "forward:/index";
		}
		//密码不正确时 提示友好信息
		session.setAttribute("loginFailed", 1);
		return "redirect:/login.jsp";
	}*/
}
