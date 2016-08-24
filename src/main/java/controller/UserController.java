package controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import Service.DeptService;
import Service.UserService;
import pojo.User;
import pojo.UserInfo;

@Controller
public class UserController {
	@Autowired
	private UserService userService;
	@Autowired
	private DeptService deptService;
	/*
	 * 展示所有用户信息
	 */
	@RequestMapping("sysadmin/user/list")
	public String list(Model model){
		List<User> dataList = userService.findAll();
		model.addAttribute("dataList", dataList);
		return "sysadmin/user/jUserList";
	}
	
	/* 
	 * 新增用户页面
	 */
	@RequestMapping("sysadmin/user/tocreate")
	public String tocreate(Model model){
		List deptList = deptService.findAll();
		List<User> userList = userService.findAll();
		model.addAttribute("deptList", deptList);
		model.addAttribute("userList", userList);
		return "sysadmin/user/jUserCreate";
	}
	
	/* 在用户新增保存的时候，页面出现400错误，这个是类型转换出错
	 * 根据经验，应该是日期的格式问题，spring默认使用的是yy/MM/dd
	 * 现在页面传过来的日期格式是：yy-MM-dd
	 * 日期格式更改：
	 * 第一种：是在UserInfo对象的私有属性里  注解Date类型的属性@DateTimeFormat注解
	 * 第二种：使用@InitBinder 更改日期格式为yy-MM-dd
	 * 
	 * 此外在页面传值时，SpringMVC也可以完成关联对象的封装，但是需要注意：前台页面的name的写法要对应上pojo对象的私有属性
	 * 新增用户
	 */
	@RequestMapping("sysadmin/user/insert")
	public String insert(User user,UserInfo userInfo ){
		
		userService.insertUser(user,userInfo);
		return "forward:/sysadmin/user/list";
	}
	
	@RequestMapping("sysadmin/user/delete")
	public String delete(String userId){
		userService.delete(userId);
		return "forward:/sysadmin/user/list";
	}
}
