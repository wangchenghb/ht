package controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {
	
	@RequestMapping("/{pageName}")
	public String goPage(@PathVariable String pageName){
		return "home/"+pageName;
	}
	
	@RequestMapping("/sysadmin/left")
	public String goL(){
		return "sysadmin/left";
	}
	
	@RequestMapping("/sysadmin/main")
	public String goM(){
		return "sysadmin/main";
	}
}
