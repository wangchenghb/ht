package controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import Service.ModuleService;
import pojo.Module;

@Controller
public class ModuleController {
	@Autowired
	private ModuleService moduleService;

	@RequestMapping("sysadmin/module/list")
	public String list(Model model){
		List<Module> dataList = moduleService.findall();
		model.addAttribute("dataList", dataList);
		return "sysadmin/module/jModuleList";
	}
	
	@RequestMapping("sysadmin/module/tocreate")
	public String tocreate(Model model){
		List<Module> dataList = moduleService.findall();
		model.addAttribute("moduleList", dataList);
		return "sysadmin/module/jModuleCreate";
	}
	
	@RequestMapping("sysadmin/module/insert")
	public String insert(Module module){
		moduleService.insert(module);
		return "forward:/sysadmin/module/list";
	}
	
	@RequestMapping("sysadmin/module/delete")
	public String delete(String moduleId){
		moduleService.delete(moduleId);
		return "forward:/sysadmin/module/list";
	}
	
	
}
