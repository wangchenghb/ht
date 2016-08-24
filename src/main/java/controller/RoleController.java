package controller;

import java.util.HashMap;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import Service.ModuleService;
import Service.RoleService;
import pojo.Module;
import pojo.Role;

@Controller
public class RoleController {
	@Autowired
	private RoleService roleService;

	@Autowired
	private ModuleService moduleService;

	@RequestMapping("sysadmin/role/list")
	public String list(Model model) {
		List<Role> dataList = roleService.findAll();
		model.addAttribute("dataList", dataList);
		return "sysadmin/role/jRoleList";
	}

	@RequestMapping("sysadmin/role/tocreate")
	public String tocreate() {
		return "sysadmin/role/jRoleCreate";
	}

	@RequestMapping("sysadmin/role/insert")
	public String insert(Role role) {
		roleService.insert(role);
		return "forward:/sysadmin/role/list";
	}

	@RequestMapping("sysadmin/role/delete")
	public String delete(String roleId) {
		roleService.delete(roleId);
		return "forward:/sysadmin/role/list";
	}

	@RequestMapping("sysadmin/role/tomodule")
	public String tomodule(String roleId, Model model) {
		List<Module> dataList = moduleService.findall();

		List<String> list = roleService.findModuleByRoleId(roleId);

		for (Module m : dataList) {
			if (list.contains(m.getId())) {
				m.setChecked("true");
			} else {
				m.setChecked("false");
			}
		}

		ObjectMapper objMapper = new ObjectMapper();
		String zTreeJson;
		try {
			zTreeJson = objMapper.writeValueAsString(dataList);
			model.addAttribute("zTreeJson", zTreeJson);
			model.addAttribute("roleId", roleId);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return "sysadmin/role/jRoleModule";
	}
	
	@RequestMapping("sysadmin/role/module")
	public String module(String[] moduleIds,String roleId){
		roleService.insertRoleAndModule(roleId,moduleIds);
		return "forward:/sysadmin/role/list";
	}
	
	@RequestMapping("sysadmin/role/toupdate")
	public String toupdate(String roleId,Model model){
		model.addAttribute("id", roleId);
		Role role =  roleService.findRoleById(roleId);
		model.addAttribute("name",role.getName() );
		model.addAttribute("remark", role.getRemark());
		return "sysadmin/role/jRoleUpdate";
	}
	
	@RequestMapping("sysadmin/role/roleAction_update")
	public String roleAction_update(Role role){
		roleService.updateRole(role);
		return "forward:/sysadmin/role/list";
	}
	
}
