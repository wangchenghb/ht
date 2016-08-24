package controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import Service.DeptService;
import pojo.Dept;

@Controller
public class DeptController {
	@Autowired
	private DeptService service;
	
	/*
	 * 展示所有部门信息
	 */
	@RequestMapping("sysadmin/dept/list")
	public String list(Model model){
		List<Dept> dateList = service.findAll();
		model.addAttribute("dateList", dateList);
		return "sysadmin/dept/jDeptList";
	}
	
	/*
	 * 展示新增部门页面
	 */
	@RequestMapping("sysadmin/dept/tocreate")
	public String toCreate(Model model){
		List<Dept> dateList = service.findAll();
		model.addAttribute("dateList", dateList);
		return "sysadmin/dept/jDeptCreate";
	}
	
	/*
	 * 新增部门
	 */
	@RequestMapping("sysadmin/dept/insert")
	public String insert(Dept dept){
		service.insert(dept);
		//部门新增完成后，转发到部门列表页面，利用forward：实现请求转发，很方便
		return "forward:/sysadmin/dept/list";
	}
	
	/*
	 * 删除一个部门
	 */
	@RequestMapping("sysadmin/dept/deleteone")
	public String deleteOne(String deptId){
		service.deleteOne(deptId);
		return "forward:/sysadmin/dept/list";
	}
	
	/*
	 * 展示修改页面
	 */
	@RequestMapping("sysadmin/dept/toupdate")
	public String toupdate(String deptId,Model model){
		List<Dept> dataList = service.findAll();
		Dept dept = service.findById(deptId);
		boolean remove = dataList.remove(dept);
		model.addAttribute("dept", dept);
		model.addAttribute("dataList", dataList);
		return "sysadmin/dept/jDeptUpdate";
	}
	
	/*
	 * 修改部门信息
	 */
	@RequestMapping("sysadmin/dept/update")
	public String update(Dept dept){
		service.update(dept);
		return "forward:/sysadmin/dept/list";
	}
	
	/*
	 * 删除多个部门
	 */
	@RequestMapping("sysadmin/dept/delete")
	public String delete(String[] deptId){
		service.delete(deptId);
		
		return "forward:/sysadmin/dept/list";
	}
	
}
