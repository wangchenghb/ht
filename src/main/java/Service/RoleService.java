package Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import mapper.RoleMapper;
import pojo.Role;

@Service
public class RoleService {
	@Autowired
	private RoleMapper roleMapper;
	
	/*
	 * 查询所有角色
	 */
	public List<Role> findAll() {
		return roleMapper.findAll();
	}
	
	/* 新增角色
	 * 角色新增的时候，别忘了指定主键id
	 */
	public void insert(Role role) {
		role.setRoleId(UUID.randomUUID().toString());
		role.setCreateTime(new Date());
		role.setUpdateTime(role.getCreateTime());
		roleMapper.insert(role);
	}
	
	/*
	 * 删除指定roleId的角色  并删除role_module_p中间表中对应信息 
	 */
	public void delete(String roleId) {
		roleMapper.deleteModuleById(roleId);
		roleMapper.deleteRoleById(roleId);
	}
	
	/*
	 * 根据指定roleId返回对应的moduleId的集合
	 */
	public List<String> findModuleByRoleId(String roleId) {
		return roleMapper.findModuleByRoleId(roleId);
	}

	
	/*	
	 * 这个方法是在role_module_p里分配角色和模块信息
	 * 
	 * 作业：当前的方法虽然能实现插入，但是有一个问题没有考虑;
	 * 比如对于一个角色，刚开始没有任何权限。第一次分配权限，比如1，2，3
	 * 但是当再次为这个角色分配权限时比如1，2权限时会报错（主键已存在）因为当前角色已经有1，2权限了
	 * 
	 */
/*	public void insertRoleAndModule(String roleId, String[] moduleIds) {
		Map map = new HashMap();
		//循环,分多次进行数据的插入
		roleMapper.deleteModuleById(roleId);
		for(String moduleId : moduleIds){
			map.put("roleId", roleId);
			map.put("moduleId", moduleId);
			roleMapper.insertRoleAndModule(map);
		}
	}*/
	
	public void insertRoleAndModule(String roleId, String[] moduleIds) {
		List<String> list1 = Arrays.asList(moduleIds);
		List<String> list2 = roleMapper.findModuleByRoleId(roleId);
		
		ArrayList<String> list3= new ArrayList<String>();
		boolean d = list3.addAll(list1);
		boolean c = list3.addAll(list2);
		
		ArrayList<String> List = new ArrayList<String>();
		List.addAll(list2);
		
		//list2为需要要增加的权限
		boolean b = list2.removeAll(list1);
		
		//list3为需要删除的权限
		boolean a = list3.removeAll(List);
		
		//删除权限
		if(list2.size()!=0){
			HashMap del = new HashMap();
			del.put("roleId",roleId);
			for(String moduleId: list2){
				del.put("moduleId", moduleId);
				roleMapper.deleteByRoleAndModuleId(del);
			}
		}
		
		//添加权限
		if(list3.size()!=0){
			HashMap add = new HashMap();
			add.put("roleId",roleId);
			for(String moduleId: list3){
				add.put("moduleId", moduleId);
				roleMapper.insertRoleAndModule(add);
			}
		}
	}
	
	/*
	 * 根据roleId查询role,并返回role
	 */
	public Role findRoleById(String roleId) {
		return roleMapper.findRoleById(roleId);
	}

	/*
	 * 更新角色信息
	 */
	public void updateRole(Role role) {
		role.setCreateTime(new Date());
		role.setUpdateTime(role.getCreateTime());
		roleMapper.updateRole(role);
	}
}
