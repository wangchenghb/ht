package mapper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import pojo.Role;


public interface RoleMapper {

	List<Role> findAll();

	void insert(Role role);

	void deleteRoleById(String roleId);

	void deleteModuleById(String roleId);

	List<String> findModuleByRoleId(String roleId);

	void insertRoleAndModule(Map map);

	Role findRoleById(String roleId);

	void updateRole(Role role);

	void deleteByRoleAndModuleId(HashMap del);

	
}
