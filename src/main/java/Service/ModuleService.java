package Service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import mapper.ModuleMapper;
import pojo.Module;

@Service
public class ModuleService {
	@Autowired
	private ModuleMapper moduleMapper;
	
	/*
	 * 查询所有权限
	 */
	public List<Module> findall() {
		return moduleMapper.findall();
	}
	
	/*
	 * 新增权限 
	 */
	public void insert(Module module) {
		module.setModuleId(UUID.randomUUID().toString());
		module.setCreateTime(new Date());
		module.setUpdateTime(module.getCreateTime());
		module.setState(1);
		module.setOrderNo(12);
		moduleMapper.insert(module);
	}
	
	/*
	 * 根据moduleId删除对应权限
	 */
	public void delete(String moduleId) {
		moduleMapper.delete(moduleId);
	} 
}
