package Service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import mapper.DeptMapper;
import pojo.Dept;

@Service
public class DeptService {
	@Autowired
	private DeptMapper mapper;
	
	/*
	 * 查询所有部门 dept
	 */
	public List findAll(){
		return mapper.findAll();
	}
	
	/*
	 * 新增部门
	 */
	public void insert(Dept dept) {
		dept.setDeptId(UUID.randomUUID().toString());
		dept.setState(1);
		dept.setCreateTime(new Date());
		dept.setUpdateTime(dept.getCreateTime());
		mapper.insert(dept);
	}
	
	/*
	 * 删除指定deptId的部门
	 */
	public void deleteOne(String deptId) {
		mapper.deleteOne(deptId);
	}
	
	/*
	 * 根据指定deptId查询对应部门
	 */
	public Dept findById(String deptId) {
		return mapper.findById(deptId);
	}
	
	/*
	 * 更新部门信息
	 */
	public void update(Dept dept) {
		mapper.update(dept);
	}

	/*
	 * 根据ids数据删除多个部门
	 */
	public void delete(String[] ids) {
		mapper.delete(ids);
	}
}
