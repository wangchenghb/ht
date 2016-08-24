package mapper;

import java.util.List;

import pojo.Dept;

public interface DeptMapper {

	List findAll();

	void insert(Dept dept);

	void deleteOne(String deptId);

	Dept findById(String deptId);

	void update(Dept dept);

	void delete(String[] ids);
	
}
