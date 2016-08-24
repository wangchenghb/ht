package mapper;

import java.util.List;

import pojo.Module;

public interface ModuleMapper {

	List<Module> findall();

	void insert(Module module);

	void delete(String moduleId);

}
