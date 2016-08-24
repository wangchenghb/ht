package Service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import mapper.UserMapper;
import pojo.User;
import pojo.UserInfo;
@Service
public class UserService {
	@Autowired
	private UserMapper userMapper;
	
	/*
	 * 查询所有用户信息
	 */
	public List<User> findAll() {
		return userMapper.findAll();
	}
	
	/* 新增用户 并新增用户信息
	 * 用户新增需要注意：
	 * 1.需要手动生成user的主键值
	 * 2.user的主键值和userinfo的主键值是一致的
	 * 3.user和userinfo分别对应两张表，所以得写两条sql插入
	 * 4.两个对象的新增，需要写在一个方法，保证事务的一致性
	 */
	public void insertUser(User user, UserInfo userInfo) {
		user.setUserId(UUID.randomUUID().toString());
		user.setCreateTime(new Date());
		user.setUpdateTime(user.getCreateTime());
		user.setState(1);
		
		userInfo.setUserInfoId(user.getUserId());
		userInfo.setCreateTime(user.getCreateTime());
		userInfo.setUpdateTime(user.getUpdateTime());
		
		userMapper.insertUser(user);
		userMapper.insertUserInfo(userInfo);
	}
	
	/*
	 * 根据用户userId删除对应用户  并删除对应用户信息
	 */
	public void delete(String userId) {
		userMapper.deleteUserInfo(userId);
		userMapper.deleteUser(userId);
	}
	
	/*
	 * 根据用户名查询用户
	 */
	public User findUserByUsername(String username) {
		return userMapper.findUserByUsername(username);
	}
}
