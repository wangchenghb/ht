package mapper;

import java.util.List;

import pojo.User;
import pojo.UserInfo;

public interface UserMapper {

	List<User> findAll();

	void insertUser(User user);

	void insertUserInfo(UserInfo userInfo);

	void deleteUser(String userId);

	void deleteUserInfo(String userId);

	User findUserByUsername(String username);

}
