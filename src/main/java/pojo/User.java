package pojo;

/*
 * 对应的是user_p表		用户表
 */
public class User extends BasePojo{

	private String userId;//主键
	private String deptId;//部门id
	private String userName;//登陆名
	private String passWord;//登陆密码
	private int state;
	
	private UserInfo userInfo;//用户对应的个人信息
	
	private Dept dept;//用户对应的部门信息
	
	@Override
	public String toString() {
		return "User [userId=" + userId + ", deptId=" + deptId + ", userName=" + userName + ", passWord=" + passWord
				+ ", state=" + state + ", userInfo=" + userInfo + ", dept=" + dept + "]";
	}
	public UserInfo getUserInfo() {
		return userInfo;
	}
	public void setUserInfo(UserInfo userInfo) {
		this.userInfo = userInfo;
	}
	public Dept getDept() {
		return dept;
	}
	public void setDept(Dept dept) {
		this.dept = dept;
	}
	public int getState() {
		return state;
	}
	public void setState(int state) {
		this.state = state;
	}
	
	
	
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getDeptId() {
		return deptId;
	}
	public void setDeptId(String deptId) {
		this.deptId = deptId;
	}
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getPassWord() {
		return passWord;
	}
	public void setPassWord(String passWord) {
		this.passWord = passWord;
	}
	
	
	
	
}
