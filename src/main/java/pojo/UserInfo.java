package pojo;
import java.util.Date;

import org.springframework.format.annotation.DateTimeFormat;

/**
 * 对应的userInfo_p表	用户信息表
 * @author tarena
 *
 */
public class UserInfo extends BasePojo{
	private String userInfoId;
	private String name;
	private String cardNo;
	private String managerId;
	
	//解决日期转换问题，页面400错误 
	@DateTimeFormat(pattern="yyyy-MM-dd")
	private Date joinDate;
	
	private double salary;
	//解决日期转换问题
	@DateTimeFormat(pattern="yyyy-MM-dd")
	private Date birthday;
	
	private char gender;
	private String station;
	private String telephone;
	private char userLevel;
	private String remark;
	private int orderNo;
	
	private UserInfo manager;
	
	@Override
	public String toString() {
		return "UserInfo [userInfoId=" + userInfoId + ", name=" + name + ", cardNo=" + cardNo + ", managerId="
				+ managerId + ", joinDate=" + joinDate + ", salary=" + salary + ", birthday=" + birthday + ", gender="
				+ gender + ", station=" + station + ", telephone=" + telephone + ", userLevel=" + userLevel
				+ ", remark=" + remark + ", orderNo=" + orderNo + ", manager=" + manager + "]";
	}
	public UserInfo getManager() {
		return manager;
	}
	public void setManager(UserInfo manager) {
		this.manager = manager;
	}
	
	public String getUserInfoId() {
		return userInfoId;
	}
	public void setUserInfoId(String userInfoId) {
		this.userInfoId = userInfoId;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getCardNo() {
		return cardNo;
	}
	public void setCardNo(String cardNo) {
		this.cardNo = cardNo;
	}
	public String getManagerId() {
		return managerId;
	}
	public void setManagerId(String managerId) {
		this.managerId = managerId;
	}
	public Date getJoinDate() {
		return joinDate;
	}
	public void setJoinDate(Date joinDate) {
		this.joinDate = joinDate;
	}
	public double getSalary() {
		return salary;
	}
	public void setSalary(double salary) {
		this.salary = salary;
	}
	public Date getBirthday() {
		return birthday;
	}
	public void setBirthday(Date birthday) {
		this.birthday = birthday;
	}
	public char getGender() {
		return gender;
	}
	public void setGender(char gender) {
		this.gender = gender;
	}
	public String getStation() {
		return station;
	}
	public void setStation(String station) {
		this.station = station;
	}
	public String getTelephone() {
		return telephone;
	}
	public void setTelephone(String telephone) {
		this.telephone = telephone;
	}
	public char getUserLevel() {
		return userLevel;
	}
	public void setUserLevel(char userLevel) {
		this.userLevel = userLevel;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	public int getOrderNo() {
		return orderNo;
	}
	public void setOrderNo(int orderNo) {
		this.orderNo = orderNo;
	}
}
