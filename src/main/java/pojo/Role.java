package pojo;
/**
 * 这个持久化类对应role_p表	 角色表
 * @author tarena
 *
 */
public class Role extends BasePojo {
	private String roleId;
	private String name;
	private String remark;
	private int orderNo;
	public String getRoleId() {
		return roleId;
	}
	public void setRoleId(String roleId) {
		this.roleId = roleId;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
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
