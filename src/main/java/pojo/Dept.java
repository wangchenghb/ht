package pojo;

import java.util.Date;
/**
 * 对应数据库中的dept_p表		 部门表
 * @author tarena
 *
 */
public class Dept {
	
	private String deptId;
	private String parentId;
	private String deptName;
	private int orderNo;
	private int state;
	private String createBy;
	private String creatDept;
	private String updateBy;
	private Date createTime;
	private Date updateTime;
	
	private Dept parent;
	
	@Override
	public String toString() {
		return "Dept [deptId=" + deptId + ", parentId=" + parentId + ", deptName=" + deptName + ", orderNo=" + orderNo
				+ ", state=" + state + ", createBy=" + createBy + ", creatDept=" + creatDept + ", updateBy=" + updateBy
				+ ", creatTime=" + createTime + ", updateTime=" + updateTime + ", parent=" + parent + "]";
	}
	public Dept getParent() {
		return parent;
	}
	public void setParent(Dept parent) {
		this.parent = parent;
	}
	public String getDeptId() {
		return deptId;
	}
	public void setDeptId(String deptId) {
		this.deptId = deptId;
	}
	public String getParentId() {
		return parentId;
	}
	public void setParentId(String parentId) {
		this.parentId = parentId;
	}
	public String getDeptName() {
		return deptName;
	}
	public void setDeptName(String deptName) {
		this.deptName = deptName;
	}
	public int getOrderNo() {
		return orderNo;
	}
	public void setOrderNo(int orderNo) {
		this.orderNo = orderNo;
	}
	public int getState() {
		return state;
	}
	public void setState(int state) {
		this.state = state;
	}
	public String getCreateBy() {
		return createBy;
	}
	public void setCreateBy(String createBy) {
		this.createBy = createBy;
	}
	public String getCreatDept() {
		return creatDept;
	}
	public void setCreatDept(String creatDept) {
		this.creatDept = creatDept;
	}
	public Date getCreateTime() {
		return createTime;
	}
	public void setCreateTime(Date creatTime) {
		this.createTime = creatTime;
	}
	public String getUpdateBy() {
		return updateBy;
	}
	public void setUpdateBy(String updateBy) {
		this.updateBy = updateBy;
	}
	public Date getUpdateTime() {
		return updateTime;
	}
	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((deptId == null) ? 0 : deptId.hashCode());
		return result;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Dept other = (Dept) obj;
		if (deptId == null) {
			if (other.deptId != null)
				return false;
		} else if (!deptId.equals(other.deptId))
			return false;
		return true;
	}
	
	
}
