package pojo;

import java.util.Date;
/**
 * 公有持久化类部分
 * @author tarena
 *
 */
public class BasePojo {
	
	private String createBy;
	private String creatDept;
	private String updateBy;
	private Date createTime;
	private Date updateTime;

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
	public String getUpdateBy() {
		return updateBy;
	}
	public void setUpdateBy(String updateBy) {
		this.updateBy = updateBy;
	}
	public Date getCreateTime() {
		return createTime;
	}
	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}
	public Date getUpdateTime() {
		return updateTime;
	}
	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}
	
	
}
