# Ruby Test Case for DRSource

# 1. SQL Injection (VULNERABLE)
user_id = params[:id]
User.find_by_sql("SELECT * FROM users WHERE id = #{user_id}")

# 2. Command Injection (VULNERABLE)
host = cookies[:host]
system("nslookup #{host}")

# 3. Constant Propagation (SAFE - Should be ignored)
safe_cmd = "ls -la"
system(safe_cmd)

# 4. Boolean Engine Test ($X == $X bug)
if x == x
  puts "Always true"
end
