# Nutanix Password Change

Takes the password on stdin and will prompt for it if one is not provided.  
The propmpt will not echo the password back.  

### Parameters
-a/--all:           Specifies that all passwords will be changed  
-h/--host:          Specifies changing the root user's password on the host  
-c/--cvm:           Specifies changing the nutanix user's password on the CVM  
-e/--prism_element: Specifies changing the admin user's password in Prism Elemet  
-i/--ipmi:          Specifies changing the ADMIN user's password in the IPMI  
-r/--cluster:       Run against the entire cluster  
-n/--nodes:         Comma separated list of virtualization host IPs  

### Log locations
Logs are located in /home/log/messages on AOS 5.19 and below  
Logs are located in /home/log/user_info on AOS 5.20 and above  

### Password Complexity Requirements
The password must meet the following complexity requirements:  
At least eight characters long  
Must not be longer than 16 characters or IPMI will break  
At least one lowercase letter  
At least one uppercase letter  
At least one number  
At least one special character  
At least four characters differ from the old password  
Must not be among the last 5 passwords  
Must not have more than 2 consecutive occurrences of a character