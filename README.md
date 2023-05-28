# Nutanix Password Change

Takes the password on stdin and will prompt for it if one is not provided. The prompt will not echo the password.  

## Parameters
```
-a/--all:           Specifies that all passwords will be changed  
-h/--host:          Specifies changing the root user's password on the host
-u/--nutanix:       Specifies changing the nutanix user's password on an AHV host
-c/--cvm:           Specifies changing the nutanix user's password on the CVM  
-e/--prism_element: Specifies changing the admin user's password in Prism Elemet  
-i/--ipmi:          Specifies changing the ADMIN user's password in the IPMI  
-r/--cluster:       Run against the entire cluster  
-n/--nodes:         Comma separated list of virtualization host IPs  
```

## Log locations
Logs are located in /home/log/messages on AOS 5.19 and below  
Logs are located in /home/log/user_info on AOS 5.20 and above  

## Password Complexity Requirements
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

## Download and Run
```bash
cd ~/tmp
```
```bash
wget https://raw.githubusercontent.com/rsoc39/nutanix-change-password/main/change_passwords.sh
```
```bash
bash ./change_passwords.sh
```

## Example Usage
```bash
bash ./change_passwords.sh -r -a
```
```bash
bash ./change_passwords.sh -c
```
```bash
bash ./change_passwords.sh --prism_element
```
```bash
bash ./change_passwords.sh --nodes 192.168.5.10,192.168.5.11,192.168.5.12 -h
```
```bash
echo -e 'mypassword\nmypassword' | bash ./change_passwords.sh -r -i
```
########## ALL CHANGES AND MODIFICATIONS ARE REQUESTED TO FOLLOW THE FOLLOWING STYLING GUIDELINES ##########

# Indentation
# Use tabs for indentation and limit each line to 80 columns.
# Example: Use tabs for indentation

# Semicolons
# Avoid using semicolons to terminate statements, except for control statements like if or while.
# Example: Avoid using semicolons at the end of statements

# Functions
# Avoid using the function keyword and make all variables local to functions.
# Example: Avoid using function keyword and make variables local

# Block Statements
# Place "then" on the same line as if statements and "do" on the same line as while statements.
# Example: Place "then" and "do" on the same line

# Comments
# Avoid modifying comments for aesthetic reasons unless necessary for rewriting or updating them.
# Example: Avoid unnecessary modifications to comments

# Test
# Use "[[ ... ]]" for testing conditions instead of "[" or "test".
# Example: Use [[ ... ]] for testing conditions

# Command Substitution
# Use "$(command)" instead of backticks for command substitution.
# Example: Use $(command) for command substitution

# Arithmetic
# Avoid using the "let" command and prefer using "((...))" over "[...]" for arithmetic operations.
# Example: Prefer ((...)) for arithmetic operations

# Parameter Expansion
# Prefer parameter expansion over external commands like echo, sed, awk, etc. for string manipulation.
# Example: Use parameter expansion for string manipulation

# Parsing ls
# Avoid parsing the output of the "ls" command and use built-in functions for looping through files.
# Example: Avoid parsing ls command output

# __dirname and __filename
# Avoid using these variables as they may not always provide reliable results. Use alternative methods to get the script's full path.
# Example: Avoid using __dirname and __filename

# Arrays
# Use bash arrays instead of strings separated by spaces or other characters to store multiple values.
# Example: Use arrays instead of space-separated strings

# Quoting Variables
# Use double quotes for variables that require expansion or interpolation and single quotes for others.
# Quote variables undergoing word-splitting unless controlled by the code. Use curly braces for proper variable expansion when necessary.
# Example: Quote variables appropriately based on context

# Variable Names
# Prefer lowercase variable names and avoid using let, readonly, or declare to create variables. Use "local" inside functions.
# Example: Use lowercase variable names and "local" inside functions

# Exit Codes
# Check exit codes for commands that may fail, such as "cd". Avoid setting "errexit" as it may have unintended consequences.
# Example: Check exit codes for commands that may fail

# Trapping Signals
# Do not attempt to trap SIGKILL or SIGSTOP signals as they are not designed to be trapped.
# Example: Do not trap SIGKILL or SIGSTOP signals

# Word-splitting
# Understand how word-splitting works and its impact on variables and loops.
# Use "read -r" to avoid word-splitting when reading input.
# Example: Understand and handle word-splitting carefully

# Portability
# Avoid using GNU-specific options when using external commands like awk, sed, grep, etc.
# Prefer bash built-ins for simple string manipulation.
# Example: Write portable code using bash built-ins

# cat
# Avoid using "cat" unnecessarily. Use redirection or built-in methods to read files instead.
# Example: Avoid unnecessary use of "cat" command

# Quotes within Quotes
# Use single quotes within double quotes and escape quotes if necessary.
# Example: Use quotes appropriately within quotes
