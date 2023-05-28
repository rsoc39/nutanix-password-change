#!/usr/bin/env bash

###############################################-----HEADER-----########################################################
#   Authors: Joel Goehring and Joseph Blake
#   Modified By: iamhumanipromise1010101
#   version: 1.2a
#   Style Guide: https://github.com/bahamas10/bash-style-guide
#######################################################################################################################

#############################################-----change-Log-----######################################################
#   Added option to change nutanix user on AHV hosts
#   Modified password input to adhere to complexity requirements
#   Implemented SHA-512 for password encryption
#######################################################################################################################

###############################################-----LICENSE-----#######################################################
#   BSD 3-Clause License
#
#   Copyright (c) 2021, Joel Goehring
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#      list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
#   3. Neither the name of the copyright holder nor the names of its
#      contributors may be used to endorse or promote products derived from
#      this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#######################################################################################################################

###############################################-----PARAMETERS-----####################################################
#   -a/--all:                   Specifies that all passwords will be changed
#   -h/--host:                  Specifies changing the root user's password on the host
#   -u/--nutanix:               Specifies changing the nutanix user's password on an AHV host
#   -c/--cvm:                   Specifies changing the nutanix user on the CVM
#   -e/--prism_element:         Specifies changing the admin user in Prism Element
#   -i/--ipmi:                  Specifies changing the ADMIN user in the IPMI
#   -r/--cluster:               If this flag exists, the script will be run against the entire cluster
#   -n/--nodes:                 Comma-separated list of CVM or host IPs to run against
#######################################################################################################################

###############################################-----Exit-Codes-----####################################################
#   13:     AHV host 'nutanix' user password change failed
#   12:     Virtualization host 'root' user password change failed
#   11:     CVM user 'nutanix' password change failed
#   10:     Prism Element user 'admin' password change failed
#   9:      IPMI user 'ADMIN' password change failed
#   8:      OS designation for changing IPMI 'ADMIN' user password was not matched
#   7:      List of hosts could not be determined
#   5:      The new password and the verification password do not match
#   1:      Parameters were specified incorrectly
#######################################################################################################################

###############################################-----BASH-OPTIONS-----##################################################
#######################################################################################################################

###############################################-----GLOBALS-----#######################################################
ssh_opts='-o LogLevel=error -o StrictHostKeyChecking=no'
ipmi_user_number='2'
#######################################################################################################################

###############################################-----FUNCTIONS-----#####################################################
# This function prints the parameters and general info for running this script. It takes no parameters.
function usage() {
    # Gets the file name of the script using parameter expansion instead of calling out to external programs.
    local base=${0##*/}
    # Inserts a backslash to escape the dot for a valid regex when printed below.
    local base=${base//\./\\\.}
    # Print parameters and general info.
    echo -e "\n
Takes the password on stdin and will prompt for it if one is not provided
The prompt will not echo the password back
-a/--all:\t\tSpecifies that all passwords will be changed
-h/--host:\t\tSpecifies changing the root user's password on the host
-u/--nutanix:\t\tSpecifies changing the nutanix user's password on an AHV host
-c/--cvm:\t\tSpecifies changing the nutanix user's password on the CVM
-e/--prism_element:\tSpecifies changing the admin user's password in Prism Element
-i/--ipmi:\t\tSpecifies changing the ADMIN user's password in the IPMI
-r/--cluster:\t\tRun against the entire cluster
-n/--nodes:\t\tComma-separated list of virtualization host IPs\n
**The logs can be viewed by issuing the below command:
sudo egrep -o '$base:.+' /home/log/user_info

The password must meet the following complexity requirements:
At least eight characters long
Must not be longer than 16 characters or IPMI will break
At least one lowercase letter
At least one uppercase letter
At least one number
At least one special character
At least four characters differ from the old password
Must not be among the last 5 passwords
Must not have more than 2 consecutive occurrences of a character\n"
}

# This function writes messages to the rsyslog service. As of AOS 5.20 user.info has been excluded from
# /home/log/messages in /etc/rsyslog.conf and directed to /home/log/user_info.
# This function expects two parameters. The first being a string 'info' or 'error' which is used to set the level and
# as a field in the line being logged. The second is the message being logged.
# Error messages will also print to stderr
function log() {
    # Get's the name of this script running to be used as a field in the log.
    source=${0##*/}
    if [[ $1 == 'info' ]] && [[ $2 ]]; then
        logger "$source: $1: $2"
    elif [[ $1 == 'error' ]] && [[ $2 ]]; then
        logger -s "$source: $1: $2"
    else
        echo 'Bad parameters to logging function'
    fi
}

# This function checks if the password meets the complexity requirements.
# It takes one parameter which is the password to be checked.
# The function returns 0 if the password is valid, and 1 otherwise.
function check_password_policy() {
    local password=$1
    local regex='^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$'
    
    if [[ $password =~ $regex ]]; then
        return 0
    else
        return 1
    fi
}

# This function hashes the given password using SHA-512 algorithm.
# It takes one parameter which is the password to be hashed.
# The hashed password is printed to stdout.
function hash_password() {
    local password=$1
    local salt=$(openssl rand -base64 12)
    local hashed_password=$(openssl passwd -6 -salt $salt $password)
    echo "$hashed_password"
}

# This function prints the usage information and exits with an error code.
function print_usage_error() {
    usage
    exit 1
}

# This function sets the 'root' user's password on the specified host.
# It takes one parameter which is the host IP.
# The function returns 0 if the password change is successful, and exits with an error code otherwise.
function set_host_root_password() {
    local host=$1
    log 'info' "--Beginning ${FUNCNAME[0]} function"
    log 'info' "Host: $host"

    local encrypted_password=$(hash_password "$password")
    
    # No output is stored from this SSH session in order to keep it silent.
    # The encrypted password is passed to the passwd command to change the password for the 'root' user.
    ssh ${ssh_opts} root@$host "echo 'root:$encrypted_password' | chpasswd"

    # Get the exit code of the above command.
    local set_host_root_password_exit=$?
    log 'info' "set_host_root_password_exit:$set_host_root_password_exit"

    # Check the exit code to determine if the password change succeeded or failed.
    if ((set_host_root_password_exit == 0)); then
        local success="Host user 'root' password change on $host SUCCEEDED"
        echo "$success"
        log 'info' "$success"
        log 'info' "Ending ${FUNCNAME[0]} function"
        return $set_host_root_password_exit
    else
        log 'error' "Host user 'root' password change on $host FAILED"
        exit 12
    fi
}

# This function sets the 'nutanix' user's password on the specified host.
# It takes one parameter which is the host IP.
# The function returns 0 if the password change is successful, and exits with an error code otherwise.
function set_host_nutanix_password() {
    local host=$1
    log 'info' "--Beginning ${FUNCNAME[0]} function"
    log 'info' "Host: $host"

    local encrypted_password=$(hash_password "$password")

    local host_os=$(host_os_discovery "$host")
    log 'info' "Host OS: $host_os"

    if [[ $host_os == 'AHV' ]]; then
        log 'info' "Setting nutanix user password"
        # No output is stored from this SSH session in order to keep it silent.
        # The encrypted password is passed to the passwd command to change the password for the 'nutanix' user.
        ssh ${ssh_opts} root@$host "echo 'nutanix:$encrypted_password' | chpasswd"

        # Get the exit code of the above command.
        local set_host_nutanix_password_exit=$?
    else
        log 'info' "Skipping set_host_nutanix_password. Host was not AHV"
        log 'info' "Ending ${FUNCNAME[0]} function"
        return
    fi

    log 'info' "set_host_nutanix_password_exit:$set_host_nutanix_password_exit"

    # Check the exit code to determine if the password change succeeded or failed.
    if ((set_host_nutanix_password_exit == 0)); then
        local success="Host user 'nutanix' password change on $host SUCCEEDED"
        echo "$success"
        log 'info' "$success"
        log 'info' "Ending ${FUNCNAME[0]} function"
        return $set_host_nutanix_password_exit
    else
        log 'error' "Host user 'nutanix' password change on $host FAILED"
        exit 13
    fi
}

# This function sets the 'nutanix' user's password on the localhost, which propagates the password change to all CVMs in the cluster.
# It does not require any parameters.
# The function returns 0 if the password change is successful, and exits with an error code otherwise.
function set_cvm_password() {
    log 'info' "--Beginning ${FUNCNAME[0]} function"

    local encrypted_password=$(hash_password "$password")

    # No output is stored from this command in order to keep it silent.
    # The encrypted password is passed to the passwd command to change the password for the 'nutanix' user on the CVM.
    echo "nutanix:$encrypted_password" | sudo chpasswd

    # Get the exit code of the above command.
    local set_cvm_password_exit=$?
    log 'info' "set_cvm_password_exit:$set_cvm_password_exit"

    # Check the exit code to determine if the password change succeeded or failed.
    if ((set_cvm_password_exit == 0)); then
        local success="CVM user 'nutanix' password change SUCCEEDED"
        echo "$success"
        log 'info' "$success"
        log 'info' "Ending ${FUNCNAME[0]} function"
        return $set_cvm_password_exit
    else
        log 'error' "CVM user 'nutanix' password change FAILED"
        exit 11
    fi
}

# This function sets the 'admin' user's password in Prism Element for the cluster.
# It does not require any parameters.
# The function returns 0 if the password change is successful, and exits with an error code otherwise.
function set_prism_element_password() {
    log 'info' "--Beginning ${FUNCNAME[0]} function"

    local encrypted_password=$(hash_password "$password")

    # No output is stored from this command in order to keep it silent.
    # The encrypted password is passed to the ncli command to reset the password for the 'admin' user in Prism Element.
    ncli user reset-password user-name='admin' password="$encrypted_password" > /dev/null 2>&1

    # Get the exit code of the above command.
    local set_prism_element_password_exit=$?
    log 'info' "set_prism_element_password_exit:$set_prism_element_password_exit"

    # Check the exit code to determine if the password change succeeded or failed.
    if ((set_prism_element_password_exit == 0)); then
        local success="Prism Element user 'admin' password change SUCCEEDED"
        echo "$success"
        log 'info' "$success"
        log 'info' "Ending ${FUNCNAME[0]} function"
        return $set_prism_element_password_exit
    else
        log 'error' "Prism Element user 'admin' password change FAILED"
        exit 10
    fi
}

# This function sets the 'ADMIN' user's password for the IPMI on the specified host.
# It takes one parameter which is the host IP.
# The function returns 0 if the password change is successful, and exits with an error code otherwise.
function set_ipmi_password() {
    local host=$1
    log 'info' "--Beginning ${FUNCNAME[0]} function"
    log 'info' "Host: $host"

    local encrypted_password=$(hash_password "$password")

    local host_os=$(host_os_discovery "$host")
    log 'info' "Host OS: $host_os"

    if [[ $host_os == 'AHV' ]]; then
        log 'info' "Skipping set_ipmi_password. IPMI is not used on AHV hosts."
        log 'info' "Ending ${FUNCNAME[0]} function"
        return
    elif [[ $host_os == 'ESXi' ]]; then
        log 'info' "Setting IPMI user password"
        # No output is stored from this SSH session in order to keep it silent.
        # The encrypted password is passed to the ipmitool command to change the password for the 'ADMIN' user on ESXi hosts.
        ssh ${ssh_opts} root@$host "ipmitool user set password $ipmi_user_number $encrypted_password" > /dev/null 2>&1

        # Get the exit code of the above command.
        local set_ipmi_password_exit=$?
    else
        log 'error' 'OS designation was not matched'
        exit 8
    fi

    log 'info' "set_ipmi_password_exit:$set_ipmi_password_exit"

    # Check the exit code to determine if the password change succeeded or failed.
    if ((set_ipmi_password_exit == 0)); then
        local success="IPMI user 'ADMIN' password change on $host SUCCEEDED"
        echo "$success"
        log 'info' "$success"
        log 'info' "Ending ${FUNCNAME[0]} function"
        return $set_ipmi_password_exit
    else
        log 'error' "IPMI user 'ADMIN' password change on $host FAILED"
        exit 9
    fi
}
#######################################################################################################################

###############################################-----BODY-----##########################################################
# Print usage function if there are no parameters.
if (($# == 0)); then
    usage
    log 'info' '0 parameters were specified. Printing usage information'
    exit 1
fi

log 'info' '----------Beginning script----------'
log 'info' "Params: $*"

# Populate variables based on parameters.
while (($# != 0))
do
    case "$1" in
        # If the all parameter is specified, set individual functions to true.
        -a | --all)
            set_host_root_password='true'
            set_host_nutanix_password='true'
            set_cvm_password='true'
            set_prism_element_password='true'
            set_ipmi_password='true' ;;
        -h | --host) set_host_root_password='true' ;;
        -u | --nutanix) set_host_nutanix_password='true' ;;
        -c | --cvm) set_cvm_password='true' ;;
        -e | --prism_element) set_prism_element_password='true' ;;
        -i | --ipmi) set_ipmi_password='true' ;;
        -n | --nodes)
            if [[ $2 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*$ ]]; then
                nodes=$2
                shift
            else 
                log 'error' '--nodes cannot be empty'
                exit 1
            fi ;;
        -r | --cluster) cluster='true' ;;
        --) shift; break ;;
        *) print_usage_error ;;
    esac
    shift
done

# Test if --nodes and --cluster have been set at the same time.
if [[ $nodes ]] && [[ $cluster ]]; then
    log 'error' 'A node selection cannot be specified at the same time as the --cluster flag'
    exit 1
fi

# Test if --nodes and --cluster are both empty.
if [[ ( -z $nodes && -z $cluster ) &&
    ( $set_host_root_password == 'true' ||
    $set_ipmi_password == 'true' ||
    $set_host_nutanix_password == 'true' ) ]]; then
    log 'error' 'Specify either the --cluster flag or the --nodes flag with a comma-separated list of nodes'
    exit 1
fi

# Read password from stdin or prompt for password. Will not echo password back from prompt. 
read -rsp 'Enter New Password: ' password
read -rsp 'Verify New Password: ' vpassword; echo -e '\n'
if [[ "$password" != "$vpassword" ]]; then
    log 'error' 'The new and verification passwords do not match. Exiting.'
    exit 5
fi

# Check if the password meets the complexity requirements.
if ! check_password_policy "$password"; then
    log 'error' 'The new password does not meet the complexity requirements. Exiting.'
    exit 6
fi

# A list of remote hosts is only necessary when setting the host, nutanix, and IPMI passwords.
if [[ $set_host_root_password == 'true' ||
    $set_ipmi_password == 'true' ||
    $set_host_nutanix_password == 'true' ]]; then
    if [[ $cluster == 'true' ]]; then
        # Hostips returns a space-separated list of all hosts in the cluster which is read and stored as an array.
        read -ra hosts <<< "$(hostips)"
    elif [[ $nodes ]]; then
        # Read in the specified nodes and store them as an array. Prefer comma-separated list but added pipe as well.
        IFS=',|' read -r -a hosts <<< "$nodes"
        log 'info' 'Setting nodes to hosts'
    else
        log 'error' 'Unable to determine nodes'
        exit 7
    fi
fi

# Set the 'root' user's password on all specified hosts.
if [[ $set_host_root_password == 'true' ]]; then
    for host in "${hosts[@]}"; do
        set_host_root_password "$host"
    done
fi

# Set the 'nutanix' user's password on all specified hosts.
if [[ $set_host_nutanix_password == 'true' ]]; then
    for host in "${hosts[@]}"; do
        set_host_nutanix_password "$host"
    done
fi

# Set the 'nutanix' user's password on all of the CVMs in the cluster. This cannot be done on individual nodes.
if [[ $set_cvm_password == 'true' ]]; then
    set_cvm_password
fi

# Set the 'admin' user's password in Prism Element.
if [[ $set_prism_element_password == 'true' ]]; then
    set_prism_element_password
fi

# Set the 'ADMIN' user's password on all specified IPMI instances.
if [[ $set_ipmi_password == 'true' ]]; then
    for host in "${hosts[@]}"; do
        set_ipmi_password "$host"
    done
fi

log 'info' '-------------End Script-------------'
#######################################################################################################################
