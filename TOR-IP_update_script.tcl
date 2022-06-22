# TOR-IP update script 
# by SylPrz
# This script is used to update the TOR-IP object-group containing suspicious IP addresses.
# v0.85 Cisco IOS

::cisco::eem::event_register_timer cron name _crontimer cron_entry "0 3 * * *" maxrun_sec 600

namespace import ::cisco::eem::*
namespace import ::cisco::lib::*

# Procedures definition

proc delete_file {file_path syslog_msg cli errorInfo} {
	if [file exists $file_path] {
		if {[string length $syslog_msg] > 0} {
			action_syslog priority info msg $syslog_msg
		}
		if [catch {cli_write $cli "delete $file_path"} result] {
			error $result $errorInfo
		}
		if [catch {cli_read_pattern $cli "Delete filename"} result] {
			error $result $errorInfo
		}
		if [catch {cli_write $cli "\n"} result] {
			error $result $errorInfo
		}
		if [catch {cli_read_pattern $cli "Delete"} result] {
			error $result $errorInfo
		}
		if [catch {cli_write $cli "\n"} result] {
			error $result $errorInfo
		}
		if [catch {cli_read $cli } result] {
			error $result $errorInfo
		}
	}
}

set errorInfo ""
action_syslog priority info msg "EEM script was triggered"

# Open CLI

if [catch {cli_open} result] {
    error $result $errorInfo
	action_syslog priority info msg "EEM script cli error"
} else {
    array set cli $result
	action_syslog priority info msg "EEM script cli opened"
}

# Delete blacklist_updt.txt if exist

delete_file "flash:ipblacklist_updt.txt" "EEM script found old ipblacklist_updt.txt and will delete it" $cli(fd) $errorInfo

# Download blacklist.txt and save it as blacklist_updt.txt

if [catch {cli_write $cli(fd) "copy scp://username:password@ipaddress/ipblacklist.txt flash:ipblacklist_updt.txt"} result] {
	error $result $errorInfo
}
if [catch {cli_read_pattern $cli(fd) "Destination filename"} result] {
	error $result $errorInfo
}
if [catch {cli_write $cli(fd) "\n"} result] {
	error $result $errorInfo
}
if [catch {cli_read $cli(fd) } result] {
	error $result $errorInfo
} else {
	if {[lsearch -glob $result *Failed* ] != -1} {
		delete_file "flash:ipblacklist_updt.txt" "EEM script could not download ipblacklist_updt.txt" $cli(fd) $errorInfo
	}
	if {[lsearch -glob $result *Error* ] != -1} {
		action_syslog priority info msg "EEM script could not connect to SCP server"
	}
}

# Set the size of files if exists  

set ipblacklist_file_size {0}
if [file exists "flash:ipblacklist.txt"] {
	file stat "flash:ipblacklist.txt" file
	set ipblacklist_file_size $file(size)
	action_syslog priority info msg "EEM script found ipblacklist.txt, file size: $ipblacklist_file_size"
}

set ipblacklist_updt_file_size {0}
if [file exists "flash:ipblacklist_updt.txt"] {
	file stat "flash:ipblacklist_updt.txt" file_updt
	set ipblacklist_updt_file_size $file_updt(size)
	action_syslog priority info msg "EEM script found ipblacklist_updt.txt, file size: $ipblacklist_updt_file_size"
} else {
	action_syslog priority info msg "EEM script did not find ipblacklist_updt.txt"
}

# Compare the files. Start update process if ipblacklist_updt.txt is different than ipblacklist.txt

if [expr $ipblacklist_updt_file_size != $ipblacklist_file_size && $ipblacklist_updt_file_size > 0] {
	action_syslog priority info msg "EEM script found that ipblacklist_updt.txt is different then ipblacklist.txt"
	delete_file "flash:ipblacklist.txt" "" $cli(fd) $errorInfo

	# Read object-group network TOR-IP

	if [catch {cli_write $cli(fd) "show object-group TOR-IP"} result] {
		error $result $errorInfo
	}
	if [catch {cli_read $cli(fd) } result] {
		error $result $errorInfo
	} else {
		set cmd_output $result
	}
	set current_ip_list [split $cmd_output "\r"]

	# Read downloaded file

	set fp [open "flash:ipblacklist_updt.txt" r]
	set file_data [read $fp]
	close $fp
	set new_ip_list [split $file_data "\n"]
	
	# Compare current list with downloaded list

	set diff {}
	foreach elem $new_ip_list {
		if {[lsearch -glob $current_ip_list *$elem ] == -1} {
		  lappend diff $elem
		}
	}
	if {[llength $diff] > 0} {
		action_syslog priority info msg  "EEM script compared the lists and found [llength $diff] elements to add:"
		foreach elem $diff {
			action_syslog priority info msg $elem
		}

		# Add addresess to object-group

		if [catch {cli_exec $cli(fd) "configure terminal"} result] {
			error $result $errorInfo
		}
		if [catch {cli_exec $cli(fd) "object-group network TOR-IP"} result] {
			error $result $errorInfo
		}
		foreach elem $diff {
			if { [regexp {^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ ]*)$} $elem ] } {
				if [catch {cli_exec $cli(fd) "host $elem"} result] {
					error $result $errorInfo
				}
			} else {
				if [catch {cli_exec $cli(fd) $elem} result] {
					error $result $errorInfo
				}
			}
		}
		if [catch {cli_exec $cli(fd) "end"} result] {
			error $result $errorInfo
		}

		# Write config to nvram
		
		if [catch {cli_write $cli(fd) "write memory"} result] {
			error $result $errorInfo
		}
		if [catch {cli_read $cli(fd) } result] {
			error $result $errorInfo
		}
	} else {
		action_syslog priority info msg  "EEM script compared the lists but elements to add were not found"
	}
	
	# Leave ipblacklist.txt file for next check
		
	if [catch {cli_write $cli(fd) "rename flash:ipblacklist_updt.txt flash:ipblacklist.txt"} result] {
		error $result $errorInfo
	}
	if [catch {cli_read_pattern $cli(fd) "Destination filename"} result] {
		error $result $errorInfo
	}
	if [catch {cli_write $cli(fd) "\n"} result] {
		error $result $errorInfo
	}
	if [catch {cli_read $cli(fd) } result] {
		error $result $errorInfo
	}
} else {
	action_syslog priority info msg  "EEM script found nothing to add"
	delete_file "flash:ipblacklist_updt.txt" "" $cli(fd) $errorInfo
}

# Close the CLI connection

if [catch {cli_close $cli(fd) $cli(tty_id)} result] {
	error $result $errorInfo
}

action_syslog priority info msg "EEM script execution has finished"
