# @title: Image user should not be 'root'
# @description: It is a good practice to run the container as a non-root user.
# @recommended_actions: Add 'USER <non root user name>' line to the Dockerfile
# @severity: High
# @id: DS002
# @links: 

package main

title = "Image user should not be 'root'"
description = "It is a good practice to run the container as a non-root user."
recommended_actions = "Add 'USER <non root user name>' line to the Dockerfile"
severity = "High"
id = "DS002"
links = "" 


# getUser returns all the usernames from
# the USER command.
getUser[user] {
  some i
  input[i].Cmd == "user"
  val := input[i].Value
  user := val[_]
}

# failUserCount is true if there is no USER command.
failUserCount {
  count(getUser) < 1
}

# failLastUserRoot is true if the last USER command
# value is "root"
failLastUserRoot {
   user := cast_array(getUser)
   len := count(getUser)
   user[len-1] == "root"
}

deny[msg] {
  failUserCount
  msg := sprintf(
    "{\"id\": \"%s\", \"title\": \"%s\", \"description\":\"%s\", \"recommended_actions\":\"%s\", \"severity\":\"%s\"}",
    [id, title, description, recommended_actions, severity])
}

deny[msg] {
  failLastUserRoot
  msg := sprintf(
    "{\"id\": \"%s\", \"title\": \"%s\", \"description\":\"%s\", \"recommended_actions\":\"%s\", \"severity\":\"%s\"}",
    [id, title, description, recommended_actions, severity])
}
