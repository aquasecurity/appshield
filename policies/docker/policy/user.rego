package main

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
  msg = "specify at least 1 USER command in Dockerfile"
}

deny[msg] {
  failLastUserRoot
  msg = "Last USER command in Dockerfile should not be root"
}
