package appshield.dockerfile.DS002

# Test failUserCount empty
test_failUserCount_empty {
  failUserCount with input as {"command": {"foo":[
    {"Cmd": "user", "Value": []}
  ]}}
}

# Test failUserCount not empty
test_failUserCount_not_empty {
  not failUserCount with input as {"command": {"foo":[
    {"Cmd": "user", "Value": ["user1", "user2"]}
  ]}}
}

# Test failLastUserRoot is root
test_failLastUserRoot_is_root {
  failLastUserRoot with input as {"command": {"foo":[
    {"Cmd": "user", "Value": ["user1", "root"]}
  ]}}
}

# Test failLastUserRoot not root
test_failLastUserRoot_not_root {
  not failLastUserRoot with input as {"command": {"foo":[
    {"Cmd": "user", "Value": ["root", "user2"]}
  ]}}
}

# Test failLastUserRoot no user
test_failLastUserRoot_not_root {
  not failLastUserRoot with input as {"command": {"foo":[
    {"Cmd": "user", "Value": []}
  ]}}
}
