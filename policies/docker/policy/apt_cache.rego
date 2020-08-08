# @title: Clean APT cache
# @description: It is a good practice to clean the APT cache.
# @recommended_actions: Add 'RUN apt-get clean' line to the Dockerfile
# @severity: Medium
# @id: DS003
# @links: 

package main

title = "Clean APT cache"
description = "It is a good practice to clean the APT cache."
recommended_actions = "Add 'RUN apt-get clean' line to the Dockerfile"
severity = "Medium"
id = "DS003"
links = ""

# runsAPT is true if there is `apt` command.
runs_apt {
  some i
  input[i].Cmd == "run"
  val := input[i].Value[_]
  re_match(`\bapt\b`, val)
}

# APTCleanCache is true if there is an apt-get clean
# command.
APTCleanCache {
  some i
  input[i].Cmd == "run"
  val := input[i].Value[_]
  re_match(`apt clean|apt-get clean`, val)
}

# failAPTCleanCache is true if apt-get clean
# is included.
failAPTCleanCache {
  runs_apt
  not APTCleanCache
}

deny[msg] {
  failAPTCleanCache
  msg := sprintf(
    "{\"id\": \"%s\", \"title\": \"%s\", \"description\":\"%s\", \"recommended_actions\":\"%s\", \"severity\":\"%s\"}",
    [id, title, description, recommended_actions, severity])
}
