# @title: Use a tag name in FROM statement
# @description: When using 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when image is updated
# @recommended_actions: Add a tag to the image in the FROM statement
# @severity: Medium
# @id: DS001
# @links: 

package main

title = "Use a tag name in FROM statement"
description = "When using 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when image is updated"
recommended_actions = "Add a tag to the image in the FROM statement"
severity = "Medium"
id = "DS001"
links = ""

# getImage returns the image in FROM statement.
getImage = image {
  some i
  input[i].Cmd == "from"
  val := input[i].Value
  image = val[i]
}

# getImageTag returns the image and tag.
getImageTag() = [img, tag] {
  i := getImage
  [img, tag] = split(i, ":")
}

# getImageTag returns the image and "latest" if
# a tag is not specified.
getImageTag() = [img, "latest"] {
  img := getImage
  not contains(img, ":")
}

# failLatest is true if image is not scratch and
# tag is latest.
failLatest {
  [img, tag] := getImageTag
  img != "scratch"
  tag == "latest"
}

deny[msg] {
  failLatest
  [img, _] := getImageTag
  msg := sprintf(
    "{\"id\": \"%s\", \"title\": \"%s\", \"description\":\"%s\", \"recommended_actions\":\"%s\", \"severity\":\"%s\"}",
    [id, title, description, recommended_actions, severity])
}
