package main

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
  msg = sprintf("specify tag for image %s", [img])
}
