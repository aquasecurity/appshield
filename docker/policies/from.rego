package appshield.dockerfile.DS001

__rego_metadata__ := {
    "id": "DS001",
    "title": "Use a tag name in FROM statement",
    "version": "v1.0.0",
    "severity": "Medium",
    "type": "Dockerfile Security Check",
    "description": "When using 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when image is updated",
    "recommended_actions": "Add a tag to the image in the FROM statement",
}

# getImage returns the image in FROM statement.
getImage = image {
  some i
  input.stages[name][i].Cmd == "from"
  val := input.stages[name][i].Value
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

deny[res] {
  failLatest
  [img, _] := getImageTag
  msg := sprintf("Specify tag for image %s", [img])
  res := {
  	"msg": msg,
    "id":  __rego_metadata__.id,
    "title": __rego_metadata__.title,
    "severity": __rego_metadata__.severity,
    "type":  __rego_metadata__.type,
    }
}
