package appshield.dockerfile.DS001

__rego_metadata__ := {
	"id": "DS001",
	"title": "Use a tag name in FROM statement",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "When using 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when image is updated",
	"recommended_actions": "Add a tag to the image in the FROM statement",
}

# get_image returns the image in FROM statement.
get_image = image {
	some i
	input.stages[name][i].Cmd == "from"
	val := input.stages[name][i].Value
	image = val[i]
}

# get_image_tag returns the image and tag.
get_image_tag = [img, tag] {
	i := get_image
	[img, tag] = split(i, ":")
}

# get_image_tag returns the image and "latest" if
# a tag is not specified.
get_image_tag = [img, "latest"] {
	img := get_image
	not contains(img, ":")
}

# fail_latest is true if image is not scratch and
# tag is latest.
fail_latest {
	[img, tag] := get_image_tag
	img != "scratch"
	tag == "latest"
}

deny[res] {
	fail_latest
	[img, _] := get_image_tag
	msg := sprintf("Specify tag for image %s", [img])
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
