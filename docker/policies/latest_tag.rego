package appshield.DS001

import data.lib.docker

__rego_metadata__ := {
	"id": "DS001",
	"title": "Use a tag name in FROM statement",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "When using 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when image is updated",
	"recommended_actions": "Add a tag to the image in the FROM statement",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# image_names returns the image in FROM statement.
image_names[image_name] {
	from := docker.from[_]
	image_name := from.Value[0]
}

# image_tags returns the image and tag.
image_tags[[img, tag]] {
	name := image_names[_]
	[img, tag] = split(name, ":")
}

# image_tags returns the image and "latest" if a tag is not specified.
image_tags[[img, "latest"]] {
	img := image_names[_]
	not contains(img, ":")
}

# fail_latest is true if image is not scratch and
# tag is latest.
fail_latest {
	[img, tag] := image_tags[_]
	img != "scratch"
	tag == "latest"
}

deny[res] {
	fail_latest
	[img, _] := image_tags[_]
	res := sprintf("Specify tag for image %s", [img])
}
