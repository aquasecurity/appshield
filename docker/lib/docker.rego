package lib.docker

from[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "from"
}

add[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "add"
}

run[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "run"
}

copy[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "copy"
}

stage_copies[stage_name] = copies {
	stage := input.stages[stage_name]
	copies := [copy | copy := stage[_]; copy.Cmd == "copy"]
}

entrypoint[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "entrypoint"
}

stage_entrypoints[stage_name] = entrypoints {
	stage := input.stages[stage_name]
	entrypoints := [entrypoint | entrypoint := stage[_]; entrypoint.Cmd == "entrypoint"]
}

expose[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "expose"
}

user[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "user"
}

workdir[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "workdir"
}