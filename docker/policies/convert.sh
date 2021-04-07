#!/bin/bash

input_dir="$1"
output_dir="$2"

for d in $(ls "$input_dir"); do
	go run convert.go -in "$input_dir/$d/query.rego" -out "$output_dir/$d.rego.convert"
done
