The Dockerfile rego policies can find the following issues:

1. Last USER in the file should not be root (but there needs to be at least one USER statment)
2. Tag the version of the FROM image explicitly (unless its scratch)
3. Avoid using "latest" in the FROM statment
4. Delete the apt-get lists after installing 

Reference: https://github.com/hadolint/hadolint
