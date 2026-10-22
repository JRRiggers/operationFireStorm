My submission for operation firestorm coding challenge

Compiled using the latest rust version and using wsl on ubuntu,
When running from the command line add an argument of 1 or 2 depending on which stage you are testing it against

cargo run 1

cargo run 2

Test files from the challenge are:
- stage1:
https://github.com/CoreTechSecurity/fire-storm 
- stage2:
https://fire-storm.s3.eu-north-1.amazonaws.com/stage-2.zip

Once the program has started to switch stages you'll need kill the program and run it with a different argument.

In stage 1 it will output a "ctfs.pdf" file and use a ctfs packet count constant for the minimum amount of packets it expects
For stage 2 output files are "file_id".pdf, this solution doesnt impliment checksum verification. 