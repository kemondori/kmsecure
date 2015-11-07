
-s SOFT MODE | -h HARD MODE [optional - default to hard]
-c CRYPT WITH THE GIVEN KEY | -d DECRYPT WITH THE GIVEN KEY [required]
-l LOCATION FOR SOFT MODE (mid point of the crypting, range 0-100. common value is 50) [required for soft mode]
-p PERCENTUAL OF CRYPTING FOR SOFT MODE (smaller is faster, range 0-100. common value is 20) [required for soft mode]
-r DIRECTORY TO CRYPT (all subdirectories will be handled too) [required]
-i IF A FILENAME CONTAINS THIS STRING IT WILL BE IGNORED (useful for extensions) [optional]

example soft crypt:
-s -c my_key -r path -i [similar_filename_to_ignore] -l 50 -p 20

example soft decrypt:
-s -d my_key -r path -i [similar_filename_to_ignore] -l 50 -p 20

example hard crypt:
-c my_key -r path -i [similar_filename_to_ignore]

example hard decrypt:
-d my_key -r path -i [similar_filename_to_ignore]
