COMMANDS:

-c CRYPT WITH THE GIVEN KEY | -d DECRYPT WITH THE GIVEN KEY **[required]**

-s SOFT MODE | -h HARD MODE **[optional - default to hard]**

-r DIRECTORY TO CRYPT (all subdirectories will be handled too) **[required]**

-l LOCATION FOR SOFT MODE (mid point of the crypting, range 0-100. common value is 50) [required for soft mode]

-p PERCENTAGE OF CRYPTING FOR SOFT MODE (smaller is faster, range 0-100. common value is 20) [required for soft mode]

-i IF A FILENAME CONTAINS THIS STRING IT WILL BE IGNORED (useful for extensions) [optional]

example soft crypt:
-s -c my_key -r path -i [similar_filename_to_ignore] -l 50 -p 20

example soft decrypt:
-s -d my_key -r path -i [similar_filename_to_ignore] -l 50 -p 20

example hard crypt:
-c my_key -r path -i [similar_filename_to_ignore]

example hard decrypt:
-d my_key -r path -i [similar_filename_to_ignore]
