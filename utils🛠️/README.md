#utiles

###backup\_logs.sh
Backs up logs form one linux system to the host. Can be used to keep logs safe. A crude alternative to Splunk.

###backup\_remote.sh
Back up a remote system. This will take a lot of storage. If we have a lot disk space this script will be used to move all of the files to a backup server periodically. 

###run\_all.sh
A util to run a bash sctipr on a list of linux systems. 


These scripts all take an IP file from it's pwd or as a paramater. There should be one ip per line and no empty lines. 
