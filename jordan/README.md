# Jordan's project work

## Setup
Install the devscripts Ubuntu package

`sudo apt update && sudo apt install devscripts`

Download the Ubuntu popularity contest list:

```
wget https://popcon.ubuntu.com/by_inst
mv by_inst all_packages

# remove comments, print only the package name and the top 1000 entries
cat all_packages | grep -ve '^#' | awk '{print $2}' | head -n1000 > top_1000_packages
```

## Download Build Logs

Download all build logs for these packages:
`mkdir buildlogs && cd buildlogs && while read pkg; do getbuildlog $pkg last amd64; done < ../top_1000_packages`
 
