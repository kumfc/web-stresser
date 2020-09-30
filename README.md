# web-stresser  
#### What is it about?
This project was originally maintained during [Digital Security](https://github.com/DSecurity) Summer of Hack 2020 internship. Main point of the tool is to simplify deployment of web stressing infrastructure, control it and collect usage stats.

### TODO
1. Control panel frontend (React)
2. Stats system
3. Finish panel-instance interactor


#### Setup:  
- Create a new service account with Compute Engine privileges, get the json key and put into panel/backend/app/secrets/main-api-key.json  
- Generate ssh key for the whole project to use for every VM here \- https://console.cloud.google.com/compute/metadata/sshKeys as well as into main-ssh-key  
- Create instance template with the name **"main-template"**, you can setup any VM you want, but the project was configured to run on Ubuntu18 \(you might need to change some setup commands\)  
- Create firewall rule on your or default network to allow incoming traffic to port 9009 on the instances from any ip \(0.0.0.0\) or **BETTER** the specific ip on which the frontend server will be running, which will be used by the backend api to launch attacks
