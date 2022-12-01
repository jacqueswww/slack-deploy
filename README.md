# slack-deploy
Deploy ansible playbook using a slack bot

Example *config.ini*:

```
[global_settings]
debug=true
user_whitelist=USC13332V
SLACK_BOT_TOKEN=xoxb-....
SLACK_APP_TOKEN=xapp-....

[env:preprod]
working_dir=/home/jacques/projects/project
playbook_params=-i project.hosts project.yml -b --tags deploy

[env:preprod-backend]
working_dir=/home/jacques/projects/project2
playbook_params=-i project2.hosts project2.yml --tags deploy
```
