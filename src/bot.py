import logging
import tempfile
import subprocess
import configparser
import shutil

from threading import (
    Thread,
    Event
)

from slack_sdk import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

RUNNING_JOBS = {}
ENVIRONMENTS = {}
GLOBAL_SETTINGS = {}


def run_cmd(web_client, payload, env):
    RUNNING_JOBS[env] = True
    envs, _ = get_config()
    env_info = envs[env]

    with tempfile.NamedTemporaryFile(suffix='.log') as logfile:
        playbook_cmd = shutil.which("ansible-playbook")
        playbook_params = env_info['playbook_params']
        completed_ps = subprocess.run(
            [playbook_cmd] + playbook_params.split(' '),
            stdout=logfile,
            stderr=logfile,
            cwd=env_info['working_dir']
        )
        logfile.seek(0)
        output_txt = logfile.read().decode()
        result_msg = 'Deployment done' if completed_ps.returncode == 0 else 'Deployment failed'
        web_client.chat_postMessage(
            channel=payload["event"]["channel"],
            thread_ts=payload["event"]["ts"],
            text=result_msg
        )
        if output_txt:
            print(output_txt)
            web_client.chat_postMessage(
                channel=payload["event"]["channel"],
                thread_ts=payload["event"]["ts"],
                text='Log Output',
                blocks=[{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```{output_txt[-2000:]}```"
                    }
                }]
            )

    RUNNING_JOBS[env] = False


def send_response(client, req, msg):
    response = client.web_client.chat_postMessage(
        channel=req.payload["event"]["channel"],
        thread_ts=req.payload["event"]["ts"],
        text=msg
    )
    return response


def start_deploy(client, req):
    envs, global_settings = get_config()
    if req.payload["event"]['user'] not in global_settings['user_whitelist'].split(','):
        send_response(client, req, "You are not authorised to deploy")
        return
    env_name = req.payload["event"]["text"].split('deploy')
    if len(env_name) != 2:
        send_response(client, req, "Could not parse environment name")
        return
    env_name = env_name[-1].strip()
    if env_name not in envs:
        send_response(client, req, "Environment not found")
        return
    if RUNNING_JOBS.get(env_name):
        send_response(client, req, "Deployment already for environment")
        return

    send_response(client, req, "Starting deployment for: " + env_name)

    thread = Thread(
        target=run_cmd,
        args=(client.web_client, req.payload, env_name)
    )
    thread.start()


def process(client, req):
    envs, global_settings = get_config()

    if global_settings.get('debug', '').lower() == 'true':
        print('------------')
        print(client, req.payload)
        print('------------')

    if not req.payload["event"]["channel"]:
        return

    if req.payload["event"]["type"] == "app_mention" \
            and "list" in req.payload["event"]["text"]:
        send_response(client, req, "Configured environments: " + ','.join(envs))

    if req.payload["event"]["type"] == "app_mention" \
            and "deploy" in req.payload["event"]["text"]:

        start_deploy(client, req)

    # Acknowledge the request
    response = SocketModeResponse(envelope_id=req.envelope_id)
    client.send_socket_mode_response(response)


def get_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    GLOBAL_SETTINGS = dict(config['global_settings'])
    for section in config.sections():
        if section.startswith('env:'):
            env_name = section.split('env:')[1]
            ENVIRONMENTS[env_name] = dict(config[section])
    return ENVIRONMENTS, GLOBAL_SETTINGS


def run():
    envs, global_settings = get_config()
    client = SocketModeClient(
        app_token=global_settings.get("slack_app_token"),
        web_client=WebClient(token=global_settings.get("slack_bot_token"))
    )
    client.socket_mode_request_listeners.append(process)
    client.connect()
    Event().wait()


if __name__ == '__main__':
    run()
