"""Slack socket-mode daemon. Reads everything from the encrypted store."""
import logging
import shlex

from slack_sdk import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse

import db
import runner
import scheduler
from db import GLOBAL_SCOPE, audit, deploy_conn

logger = logging.getLogger(__name__)

HELP = ('Commands: `list`, `deploy <project>/<env>`, `refresh-repos [project]`')


def _notifier(web_client, payload):
    def notify(msg, log=None):
        web_client.chat_postMessage(channel=payload['event']['channel'],
                                    thread_ts=payload['event']['ts'], text=msg)
        if log:
            web_client.chat_postMessage(
                channel=payload['event']['channel'], thread_ts=payload['event']['ts'],
                text='Log output', blocks=[{'type': 'section', 'text': {
                    'type': 'mrkdwn', 'text': f'```{log[-runner.LOG_TAIL:]}```'}}])
    return notify


def _authorised(slack_user_id):
    with deploy_conn() as conn:
        row = conn.execute('SELECT id, username FROM user WHERE slack_user_id=? '
                           'AND disabled=0', (slack_user_id,)).fetchone()
    return row['username'] if row else None


def _resolve(token, envs):
    """Accept `project/env`, or a bare env name when it is unique."""
    if '/' in token:
        project, _, name = token.partition('/')
        matches = [e for e in envs if e['project_name'] == project and e['name'] == name]
    else:
        matches = [e for e in envs if e['name'] == token]
    return matches[0] if len(matches) == 1 else None


def handle(store, client, req):
    event = req.payload.get('event', {})
    if event.get('type') != 'app_mention' or not event.get('channel'):
        return
    notify = _notifier(client.web_client, req.payload)
    actor = _authorised(event.get('user'))
    # drop the leading <@bot> mention, then dispatch on the first word
    try:
        words = [w for w in shlex.split(event.get('text', '')) if not w.startswith('<@')]
    except ValueError:          # an unbalanced quote
        notify(HELP)
        return
    command = words[0].lower() if words else ''
    arg = words[1] if len(words) > 1 else None

    if command not in ('list', 'deploy', 'refresh-repos', 'help'):
        notify(HELP)
        return
    if command == 'help':
        notify(HELP)
        return
    if not actor:
        notify('You are not authorised')
        audit(event.get('user'), 'slack-denied', command)
        return

    envs = db.environments()
    if command == 'list':
        if not envs:
            notify('No environments configured')
            return
        notify('Configured environments:\n' + '\n'.join(
            f"{e['project_name']}/{e['name']}" for e in envs))
    elif command == 'deploy':
        if not arg:
            notify('Usage: `deploy <project>/<env>`')
            return
        env = _resolve(arg, envs)
        if not env:
            notify(f'Environment not found or ambiguous: {arg}')
            return
        project = db.projects(env['project_name'])[0]
        notify(f"Starting deployment for {env['project_name']}/{env['name']}")
        runner.spawn(runner.deploy, project, env, store, actor, notify)
    elif command == 'refresh-repos':
        projects = db.projects(arg)
        if not projects:
            notify(f'No such project: {arg}' if arg else 'No projects configured')
            return
        for project in projects:
            runner.spawn(runner.git_sync, project, store, actor, notify)


def process(store):
    def listener(client, req):
        try:
            handle(store, client, req)
        except Exception:
            logger.exception('failed handling slack event')
        finally:
            client.send_socket_mode_response(
                SocketModeResponse(envelope_id=req.envelope_id))
    return listener


def run(store):
    app_token = store.get(GLOBAL_SCOPE, 0, 'slack_app_token')
    bot_token = store.get(GLOBAL_SCOPE, 0, 'slack_bot_token')
    if not app_token or not bot_token:
        raise SystemExit('slack_app_token / slack_bot_token not set in the store '
                         '(manage.py secret-set global slack_bot_token)')
    runner.reap_running()
    scheduler.start(store)
    client = SocketModeClient(app_token=app_token, web_client=WebClient(token=bot_token))
    client.socket_mode_request_listeners.append(process(store))
    client.connect()
    logger.info('slack-deploy connected')
    import threading
    threading.Event().wait()
