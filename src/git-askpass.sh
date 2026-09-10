#!/bin/sh
# Hands the read-only PAT to git over a pipe. Contains no secret itself: the
# token arrives in the child's environment, never in argv or the remote URL.
exec printf '%s\n' "$SLACK_DEPLOY_GIT_PAT"
