FROM node:16.18.0

ENV NODE_ENV=production

WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]

RUN npm install --production

COPY . .

LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.allow_env_override"="NODE_URL,RESULTS_BUCKET,KEY_BUCKET,PRIMUS_PROJECT_NUMBER,PRIMUS_PROJECT_LOCATION,PRIMUS_PROJECT_ID,PRIMUS_WORKLOAD_IDENTITY_POOL,PRIMUS_WIP_PROVIDER,PRIMUS_SERVICEACCOUNT,PRIMUS_KEYRING,PRIMUS_KEY"

CMD [ "node", "index.js" ]