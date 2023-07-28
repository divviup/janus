-- A non-end-user agent or process capable of creating tasks.
CREATE TYPE TASK_CREATOR AS ENUM(
    'UNKNOWN',        -- Catch-all, mainly used in tests.
    'JANUS_CLI',      -- Created by an operator using the janus_cli.
    'AGGREGATOR_API', -- Created by someone or something using the aggregator API.
    'TASKPROV'        -- Created by the taskprov extension.
);

ALTER TABLE tasks ADD COLUMN created_by TASK_CREATOR NOT NULL;
